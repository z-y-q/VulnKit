// 灵眸 v6.0 — 消息来源校验
// background.onMessage 的统一前置门控：只放行本扩展自身（页面或 content script）发出的消息，
// 并按消息类型施加更细的来源策略（扩展页面 / content script / 任意可信来源）。
//
// 安全模型：
// - 浏览器保证 runtime.onMessage 的 sender 反映真实来源；
// - sender.id === runtime.id ⇒ 来自本扩展（页面或我们注入的 content script）；
// - 外部扩展 / 网页（未声明 externally_connectable）无法伪造本扩展 id，因此被天然排除；
// - 在「本扩展」内部再按 tab/origin 区分扩展页面与 content script，收敛高权限操作的来源面。

import type { Browser } from 'wxt/browser';
import type { BackgroundMessage } from '@/lib/types/messaging';

// browser 由 WXT 作为全局注入（与 background.ts / context-menus.ts 等保持一致），无需 import。

/** 来源策略：决定某类消息允许由谁发起。 */
export type SenderPolicy = 'any-trusted' | 'extension-page' | 'content-script';

/** 是否来自本扩展（页面或我们注入的 content script）。 */
export function isOwnExtension(sender: Browser.runtime.MessageSender | undefined): boolean {
  return !!sender && sender.id === browser.runtime.id;
}

/** 是否来自本扩展的页面（popup/options/sidepanel 等）：本扩展 id、无 tab、url 落在扩展 origin。 */
export function isExtensionPage(sender: Browser.runtime.MessageSender | undefined): boolean {
  if (!isOwnExtension(sender) || sender!.tab) return false;
  const url = sender!.url || '';
  // 无 url（理论上不会发生）按宽松处理；否则必须是扩展自身页面
  return url === '' || url.startsWith(browser.runtime.getURL(''));
}

/** 是否来自本扩展注入的 content script：本扩展 id 且带 tab。 */
export function isContentScript(sender: Browser.runtime.MessageSender | undefined): boolean {
  return isOwnExtension(sender) && !!sender!.tab;
}

/** sender 是否满足指定策略。 */
export function senderMatches(
  sender: Browser.runtime.MessageSender | undefined,
  policy: SenderPolicy,
): boolean {
  switch (policy) {
    case 'any-trusted':
      return isOwnExtension(sender);
    case 'extension-page':
      return isExtensionPage(sender);
    case 'content-script':
      return isContentScript(sender);
  }
}

/**
 * 每类消息的来源策略表。
 * - 抓取/探测类：扩展页面与 content script 都可能发起，且已有 URL guard / 速率限制兜底 → any-trusted；
 * - 伪造请求头 / JS 阻断：仅扩展面板触发，content script 不应越权 → extension-page；
 * - 若依 Hook 注册/注销：仅 RuoYi 面板触发 → extension-page；
 * - VK_RUOYI_HOOK_EVENT：由 content bridge 转发 → content-script。
 */
export const MESSAGE_POLICY: Record<BackgroundMessage['type'], SenderPolicy> = {
  FETCH_URL: 'any-trusted',
  FETCH_URL_AUTH: 'any-trusted',
  FETCH_PROBE: 'any-trusted',
  FETCH_CORS_PROBE: 'any-trusted',
  FETCH_HEADER_PROBE: 'any-trusted',
  FETCH_DNS_RESOLVE: 'any-trusted',
  FETCH_WAF_PROBE: 'any-trusted',
  FETCH_IMAGE: 'any-trusted',
  QUERY_JS_BLOCK: 'extension-page',
  TOGGLE_JS: 'extension-page',
  SPOOF_UA: 'extension-page',
  RESET_SPOOF_UA: 'extension-page',
  SPOOF_HEADERS: 'extension-page',
  RESET_SPOOF_HEADERS: 'extension-page',
  REGISTER_RUOYI_HOOK: 'extension-page',
  UNREGISTER_RUOYI_HOOK: 'extension-page',
  VK_RUOYI_HOOK_EVENT: 'content-script',
};

/** 校验消息是否被授权：类型已知且 sender 满足其策略。未知类型一律拒绝。 */
export function isAuthorized(
  message: { type?: string } | null | undefined,
  sender: Browser.runtime.MessageSender | undefined,
): message is BackgroundMessage {
  if (!message || typeof message.type !== 'string') return false;
  const policy = MESSAGE_POLICY[message.type as BackgroundMessage['type']];
  if (!policy) return false; // 未知类型拒绝
  return senderMatches(sender, policy);
}
