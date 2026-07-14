// 类型安全的消息发送器（UI/content 侧调用）
// 用法：const r = await sendMessage({ type: 'FETCH_URL', url });  // r 自动推断为 FetchResult

import type {
  BackgroundMessage,
  ContentMessage,
  FetchResult,
  ProbeResult,
  DnsResolveResult,
  DomFingerprint,
} from '@/lib/types/messaging';

// 消息类型 → 期望响应类型
export interface ResponseMap {
  FETCH_URL: FetchResult<string>;
  FETCH_URL_AUTH: FetchResult<string>;
  FETCH_PROBE: ProbeResult;
  FETCH_CORS_PROBE: ProbeResult;
  FETCH_HEADER_PROBE: ProbeResult;
  FETCH_DNS_RESOLVE: DnsResolveResult;
  FETCH_DNS_PROBE: ProbeResult;
  FETCH_WAF_PROBE: ProbeResult;
  FETCH_IMAGE: FetchResult<string>;
  QUERY_JS_BLOCK: { blocked: boolean };
  TOGGLE_JS: { success: boolean; error?: string };
  SPOOF_UA: { success: boolean; error?: string };
  RESET_SPOOF_UA: { success: boolean; error?: string };
  SPOOF_HEADERS: { success: boolean; error?: string };
  RESET_SPOOF_HEADERS: { success: boolean; error?: string };
  REGISTER_RUOYI_HOOK: { success: boolean; error?: string };
  UNREGISTER_RUOYI_HOOK: { success: boolean; error?: string };
  VK_RUOYI_HOOK_EVENT: void;
}

export interface ContentResponseMap {
  VK_VUE_DETECT: unknown;
  VK_REACT_DETECT: unknown;
  VK_ANGULAR_DETECT: unknown;
  VK_SOURCEMAP_DETECT: unknown;
  VK_SVELTE_DETECT: unknown;
  VK_VUE_STORE_EXPLORE: unknown;
  VK_REACT_STORE_EXPLORE: unknown;
  VK_ANGULAR_STORE_EXPLORE: unknown;
  VK_PAGE_INSPECT: unknown;
  VK_VUE_ATTACK: { success: boolean; error?: string; guards?: Record<string, number>; disabledMeta?: number; path?: string };
  CONTEXT_EXTRACT_LINKS: { count: number };
  VK_FINGERPRINT_DOM: DomFingerprint;
}

/**
 * 向 background 发送消息，返回类型安全的响应。
 * 失败时（runtime 错误）抛出 Error。
 */
export function sendMessage<T extends BackgroundMessage['type']>(
  msg: Extract<BackgroundMessage, { type: T }>,
): Promise<ResponseMap[T]> {
  return browser.runtime.sendMessage(msg);
}

/**
 * 向当前 tab 的 content script 发送消息。
 *
 * 容错：content script 是声明式注入（document_start），只在新导航时自动注入。
 * 若用户在「已打开但早于扩展加载」的 tab 上调用（典型如首次打开 side-panel），
 * 该 tab 上没有 content script，sendMessage 会抛 "Receiving end does not exist"。
 * 此时主动用 scripting.executeScript 注入 bridge.js（bridge 内有 __VK_CONTENT_BRIDGE__
 * 守卫，幂等），短暂等待监听器注册后重试一次。
 */
const BRIDGE_CONTENT_FILE = '/content-scripts/bridge.js';

export async function sendToContent<T extends ContentMessage['type']>(
  msg: Extract<ContentMessage, { type: T }>,
): Promise<ContentResponseMap[T] | null> {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return null;
  try {
    return (await browser.tabs.sendMessage(tab.id, msg)) as ContentResponseMap[T];
  } catch {
    // content script 未就绪 —— 主动注入后重试一次
    try {
      await browser.scripting.executeScript({
        target: { tabId: tab.id },
        files: [BRIDGE_CONTENT_FILE],
      });
      // 等待 bridge 的 onMessage 监听器注册
      await new Promise((r) => setTimeout(r, 60));
      return (await browser.tabs.sendMessage(tab.id, msg)) as ContentResponseMap[T];
    } catch {
      return null;
    }
  }
}
