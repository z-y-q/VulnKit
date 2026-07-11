// 灵眸 v6.0 — 类型安全的消息发送器（UI/content 侧调用）
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
 */
export async function sendToContent<T extends ContentMessage['type']>(
  msg: Extract<ContentMessage, { type: T }>,
): Promise<ContentResponseMap[T] | null> {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return null;
  try {
    return (await browser.tabs.sendMessage(tab.id, msg)) as ContentResponseMap[T];
  } catch {
    return null;
  }
}
