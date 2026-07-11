// 灵眸 v6.0 — Background Service Worker
// 编排：消息分发 → fetchers / dnr / context-menus / ruoyi-hook
// SSRF 防护统一在分发层用 url-guard 校验。

import { isAllowedUrl, validateProbeUrl } from '@/lib/core/url-guard';
import {
  fetchUrl,
  fetchImage,
  fetchZoomEyeAuth,
  fetchProbe,
  fetchCorsProbe,
  fetchHeaderProbe,
  fetchWafProbe,
  fetchDnsProbe,
  fetchDnsResolve,
} from '@/lib/background/fetchers';
import {
  queryJsBlocked,
  toggleJs,
  spoofUa,
  resetSpoofUa,
  spoofHeaders,
  resetSpoofHeaders,
  restoreSpoofState,
} from '@/lib/background/dnr';
import { createContextMenus, handleMenuClick } from '@/lib/background/context-menus';
import {
  registerRuoYiHook,
  unregisterRuoYiHook,
  restoreRuoYiHook,
  cleanupRuoYiTabOnClose,
} from '@/lib/background/ruoyi-hook';
import type { BackgroundMessage } from '@/lib/types/messaging';

export default defineBackground(() => {
  // ====== 消息分发 ======
  browser.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (!msg || !msg.type) return false;
    const message = msg as BackgroundMessage;
    handle(message).then(
      (resp) => sendResponse(resp),
      (e) => sendResponse({ error: (e as Error).message }),
    );
    return true; // 异步响应
  });

  async function handle(message: BackgroundMessage): Promise<any> {
    switch (message.type) {
      // —— 抓取代理 ——
      case 'FETCH_URL': {
        if (!isAllowedUrl(message.url)) {
          return { error: 'URL not allowed (must be http/https, no private IPs)' };
        }
        const r = await fetchUrl(message.url, message.tailOnly, message.timeout);
        return r.success ? { data: r.data } : { error: r.error };
      }
      case 'FETCH_URL_AUTH': {
        if (!isAllowedUrl(message.url)) {
          return { error: 'URL not allowed (must be http/https, no private IPs)' };
        }
        if (message.provider !== 'zoomeye') {
          return { error: 'Unknown provider: ' + (message.provider || '(none)') };
        }
        const r = await fetchZoomEyeAuth(message.url, message.key);
        return r.success ? { data: r.data } : { error: r.error };
      }

      // —— 探测类 ——
      case 'FETCH_PROBE': {
        const v = validateProbeUrl(message.url);
        if ('error' in v) return { error: v.error };
        return fetchProbe(v.parsed.href, message);
      }
      case 'FETCH_CORS_PROBE': {
        const v = validateProbeUrl(message.url);
        if ('error' in v) return { error: v.error };
        if (!isAllowedUrl(v.parsed.href)) return { error: 'URL not allowed (no private IPs)' };
        return fetchCorsProbe(v.parsed.href, message);
      }
      case 'FETCH_HEADER_PROBE': {
        const v = validateProbeUrl(message.url);
        if ('error' in v) return { error: v.error };
        if (!isAllowedUrl(v.parsed.href)) return { error: 'URL not allowed (no private IPs)' };
        return fetchHeaderProbe(v.parsed.href, message.timeout);
      }
      case 'FETCH_DNS_RESOLVE': {
        if (!message.hostname || typeof message.hostname !== 'string') {
          return { error: 'Invalid hostname' };
        }
        return fetchDnsResolve(message.hostname, message.recordType);
      }
      case 'FETCH_DNS_PROBE': {
        const v = validateProbeUrl(message.url);
        if ('error' in v) return { error: v.error };
        if (!isAllowedUrl(v.parsed.href)) return { error: 'URL not allowed (no private IPs)' };
        return fetchDnsProbe(v.parsed.href, message.method, message.timeout);
      }
      case 'FETCH_WAF_PROBE': {
        const v = validateProbeUrl(message.url);
        if ('error' in v) return { error: v.error };
        if (!isAllowedUrl(v.parsed.href)) return { error: 'URL not allowed (no private IPs)' };
        return fetchWafProbe(v.parsed.href, message);
      }
      case 'FETCH_IMAGE': {
        if (!isAllowedUrl(message.url)) {
          return { error: 'URL not allowed (must be http/https, no private IPs)' };
        }
        const r = await fetchImage(message.url);
        return r.success ? { data: r.data } : { error: r.error };
      }

      // —— JS 阻断 ——
      case 'QUERY_JS_BLOCK':
        return { blocked: await queryJsBlocked() };
      case 'TOGGLE_JS':
        try {
          await toggleJs(message.enable);
          return { success: true };
        } catch (e) {
          return { success: false, error: (e as Error).message };
        }

      // —— 请求伪造 ——
      case 'SPOOF_UA':
        try {
          await spoofUa(message.url, message.userAgent);
          return { success: true };
        } catch (e) {
          return { success: false, error: (e as Error).message };
        }
      case 'RESET_SPOOF_UA':
        try {
          await resetSpoofUa();
          return { success: true };
        } catch (e) {
          return { success: false, error: (e as Error).message };
        }
      case 'SPOOF_HEADERS':
        try {
          await spoofHeaders(message.url, message.headers);
          return { success: true };
        } catch (e) {
          return { success: false, error: (e as Error).message };
        }
      case 'RESET_SPOOF_HEADERS':
        try {
          await resetSpoofHeaders();
          return { success: true };
        } catch (e) {
          return { success: false, error: (e as Error).message };
        }

      // —— 若依 Hook ——
      case 'REGISTER_RUOYI_HOOK':
        if (!message.origin) return { success: false, error: 'Missing origin' };
        await registerRuoYiHook(message.origin);
        return { success: true };
      case 'UNREGISTER_RUOYI_HOOK':
        await unregisterRuoYiHook();
        return { success: true };
      case 'VK_RUOYI_HOOK_EVENT':
        return undefined; // 转发事件，无需响应

      default:
        return { error: 'Unknown message type' };
    }
  }

  // ====== 启动恢复 ======
  restoreSpoofState();
  restoreRuoYiHook();

  // ====== 右键菜单 ======
  browser.runtime.onInstalled.addListener(() => {
    createContextMenus();
    restoreRuoYiHook();
  });

  browser.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.pentestSettings) createContextMenus();
  });

  browser.contextMenus.onClicked.addListener((info, tab) => {
    if (tab) handleMenuClick(info, tab);
  });

  // ====== tab 关闭清理 ======
  browser.tabs.onRemoved.addListener(tabId => cleanupRuoYiTabOnClose(tabId));
});
