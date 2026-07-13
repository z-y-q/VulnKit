// 灵眸 v6.0 — Background Service Worker
// 编排：消息分发 → fetchers / dnr / context-menus / ruoyi-hook
// SSRF 防护统一在分发层用 url-guard 校验；消息来源统一由 sender-guard 校验。

import { isAllowedUrl, validateProbeUrl } from '@/lib/core/url-guard';
import { isAuthorized } from '@/lib/background/sender-guard';
import {
  fetchUrl,
  fetchImage,
  fetchZoomEyeAuth,
  fetchProbe,
  fetchCorsProbe,
  fetchHeaderProbe,
  fetchWafProbe,
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
import { clearPendingActionForTab } from '@/lib/navigation/pending-actions';
import {
  registerRuoYiHook,
  unregisterRuoYiHook,
  restoreRuoYiHook,
  cleanupRuoYiTabOnClose,
} from '@/lib/background/ruoyi-hook';
import { initRateLimiter } from '@/lib/background/rate-limit';
import type { BackgroundMessage } from '@/lib/types/messaging';

export default defineBackground(() => {
  // ====== 消息分发 ======
  // 统一门控：sender 必须满足该消息类型的来源策略（见 sender-guard.ts）。
  // 不合法来源立即拒绝，不进入 handle，避免外部上下文调用高权限操作。
  browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!isAuthorized(msg as { type?: string } | null, sender)) {
      sendResponse({ error: 'Unauthorized sender' });
      return false; // 同步响应，无需异步
    }
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
        if (typeof message.url !== 'string' || !message.url) {
          return { success: false, error: 'Invalid url' };
        }
        if (!isAllowedUrl(message.url)) {
          return { success: false, error: 'URL not allowed (must be http/https, no private IPs)' };
        }
        return fetchUrl(message.url, message.tailOnly, message.timeout, message.maxBytes);
      }
      case 'FETCH_URL_AUTH': {
        if (typeof message.url !== 'string' || !message.url) {
          return { success: false, error: 'Invalid url' };
        }
        if (!isAllowedUrl(message.url)) {
          return { success: false, error: 'URL not allowed (must be http/https, no private IPs)' };
        }
        if (message.provider !== 'zoomeye') {
          return { success: false, error: 'Unknown provider: ' + (message.provider || '(none)') };
        }
        return fetchZoomEyeAuth(message.url, message.key);
      }

      // —— 探测类 ——
      case 'FETCH_PROBE': {
        if (typeof message.url !== 'string' || !message.url) return { error: 'Invalid url' };
        const v = validateProbeUrl(message.url);
        if ('error' in v) return { error: v.error };
        return fetchProbe(v.parsed.href, message);
      }
      case 'FETCH_CORS_PROBE': {
        if (typeof message.url !== 'string' || !message.url) return { error: 'Invalid url' };
        const v = validateProbeUrl(message.url);
        if ('error' in v) return { error: v.error };
        if (!isAllowedUrl(v.parsed.href)) return { error: 'URL not allowed (no private IPs)' };
        return fetchCorsProbe(v.parsed.href, message);
      }
      case 'FETCH_HEADER_PROBE': {
        if (typeof message.url !== 'string' || !message.url) return { error: 'Invalid url' };
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
      case 'FETCH_WAF_PROBE': {
        if (typeof message.url !== 'string' || !message.url) return { error: 'Invalid url' };
        const v = validateProbeUrl(message.url);
        if ('error' in v) return { error: v.error };
        if (!isAllowedUrl(v.parsed.href)) return { error: 'URL not allowed (no private IPs)' };
        return fetchWafProbe(v.parsed.href, message);
      }
      case 'FETCH_IMAGE': {
        if (typeof message.url !== 'string' || !message.url) {
          return { success: false, error: 'Invalid url' };
        }
        if (!isAllowedUrl(message.url)) {
          return { success: false, error: 'URL not allowed (must be http/https, no private IPs)' };
        }
        return fetchImage(message.url);
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
          if (typeof message.url !== 'string' || typeof message.userAgent !== 'string') {
            return { success: false, error: 'Invalid url or userAgent' };
          }
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
          if (typeof message.url !== 'string' || typeof message.headers !== 'object' || !message.headers) {
            return { success: false, error: 'Invalid url or headers' };
          }
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
        if (typeof message.origin !== 'string' || !message.origin) {
          return { success: false, error: 'Missing origin' };
        }
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
  initRateLimiter(); // 加载限流设置并订阅变更（不阻塞，首次请求前就绪）

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
  browser.tabs.onRemoved.addListener(tabId => {
    cleanupRuoYiTabOnClose(tabId);
    clearPendingActionForTab(tabId); // 清理该 tab 的 pending action（§3.1）
  });
});
