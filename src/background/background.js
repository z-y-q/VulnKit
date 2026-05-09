/* 灵眸 Background Service Worker */
/* eslint-disable no-undef */

// ====== declarativeNetRequest helpers ======
const JS_BLOCK_RULE_ID = 9001;
const UA_RULE_ID = 9002;
const HEADER_RULES_START = 9010;
const MAX_HEADER_RULES = 20;

// Track active spoof state
let spoofState = {
  ua: { enabled: false, current: '' },
  headers: { xff: '', referer: '', clientIp: '', custom: [] },
};

function persistSpoofState() {
  chrome.storage.local.set({ pentest_spoof: spoofState }).catch(() => {});
}

// Restore spoof state from storage on startup
chrome.storage.local.get(['pentest_spoof'], result => {
  if (result.pentest_spoof) {
    spoofState = result.pentest_spoof;
    // Re-create DNR rules after browser restart
    if (spoofState.ua.enabled && spoofState.ua.current) {
      addUaRule(null, null, spoofState.ua.current).catch(() => {});
    }
    if (
      spoofState.headers &&
      (spoofState.headers.xff ||
        spoofState.headers.referer ||
        spoofState.headers.clientIp ||
        (spoofState.headers.custom && spoofState.headers.custom.length > 0))
    ) {
      addHeaderRules(null, null, spoofState.headers).catch(() => {});
    }
  }
});

async function addJsBlockRule() {
  await chrome.declarativeNetRequest.updateDynamicRules({
    addRules: [
      {
        id: JS_BLOCK_RULE_ID,
        priority: 1,
        action: { type: 'block' },
        condition: {
          urlFilter: '.js',
          resourceTypes: ['script'],
        },
      },
    ],
    removeRuleIds: [JS_BLOCK_RULE_ID],
  });
}

async function removeJsBlockRule() {
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [JS_BLOCK_RULE_ID],
  });
}

async function addUaRule(tabId, url, ua) {
  let urlFilter;
  try {
    const parsed = new URL(url);
    urlFilter = parsed.hostname + '/*';
  } catch {
    urlFilter = '*';
  }

  // Remove old UA rules first
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [UA_RULE_ID],
  });

  await chrome.declarativeNetRequest.updateDynamicRules({
    addRules: [
      {
        id: UA_RULE_ID,
        priority: 2,
        action: {
          type: 'modifyHeaders',
          requestHeaders: [
            {
              header: 'User-Agent',
              operation: 'set',
              value: ua,
            },
          ],
        },
        condition: {
          urlFilter: urlFilter,
          resourceTypes: [
            'main_frame',
            'sub_frame',
            'stylesheet',
            'script',
            'image',
            'xmlhttprequest',
            'font',
            'other',
          ],
        },
      },
    ],
  });
}

async function removeUaRule() {
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [UA_RULE_ID],
  });
}

async function addHeaderRules(tabId, url, headers) {
  const requestHeaders = [];
  let urlFilter;
  try {
    let parsed = new URL(url);
    urlFilter = parsed.hostname + '/*';
  } catch {
    urlFilter = '*';
  }

  if (headers.xff) {
    requestHeaders.push({ header: 'X-Forwarded-For', operation: 'set', value: headers.xff });
  }
  if (headers.referer) {
    requestHeaders.push({ header: 'Referer', operation: 'set', value: headers.referer });
  }
  if (headers.clientIp) {
    requestHeaders.push({ header: 'Client-IP', operation: 'set', value: headers.clientIp });
    requestHeaders.push({ header: 'X-Real-IP', operation: 'set', value: headers.clientIp });
  }
  if (headers.custom && headers.custom.length > 0) {
    headers.custom.forEach(h => {
      if (h.name && h.value) {
        requestHeaders.push({ header: h.name, operation: 'set', value: h.value });
      }
    });
  }

  if (requestHeaders.length === 0) return;

  // Remove all existing header rules
  const removeIds = [];
  for (let i = 0; i < MAX_HEADER_RULES; i++) {
    removeIds.push(HEADER_RULES_START + i);
  }

  const rules = requestHeaders.map((h, i) => ({
    id: HEADER_RULES_START + i,
    priority: 3,
    action: { type: 'modifyHeaders', requestHeaders: [h] },
    condition: {
      urlFilter: urlFilter,
      resourceTypes: ['main_frame', 'sub_frame', 'xmlhttprequest', 'other'],
    },
  }));

  await chrome.declarativeNetRequest.updateDynamicRules({
    addRules: rules,
    removeRuleIds: removeIds,
  });
}

async function removeAllHeaderRules() {
  const removeIds = [];
  for (let i = 0; i < MAX_HEADER_RULES; i++) {
    removeIds.push(HEADER_RULES_START + i);
  }
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: removeIds,
  });
}

// ====== URL validation (SSRF prevention) ======
function isAllowedUrl(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
    const hostname = parsed.hostname.toLowerCase();
    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '[::1]' ||
      hostname === '[::ffff:127.0.0.1]'
    )
      return false;
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|127\.)/.test(hostname)) return false;
    if (/\[::ffff:(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(hostname)) return false;
    if (/^\d+$/.test(hostname)) return false;
    if (hostname.endsWith('.local') || hostname.endsWith('.internal')) return false;
    return true;
  } catch {
    return false;
  }
}

// ====== Fetch helpers ======
async function fetchUrl(url, tailOnly, timeoutMs) {
  try {
    const opts = {};
    if (tailOnly) {
      opts.headers = { Range: 'bytes=-500' };
    }
    let controller = new AbortController();
    let timer = setTimeout(function () {
      controller.abort();
    }, timeoutMs || 10000);
    opts.signal = controller.signal;
    const resp = await fetch(url, opts);
    clearTimeout(timer);
    if (!resp.ok && resp.status !== 206) {
      let body = await resp.text().catch(function () {
        return '';
      });
      throw new Error('HTTP ' + resp.status + (body ? ': ' + body.slice(0, 200) : ''));
    }
    const data = await resp.text();
    return { success: true, data };
  } catch (e) {
    return { success: false, error: e.message || '请求超时' };
  }
}

async function fetchImage(url) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(function () {
      controller.abort();
    }, 15000);
    const resp = await fetch(url, { signal: controller.signal });
    clearTimeout(timer);
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const buf = await resp.arrayBuffer();
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.length; i += 8192) {
      const chunk = bytes.subarray(i, Math.min(i + 8192, bytes.length));
      binary += String.fromCharCode.apply(null, chunk);
    }
    const b64 = btoa(binary);
    const mime = resp.headers.get('content-type') || 'image/jpeg';
    return { success: true, data: 'data:' + mime + ';base64,' + b64 };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

let zoomEyeTokenCache = { token: null, expiresAt: 0 };

async function fetchZoomEyeAuth(url, apiKey) {
  try {
    const now = Date.now();
    if (zoomEyeTokenCache.token && zoomEyeTokenCache.expiresAt > now) {
      const resp = await fetch(url, {
        headers: { Authorization: 'JWT ' + zoomEyeTokenCache.token },
        signal: AbortSignal.timeout(15000),
      });
      if (!resp.ok) {
        const body = await resp.text().catch(function () {
          return '';
        });
        if (resp.status === 401) zoomEyeTokenCache = { token: null, expiresAt: 0 };
        throw new Error('HTTP ' + resp.status + (body ? ': ' + body.slice(0, 200) : ''));
      }
      const data = await resp.text();
      return { success: true, data: data };
    }

    const loginResp = await fetch('https://api.zoomeye.org/user/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: apiKey }),
      signal: AbortSignal.timeout(15000),
    });
    if (!loginResp.ok) throw new Error('ZoomEye login failed: HTTP ' + loginResp.status);
    const loginData = await loginResp.json();
    if (!loginData.access_token) throw new Error('ZoomEye login failed: no access_token');
    zoomEyeTokenCache = { token: loginData.access_token, expiresAt: now + 3600000 };

    const apiResp = await fetch(url, {
      headers: { Authorization: 'JWT ' + loginData.access_token },
      signal: AbortSignal.timeout(15000),
    });
    if (!apiResp.ok) {
      const apiBody = await apiResp.text().catch(function () {
        return '';
      });
      throw new Error('HTTP ' + apiResp.status + (apiBody ? ': ' + apiBody.slice(0, 200) : ''));
    }
    const apiData = await apiResp.text();
    return { success: true, data: apiData };
  } catch (e) {
    return { success: false, error: e.message || '请求超时' };
  }
}

// ====== Message handler ======
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) return false;

  switch (message.type) {
    case 'QUERY_JS_BLOCK':
      chrome.declarativeNetRequest
        .getDynamicRules()
        .then(rules => {
          sendResponse({ blocked: rules.some(r => r.id === JS_BLOCK_RULE_ID) });
        })
        .catch(() => sendResponse({ blocked: false }));
      return true;

    case 'TOGGLE_JS':
      if (message.enable) {
        removeJsBlockRule()
          .then(() => sendResponse({ success: true }))
          .catch(e => sendResponse({ success: false, error: e.message }));
      } else {
        addJsBlockRule()
          .then(() => sendResponse({ success: true }))
          .catch(e => sendResponse({ success: false, error: e.message }));
      }
      return true; // async sendResponse

    case 'SPOOF_UA':
      if (message.url && message.userAgent) {
        spoofState.ua = { enabled: true, current: message.userAgent };
        persistSpoofState();
        addUaRule(message.tabId, message.url, message.userAgent)
          .then(() => sendResponse({ success: true }))
          .catch(e => sendResponse({ success: false, error: e.message }));
      } else {
        sendResponse({ success: false, error: 'Missing url or userAgent' });
      }
      return true;

    case 'RESET_SPOOF_UA':
      spoofState.ua = { enabled: false, current: '' };
      persistSpoofState();
      removeUaRule()
        .then(() => sendResponse({ success: true }))
        .catch(e => sendResponse({ success: false, error: e.message }));
      return true;

    case 'SPOOF_HEADERS':
      if (message.headers) {
        spoofState.headers = message.headers;
        persistSpoofState();
        addHeaderRules(message.tabId, message.url, message.headers)
          .then(() => sendResponse({ success: true }))
          .catch(e => sendResponse({ success: false, error: e.message }));
      } else {
        sendResponse({ success: false, error: 'Missing headers' });
      }
      return true;

    case 'RESET_SPOOF_HEADERS':
      spoofState.headers = { xff: '', referer: '', clientIp: '', custom: [] };
      persistSpoofState();
      removeAllHeaderRules()
        .then(() => sendResponse({ success: true }))
        .catch(e => sendResponse({ success: false, error: e.message }));
      return true;

    case 'FETCH_URL':
      if (!isAllowedUrl(message.url)) {
        sendResponse({ error: 'URL not allowed (must be http/https, no private IPs)' });
      } else {
        fetchUrl(message.url, message.tailOnly, message.timeout).then(result => {
          sendResponse(result.success ? { data: result.data } : { error: result.error });
        });
      }
      return true;

    case 'FETCH_URL_AUTH':
      if (!isAllowedUrl(message.url)) {
        sendResponse({ error: 'URL not allowed (must be http/https, no private IPs)' });
      } else if (message.provider === 'zoomeye') {
        fetchZoomEyeAuth(message.url, message.key).then(result => {
          sendResponse(result.success ? { data: result.data } : { error: result.error });
        });
      } else {
        sendResponse({ error: 'Unknown provider: ' + (message.provider || '(none)') });
      }
      return true;

    case 'FETCH_PROBE':
      // Probing uses the tab's own origin — allow private IPs but validate protocol and sender origin
      {
        let probeUrl;
        try {
          probeUrl = new URL(message.url);
          if (probeUrl.protocol !== 'http:' && probeUrl.protocol !== 'https:') {
            sendResponse({ error: 'Invalid protocol' });
            return true;
          }
        } catch {
          sendResponse({ error: 'Invalid URL' });
          return true;
        }
        if (sender.tab && sender.tab.url) {
          try {
            const senderOrigin = new URL(sender.tab.url).origin;
            if (
              probeUrl.origin !== senderOrigin &&
              probeUrl.hostname !== new URL(sender.tab.url).hostname
            ) {
              sendResponse({ error: 'Origin mismatch' });
              return true;
            }
          } catch (e) {
            console.debug('URL origin check failed', e);
          }
        }
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), message.timeout || 5000);
        fetch(probeUrl.href, {
          method: message.method || 'GET',
          redirect: message.followRedirect !== false ? 'follow' : 'manual',
          signal: controller.signal,
          headers: message.headers || {},
        })
          .then(async resp => {
            clearTimeout(timer);
            const hdrs = {};
            resp.headers.forEach((v, k) => {
              hdrs[k] = v;
            });
            const result = {
              status: resp.status,
              statusText: resp.statusText,
              headers: hdrs,
              redirected: resp.redirected,
              url: resp.url,
            };
            if (message.includeBody && resp.status >= 200 && resp.status < 300) {
              try {
                result.body = await resp.text();
              } catch {
                result.body = '';
              }
            }
            sendResponse(result);
          })
          .catch(e => {
            clearTimeout(timer);
            sendResponse({ error: e.message, status: 0 });
          });
      }
      return true;

    case 'FETCH_CORS_PROBE':
      // CORS probe: background fetch can set Origin header (not forbidden in service worker)
      {
        let probeUrl;
        try {
          probeUrl = new URL(message.url);
          if (probeUrl.protocol !== 'http:' && probeUrl.protocol !== 'https:') {
            sendResponse({ error: 'Invalid protocol' });
            return true;
          }
        } catch {
          sendResponse({ error: 'Invalid URL' });
          return true;
        }
        if (!isAllowedUrl(probeUrl.href)) {
          sendResponse({ error: 'URL not allowed (no private IPs)' });
          return true;
        }
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), message.timeout || 10000);
        const corsHeaders = message.headers || {};
        // In service worker fetch, Origin is not a forbidden header — browser allows it
        fetch(probeUrl.href, {
          method: message.method || 'GET',
          redirect: 'follow',
          signal: controller.signal,
          headers: corsHeaders,
          credentials: 'omit',
        })
          .then(async resp => {
            clearTimeout(timer);
            const hdrs = {};
            resp.headers.forEach((v, k) => {
              hdrs[k] = v;
            });
            const result = {
              status: resp.status,
              statusText: resp.statusText,
              headers: hdrs,
              type: resp.type,
            };
            try {
              result.body = await resp.text();
            } catch {
              result.body = '';
            }
            sendResponse(result);
          })
          .catch(e => {
            clearTimeout(timer);
            sendResponse({ error: e.message, status: 0 });
          });
      }
      return true;

    case 'FETCH_DNS_RESOLVE':
      {
        const hostname = message.hostname;
        if (!hostname || typeof hostname !== 'string') {
          sendResponse({ error: 'Invalid hostname' });
          return true;
        }
        try {
          chrome.dns.resolve(hostname, result => {
            if (chrome.runtime.lastError) {
              sendResponse({ error: chrome.runtime.lastError.message, addresses: [] });
            } else {
              sendResponse({ addresses: result.addresses || [], resultCode: result.resultCode });
            }
          });
        } catch (e) {
          sendResponse({ error: e.message, addresses: [] });
        }
      }
      return true;

    case 'FETCH_DNS_PROBE':
      // DNS subdomain probe: background fetch without CORS restrictions
      {
        let probeUrl;
        try {
          probeUrl = new URL(message.url);
          if (probeUrl.protocol !== 'http:' && probeUrl.protocol !== 'https:') {
            sendResponse({ error: 'Invalid protocol' });
            return true;
          }
        } catch {
          sendResponse({ error: 'Invalid URL' });
          return true;
        }
        if (!isAllowedUrl(probeUrl.href)) {
          sendResponse({ error: 'URL not allowed (no private IPs)' });
          return true;
        }
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), message.timeout || 5000);
        fetch(probeUrl.href, {
          method: message.method || 'HEAD',
          redirect: 'follow',
          signal: controller.signal,
          mode: 'no-cors',
        })
          .then(resp => {
            clearTimeout(timer);
            // no-cors mode: opaque response, status=0 means reachable, error means unreachable
            sendResponse({ status: resp.type === 'opaque' ? 1 : resp.status, type: resp.type });
          })
          .catch(e => {
            clearTimeout(timer);
            sendResponse({ error: e.message, status: 0 });
          });
      }
      return true;

    case 'FETCH_WAF_PROBE':
      // WAF probe: background fetch without cookies/session to trigger WAF blocks
      {
        let probeUrl;
        try {
          probeUrl = new URL(message.url);
          if (probeUrl.protocol !== 'http:' && probeUrl.protocol !== 'https:') {
            sendResponse({ error: 'Invalid protocol' });
            return true;
          }
        } catch {
          sendResponse({ error: 'Invalid URL' });
          return true;
        }
        if (!isAllowedUrl(probeUrl.href)) {
          sendResponse({ error: 'URL not allowed (no private IPs)' });
          return true;
        }
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), message.timeout || 8000);
        fetch(probeUrl.href, {
          method: message.method || 'GET',
          redirect: 'follow',
          signal: controller.signal,
          credentials: 'omit',
          headers: message.headers || {},
        })
          .then(async resp => {
            clearTimeout(timer);
            const hdrs = {};
            resp.headers.forEach((v, k) => {
              hdrs[k] = v;
            });
            const result = {
              status: resp.status,
              statusText: resp.statusText,
              headers: hdrs,
              redirected: resp.redirected,
              url: resp.url,
            };
            try {
              const body = await resp.text();
              result.body = body.length > 50000 ? body.substring(0, 50000) : body;
            } catch {
              result.body = '';
            }
            sendResponse(result);
          })
          .catch(e => {
            clearTimeout(timer);
            sendResponse({ error: e.message, status: 0 });
          });
      }
      return true;

    case 'FETCH_IMAGE':
      if (!isAllowedUrl(message.url)) {
        sendResponse({ error: 'URL not allowed (must be http/https, no private IPs)' });
      } else {
        fetchImage(message.url).then(result => {
          sendResponse(result.success ? { data: result.data } : { error: result.error });
        });
      }
      return true;

    case 'VK_RUOYI_HOOK_EVENT':
      chrome.storage.local
        .set({
          __vk_ruoyi_event: {
            event: message.event,
            augmented: message.augmented || false,
            ts: Date.now(),
          },
        })
        .catch(function (e) {
          console.debug('analytics event send failed', e);
        });
      return false;

    case 'REGISTER_RUOYI_HOOK':
      if (message.origin) {
        registerRuoYiHook(message.origin).then(function () {
          sendResponse({ success: true });
        });
      } else {
        sendResponse({ success: false, error: 'Missing origin' });
      }
      return true;

    case 'UNREGISTER_RUOYI_HOOK':
      unregisterRuoYiHook().then(function () {
        sendResponse({ success: true });
      });
      return true;

    default:
      return false;
  }
});

// ====== RuoYi Route Hook auto re-injection ======
const RUOYI_HOOK_CS_ID = 'ruoyi-route-hook-auto';

async function registerRuoYiHook(origin) {
  try {
    await chrome.scripting.unregisterContentScripts([RUOYI_HOOK_CS_ID]).catch(function (e) {
      console.debug('unregisterContentScripts failed', e);
    });
    await chrome.scripting.registerContentScripts([
      {
        id: RUOYI_HOOK_CS_ID,
        js: ['src/inject/ruoyi-route-hook.js'],
        matches: [origin + '/*'],
        runAt: 'document_start',
        world: 'MAIN',
      },
    ]);
  } catch (e) {
    console.warn('[灵眸] registerRuoYiHook:', e);
  }
}

async function unregisterRuoYiHook() {
  try {
    await chrome.scripting.unregisterContentScripts([RUOYI_HOOK_CS_ID]);
  } catch (e) {
    // ignore
  }
}

// Restore hook content script on service worker startup
chrome.storage.local.get(['ruoyiHookEnabled', 'ruoyiHookOrigin'], function (result) {
  if (result.ruoyiHookEnabled && result.ruoyiHookOrigin) {
    registerRuoYiHook(result.ruoyiHookOrigin);
  }
});

// Clean up tab-specific tracking when tab closes (hook persists for the origin)
chrome.tabs.onRemoved.addListener(function (tabId) {
  chrome.storage.local.get(['ruoyiHookTabId'], function (result) {
    if (result.ruoyiHookTabId === tabId) {
      chrome.storage.local.remove(['ruoyiHookTabId']).catch(function (e) {
        console.debug('remove ruoyiHookTabId failed', e);
      });
    }
  });
});

// ====== Context menus ======
function createContextMenus() {
  chrome.storage.local.get(['pentestSettings'], result => {
    const settings = result.pentestSettings || {};
    if (settings.enableContextMenu === false) {
      chrome.contextMenus.removeAll().catch(() => {});
      return;
    }
    chrome.contextMenus.removeAll(() => {
      chrome.contextMenus.create({
        id: 'vulnkit-extract-links',
        title: '灵眸: Extract Links',
        contexts: ['page'],
      });
      chrome.contextMenus.create({
        id: 'vulnkit-encode',
        title: '灵眸: Encode Selection',
        contexts: ['selection'],
      });
      chrome.contextMenus.create({
        id: 'vulnkit-decode',
        title: '灵眸: Decode Selection',
        contexts: ['selection'],
      });
    });
  });
}

chrome.runtime.onInstalled.addListener(function () {
  createContextMenus();
  // Restore RuoYi hook content script if it was active
  chrome.storage.local.get(['ruoyiHookEnabled', 'ruoyiHookOrigin'], function (result) {
    if (result.ruoyiHookEnabled && result.ruoyiHookOrigin) {
      registerRuoYiHook(result.ruoyiHookOrigin);
    }
  });
});

// Rebuild menus when settings change
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.pentestSettings) {
    createContextMenus();
  }
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (!tab?.id) return;
  switch (info.menuItemId) {
    case 'vulnkit-extract-links':
      chrome.tabs.sendMessage(tab.id, { type: 'CONTEXT_EXTRACT_LINKS' }).catch(function (e) {
        console.debug('context extract links failed', e);
      });
      chrome.storage.local.set({ contextExtractUrl: tab.url || '' }, function () {
        setTimeout(function () {
          chrome.tabs.create({
            url: chrome.runtime.getURL('src/extracted-links/extracted-links.html'),
          });
        }, 500);
      });
      break;
    case 'vulnkit-encode':
    case 'vulnkit-decode':
      if (info.selectionText) {
        chrome.storage.local.set({
          contextSelection: info.selectionText,
          contextAction: info.menuItemId === 'vulnkit-encode' ? 'encode' : 'decode',
        });
        chrome.action.setBadgeText({ text: '↑' });
        chrome.action.setBadgeBackgroundColor({ color: '#4CAF50' });
        if (typeof chrome.action.openPopup === 'function') {
          try {
            chrome.action.openPopup({ windowId: tab.windowId });
          } catch (e) {
            console.debug('openPopup failed', e);
          }
        }
      }
      break;
  }
});
