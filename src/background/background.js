/* 灵眸 Background Service Worker */
/* eslint-disable no-undef */

// ====== declarativeNetRequest helpers ======
const JS_BLOCK_RULE_ID = 9001;
const UA_RULE_ID = 9002;
const HEADER_RULES_START = 9010;
const MAX_HEADER_RULES = 20;

// Track active spoof state
let spoofState = {
  ua: { enabled: false, current: '', url: '' },
  headers: { xff: '', referer: '', clientIp: '', custom: [], url: '' },
};

function persistSpoofState() {
  chrome.storage.local.set({ pentest_spoof: spoofState }).catch(function (e) {
    console.debug('persist spoof state failed', e);
  });
}

// Restore spoof state from storage on startup
chrome.storage.local.get(['pentest_spoof'], result => {
  if (result.pentest_spoof) {
    spoofState = result.pentest_spoof;
    if (spoofState.ua.enabled && spoofState.ua.current) {
      addUaRule(null, spoofState.ua.url || null, spoofState.ua.current).catch(function (e) {
        console.debug('restore UA rule failed', e);
      });
    }
    if (
      spoofState.headers &&
      (spoofState.headers.xff ||
        spoofState.headers.referer ||
        spoofState.headers.clientIp ||
        (spoofState.headers.custom && spoofState.headers.custom.length > 0))
    ) {
      addHeaderRules(null, spoofState.headers.url || null, spoofState.headers).catch(function (e) {
        console.debug('restore header rules failed', e);
      });
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
    throw new Error('Invalid URL for UA spoof rule');
  }

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [UA_RULE_ID],
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
    throw new Error('Invalid URL for header spoof rule');
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
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|127\.|169\.254\.)/.test(hostname))
      return false;
    if (/\[::ffff:(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(hostname)) return false;
    if (/^\d+$/.test(hostname)) return false;
    if (hostname.endsWith('.local') || hostname.endsWith('.internal')) return false;
    return true;
  } catch {
    return false;
  }
}

// ====== Probe utilities ======
function validateProbeUrl(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { error: 'Invalid protocol' };
    }
    return { parsed: parsed };
  } catch {
    return { error: 'Invalid URL' };
  }
}

function createTimeoutController(timeoutMs) {
  var controller = new AbortController();
  var timer = setTimeout(function () {
    controller.abort();
  }, timeoutMs);
  return { controller: controller, cleanup: function () { clearTimeout(timer); } };
}

function collectHeaders(resp) {
  var hdrs = {};
  resp.headers.forEach(function (v, k) {
    hdrs[k] = v;
  });
  return hdrs;
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
    if (!resp.ok && resp.status !== 206) {
      let body = await resp.text().catch(function () {
        return '';
      });
      clearTimeout(timer);
      throw new Error('HTTP ' + resp.status + (body ? ': ' + body.slice(0, 200) : ''));
    }
    const data = await resp.text();
    clearTimeout(timer);
    return { success: true, data };
  } catch (e) {
    clearTimeout(timer);
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

// ====== Message handler map ======
var handlers = {
  QUERY_JS_BLOCK: function (_msg, _sender, sendResponse) {
    chrome.declarativeNetRequest
      .getDynamicRules()
      .then(function (rules) {
        sendResponse({ blocked: rules.some(function (r) { return r.id === JS_BLOCK_RULE_ID; }) });
      })
      .catch(function () { sendResponse({ blocked: false }); });
    return true;
  },

  TOGGLE_JS: function (msg, _sender, sendResponse) {
    var promise = msg.enable ? removeJsBlockRule() : addJsBlockRule();
    promise
      .then(function () { sendResponse({ success: true }); })
      .catch(function (e) { sendResponse({ success: false, error: e.message }); });
    return true;
  },

  SPOOF_UA: function (msg, _sender, sendResponse) {
    if (msg.url && msg.userAgent) {
      spoofState.ua = { enabled: true, current: msg.userAgent, url: msg.url };
      persistSpoofState();
      addUaRule(msg.tabId, msg.url, msg.userAgent)
        .then(function () { sendResponse({ success: true }); })
        .catch(function (e) { sendResponse({ success: false, error: e.message }); });
    } else {
      sendResponse({ success: false, error: 'Missing url or userAgent' });
    }
    return true;
  },

  RESET_SPOOF_UA: function (_msg, _sender, sendResponse) {
    spoofState.ua = { enabled: false, current: '', url: '' };
    persistSpoofState();
    removeUaRule()
      .then(function () { sendResponse({ success: true }); })
      .catch(function (e) { sendResponse({ success: false, error: e.message }); });
    return true;
  },

  SPOOF_HEADERS: function (msg, _sender, sendResponse) {
    if (msg.headers) {
      spoofState.headers = Object.assign({}, msg.headers, { url: msg.url });
      persistSpoofState();
      addHeaderRules(msg.tabId, msg.url, msg.headers)
        .then(function () { sendResponse({ success: true }); })
        .catch(function (e) { sendResponse({ success: false, error: e.message }); });
    } else {
      sendResponse({ success: false, error: 'Missing headers' });
    }
    return true;
  },

  RESET_SPOOF_HEADERS: function (_msg, _sender, sendResponse) {
    spoofState.headers = { xff: '', referer: '', clientIp: '', custom: [], url: '' };
    persistSpoofState();
    removeAllHeaderRules()
      .then(function () { sendResponse({ success: true }); })
      .catch(function (e) { sendResponse({ success: false, error: e.message }); });
    return true;
  },

  FETCH_URL: function (msg, _sender, sendResponse) {
    if (!isAllowedUrl(msg.url)) {
      sendResponse({ error: 'URL not allowed (must be http/https, no private IPs)' });
    } else {
      fetchUrl(msg.url, msg.tailOnly, msg.timeout)
        .then(function (result) {
          sendResponse(result.success ? { data: result.data } : { error: result.error });
        })
        .catch(function (e) { sendResponse({ error: e.message || 'fetch failed' }); });
    }
    return true;
  },

  FETCH_URL_AUTH: function (msg, _sender, sendResponse) {
    if (!isAllowedUrl(msg.url)) {
      sendResponse({ error: 'URL not allowed (must be http/https, no private IPs)' });
    } else if (msg.provider === 'zoomeye') {
      fetchZoomEyeAuth(msg.url, msg.key)
        .then(function (result) {
          sendResponse(result.success ? { data: result.data } : { error: result.error });
        })
        .catch(function (e) { sendResponse({ error: e.message || 'auth fetch failed' }); });
    } else {
      sendResponse({ error: 'Unknown provider: ' + (msg.provider || '(none)') });
    }
    return true;
  },

  FETCH_PROBE: function (msg, _sender, sendResponse) {
    var v = validateProbeUrl(msg.url);
    if (v.error) { sendResponse({ error: v.error }); return true; }
    var tc = createTimeoutController(msg.timeout || 5000);
    var t0 = performance.now();
    fetch(v.parsed.href, {
      method: msg.method || 'GET',
      redirect: msg.followRedirect !== false ? 'follow' : 'manual',
      signal: tc.controller.signal,
      headers: msg.headers || {},
    })
      .then(function (resp) {
        tc.cleanup();
        var elapsed = Math.round(performance.now() - t0);
        var result = {
          status: resp.status,
          statusText: resp.statusText,
          headers: collectHeaders(resp),
          redirected: resp.redirected,
          url: resp.url,
          time: elapsed,
        };
        if (msg.includeBody && resp.status >= 200 && resp.status < 300) {
          return resp.text().then(function (body) { result.body = body; return result; });
        }
        return result;
      })
      .then(function (result) { sendResponse(result); })
      .catch(function (e) {
        tc.cleanup();
        sendResponse({ error: e.message, status: 0, body: '', headers: {}, time: 0 });
      });
    return true;
  },

  FETCH_CORS_PROBE: function (msg, _sender, sendResponse) {
    var v = validateProbeUrl(msg.url);
    if (v.error) { sendResponse({ error: v.error }); return true; }
    if (!isAllowedUrl(v.parsed.href)) {
      sendResponse({ error: 'URL not allowed (no private IPs)' });
      return true;
    }
    var tc = createTimeoutController(msg.timeout || 10000);
    var corsHeaders = msg.headers || {};
    fetch(v.parsed.href, {
      method: msg.method || 'GET',
      redirect: 'follow',
      signal: tc.controller.signal,
      headers: corsHeaders,
      credentials: msg.credentials || 'omit',
      body: msg.body || undefined,
    })
      .then(function (resp) {
        tc.cleanup();
        var result = {
          status: resp.status,
          statusText: resp.statusText,
          headers: collectHeaders(resp),
          type: resp.type,
        };
        return resp.text().then(function (body) { result.body = body; return result; }).catch(function () { result.body = ''; return result; });
      })
      .then(function (result) { sendResponse(result); })
      .catch(function (e) {
        tc.cleanup();
        sendResponse({ error: e.message, status: 0 });
      });
    return true;
  },

  FETCH_HEADER_PROBE: function (msg, _sender, sendResponse) {
    var v = validateProbeUrl(msg.url);
    if (v.error) { sendResponse({ error: v.error }); return true; }
    if (!isAllowedUrl(v.parsed.href)) {
      sendResponse({ error: 'URL not allowed (no private IPs)' });
      return true;
    }
    var tc = createTimeoutController(msg.timeout || 8000);
    fetch(v.parsed.href, {
      method: 'HEAD',
      redirect: 'follow',
      signal: tc.controller.signal,
      credentials: 'omit',
    })
      .then(function (resp) {
        tc.cleanup();
        sendResponse({ status: resp.status, statusText: resp.statusText, headers: collectHeaders(resp) });
      })
      .catch(function (e) {
        tc.cleanup();
        // HEAD may be blocked, fallback to GET with body drain
        fetch(v.parsed.href, {
          method: 'GET',
          redirect: 'follow',
          signal: AbortSignal.timeout(msg.timeout || 8000),
          credentials: 'omit',
        })
          .then(function (resp2) {
            sendResponse({ status: resp2.status, statusText: resp2.statusText, headers: collectHeaders(resp2) });
          })
          .catch(function (e2) {
            sendResponse({ error: e2.message, status: 0 });
          });
      });
    return true;
  },

  FETCH_DNS_RESOLVE: function (msg, _sender, sendResponse) {
    var hostname = msg.hostname;
    if (!hostname || typeof hostname !== 'string') {
      sendResponse({ error: 'Invalid hostname' });
      return true;
    }
    fetch('https://dns.google/resolve?name=' + encodeURIComponent(hostname) + '&type=A')
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var addresses = (data.Answer || [])
          .filter(function (a) { return a.type === 1; })
          .map(function (a) { return a.data; });
        sendResponse({ addresses: addresses, resultCode: 0 });
      })
      .catch(function (err) { sendResponse({ error: err.message, addresses: [] }); });
    return true;
  },

  FETCH_DNS_PROBE: function (msg, _sender, sendResponse) {
    var v = validateProbeUrl(msg.url);
    if (v.error) { sendResponse({ error: v.error }); return true; }
    if (!isAllowedUrl(v.parsed.href)) {
      sendResponse({ error: 'URL not allowed (no private IPs)' });
      return true;
    }
    var tc = createTimeoutController(msg.timeout || 5000);
    fetch(v.parsed.href, {
      method: msg.method || 'HEAD',
      redirect: 'follow',
      signal: tc.controller.signal,
      mode: 'no-cors',
    })
      .then(function (resp) {
        tc.cleanup();
        sendResponse({ status: resp.type === 'opaque' ? 1 : resp.status, type: resp.type });
      })
      .catch(function (e) {
        tc.cleanup();
        sendResponse({ error: e.message, status: 0 });
      });
    return true;
  },

  FETCH_WAF_PROBE: function (msg, _sender, sendResponse) {
    var v = validateProbeUrl(msg.url);
    if (v.error) { sendResponse({ error: v.error }); return true; }
    if (!isAllowedUrl(v.parsed.href)) {
      sendResponse({ error: 'URL not allowed (no private IPs)' });
      return true;
    }
    var tc = createTimeoutController(msg.timeout || 8000);
    fetch(v.parsed.href, {
      method: msg.method || 'GET',
      redirect: 'follow',
      signal: tc.controller.signal,
      credentials: 'omit',
      headers: msg.headers || {},
    })
      .then(function (resp) {
        tc.cleanup();
        var result = {
          status: resp.status,
          statusText: resp.statusText,
          headers: collectHeaders(resp),
          redirected: resp.redirected,
          url: resp.url,
        };
        return resp.text().then(function (body) {
          result.body = body.length > 50000 ? body.substring(0, 50000) : body;
          return result;
        }).catch(function () { result.body = ''; return result; });
      })
      .then(function (result) { sendResponse(result); })
      .catch(function (e) {
        tc.cleanup();
        sendResponse({ error: e.message, status: 0 });
      });
    return true;
  },

  FETCH_IMAGE: function (msg, _sender, sendResponse) {
    if (!isAllowedUrl(msg.url)) {
      sendResponse({ error: 'URL not allowed (must be http/https, no private IPs)' });
    } else {
      fetchImage(msg.url)
        .then(function (result) {
          sendResponse(result.success ? { data: result.data } : { error: result.error });
        })
        .catch(function (e) { sendResponse({ error: e.message || 'image fetch failed' }); });
    }
    return true;
  },

  VK_RUOYI_HOOK_EVENT: function (msg, _sender, _sendResponse) {
    chrome.storage.local
      .set({
        __vk_ruoyi_event: {
          event: msg.event,
          augmented: msg.augmented || false,
          ts: Date.now(),
        },
      })
      .catch(function (e) {
        console.debug('analytics event send failed', e);
      });
    return false;
  },

  REGISTER_RUOYI_HOOK: function (msg, _sender, sendResponse) {
    if (msg.origin) {
      registerRuoYiHook(msg.origin).then(function () {
        sendResponse({ success: true });
      });
    } else {
      sendResponse({ success: false, error: 'Missing origin' });
    }
    return true;
  },

  UNREGISTER_RUOYI_HOOK: function (_msg, _sender, sendResponse) {
    unregisterRuoYiHook().then(function () {
      sendResponse({ success: true });
    });
    return true;
  },
};

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  if (!message || !message.type) return false;
  var handler = handlers[message.type];
  if (!handler) return false;
  return handler(message, sender, sendResponse);
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

function restoreRuoYiHook() {
  chrome.storage.local.get(['ruoyiHookEnabled', 'ruoyiHookOrigin'], function (result) {
    if (result.ruoyiHookEnabled && result.ruoyiHookOrigin) {
      registerRuoYiHook(result.ruoyiHookOrigin);
    }
  });
}

// Restore hook content script on service worker startup
restoreRuoYiHook();

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
      chrome.contextMenus.removeAll().catch(function (e) {
        console.debug('remove context menus failed', e);
      });
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
  restoreRuoYiHook();
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
