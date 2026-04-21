/* VulnKit Background Service Worker */
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

// Restore spoof state from storage on startup
chrome.storage.local.get(['pentest_spoof'], result => {
  if (result.pentest_spoof) {
    spoofState = result.pentest_spoof;
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
  const urlFilter = '*';

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

// ====== Fetch helpers ======
async function fetchUrl(url, tailOnly) {
  try {
    var opts = {};
    if (tailOnly) {
      opts.headers = { Range: 'bytes=-500' };
    }
    var controller = new AbortController();
    var timer = setTimeout(function () {
      controller.abort();
    }, 10000);
    opts.signal = controller.signal;
    const resp = await fetch(url, opts);
    clearTimeout(timer);
    if (!resp.ok && resp.status !== 206) throw new Error('HTTP ' + resp.status);
    const data = await resp.text();
    return { success: true, data };
  } catch (e) {
    return { success: false, error: e.message || '请求超时' };
  }
}

async function fetchUrlAuth(url, key, header) {
  try {
    const resp = await fetch(url, {
      headers: { [header]: key },
    });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const data = await resp.text();
    return { success: true, data };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

async function fetchImage(url) {
  try {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const blob = await resp.blob();
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onloadend = () => resolve({ success: true, data: reader.result });
      reader.onerror = () => reject(new Error('Failed to read image'));
      reader.readAsDataURL(blob);
    });
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// ====== Message handler ======
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) return false;

  switch (message.type) {
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
        addUaRule(message.tabId, message.url, message.userAgent)
          .then(() => sendResponse({ success: true }))
          .catch(e => sendResponse({ success: false, error: e.message }));
      } else {
        sendResponse({ success: false, error: 'Missing url or userAgent' });
      }
      return true;

    case 'RESET_SPOOF_UA':
      spoofState.ua = { enabled: false, current: '' };
      removeUaRule()
        .then(() => sendResponse({ success: true }))
        .catch(e => sendResponse({ success: false, error: e.message }));
      return true;

    case 'SPOOF_HEADERS':
      if (message.headers) {
        spoofState.headers = message.headers;
        addHeaderRules(message.tabId, message.url, message.headers)
          .then(() => sendResponse({ success: true }))
          .catch(e => sendResponse({ success: false, error: e.message }));
      } else {
        sendResponse({ success: false, error: 'Missing headers' });
      }
      return true;

    case 'RESET_SPOOF_HEADERS':
      spoofState.headers = { xff: '', referer: '', clientIp: '', custom: [] };
      removeAllHeaderRules()
        .then(() => sendResponse({ success: true }))
        .catch(e => sendResponse({ success: false, error: e.message }));
      return true;

    case 'FETCH_URL':
      fetchUrl(message.url, message.tailOnly).then(result => {
        sendResponse(result.success ? { data: result.data } : { error: result.error });
      });
      return true;

    case 'FETCH_URL_AUTH':
      fetchUrlAuth(message.url, message.key, message.header).then(result => {
        sendResponse(result.success ? { data: result.data } : { error: result.error });
      });
      return true;

    case 'FETCH_IMAGE':
      fetchImage(message.url).then(result => {
        sendResponse(result.success ? { data: result.data } : { error: result.error });
      });
      return true;

    default:
      return false;
  }
});

// ====== Context menus ======
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'vulnkit-extract-links',
    title: 'VulnKit: Extract Links',
    contexts: ['page'],
  });

  chrome.contextMenus.create({
    id: 'vulnkit-encode',
    title: 'VulnKit: Encode Selection',
    contexts: ['selection'],
  });

  chrome.contextMenus.create({
    id: 'vulnkit-decode',
    title: 'VulnKit: Decode Selection',
    contexts: ['selection'],
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (!tab?.id) return;
  switch (info.menuItemId) {
    case 'vulnkit-extract-links':
      chrome.tabs.sendMessage(tab.id, { type: 'CONTEXT_EXTRACT_LINKS' }).catch(() => {});
      break;
    case 'vulnkit-encode':
    case 'vulnkit-decode':
      if (info.selectionText) {
        chrome.storage.local.set({ contextSelection: info.selectionText });
      }
      break;
  }
});
