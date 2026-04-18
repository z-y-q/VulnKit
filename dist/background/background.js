// Background Script - VulnKit v5.0
(function () {
  'use strict';

  var _syncing = false;

  function createContextMenus() {
    chrome.contextMenus.removeAll(() => {
      if (chrome.runtime.lastError) {
        _syncing = false;
        return;
      }
      chrome.contextMenus.create(
        {
          id: 'pentest-main',
          title: 'VulnKit',
          contexts: ['page', 'selection'],
        },
        () => {
          if (chrome.runtime.lastError) {
            _syncing = false;
            return;
          }
          chrome.contextMenus.create(
            {
              id: 'encode-selection',
              parentId: 'pentest-main',
              title: 'Base64 编码选中内容',
              contexts: ['selection'],
            },
            () => {
              if (chrome.runtime.lastError) {
                _syncing = false;
                return;
              }
              chrome.contextMenus.create(
                {
                  id: 'exif-image',
                  parentId: 'pentest-main',
                  title: '查看图片 EXIF',
                  contexts: ['image'],
                },
                () => {
                  _syncing = false;
                }
              );
            }
          );
        }
      );
    });
  }

  function removeContextMenus() {
    chrome.contextMenus.removeAll(() => {
      _syncing = false;
    });
  }

  function syncContextMenu() {
    if (_syncing) return;
    _syncing = true;
    chrome.storage.local.get(['pentestSettings'], result => {
      if (chrome.runtime.lastError) {
        _syncing = false;
        return;
      }
      var enabled = result.pentestSettings && result.pentestSettings.enableContextMenu !== false;
      if (enabled) {
        createContextMenus();
      } else {
        removeContextMenus();
      }
    });
  }

  chrome.runtime.onInstalled.addListener(syncContextMenu);
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.pentestSettings) {
      syncContextMenu();
    }
  });
  syncContextMenu();

  chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === 'encode-selection' && info.selectionText) {
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: text => btoa(unescape(encodeURIComponent(text))),
        args: [info.selectionText],
      });
    }
    if (info.menuItemId === 'exif-image' && info.srcUrl) {
      chrome.storage.local.set({ exif_pending_url: info.srcUrl });
    }
  });

  // API proxy: fetch external URLs from background (bypasses CORS/CSP)
  async function fetchUrl(url, headers) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15000);
      const opts = { method: 'GET', signal: controller.signal };
      if (headers) opts.headers = headers;
      const resp = await fetch(url, opts);
      clearTimeout(timeout);
      const text = await resp.text();
      return { data: text };
    } catch (e) {
      return { error: e.message };
    }
  }

  function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_CURRENT_URL') {
      chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        sendResponse({ url: tabs[0]?.url });
      });
      return true;
    }

    if (message.type === 'ENCODE_TEXT') {
      try {
        const encoded = btoa(unescape(encodeURIComponent(message.text)));
        sendResponse({ success: true, result: encoded });
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
      return true;
    }

    if (message.type === 'FETCH_URL') {
      try {
        const urlObj = new URL(message.url);
        if (urlObj.protocol !== 'https:' && urlObj.protocol !== 'http:') {
          sendResponse({ error: 'Only HTTP/HTTPS URLs are allowed' });
          return true;
        }
      } catch {
        sendResponse({ error: 'Invalid URL' });
        return true;
      }
      fetchUrl(message.url).then(sendResponse);
      return true;
    }

    if (message.type === 'FETCH_URL_AUTH') {
      try {
        const authUrlObj = new URL(message.url);
        if (authUrlObj.protocol !== 'https:' && authUrlObj.protocol !== 'http:') {
          sendResponse({ error: 'Only HTTP/HTTPS URLs are allowed' });
          return true;
        }
      } catch {
        sendResponse({ error: 'Invalid URL' });
        return true;
      }
      const headers = {};
      if (message.header && message.key) {
        headers[message.header] = message.key;
      }
      fetchUrl(message.url, headers).then(sendResponse);
      return true;
    }

    if (message.type === 'FETCH_IMAGE') {
      try {
        const imgUrlObj = new URL(message.url);
        if (imgUrlObj.protocol !== 'https:' && imgUrlObj.protocol !== 'http:') {
          sendResponse({ error: 'Only HTTP/HTTPS URLs are allowed' });
          return true;
        }
      } catch {
        sendResponse({ error: 'Invalid URL' });
        return true;
      }
      fetch(message.url)
        .then(resp => {
          if (!resp.ok) throw new Error('HTTP ' + resp.status);
          return resp.arrayBuffer();
        })
        .then(buffer => {
          const bytes = new Uint8Array(buffer);
          const b64 = bytesToBase64(bytes);
          sendResponse({ data: b64, size: bytes.length });
        })
        .catch(e => sendResponse({ error: e.message }));
      return true;
    }

    if (message.type === 'SPOOF_UA') {
      try {
        const urlObj = new URL(message.url);
        chrome.declarativeNetRequest
          .updateSessionRules({
            removeRuleIds: [1],
            addRules: [
              {
                id: 1,
                priority: 1,
                action: {
                  type: 'modifyHeaders',
                  requestHeaders: [
                    { header: 'User-Agent', operation: 'set', value: message.userAgent },
                  ],
                },
                condition: {
                  urlFilter: '||' + urlObj.hostname,
                  resourceTypes: [
                    'main_frame',
                    'sub_frame',
                    'stylesheet',
                    'script',
                    'image',
                    'font',
                    'object',
                    'xmlhttprequest',
                    'ping',
                    'csp_report',
                    'media',
                    'websocket',
                    'webtransport',
                    'other',
                  ],
                  tabIds: [message.tabId],
                },
              },
            ],
          })
          .then(() => sendResponse({ success: true }))
          .catch(e => sendResponse({ success: false, error: e.message }));
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
      return true;
    }

    if (message.type === 'RESET_SPOOF_UA') {
      chrome.declarativeNetRequest
        .updateSessionRules({ removeRuleIds: [1] })
        .then(() => sendResponse({ success: true }))
        .catch(e => sendResponse({ success: false, error: e.message }));
      return true;
    }

    if (message.type === 'SPOOF_HEADERS') {
      try {
        const urlObj = new URL(message.url);
        const headers = message.headers;
        const requestHeaders = [];

        if (headers.xff) {
          requestHeaders.push({ header: 'X-Forwarded-For', operation: 'set', value: headers.xff });
        }
        if (headers.referer) {
          let refValue = headers.referer;
          if (refValue === 'same') refValue = message.url;
          requestHeaders.push({ header: 'Referer', operation: 'set', value: refValue });
        }
        if (headers.clientIp) {
          requestHeaders.push({ header: 'Client-IP', operation: 'set', value: headers.clientIp });
          requestHeaders.push({ header: 'X-Real-IP', operation: 'set', value: headers.clientIp });
        }

        (headers.custom || []).forEach(h => {
          requestHeaders.push({ header: h.name, operation: 'set', value: h.value });
        });

        const removeIds = [2, 3, 4];
        for (let i = 100; i < 200; i++) removeIds.push(i);

        const addRules = requestHeaders.map((h, i) => ({
          id: 2 + i,
          priority: 1,
          action: { type: 'modifyHeaders', requestHeaders: [h] },
          condition: {
            urlFilter: '||' + urlObj.hostname,
            resourceTypes: [
              'main_frame',
              'sub_frame',
              'stylesheet',
              'script',
              'image',
              'font',
              'object',
              'xmlhttprequest',
              'ping',
              'csp_report',
              'media',
              'websocket',
              'webtransport',
              'other',
            ],
            tabIds: [message.tabId],
          },
        }));

        chrome.declarativeNetRequest
          .updateSessionRules({ removeRuleIds: removeIds, addRules: addRules })
          .then(() => sendResponse({ success: true }))
          .catch(e => sendResponse({ success: false, error: e.message }));
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
      return true;
    }

    if (message.type === 'RESET_SPOOF_HEADERS') {
      const removeIds = [2, 3, 4];
      for (let i = 100; i < 200; i++) removeIds.push(i);
      chrome.declarativeNetRequest
        .updateSessionRules({ removeRuleIds: removeIds })
        .then(() => sendResponse({ success: true }))
        .catch(e => sendResponse({ success: false, error: e.message }));
      return true;
    }

    if (message.type === 'TOGGLE_JS') {
      try {
        if (message.enable) {
          chrome.declarativeNetRequest
            .updateSessionRules({ removeRuleIds: [500] })
            .then(() => sendResponse({ success: true }))
            .catch(e => sendResponse({ success: false, error: e.message }));
        } else {
          chrome.declarativeNetRequest
            .updateSessionRules({
              removeRuleIds: [500],
              addRules: [
                {
                  id: 500,
                  priority: 2,
                  action: { type: 'block' },
                  condition: {
                    resourceTypes: ['script'],
                    tabIds: [message.tabId],
                  },
                },
              ],
            })
            .then(() => sendResponse({ success: true }))
            .catch(e => sendResponse({ success: false, error: e.message }));
        }
      } catch (e) {
        sendResponse({ success: false, error: e.message });
      }
      return true;
    }
  });

  // Auto re-inject permission menu interceptor on page navigation
  const PERM_INTERCEPT_FUNC = function () {
    if (window.__PERM_INTERCEPTOR__) {
      window.__PERM_INTERCEPTOR__.active = true;
      return 'already_injected';
    }

    var MENU_KEYWORDS = [
      'menu',
      'menulist',
      'menuList',
      'menuData',
      'permission',
      'permissions',
      'permList',
      'menuIds',
      'menu_ids',
      'menuId',
      'isAdmin',
      'isadmin',
      'role',
      'roles',
      'getMenu',
      'getMenus',
      'getPermission',
      'getUserInfo',
      'navList',
      'sideMenu',
      'sidebar',
    ];
    var URL_MENU_PATTERNS = [
      /\/api\/.*menu/i,
      /\/api\/.*permission/i,
      /\/api\/.*role/i,
      /\/api\/.*user.*info/i,
      /\/api\/.*auth/i,
      /\/api\/.*nav/i,
      /\/menu/,
      /\/permission/,
      /\/getMenu/i,
      /\/getUserInfo/i,
      /\/getRouters/i,
      /\/getRoutes/,
    ];

    function classifyResponse(data, url) {
      var str = typeof data === 'string' ? data : JSON.stringify(data);
      var urlLower = url.toLowerCase();
      try {
        var json = typeof data === 'string' ? JSON.parse(data) : data;
        if (json && typeof json === 'object' && !Array.isArray(json)) {
          var keys = Object.keys(json);
          for (var k = 0; k < keys.length; k++) {
            if (/^(isadmin|admin|is_superuser)$/i.test(keys[k]))
              return { type: 'role', subtype: 'special_zero' };
          }
        }
      } catch (e) {}
      if (/permission/i.test(urlLower)) return { type: 'permission', subtype: null };
      if (/role/i.test(urlLower)) return { type: 'role', subtype: null };
      if (/menu/i.test(urlLower)) return { type: 'menu', subtype: null };
      for (var i = 0; i < MENU_KEYWORDS.length; i++) {
        if (str.indexOf(MENU_KEYWORDS[i]) !== -1) return { type: 'menu', subtype: null };
      }
      return { type: 'other', subtype: null };
    }

    function parseBody(text) {
      try {
        var json = JSON.parse(text);
        if (json && typeof json === 'object' && !Array.isArray(json)) {
          if (json.data !== undefined) return json.data;
          if (json.result !== undefined) return json.result;
          if (json.Data !== undefined) return json.Data;
          if (json.Result !== undefined) return json.Result;
        }
        return json;
      } catch (e) {
        return text;
      }
    }

    var captured = [];

    var originalFetch = window.fetch;
    window.fetch = function () {
      var args = arguments;
      return originalFetch.apply(this, args).then(function (response) {
        if (window.__PERM_INTERCEPTOR__ && window.__PERM_INTERCEPTOR__.active) {
          var url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
          var isMenuApi = URL_MENU_PATTERNS.some(function (p) {
            return p.test(url);
          });
          if (isMenuApi) {
            var cloned = response.clone();
            cloned.text().then(function (text) {
              try {
                var parsed = parseBody(text);
                var info = classifyResponse(parsed, url);
                if (info.type !== 'other') {
                  captured.push({
                    url: url,
                    type: info.type,
                    subtype: info.subtype,
                    data: parsed,
                    rawText: text,
                    size: text.length,
                    timestamp: Date.now(),
                    method: 'fetch',
                  });
                }
              } catch (e) {}
            });
          }
        }
        return response;
      });
    };

    var origOpen = XMLHttpRequest.prototype.open;
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url) {
      this.__perm_url = url;
      return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function () {
      var self = this;
      if (window.__PERM_INTERCEPTOR__ && window.__PERM_INTERCEPTOR__.active && this.__perm_url) {
        var url = this.__perm_url;
        var isMenuApi = URL_MENU_PATTERNS.some(function (p) {
          return p.test(url);
        });
        if (isMenuApi) {
          this.addEventListener('load', function () {
            try {
              var text = self.responseText;
              if (!text) return;
              var parsed = parseBody(text);
              var info = classifyResponse(parsed, url);
              if (info.type !== 'other') {
                captured.push({
                  url: url,
                  type: info.type,
                  subtype: info.subtype,
                  data: parsed,
                  rawText: text,
                  size: text.length,
                  timestamp: Date.now(),
                  method: 'xhr',
                });
              }
            } catch (e) {}
          });
        }
      }
      return origSend.apply(this, arguments);
    };

    window.__PERM_INTERCEPTOR__ = {
      active: true,
      captured: captured,
      getCaptured: function () {
        return captured;
      },
      clear: function () {
        captured.length = 0;
      },
      stop: function () {
        this.active = false;
      },
      start: function () {
        this.active = true;
      },
      _overrideData: null,
      getOverride: function () {
        return this._overrideData;
      },
      setOverride: function (d) {
        this._overrideData = d;
      },
    };
    return 'injected';
  };

  chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status !== 'complete') return;
    chrome.storage.local.get(['permInterceptTabId'], result => {
      if (result.permInterceptTabId === tabId) {
        chrome.scripting.executeScript({
          target: { tabId: tabId },
          world: 'MAIN',
          func: PERM_INTERCEPT_FUNC,
        });
      }
    });
  });
})();
