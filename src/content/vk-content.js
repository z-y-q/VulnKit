// 灵眸 - Content Script Bridge
(function () {
  'use strict';

  if (window.__VK_CONTENT_BRIDGE__) return;
  window.__VK_CONTENT_BRIDGE__ = true;

  var GEN_TOKEN = function () {
    return Math.random().toString(36).slice(2) + Date.now().toString(36);
  };

  // ====== Message dispatcher ======

  // Maps window message data key → { resolve ref, token ref }
  var channels = {};

  function registerChannel(dataKey) {
    channels[dataKey] = { resolve: null, token: null };
  }

  Object.keys({
    __vk_detect: true,
    __vk_react_detect: true,
    __vk_angular_detect: true,
    __vk_sourcemap_detect: true,
    __vk_vue_store: true,
    __vk_page_inspect: true,
    __vk_react_store: true,
    __vk_angular_store: true,
    __vk_svelte_detect: true,
  }).forEach(registerChannel);

  // Vue detect guard (prevents concurrent calls)
  var vueDetecting = false;

  window.addEventListener('message', function (e) {
    if (e.origin !== location.origin) return;
    if (!e.data || typeof e.data !== 'object') return;

    // RuoYi hook forward (no token matching needed)
    if (e.data.__vk_ruoyi_hook && e.data.event) {
      chrome.runtime
        .sendMessage({
          type: 'VK_RUOYI_HOOK_EVENT',
          event: e.data.event,
          augmented: e.data.augmented,
          injected: e.data.injected,
        })
        .catch(function () {});
      return;
    }

    for (var key in channels) {
      if (!e.data[key]) continue;
      var ch = channels[key];
      if (ch.resolve && ch.token && e.data.__vk_token === ch.token) {
        ch.resolve(e.data.result);
        ch.resolve = null;
        ch.token = null;
        if (key === '__vk_detect') vueDetecting = false;
      }
      return;
    }
  });

  // ====== Script injection ======

  function injectScript(url, dataKey, timeoutMs) {
    var ch = channels[dataKey];
    if (!ch) return Promise.resolve(null);
    if (dataKey === '__vk_detect' && vueDetecting) return Promise.resolve(null);

    if (dataKey === '__vk_detect') vueDetecting = true;

    return new Promise(function (resolve) {
      var token = GEN_TOKEN();
      ch.token = token;

      var timer = setTimeout(function () {
        ch.resolve = null;
        if (dataKey === '__vk_detect') vueDetecting = false;
        resolve(null);
      }, timeoutMs || 3000);

      ch.resolve = function (result) {
        clearTimeout(timer);
        resolve(result);
      };

      var script = document.createElement('script');
      script.src = chrome.runtime.getURL(url);
      script.dataset.vkToken = token;
      script.onload = function () {
        script.remove();
      };
      script.onerror = function () {
        script.remove();
        clearTimeout(timer);
        ch.resolve = null;
        if (dataKey === '__vk_detect') vueDetecting = false;
        resolve(null);
      };
      (document.head || document.documentElement).appendChild(script);
    });
  }

  // ====== Message handlers ======

  // Inject message types → { url, dataKey, timeout }
  var INJECT_HANDLERS = {
    VK_VUE_DETECT: { url: 'src/inject/vue-detect.js', dataKey: '__vk_detect', timeout: 3000 },
    VK_REACT_DETECT: {
      url: 'src/inject/react-detect.js',
      dataKey: '__vk_react_detect',
      timeout: 3000,
    },
    VK_ANGULAR_DETECT: {
      url: 'src/inject/angular-detect.js',
      dataKey: '__vk_angular_detect',
      timeout: 3000,
    },
    VK_SOURCEMAP_DETECT: {
      url: 'src/inject/sourcemap-detect.js',
      dataKey: '__vk_sourcemap_detect',
      timeout: 3000,
    },
    VK_SVELTE_DETECT: {
      url: 'src/inject/svelte-detect.js',
      dataKey: '__vk_svelte_detect',
      timeout: 3000,
    },
    VK_VUE_STORE_EXPLORE: {
      url: 'src/inject/vue-store-explorer.js',
      dataKey: '__vk_vue_store',
      timeout: 5000,
    },
    VK_REACT_STORE_EXPLORE: {
      url: 'src/inject/react-store-explorer.js',
      dataKey: '__vk_react_store',
      timeout: 5000,
    },
    VK_ANGULAR_STORE_EXPLORE: {
      url: 'src/inject/angular-store-explorer.js',
      dataKey: '__vk_angular_store',
      timeout: 5000,
    },
  };

  chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    // Script injection dispatch
    var handler = INJECT_HANDLERS[message.type];
    if (handler) {
      injectScript(handler.url, handler.dataKey, handler.timeout).then(sendResponse);
      return true;
    }

    // Page inspect (has extra dataset attributes)
    if (message.type === 'VK_PAGE_INSPECT') {
      var action = message.action || '';
      if (!action) {
        sendResponse({ error: 'Missing action' });
        return true;
      }
      var ch = channels.__vk_page_inspect;
      var piToken = GEN_TOKEN();
      ch.token = piToken;
      var piTimer = setTimeout(function () {
        ch.resolve = null;
        sendResponse(null);
      }, message.timeout || 5000);

      ch.resolve = function (result) {
        clearTimeout(piTimer);
        ch.resolve = null;
        sendResponse(result);
      };

      var piScript = document.createElement('script');
      piScript.src = chrome.runtime.getURL('src/inject/page-inspect.js');
      piScript.dataset.vkToken = piToken;
      piScript.dataset.vkAction = action;
      piScript.onload = function () {
        piScript.remove();
      };
      piScript.onerror = function () {
        piScript.remove();
        clearTimeout(piTimer);
        ch.resolve = null;
        sendResponse(null);
      };
      (document.head || document.documentElement).appendChild(piScript);
      return true;
    }

    // Link extraction (synchronous, no script injection)
    if (message.type === 'CONTEXT_EXTRACT_LINKS') {
      var pageUrl = location.href;
      var links = [];
      var seen = {};

      function addLink(href, text, tag) {
        if (!href || href === '#' || href.startsWith('javascript:') || seen[href]) return;
        seen[href] = true;
        var domain = '';
        try {
          domain = new URL(href, pageUrl).hostname;
        } catch (e) {
          console.debug('link domain parse:', e.message);
        }
        links.push({ href: href, text: text || '', tag: tag, domain: domain });
      }

      document.querySelectorAll('a[href]').forEach(function (el) {
        addLink(
          el.href,
          (el.textContent || '').trim().substring(0, 60) || el.getAttribute('title') || '',
          'a'
        );
      });
      document.querySelectorAll('script[src]').forEach(function (el) {
        addLink(el.src, '', 'script');
      });
      document.querySelectorAll('link[href]').forEach(function (el) {
        addLink(el.href, el.rel || '', 'link');
      });
      document.querySelectorAll('iframe[src],frame[src]').forEach(function (el) {
        addLink(el.src, '', 'iframe');
      });

      chrome.storage.local.set({ contextExtractedLinks: links, contextExtractedUrl: pageUrl });
      sendResponse({ count: links.length });
      return true;
    }

    // DOM fingerprint (synchronous, no script injection)
    if (message.type === 'VK_FINGERPRINT_DOM') {
      var metaTags = [];
      document.querySelectorAll('meta').forEach(function (m) {
        var name =
          m.getAttribute('name') ||
          m.getAttribute('http-equiv') ||
          m.getAttribute('property') ||
          '';
        var content = m.getAttribute('content') || '';
        if (name) metaTags.push({ name: name, content: content });
      });
      var bodyHtml = '';
      try {
        bodyHtml = (document.body ? document.body.innerHTML : '').substring(0, 200000);
      } catch (e) {
        console.debug('body innerHTML access:', e.message);
      }
      var scriptSrcs = [];
      document.querySelectorAll('script[src]').forEach(function (s) {
        if (s.src) scriptSrcs.push(s.src);
      });
      var styleHrefs = [];
      document.querySelectorAll('link[rel="stylesheet"]').forEach(function (l) {
        if (l.href) styleHrefs.push(l.href);
      });
      sendResponse({
        metaTags: metaTags,
        bodyHtml: bodyHtml,
        scriptSrcs: scriptSrcs,
        styleHrefs: styleHrefs,
      });
      return true;
    }

    return false;
  });
})();
