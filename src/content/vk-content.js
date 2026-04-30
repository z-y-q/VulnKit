// VulnKit - Content Script Bridge
(function () {
  'use strict';

  if (window.__VK_CONTENT_BRIDGE__) return;
  window.__VK_CONTENT_BRIDGE__ = true;

  var extId = chrome.runtime.id;
  var pendingResolve = null;
  var detecting = false;

  window.addEventListener('message', function (e) {
    if (e.data && e.data.__vk_detect && pendingResolve) {
      if (e.origin !== location.origin) return;
      var result = e.data.result;
      pendingResolve(result);
      pendingResolve = null;
      detecting = false;
    }
  });

  function injectAndDetect() {
    if (detecting) return Promise.resolve(null);
    detecting = true;
    return new Promise(function (resolve) {
      pendingResolve = resolve;

      var script = document.createElement('script');
      script.src = chrome.runtime.getURL('src/inject/vue-detect.js');
      script.onload = function () {
        script.remove();
        // Timeout fallback in case postMessage doesn't fire
        setTimeout(function () {
          if (pendingResolve) {
            pendingResolve(null);
            pendingResolve = null;
            detecting = false;
          }
        }, 3000);
      };
      script.onerror = function () {
        script.remove();
        if (pendingResolve) {
          pendingResolve(null);
          pendingResolve = null;
          detecting = false;
        }
      };
      (document.head || document.documentElement).appendChild(script);
    });
  }

  chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message.type === 'VK_VUE_DETECT') {
      injectAndDetect().then(function (result) {
        sendResponse(result);
      });
      return true;
    }
    if (message.type === 'CONTEXT_EXTRACT_LINKS') {
      var pageUrl = location.href;
      var pageDomain = location.hostname;
      var links = [];
      var seen = {};
      function addLink(href, text, tag) {
        if (!href || href === '#' || href.startsWith('javascript:') || seen[href]) return;
        seen[href] = true;
        var domain = '';
        try {
          domain = new URL(href, pageUrl).hostname;
        } catch (e) {}
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
    if (message.type === 'VK_RUOYI_INJECT_HOOK') {
      // Hook is auto-injected via manifest.json document_start + world:MAIN
      // This handler is a fallback for dynamic injection scenarios
      var hookScript = document.createElement('script');
      hookScript.src = chrome.runtime.getURL('src/inject/ruoyi-route-hook.js');
      hookScript.onload = function () {
        hookScript.remove();
      };
      (document.head || document.documentElement).appendChild(hookScript);
      sendResponse({ status: 'ok' });
      return true;
    }
    if (message.type === 'VK_RUOYI_STATUS') {
      var statusHandler = function (e) {
        if (e.data && e.data.__vk_ruoyi_hook_status) {
          sendResponse(e.data);
          window.removeEventListener('message', statusHandler);
        }
      };
      window.addEventListener('message', statusHandler);
      window.postMessage({ __vk_ruoyi_hook_query: true }, '*');
      setTimeout(function () {
        window.removeEventListener('message', statusHandler);
        sendResponse({ status: 'not_installed' });
      }, 1000);
      return true;
    }
  });
})();
