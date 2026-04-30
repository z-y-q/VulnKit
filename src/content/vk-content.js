// VulnKit - Content Script Bridge
(function () {
  'use strict';

  if (window.__VK_CONTENT_BRIDGE__) return;
  window.__VK_CONTENT_BRIDGE__ = true;

  var extId = chrome.runtime.id;
  var pendingResolve = null;
  var storeExploreResolve = null;
  var detecting = false;

  // Vue detect response relay
  window.addEventListener('message', function (e) {
    if (e.origin !== location.origin) return;

    // Vue detection result
    if (e.data && e.data.__vk_detect && pendingResolve) {
      pendingResolve(e.data.result);
      pendingResolve = null;
      detecting = false;
      return;
    }

    // RuoYi hook events → forward to popup
    if (e.data && e.data.__vk_ruoyi_hook && e.data.event) {
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

    // Vue store explorer result
    if (e.data && e.data.__vk_vue_store && storeExploreResolve) {
      storeExploreResolve(e.data.result);
      storeExploreResolve = null;
      return;
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
      var hookScript = document.createElement('script');
      hookScript.src = chrome.runtime.getURL('src/inject/ruoyi-route-hook.js');
      hookScript.onload = function () {
        hookScript.remove();
        sendResponse({ status: 'ok' });
      };
      hookScript.onerror = function () {
        hookScript.remove();
        sendResponse({ status: 'load-failed' });
      };
      (document.head || document.documentElement).appendChild(hookScript);
      return true;
    }
    if (message.type === 'VK_VUE_STORE_EXPLORE') {
      storeExploreResolve = null;
      return new Promise(function (resolve) {
        storeExploreResolve = resolve;
        var script = document.createElement('script');
        script.src = chrome.runtime.getURL('src/inject/vue-store-explorer.js');
        script.onload = function () {
          script.remove();
          setTimeout(function () {
            if (storeExploreResolve) {
              storeExploreResolve({ error: 'Store explorer timeout' });
              storeExploreResolve = null;
            }
          }, 5000);
        };
        script.onerror = function () {
          script.remove();
          if (storeExploreResolve) {
            storeExploreResolve({ error: 'Failed to load store explorer' });
            storeExploreResolve = null;
          }
        };
        (document.head || document.documentElement).appendChild(script);
      }).then(function (result) {
        sendResponse(result);
      });
      return true;
    }
  });
})();
