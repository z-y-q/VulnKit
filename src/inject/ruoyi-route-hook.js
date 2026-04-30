// VulnKit - RuoYi Route Hook (document_start, MAIN world)
// Intercepts fetch/XHR to capture and augment /getRouters responses
(function () {
  'use strict';

  if (window.__VK_RUOYI_HOOK__) return;

  window.__VK_RUOYI_HOOK__ = {
    version: '1.0',
    enabled: false,
    capturedRouters: null,
    augmentMode: 'auto',
    extraRoutes: [],
    hookInstalledAt: Date.now(),
  };

  var ROUTER_URLS = [
    /\/getRouters/i,
    /\/getRoutes/i,
    /\/system\/menu\/getRouters/i,
  ];

  var USERINFO_URLS = [
    /\/getUserInfo/i,
    /\/getInfo/i,
  ];

  function isRouterUrl(url) {
    return ROUTER_URLS.some(function (p) { return p.test(url); });
  }

  function isUserInfoUrl(url) {
    return USERINFO_URLS.some(function (p) { return p.test(url); });
  }

  function mergeExtraRoutes(raw) {
    var config = window.__VK_RUOYI_HOOK__;
    if (!config.extraRoutes || config.extraRoutes.length === 0) return raw;
    try {
      var data = typeof raw === 'string' ? JSON.parse(raw) : raw;
      var routeArray = data.data;
      if (!Array.isArray(routeArray)) return raw;

      var existing = {};
      (function collect(routes) {
        routes.forEach(function (r) {
          if (r.path) existing[r.path] = true;
          if (r.children) collect(r.children);
        });
      })(routeArray);

      var injected = 0;
      config.extraRoutes.forEach(function (extra) {
        if (existing[extra.path]) return;
        routeArray.push({
          name: extra.name || extra.path,
          path: extra.path,
          hidden: false,
          component: 'Layout',
          meta: { title: extra.title || extra.path, icon: extra.icon || 'menu' },
          children: [{
            name: extra.name ? extra.name + 'Index' : extra.path + 'Index',
            path: extra.childPath || 'index',
            hidden: false,
            component: extra.component || '',
            meta: { title: extra.title || extra.path, icon: extra.icon || 'menu', activeMenu: extra.path },
          }],
        });
        existing[extra.path] = true;
        injected++;
      });

      return JSON.stringify(data);
    } catch (e) {
      return raw;
    }
  }

  // Fetch hook
  var origFetch = window.fetch;
  window.fetch = function () {
    var args = arguments;
    var url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
    return origFetch.apply(this, args).then(function (response) {
      var config = window.__VK_RUOYI_HOOK__;
      if (!config || !config.enabled) return response;

      if (isRouterUrl(url) && response.ok) {
        return response.clone().text().then(function (body) {
          config.capturedRouters = body;
          var modified = body;
          if (config.augmentMode !== 'off' && config.extraRoutes.length > 0) {
            modified = mergeExtraRoutes(body);
          }
          window.postMessage({
            __vk_ruoyi_hook: true,
            event: 'routers_captured',
            augmented: modified !== body,
          }, '*');
          if (modified !== body) {
            return new Response(modified, {
              status: response.status,
              statusText: response.statusText,
              headers: response.headers,
            });
          }
          return response;
        }).catch(function () {
          return response;
        });
      }

      if (isUserInfoUrl(url) && response.ok) {
        response.clone().text().then(function () {
          window.postMessage({ __vk_ruoyi_hook: true, event: 'userinfo_captured' }, '*');
        }).catch(function () {});
      }

      return response;
    });
  };

  // XHR hook
  var origOpen = XMLHttpRequest.prototype.open;
  var origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, reqUrl) {
    this.__vk_ruoyi_url = reqUrl;
    return origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function () {
    var self = this;
    var config = window.__VK_RUOYI_HOOK__;
    if (config && config.enabled && this.__vk_ruoyi_url && isRouterUrl(this.__vk_ruoyi_url)) {
      this.addEventListener('readystatechange', function () {
        if (self.readyState === 4 && self.status === 200) {
          var original = self.responseText;
          config.capturedRouters = original;
          if (config.augmentMode !== 'off' && config.extraRoutes.length > 0) {
            var modified = mergeExtraRoutes(original);
            Object.defineProperty(self, 'responseText', { value: modified, writable: true, configurable: true });
            Object.defineProperty(self, 'response', { value: modified, writable: true, configurable: true });
            window.postMessage({ __vk_ruoyi_hook: true, event: 'routers_captured', augmented: true }, '*');
          } else {
            window.postMessage({ __vk_ruoyi_hook: true, event: 'routers_captured', augmented: false }, '*');
          }
        }
      });
    }
    return origSend.apply(this, arguments);
  };

  // JS route discovery helper
  window.__VK_RUOYI_HOOK__.discoverRoutesFromJs = function () {
    var discovered = [];
    var seen = {};
    var routePattern = /path\s*:\s*['"`](\/[a-zA-Z0-9_\-\/]+)['"`]/g;
    var pathPattern = /['"`](\/[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-]+){1,})['"`]/g;
    var skipRe = /\/api\/|\.js$|\.css$|\.(png|jpg|svg|ico|woff|ttf)/i;

    function scanText(text, source) {
      var m;
      routePattern.lastIndex = 0;
      while ((m = routePattern.exec(text)) !== null) {
        var path = m[1];
        if (skipRe.test(path) || path.length < 4) continue;
        if (!seen[path]) {
          seen[path] = true;
          discovered.push({ path: path, source: source, type: 'route-def' });
        }
      }
      pathPattern.lastIndex = 0;
      while ((m = pathPattern.exec(text)) !== null) {
        var p = m[1];
        if (skipRe.test(p) || p.length < 5 || seen[p]) continue;
        seen[p] = true;
        discovered.push({ path: p, source: source, type: 'path-string' });
      }
    }

    document.querySelectorAll('script:not([src])').forEach(function (s, i) {
      var text = s.textContent || '';
      if (text.length > 500000) return;
      scanText(text, 'inline#' + (i + 1));
    });

    var extUrls = [];
    document.querySelectorAll('script[src]').forEach(function (s) {
      extUrls.push(s.src);
    });

    return { discovered: discovered, extUrls: extUrls };
  };
})();
