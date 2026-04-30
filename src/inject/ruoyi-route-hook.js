// VulnKit - RuoYi Route Hook (document_start, MAIN world)
// Intercepts fetch/XHR to capture and augment /getRouters responses
(function () {
  'use strict';

  if (window.__VK_RUOYI_HOOK__) return;

  var defaultRouterUrls = [
    /\/getRouters/i,
    /\/getRoutes/i,
    /\/system\/menu\/getRouters/i,
  ];

  var userInfoUrls = [
    /\/getUserInfo/i,
    /\/getInfo/i,
  ];

  window.__VK_RUOYI_HOOK__ = {
    version: '1.1',
    enabled: false,
    capturedRouters: null,
    augmentMode: 'auto',
    extraRoutes: [],
    customRouterUrls: [],
    requestLog: [],
    hookInstalledAt: Date.now(),
  };

  function getTime() {
    var d = new Date();
    return String(d.getHours()).padStart(2, '0') + ':' +
      String(d.getMinutes()).padStart(2, '0') + ':' +
      String(d.getSeconds()).padStart(2, '0');
  }

  function isRouterUrl(url) {
    var hook = window.__VK_RUOYI_HOOK__;
    var allPatterns = defaultRouterUrls.slice();
    if (hook.customRouterUrls) {
      hook.customRouterUrls.forEach(function (custom) {
        try { allPatterns.push(new RegExp(custom, 'i')); } catch (e) { /* ignore bad regex */ }
      });
    }
    return allPatterns.some(function (p) { return p.test(url); });
  }

  function isUserInfoUrl(url) {
    return userInfoUrls.some(function (p) { return p.test(url); });
  }

  function logRequest(type, url, status) {
    var hook = window.__VK_RUOYI_HOOK__;
    if (!hook) return;
    var entry = { type: type, url: url, status: status || '', time: getTime() };
    if (!hook.requestLog) hook.requestLog = [];
    hook.requestLog.push(entry);
    // Keep log bounded
    if (hook.requestLog.length > 100) hook.requestLog = hook.requestLog.slice(-50);
  }

  function mergeExtraRoutes(raw) {
    var config = window.__VK_RUOYI_HOOK__;
    if (!config.extraRoutes || config.extraRoutes.length === 0) return raw;
    try {
      var data = typeof raw === 'string' ? JSON.parse(raw) : JSON.parse(JSON.stringify(raw));
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

      var modified = JSON.stringify(data);
      return { body: modified, injected: injected };
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
        logRequest('router', url, response.status);
        return response.clone().text().then(function (body) {
          config.capturedRouters = body;
          if (config.augmentMode !== 'off' && config.extraRoutes.length > 0) {
            var result = mergeExtraRoutes(body);
            if (typeof result === 'object' && result.body) {
              logRequest('augment', url, 'injected:' + (result.injected || 0));
              window.postMessage({
                __vk_ruoyi_hook: true,
                event: 'routers_captured',
                augmented: true,
                injected: result.injected,
              }, '*');
              return new Response(result.body, {
                status: response.status,
                statusText: response.statusText,
                headers: response.headers,
              });
            }
          }
          window.postMessage({
            __vk_ruoyi_hook: true,
            event: 'routers_captured',
            augmented: false,
          }, '*');
          return response;
        }).catch(function () {
          return response;
        });
      }

      if (isUserInfoUrl(url) && response.ok) {
        logRequest('userinfo', url, response.status);
        window.postMessage({ __vk_ruoyi_hook: true, event: 'userinfo_captured' }, '*');
      }

      return response;
    });
  };

  // XHR hook
  var origOpen = XMLHttpRequest.prototype.open;
  var origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, reqUrl) {
    this.__vk_ruoyi_url = reqUrl;
    this.__vk_ruoyi_method = method;
    return origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function () {
    var self = this;
    var config = window.__VK_RUOYI_HOOK__;
    if (config && config.enabled && this.__vk_ruoyi_url && isRouterUrl(this.__vk_ruoyi_url)) {
      this.addEventListener('readystatechange', function () {
        if (self.readyState === 4 && self.status === 200) {
          var original = self.responseText;
          logRequest('router', self.__vk_ruoyi_url, self.status);
          config.capturedRouters = original;
          if (config.augmentMode !== 'off' && config.extraRoutes.length > 0) {
            var result = mergeExtraRoutes(original);
            if (typeof result === 'object' && result.body) {
              Object.defineProperty(self, 'responseText', { value: result.body, writable: true, configurable: true });
              Object.defineProperty(self, 'response', { value: result.body, writable: true, configurable: true });
              window.postMessage({
                __vk_ruoyi_hook: true,
                event: 'routers_captured',
                augmented: true,
                injected: result.injected,
              }, '*');
              return;
            }
          }
          window.postMessage({ __vk_ruoyi_hook: true, event: 'routers_captured', augmented: false }, '*');
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
    var compPattern = /component\s*:\s*['"`]((?:views|pages|src)\/[^'"`]+?)['"`]/gi;
    var pathPattern = /['"`](\/[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-]+){1,})['"`]/g;
    var skipRe = /\/api\/|\.js$|\.css$|\.(png|jpg|svg|ico|woff|ttf)|\/login$|\/index$/i;

    function scanText(text, source) {
      var m;
      // Route definitions: path: '/xxx'
      routePattern.lastIndex = 0;
      while ((m = routePattern.exec(text)) !== null) {
        var path = m[1];
        if (skipRe.test(path) || path.length < 4) continue;
        if (!seen[path]) {
          seen[path] = true;
          discovered.push({ path: path, source: source, type: 'route-def' });
        }
      }

      // Component references: component: 'views/xxx'
      compPattern.lastIndex = 0;
      while ((m = compPattern.exec(text)) !== null) {
        var comp = m[1];
        if (!seen[comp]) {
          seen[comp] = true;
          discovered.push({ path: '', source: source, type: 'component-ref', component: comp });
        }
      }

      // Generic path strings
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
