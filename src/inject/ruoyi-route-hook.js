// 灵眸 - RuoYi Route Hook (document_start, MAIN world)
// Intercepts fetch/XHR to capture and augment /getRouters responses
// Capture is ALWAYS active (passive). `enabled` controls augmentation and API logging.
(function () {
  'use strict';

  if (window.__VK_RUOYI_HOOK__) return;

  var defaultRouterUrls = [/\/getRouters/i, /\/getRoutes/i, /\/system\/menu\/getRouters/i];

  var userInfoUrls = [/\/getUserInfo/i, /\/getInfo/i];

  // Read persisted config from localStorage (survives page refresh)
  var savedConfig = null;
  try {
    var raw = localStorage.getItem('__vk_ruoyi_hook_config');
    if (raw) savedConfig = JSON.parse(raw);
  } catch (e) {
    savedConfig = null;
  }

  // Only restore if saved for this origin (security check)
  var configEnabled = false;
  var configAugmentMode = 'auto';
  var configExtraRoutes = [];
  var configCustomUrls = [];

  if (savedConfig && savedConfig.origin === location.origin) {
    configEnabled = true;
    configAugmentMode = savedConfig.augmentMode || 'auto';
    configExtraRoutes = savedConfig.extraRoutes || [];
    configCustomUrls = savedConfig.customRouterUrls || [];
  }

  window.__VK_RUOYI_HOOK__ = {
    version: '1.4',
    enabled: configEnabled,
    capturedRouters: null,
    augmentMode: configAugmentMode,
    extraRoutes: configExtraRoutes,
    customRouterUrls: configCustomUrls,
    requestLog: [],
    apiLog: [],
    hookInstalledAt: Date.now(),
    restoredFromStorage: configEnabled,
    alwaysCapture: true,
  };

  function getTime() {
    var d = new Date();
    return (
      String(d.getHours()).padStart(2, '0') +
      ':' +
      String(d.getMinutes()).padStart(2, '0') +
      ':' +
      String(d.getSeconds()).padStart(2, '0')
    );
  }

  var _cachedCustomUrls = '';
  var _cachedPatterns = null;
  var _quickSkipRe = /(?:getRouters?|getUserInfo|getInfo)\b/i;
  var _quickApiSkipRe =
    /\b(?:api|admin|system|monitor|tool|gen|auth|login|logout|captcha|code|user|role|menu|dept|post|dict|config|notice|log)\b|\.(?:json|xml)\b/i;

  function isRouterUrl(url) {
    var hook = window.__VK_RUOYI_HOOK__;
    var customKey = (hook.customRouterUrls || []).join('|');
    if (customKey !== _cachedCustomUrls) {
      _cachedCustomUrls = customKey;
      _cachedPatterns = defaultRouterUrls.slice();
      (hook.customRouterUrls || []).forEach(function (custom) {
        try {
          _cachedPatterns.push(new RegExp(custom, 'i'));
        } catch (e) {
          /* ignore */
        }
      });
    }
    return _cachedPatterns.some(function (p) {
      return p.test(url);
    });
  }

  function isUserInfoUrl(url) {
    return userInfoUrls.some(function (p) {
      return p.test(url);
    });
  }

  function isApiUrl(url) {
    try {
      var pathname = new URL(url, location.origin).pathname;
      return (
        /^\/(api|admin|system|monitor|tool|gen|auth|login|logout|captcha|code|user|role|menu|dept|post|dict|config|notice|log)\b/i.test(
          pathname
        ) ||
        /\.(json|xml)$/i.test(pathname) ||
        /\/(get|list|add|edit|update|delete|remove|export|import|upload|download|query)\b/i.test(
          pathname
        )
      );
    } catch (e) {
      return false;
    }
  }

  function logApiRequest(url, method, status, body) {
    var hook = window.__VK_RUOYI_HOOK__;
    if (!hook) return;
    if (!hook.apiLog) hook.apiLog = [];
    hook.apiLog.push({
      url: url,
      method: method || 'GET',
      status: status || 0,
      body: body ? body.substring(0, 5000) : '',
      time: getTime(),
    });
    if (hook.apiLog.length > 200) hook.apiLog = hook.apiLog.slice(-150);
  }

  function logRequest(type, url, status, method) {
    var hook = window.__VK_RUOYI_HOOK__;
    if (!hook) return;
    var entry = {
      type: type,
      url: url,
      status: status || '',
      method: method || '',
      time: getTime(),
    };
    if (!hook.requestLog) hook.requestLog = [];
    hook.requestLog.push(entry);
    if (hook.requestLog.length > 100) hook.requestLog = hook.requestLog.slice(-50);
  }

  function findParentByPath(routes, parentPath) {
    for (var i = 0; i < routes.length; i++) {
      if (routes[i].path === parentPath) return routes[i];
      if (routes[i].children) {
        var found = findParentByPath(routes[i].children, parentPath);
        if (found) return found;
      }
    }
    return null;
  }

  function ensureParent(routeArray, parentPath) {
    var existing = findParentByPath(routeArray, parentPath);
    if (existing) return existing;
    var parent = {
      name: parentPath.replace(/\//g, '') || 'Root',
      path: parentPath,
      hidden: false,
      component: 'Layout',
      meta: { title: parentPath, icon: 'menu' },
      children: [],
    };
    routeArray.push(parent);
    return parent;
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

        var segments = extra.path.replace(/^\/+/, '').split('/');
        var childNode = {
          name: extra.name || segments.join('') || extra.path,
          path: extra.childPath || (segments.length > 1 ? segments.slice(1).join('/') : 'index'),
          hidden: false,
          component: extra.component || '',
          meta: {
            title: extra.title || extra.path,
            icon: extra.icon || 'menu',
            activeMenu: extra.path,
          },
        };

        if (segments.length > 1) {
          var parentPath = '/' + segments[0];
          var parent = ensureParent(routeArray, parentPath);
          if (!parent.children) parent.children = [];
          parent.children.push(childNode);
          existing[extra.path] = true;
          injected++;
        } else {
          routeArray.push({
            name: extra.name || extra.path,
            path: extra.path,
            hidden: false,
            component: 'Layout',
            meta: { title: extra.title || extra.path, icon: extra.icon || 'menu' },
            children: [childNode],
          });
          existing[extra.path] = true;
          injected++;
        }
      });

      var modified = JSON.stringify(data);
      return { body: modified, injected: injected };
    } catch (e) {
      return raw;
    }
  }

  // Fetch hook — ALWAYS captures router/userinfo data regardless of enabled flag.
  // enabled only controls augmentation (injecting extra routes) and API traffic logging.
  var origFetch = window.fetch;
  window.fetch = function () {
    var args = arguments;
    var url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
    var fetchOpts = args[1] && typeof args[1] === 'object' ? args[1] : {};
    var fetchMethod = (fetchOpts.method || 'GET').toUpperCase();
    var isRouter = _quickSkipRe.test(url);
    var isUserInfo = !isRouter && /(?:getUserInfo|getInfo)\b/i.test(url);
    return origFetch.apply(this, args).then(function (response) {
      var config = window.__VK_RUOYI_HOOK__;

      // ALWAYS capture /getRouters responses (passive, no modification)
      if (isRouter) {
        if (!response.ok) {
          logRequest('router-error', url, response.status, fetchMethod);
          return response;
        }
        logRequest('router', url, response.status, fetchMethod);
        return response
          .clone()
          .text()
          .then(function (body) {
            if (config) config.capturedRouters = body;

            // Augmentation (modifying response) only when enabled
            if (
              config &&
              config.enabled &&
              config.augmentMode !== 'off' &&
              config.extraRoutes.length > 0
            ) {
              var result = mergeExtraRoutes(body);
              if (typeof result === 'object' && result.body) {
                logRequest('augment', url, 'injected:' + (result.injected || 0), fetchMethod);
                window.postMessage(
                  {
                    __vk_ruoyi_hook: true,
                    event: 'routers_captured',
                    augmented: true,
                    injected: result.injected,
                  },
                  location.origin
                );
                return new Response(result.body, {
                  status: response.status,
                  statusText: response.statusText,
                  headers: response.headers,
                });
              }
            }
            window.postMessage(
              {
                __vk_ruoyi_hook: true,
                event: 'routers_captured',
                augmented: false,
              },
              location.origin
            );
            return response;
          })
          .catch(function () {
            return response;
          });
      }

      // ALWAYS capture userinfo responses
      if (isUserInfo) {
        if (!response.ok) {
          logRequest('userinfo-error', url, response.status, fetchMethod);
          return response;
        }
        logRequest('userinfo', url, response.status, fetchMethod);
        window.postMessage({ __vk_ruoyi_hook: true, event: 'userinfo_captured' }, location.origin);
      }

      // API traffic logging only when enabled (more expensive)
      if (config && config.enabled && _quickApiSkipRe.test(url) && !isRouter && !isUserInfo) {
        response
          .clone()
          .text()
          .then(function (body) {
            logApiRequest(url, fetchMethod, response.status, body);
          })
          .catch(function () {
            logApiRequest(url, fetchMethod, response.status, '');
          });
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
    var reqUrl = this.__vk_ruoyi_url;
    var xhrIsRouter = reqUrl ? _quickSkipRe.test(reqUrl) : false;
    var xhrIsUserInfo = !xhrIsRouter && reqUrl ? /(?:getUserInfo|getInfo)\b/i.test(reqUrl) : false;

    // ALWAYS capture router responses (passive)
    if (xhrIsRouter) {
      this.addEventListener('readystatechange', function () {
        if (self.readyState === 4) {
          if (self.status !== 200) {
            logRequest('router-error', self.__vk_ruoyi_url, self.status, self.__vk_ruoyi_method);
            return;
          }
          var original = self.responseText;
          logRequest('router', self.__vk_ruoyi_url, self.status, self.__vk_ruoyi_method);
          if (config) config.capturedRouters = original;

          // Augmentation only when enabled
          if (
            config &&
            config.enabled &&
            config.augmentMode !== 'off' &&
            config.extraRoutes.length > 0
          ) {
            var result = mergeExtraRoutes(original);
            if (typeof result === 'object' && result.body) {
              Object.defineProperty(self, 'responseText', {
                value: result.body,
                writable: true,
                configurable: true,
              });
              try {
                var parsed = JSON.parse(result.body);
                Object.defineProperty(self, 'response', {
                  value: parsed,
                  writable: true,
                  configurable: true,
                });
              } catch (ex) {
                Object.defineProperty(self, 'response', {
                  value: result.body,
                  writable: true,
                  configurable: true,
                });
              }
              window.postMessage(
                {
                  __vk_ruoyi_hook: true,
                  event: 'routers_captured',
                  augmented: true,
                  injected: result.injected,
                },
                location.origin
              );
              return;
            }
          }
          window.postMessage(
            { __vk_ruoyi_hook: true, event: 'routers_captured', augmented: false },
            location.origin
          );
        }
      });
    } else if (
      config &&
      config.enabled &&
      reqUrl &&
      _quickApiSkipRe.test(reqUrl) &&
      !xhrIsRouter &&
      !xhrIsUserInfo
    ) {
      this.addEventListener('load', function () {
        logApiRequest(
          self.__vk_ruoyi_url,
          self.__vk_ruoyi_method,
          self.status,
          self.responseText || ''
        );
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

  // Persist/restore hook config via localStorage (survives page refresh)
  window.__VK_RUOYI_HOOK__.saveConfig = function () {
    try {
      localStorage.setItem(
        '__vk_ruoyi_hook_config',
        JSON.stringify({
          origin: location.origin,
          enabled: window.__VK_RUOYI_HOOK__.enabled,
          augmentMode: window.__VK_RUOYI_HOOK__.augmentMode,
          extraRoutes: window.__VK_RUOYI_HOOK__.extraRoutes || [],
          customRouterUrls: window.__VK_RUOYI_HOOK__.customRouterUrls || [],
        })
      );
      return true;
    } catch (e) {
      return false;
    }
  };

  window.__VK_RUOYI_HOOK__.clearConfig = function () {
    try {
      localStorage.removeItem('__vk_ruoyi_hook_config');
      return true;
    } catch (e) {
      return false;
    }
  };

  // ====== Vue Router Injection (MaR-style dynamic route loading) ======

  function findVueRouter() {
    var router = null;

    // Vue 3: check __vue_app__
    if (window.__vue_app__) {
      try {
        var cfg = window.__vue_app__.config;
        if (cfg && cfg.globalProperties && cfg.globalProperties.$router) {
          return cfg.globalProperties.$router;
        }
      } catch (e) {
        /* ignore */
      }
    }

    // Search DOM elements for Vue instances
    var selectors = ['#app', '[data-v-app]', '.app-wrapper', '#app-main'];
    for (var si = 0; si < selectors.length && !router; si++) {
      var els = document.querySelectorAll(selectors[si]);
      for (var ei = 0; ei < els.length && !router; ei++) {
        var el = els[ei];
        // Vue 3 app instance
        if (el.__vue_app__) {
          try {
            router = el.__vue_app__.config.globalProperties.$router;
          } catch (e) {
            /* ignore */
          }
        }
        // Vue 2 instance
        if (!router && el.__vue__) {
          router = el.__vue__.$router || (el.__vue__.$root && el.__vue__.$root.$router);
        }
      }
    }

    // Deep scan for Vue 2 instances on all elements
    if (!router) {
      var allEls = document.querySelectorAll('*');
      for (var ai = 0; ai < allEls.length && !router; ai++) {
        var ael = allEls[ai];
        if (ael.__vue__ && ael.__vue__.$router) {
          router = ael.__vue__.$router;
        } else if (ael.__vue__ && ael.__vue__.$root && ael.__vue__.$root.$router) {
          router = ael.__vue__.$root.$router;
        }
      }
    }

    return router;
  }

  window.__VK_RUOYI_HOOK__.findVueRouter = findVueRouter;

  window.__VK_RUOYI_HOOK__.getRouterInfo = function () {
    var router = findVueRouter();
    if (!router) return { found: false, routes: [], currentRoutes: [] };
    var currentRoutes = [];
    try {
      var rawRoutes = router.getRoutes
        ? router.getRoutes()
        : (router.options && router.options.routes) || [];
      rawRoutes.forEach(function (r) {
        if (r.path) currentRoutes.push(r.path);
      });
    } catch (e) {
      /* ignore */
    }
    return {
      found: true,
      mode: router.mode || (router.options && router.options.history ? 'history' : 'hash'),
      routeCount: currentRoutes.length,
      currentRoutes: currentRoutes,
    };
  };

  window.__VK_RUOYI_HOOK__.injectRoutesToVueRouter = function (routes) {
    var result = { injected: 0, skipped: 0, errors: [], routerFound: false, routerMode: '' };
    var router = findVueRouter();

    if (!router) {
      result.errors.push('Vue Router 实例未找到');
      return result;
    }

    result.routerFound = true;
    result.routerMode = router.mode || 'unknown';

    // Try to find RuoYi's loadView function for component resolution
    var loadView = null;
    try {
      // Check global scope or common RuoYi patterns
      if (typeof window.loadView === 'function') loadView = window.loadView;
      if (!loadView && typeof window.loadComponent === 'function') loadView = window.loadComponent;
    } catch (e) {
      /* ignore */
    }

    // Get current route paths for dedup
    var existingPaths = {};
    try {
      var currentRoutes = router.getRoutes ? router.getRoutes() : [];
      currentRoutes.forEach(function (r) {
        if (r.path) existingPaths[r.path] = true;
      });
    } catch (e) {
      /* ignore */
    }

    routes.forEach(function (route) {
      try {
        var path = route.path;
        if (!path) {
          result.skipped++;
          return;
        }
        if (existingPaths[path]) {
          result.skipped++;
          return;
        }

        // Build a proper route object with component resolution
        var routeObj = {
          path: path,
          name: route.name || path.replace(/^\/+/, '').replace(/\//g, '-'),
          meta: route.meta || {},
        };

        // Resolve component string to actual component
        if (route.component && typeof route.component === 'string') {
          if (loadView) {
            try {
              routeObj.component = loadView(route.component);
            } catch (e) {
              // loadView failed — use a placeholder component
              routeObj.component = { template: '<div>Loading: ' + path + '</div>' };
            }
          } else {
            // No loadView — try webpack dynamic import pattern
            try {
              var viewPath = route.component;
              if (!/^views\//i.test(viewPath) && !/^\//i.test(viewPath)) {
                viewPath = 'views/' + viewPath;
              }
              routeObj.component = function () {
                return import(
                  /* webpackChunkName: "mar-[request]" */ '@/'.concat(viewPath, '.vue')
                );
              };
            } catch (e) {
              routeObj.component = { template: '<div>Loading: ' + path + '</div>' };
            }
          }
        } else if (route.component) {
          routeObj.component = route.component;
        } else {
          // No component specified — use placeholder
          routeObj.component = { template: '<div>Route: ' + path + '</div>' };
        }

        if (typeof router.addRoute === 'function') {
          // Vue Router 4 (Vue 3) — wrap under a parent Layout route if needed
          router.addRoute(routeObj);
        } else if (typeof router.addRoutes === 'function') {
          // Vue Router 3 (Vue 2)
          router.addRoutes([routeObj]);
        } else {
          result.errors.push('No addRoute/addRoutes method');
          return;
        }
        result.injected++;
        existingPaths[path] = true;
      } catch (e) {
        result.errors.push((route.path || '?') + ': ' + e.message);
      }
    });

    return result;
  };

  // Notify popup if hook was auto-restored from storage
  if (configEnabled) {
    setTimeout(function () {
      window.postMessage(
        {
          __vk_ruoyi_hook: true,
          event: 'hook_restored',
          augmented: false,
          injected: 0,
        },
        location.origin
      );
    }, 500);
  }
})();
