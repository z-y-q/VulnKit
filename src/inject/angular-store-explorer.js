// 灵眸 - Angular Store/Router Explorer (MAIN world injection)
// Extracts NgRx store state, Angular signals, Router config, API endpoints
(function () {
  'use strict';

  var __vk_token = document.currentScript ? document.currentScript.dataset.vkToken || '' : '';

  function safeClone(obj, depth) {
    if (depth === undefined) depth = 0;
    if (obj === null || obj === undefined) return obj;
    if (typeof obj !== 'object') return obj;
    if (depth > 6) return '[Max Depth]';
    try {
      return JSON.parse(
        JSON.stringify(obj, function (key, value) {
          if (typeof value === 'function') return '[Function]';
          if (value instanceof HTMLElement) return '[HTMLElement: ' + (value.tagName || 'unknown') + ']';
          if (value instanceof Window) return '[Window]';
          if (value instanceof Error) return '[Error: ' + value.message + ']';
          if (typeof value === 'symbol') return value.toString();
          if (typeof value === 'bigint') return '[BigInt: ' + value.toString() + ']';
          if (value instanceof Promise) return '[Promise]';
          if (value instanceof Map) {
            try { return { __type__: 'Map', size: value.size }; } catch (_) { return '[Map]'; }
          }
          if (value instanceof Set) {
            try { return { __type__: 'Set', size: value.size }; } catch (_) { return '[Set]'; }
          }
          if (value instanceof WeakMap || value instanceof WeakSet) return '[WeakRef]';
          return value;
        })
      );
    } catch (e) {
      return String(obj);
    }
  }

  function findRootComponent() {
    var roots = document.querySelectorAll('[ng-version], app-root, [app-root], app-root > *, [ng-version] > *');
    if (roots.length > 0) return roots[0];
    var app = document.querySelector('app-root, app-app, [app-root]');
    return app || document.body;
  }

  function extractNgrxStores() {
    var stores = [];
    var errors = [];

    // Method 1: Global __NGRX_ROOT__ or window store references
    try {
      if (window.__NGRX_ROOT__) {
        stores.push({ name: 'NgRx Root', store: window.__NGRX_ROOT__ });
      }
    } catch (_) { /* skip */ }

    // Method 2: __REDUX_DEVTOOLS_EXTENSION__ — works for NgRx since it uses Redux DevTools
    try {
      if (window.__REDUX_DEVTOOLS_EXTENSION__) {
        var devTools = window.__REDUX_DEVTOOLS_EXTENSION__;
        if (devTools._instances) {
          devTools._instances.forEach(function (store, id) {
            if (store && typeof store.getState === 'function') {
              stores.push({ name: 'ngrx-devtools-' + id, store: store });
            }
          });
        }
      }
    } catch (e) {
      errors.push('NgRx DevTools: ' + (e.message || String(e)));
    }

    // Method 3: Try ng.probe in dev mode to access Angular DI
    try {
      if (typeof ng !== 'undefined' && ng.probe) {
        var rootEl = findRootComponent();
        var componentRef = ng.probe(rootEl);
        if (componentRef) {
          // Try to get Store from injector
          try {
            var injector = componentRef.injector;
            // Walk up injectors to find Store
            var current = injector;
            var depth = 0;
            while (current && depth < 15) {
              try {
                // NgRx Store has getState()
                var storeInstance = current.get && current.get({ toString: function() { return 'Store'; } });
                if (storeInstance && typeof storeInstance.getState === 'function') {
                  stores.push({ name: 'ngrx-injector-store', store: storeInstance });
                  break;
                }
              } catch (e) {
                // Not found in this injector level, try parent
              }
              try {
                if (current.viewContainerRef && current.viewContainerRef.injector) {
                  current = current.viewContainerRef.injector;
                } else if (current.parent) {
                  current = current.parent;
                } else {
                  break;
                }
              } catch (_) { break; }
              depth++;
            }
          } catch (e) {
            errors.push('NgRx DI scan: ' + (e.message || String(e)));
          }
        }
      }
    } catch (e) {
      errors.push('ng.probe scan: ' + (e.message || String(e)));
    }

    var result = {};
    var seenStates = {};
    stores.forEach(function (entry) {
      try {
        var state = entry.store.getState();
        var stateKey = Object.keys(state || {}).sort().join(',');
        if (seenStates[stateKey]) return;
        seenStates[stateKey] = true;
        result[entry.name] = {
          state: safeClone(state),
          type: 'ngrx-store',
        };
      } catch (e) {
        errors.push(entry.name + ': ' + (e.message || String(e)));
      }
    });

    return { stores: result, errors: errors };
  }

  function extractAngularSignals() {
    var signals = [];
    var errors = [];

    try {
      if (typeof ng !== 'undefined' && ng.probe) {
        var rootEl = findRootComponent();
        var componentRef = ng.probe(rootEl);
        if (componentRef && componentRef.componentInstance) {
          var instance = componentRef.componentInstance;
          Object.keys(instance).forEach(function (key) {
            try {
              var val = instance[key];
              if (!val || typeof val !== 'object') return;
              // Angular signals have a __v_isRef or internal signal marker
              if (typeof val === 'function' || (val.constructor && val.constructor.name === 'Signal')) {
                signals.push({ name: key, component: 'root', type: 'signal' });
              }
              // SignalStore patterns: { state, ...methods }
              if (val.state && typeof val.state === 'object' && Object.keys(val).length > 1) {
                signals.push({ name: key, component: 'root', type: 'signal-store', state: safeClone(val.state) });
              }
            } catch (_) { /* skip */ }
          });
        }
      }
    } catch (e) {
      errors.push('Signal extraction: ' + (e.message || String(e)));
    }

    // Scan window for signal-related globals
    try {
      Object.keys(window).forEach(function (key) {
        if (key.indexOf('__') === 0 || key.indexOf('webkit') === 0 || key.indexOf('on') === 0) return;
        try {
          var val = window[key];
          if (!val || typeof val !== 'object') return;
          if (val.__signal__ || (val.constructor && val.constructor.name && val.constructor.name.indexOf('Signal') !== -1)) {
            signals.push({ name: key, component: 'global', type: 'signal' });
          }
        } catch (_) { /* skip */ }
      });
    } catch (_) { /* skip */ }

    return { signals: signals, errors: errors };
  }

  function extractAngularRoutes() {
    var routes = [];
    var errors = [];

    // Method 1: ng.probe + Router DI
    try {
      if (typeof ng !== 'undefined' && ng.probe) {
        var rootEl = findRootComponent();
        var componentRef = ng.probe(rootEl);
        if (componentRef) {
          var injector = componentRef.injector;
          var current = injector;
          var depth = 0;
          while (current && depth < 15) {
            try {
              var router = current.get && current.get({ toString: function() { return 'Router'; } });
              if (router && router.config) {
                processRouteConfig(router.config, '', routes);
                break;
              }
            } catch (e) {
              // Not found at this level
            }
            try {
              if (current.parent) {
                current = current.parent;
              } else {
                break;
              }
            } catch (_) { break; }
            depth++;
          }
        }
      }
    } catch (e) {
      errors.push('Router DI: ' + (e.message || String(e)));
    }

    // Method 2: Anchor-based fallback
    try {
      var anchorRoutes = {};
      document.querySelectorAll('a[href^="/"]').forEach(function (a) {
        var href = a.getAttribute('href');
        if (!href || href.length <= 1) return;
        var clean = href.split('?')[0].split('#')[0];
        if (clean.length > 1 && !anchorRoutes[clean]) {
          anchorRoutes[clean] = true;
          routes.push({ path: clean, source: 'anchor href' });
        }
      });
    } catch (_) { /* skip */ }

    if (routes.length > 100) routes = routes.slice(0, 100);
    return { routes: routes, errors: errors };
  }

  function processRouteConfig(config, parentPath, routes) {
    if (!Array.isArray(config)) return;
    config.forEach(function (route) {
      if (!route || typeof route !== 'object') return;
      var fullPath = parentPath ? parentPath + '/' + (route.path || '') : route.path || '';
      if (fullPath.charAt(0) !== '/') fullPath = '/' + fullPath;
      if (fullPath === '//') fullPath = '/';
      // Normalize double slashes
      fullPath = fullPath.replace(/\/+/g, '/');

      var routeEntry = {
        path: fullPath,
        source: 'Angular Router config',
      };

      if (route.component) {
        routeEntry.component = route.component.name || String(route.component);
      }
      if (route.loadChildren || route.loadComponent) {
        routeEntry.lazy = true;
      }
      if (route.canActivate && route.canActivate.length > 0) {
        routeEntry.guards = route.canActivate.map(function (g) { return g.name || String(g); });
      }
      if (route.canDeactivate && route.canDeactivate.length > 0) {
        routeEntry.guards = (routeEntry.guards || []).concat(
          route.canDeactivate.map(function (g) { return g.name || String(g); })
        );
      }
      if (route.canMatch && route.canMatch.length > 0) {
        routeEntry.guards = (routeEntry.guards || []).concat(
          route.canMatch.map(function (g) { return g.name || String(g); })
        );
      }
      if (route.data && typeof route.data === 'object') {
        routeEntry.data = safeClone(route.data);
      }
      routes.push(routeEntry);

      if (route.children) {
        processRouteConfig(route.children, fullPath, routes);
      }
    });
  }

  function extractApiEndpoints() {
    var endpoints = [];
    var seen = {};

    var urlPatterns = [
      /['"`](\/(?:api|v[0-9]+|admin|system|user|auth|login|register|query|search|list|get|post|put|delete|patch|upload|download|config|setting|profile|account|role|permission|menu|dict|file|image|log|monitor|report|dashboard|health|status|info|version|token|session|captcha|common|public|static|resource|data|base|core|service|gateway|proxy|ws|graphql|rest)\/[^\s'"`)\]]{2,120})['"`]/gi,
    ];

    try {
      document.querySelectorAll('script:not([src])').forEach(function (s) {
        var text = s.textContent || '';
        if (text.length > 500000) text = text.substring(0, 500000);
        urlPatterns.forEach(function (pattern) {
          var match;
          pattern.lastIndex = 0;
          while ((match = pattern.exec(text)) !== null) {
            var url = match[1];
            if (!seen[url] && !url.startsWith('//') && url.length > 3) {
              seen[url] = true;
              endpoints.push(url);
            }
          }
        });
      });
    } catch (_) { /* skip */ }

    if (endpoints.length > 100) endpoints = endpoints.slice(0, 100);
    return endpoints;
  }

  // === Main execution ===
  var result = {
    stores: {},
    signals: [],
    routes: [],
    apiEndpoints: [],
    errors: [],
  };

  // NgRx Stores
  try {
    var ngrxResult = extractNgrxStores();
    Object.keys(ngrxResult.stores).forEach(function (k) {
      result.stores[k] = ngrxResult.stores[k];
    });
    result.errors = result.errors.concat(ngrxResult.errors);
  } catch (e) {
    result.errors.push('NgRx extraction: ' + (e.message || String(e)));
  }

  // Angular Signals
  try {
    var signalResult = extractAngularSignals();
    signalResult.signals.forEach(function (s) {
      if (s.type === 'signal-store' && s.state) {
        result.stores['signal:' + s.name] = { state: s.state, type: 'signal-store' };
      } else {
        result.signals.push({ name: s.name, component: s.component });
      }
    });
    result.errors = result.errors.concat(signalResult.errors);
  } catch (e) {
    result.errors.push('Signal extraction: ' + (e.message || String(e)));
  }

  // Routes
  try {
    var routeResult = extractAngularRoutes();
    result.routes = routeResult.routes;
    result.errors = result.errors.concat(routeResult.errors);
  } catch (e) {
    result.errors.push('Route extraction: ' + (e.message || String(e)));
  }

  // API Endpoints
  try {
    result.apiEndpoints = extractApiEndpoints();
  } catch (e) {
    result.errors.push('API endpoint extraction: ' + (e.message || String(e)));
  }

  window.postMessage(
    { __vk_angular_store: true, __vk_token: __vk_token, result: result },
    location.origin
  );
})();
