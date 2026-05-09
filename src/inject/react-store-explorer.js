// 灵眸 - React Store/Router Explorer (MAIN world injection)
// Extracts Redux/Zustand store state, React Router routes, API endpoints
(function () {
  'use strict';

  const __vk_token = document.currentScript ? document.currentScript.dataset.vkToken || '' : '';

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

  function getFiberRoot() {
    var rootEl =
      document.getElementById('root') ||
      document.getElementById('app') ||
      document.getElementById('__next');
    if (!rootEl) return null;

    var fiberKey = Object.keys(rootEl).find(function (k) {
      return k.startsWith('__reactFiber$') || k.startsWith('__reactInternalInstance$');
    });
    if (!fiberKey) return null;

    var fiberNode = rootEl[fiberKey];
    if (!fiberNode) return null;

    if (fiberNode.stateNode && fiberNode.stateNode._reactRootContainer) {
      return fiberNode.stateNode._reactRootContainer._internalRoot;
    }
    if (fiberNode.stateNode && fiberNode.stateNode._internalRoot) {
      return fiberNode.stateNode._internalRoot;
    }
    if (fiberNode._internalRoot) return fiberNode._internalRoot;
    return fiberNode;
  }

  function walkFiberForStore(fiber, depth) {
    if (!fiber || depth > 30) return null;
    try {
      if (fiber.memoizedProps && fiber.memoizedProps.store) {
        var s = fiber.memoizedProps.store;
        if (s && typeof s.getState === 'function') return s;
      }
      if (fiber.stateNode && fiber.stateNode.store && typeof fiber.stateNode.store.getState === 'function') {
        return fiber.stateNode.store;
      }
      if (fiber.type && fiber.type._context && fiber.stateNode) {
        var ctxValue = fiber.stateNode;
        if (ctxValue && typeof ctxValue.getState === 'function') return ctxValue;
      }
    } catch (e) { /* skip */ }
    var r = walkFiberForStore(fiber.child, depth + 1);
    if (r) return r;
    return walkFiberForStore(fiber.sibling, depth + 1);
  }

  function extractReduxStores() {
    var stores = [];
    var errors = [];

    // Method 1: Direct window globals
    if (window.__store__ && typeof window.__store__.getState === 'function') {
      stores.push({ name: 'window.__store__', store: window.__store__ });
    }
    if (window.__NEXT_REDUX_STORE__ && typeof window.__NEXT_REDUX_STORE__.getState === 'function') {
      stores.push({ name: '__NEXT_REDUX_STORE__', store: window.__NEXT_REDUX_STORE__ });
    }

    // Method 2: Fiber tree walk for Redux Provider
    try {
      var fiberRoot = getFiberRoot();
      if (fiberRoot) {
        var found = walkFiberForStore(fiberRoot.current, 0);
        if (found) stores.push({ name: 'fiber:ReduxProvider', store: found });
      }
    } catch (e) {
      errors.push('Redux fiber walk: ' + (e.message || String(e)));
    }

    // Method 3: __REDUX_DEVTOOLS_EXTENSION__ stores
    try {
      if (window.__REDUX_DEVTOOLS_EXTENSION__) {
        var devTools = window.__REDUX_DEVTOOLS_EXTENSION__;
        if (devTools._instances) {
          devTools._instances.forEach(function (store, id) {
            if (store && typeof store.getState === 'function') {
              stores.push({ name: 'devtools-instance-' + id, store: store });
            }
          });
        }
      }
    } catch (e) {
      errors.push('Redux DevTools: ' + (e.message || String(e)));
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
          type: 'redux',
        };

        // Extract action names from dispatch history if available
        try {
          if (entry.store.dispatch && entry.store.getState) {
            var thunkActions = [];
            if (Array.isArray(entry.store._middleware)) {
              entry.store._middleware.forEach(function (mw) {
                if (typeof mw === 'function') {
                  var src = mw.toString();
                  thunkActions.push(src);
                }
              });
            }
          }
        } catch (_) { /* no middleware access */ }
      } catch (e) {
        errors.push(entry.name + ': ' + (e.message || String(e)));
      }
    });

    return { stores: result, errors: errors };
  }

  function extractZustandStores() {
    var result = {};
    var errors = [];

    try {
      if (window.__ZUSTAND_DEVTOOLS__ && window.__ZUSTAND_DEVTOOLS__.stores) {
        window.__ZUSTAND_DEVTOOLS__.stores.forEach(function (store, name) {
          try {
            var state = store.getState();
            result[name || 'unnamed'] = {
              state: safeClone(state),
              type: 'zustand',
            };
          } catch (e) {
            errors.push('Zustand "' + name + '": ' + (e.message || String(e)));
          }
        });
      }
    } catch (e) {
      errors.push('Zustand DevTools: ' + (e.message || String(e)));
    }

    // Fallback: scan window for common Zustand patterns
    try {
      var zustandKeys = Object.keys(window).filter(function (k) {
        if (k.startsWith('__') || k.startsWith('_') || k.startsWith('webkit') || k.startsWith('on')) return false;
        try {
          var v = window[k];
          return v && typeof v === 'object' && typeof v.getState === 'function' && typeof v.setState === 'function' && typeof v.subscribe === 'function';
        } catch (_) { return false; }
      });
      zustandKeys.forEach(function (key) {
        if (result[key]) return;
        try {
          var state = window[key].getState();
          result[key] = {
            state: safeClone(state),
            type: 'zustand',
          };
        } catch (_) { /* skip */ }
      });
    } catch (e) {
      errors.push('Zustand window scan: ' + (e.message || String(e)));
    }

    return { stores: result, errors: errors };
  }

  function extractJotaiAtoms() {
    var result = {};
    try {
      if (typeof jotai !== 'undefined' && jotai.useStore) {
        // Jotai atoms are accessed via useStore hooks — limited extraction
        result['jotai'] = {
          state: { note: 'Jotai atoms accessed via React hooks, direct state extraction limited' },
          type: 'jotai',
        };
      }
    } catch (_) { /* skip */ }
    return result;
  }

  function extractRecoilState() {
    var result = {};
    try {
      var recoilRoot = document.querySelector('[data-recoil-root]');
      if (recoilRoot || typeof Recoil !== 'undefined') {
        result['recoil'] = {
          state: { note: 'Recoil state accessed via React hooks, direct state extraction limited' },
          type: 'recoil',
        };
      }
    } catch (_) { /* skip */ }
    return result;
  }

  function extractRoutes() {
    var routes = [];
    var errors = [];

    // Next.js routes
    try {
      if (window.__NEXT_DATA__) {
        var nd = window.__NEXT_DATA__;
        if (nd.page) routes.push({ path: nd.page, source: 'Next.js current page' });
        if (nd.buildManifest && nd.buildManifest.pages) {
          Object.keys(nd.buildManifest.pages).forEach(function (p) {
            if (p.charAt(0) === '/') {
              routes.push({ path: p, source: 'Next.js buildManifest' });
            }
          });
        }
      }
    } catch (e) {
      errors.push('Next.js routes: ' + (e.message || String(e)));
    }

    // React Router v6: walk fiber tree for Route components
    try {
      var fiberRoot = getFiberRoot();
      if (fiberRoot) {
        var routePaths = {};
        function walkForRoutes(fiber, depth) {
          if (!fiber || depth > 25) return;
          try {
            if (fiber.memoizedProps && fiber.memoizedProps.path && typeof fiber.memoizedProps.path === 'string') {
              var p = fiber.memoizedProps.path;
              if (p.charAt(0) === '/' || p === '*') {
                routePaths[p] = routePaths[p] || { path: p, source: 'React Router (fiber)' };
                if (fiber.memoizedProps.element) routePaths[p].hasElement = true;
              }
            }
            // React Router v6 data router: route objects in routeLoader
            if (fiber.memoizedProps && fiber.memoizedProps.routes && Array.isArray(fiber.memoizedProps.routes)) {
              fiber.memoizedProps.routes.forEach(function (r) {
                if (r && r.path) {
                  routePaths[r.path] = { path: r.path, source: 'React Router data router' };
                }
              });
            }
          } catch (_) { /* skip */ }
          walkForRoutes(fiber.child, depth + 1);
          walkForRoutes(fiber.sibling, depth + 1);
        }
        walkForRoutes(fiberRoot.current, 0);
        Object.values(routePaths).forEach(function (r) {
          if (!routes.some(function (existing) { return existing.path === r.path; })) {
            routes.push(r);
          }
        });
      }
    } catch (e) {
      errors.push('React Router routes: ' + (e.message || String(e)));
    }

    // Anchor-based route discovery
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

    // Limit
    if (routes.length > 80) routes = routes.slice(0, 80);

    return { routes: routes, errors: errors };
  }

  function extractApiEndpoints() {
    var endpoints = [];
    var seen = {};

    // From Redux store: scan middleware/thunk action creators
    try {
      var fiberRoot = getFiberRoot();
      if (fiberRoot) {
        var store = walkFiberForStore(fiberRoot.current, 0);
        if (store && store.dispatch) {
          // Try to access the store's internal middleware chain
          var srcList = [];
          try {
            if (store.__INITIAL_ACTION__) srcList.push(JSON.stringify(store.__INITIAL_ACTION__));
          } catch (_) { /* skip */ }
        }
      }
    } catch (_) { /* skip */ }

    // Scan window globals for fetch/axios interceptors
    var urlPatterns = [
      /['"`](\/(?:api|v[0-9]+|admin|system|user|auth|login|register|query|search|list|get|post|put|delete|patch|upload|download|config|setting|profile|account|role|permission|menu|dict|file|image|log|monitor|report|dashboard|health|status|info|version|token|session|captcha|common|public|static|resource|data|base|core|service|gateway|proxy|ws|graphql|rest)\/[^\s'"`)\]]{2,120})['"`]/gi,
      /['"`]https?:\/\/[^\s'"`)\]]{10,200}['"`]/gi,
    ];

    // Scan all script contents for API patterns
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

    // Scan Redux dispatch calls in inline scripts
    try {
      var dispatchPattern = /dispatch\s*\(\s*\w+\.(\w+)\s*\(/g;
      document.querySelectorAll('script:not([src])').forEach(function (s) {
        var text = s.textContent || '';
        if (text.length > 200000) text = text.substring(0, 200000);
        var m;
        dispatchPattern.lastIndex = 0;
        while ((m = dispatchPattern.exec(text)) !== null) {
          var actionName = m[1];
          if (!seen['action:' + actionName]) {
            seen['action:' + actionName] = true;
            endpoints.push('[Action] ' + actionName);
          }
        }
      });
    } catch (_) { /* skip */ }

    if (endpoints.length > 100) endpoints = endpoints.slice(0, 100);
    return endpoints;
  }

  // === Main execution ===
  var result = {
    stores: {},
    routes: [],
    apiEndpoints: [],
    errors: [],
  };

  // Redux
  try {
    var reduxResult = extractReduxStores();
    Object.keys(reduxResult.stores).forEach(function (k) {
      result.stores[k] = reduxResult.stores[k];
    });
    result.errors = result.errors.concat(reduxResult.errors);
  } catch (e) {
    result.errors.push('Redux extraction: ' + (e.message || String(e)));
  }

  // Zustand
  try {
    var zustandResult = extractZustandStores();
    Object.keys(zustandResult.stores).forEach(function (k) {
      result.stores[k] = zustandResult.stores[k];
    });
    result.errors = result.errors.concat(zustandResult.errors);
  } catch (e) {
    result.errors.push('Zustand extraction: ' + (e.message || String(e)));
  }

  // Jotai
  try {
    var jotaiResult = extractJotaiAtoms();
    Object.keys(jotaiResult).forEach(function (k) {
      result.stores[k] = jotaiResult[k];
    });
  } catch (_) { /* skip */ }

  // Recoil
  try {
    var recoilResult = extractRecoilState();
    Object.keys(recoilResult).forEach(function (k) {
      result.stores[k] = recoilResult[k];
    });
  } catch (_) { /* skip */ }

  // Routes
  try {
    var routeResult = extractRoutes();
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
    {
      __vk_react_store: true,
      __vk_token: __vk_token,
      result: result,
    },
    location.origin
  );
})();
