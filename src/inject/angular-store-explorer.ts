// 灵眸 - Angular Store/Router Explorer (MAIN world injection)
// Extracts NgRx store state, Angular signals, Router config, API endpoints
(function () {
  'use strict';

  const __vk_token: string = document.currentScript ? (document.currentScript as HTMLScriptElement).dataset.vkToken || '' : '';

  function safeClone(obj: any, depth?: number): any {
    if (depth === undefined) depth = 0;
    if (obj === null || obj === undefined) return obj;
    if (typeof obj !== 'object') return obj;
    if (depth > 6) return '[Max Depth]';
    try {
      return JSON.parse(
        JSON.stringify(obj, function (key: string, value: any) {
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

  function findRootComponent(): Element {
    const roots: NodeListOf<Element> = document.querySelectorAll('[ng-version], app-root, [app-root], app-root > *, [ng-version] > *');
    if (roots.length > 0) return roots[0];
    const app: Element | null = document.querySelector('app-root, app-app, [app-root]');
    return app || document.body;
  }

  function extractNgrxStores(): { stores: Record<string, any>; errors: string[] } {
    const stores: { name: string; store: any }[] = [];
    const errors: string[] = [];

    // Method 1: Global __NGRX_ROOT__ or window store references
    try {
      if ((window as any).__NGRX_ROOT__) {
        stores.push({ name: 'NgRx Root', store: (window as any).__NGRX_ROOT__ });
      }
    } catch (_) { /* skip */ }

    // Method 2: __REDUX_DEVTOOLS_EXTENSION__ — works for NgRx since it uses Redux DevTools
    try {
      if ((window as any).__REDUX_DEVTOOLS_EXTENSION__) {
        const devTools: any = (window as any).__REDUX_DEVTOOLS_EXTENSION__;
        if (devTools._instances) {
          devTools._instances.forEach(function (store: any, id: number) {
            if (store && typeof store.getState === 'function') {
              stores.push({ name: 'ngrx-devtools-' + id, store: store });
            }
          });
        }
      }
    } catch (e: any) {
      errors.push('NgRx DevTools: ' + (e.message || String(e)));
    }

    // Method 3: Try ng.probe in dev mode to access Angular DI
    try {
      const ngAny: any = (window as any).ng;
      if (typeof ngAny !== 'undefined' && ngAny.probe) {
        const rootEl: Element = findRootComponent();
        const componentRef: any = ngAny.probe(rootEl);
        if (componentRef) {
          // Try to get Store from injector
          try {
            let injector: any = componentRef.injector;
            // Walk up injectors to find Store
            let depth: number = 0;
            while (injector && depth < 15) {
              try {
                // NgRx Store has getState()
                const storeInstance: any = injector.get && injector.get({ toString: function() { return 'Store'; } });
                if (storeInstance && typeof storeInstance.getState === 'function') {
                  stores.push({ name: 'ngrx-injector-store', store: storeInstance });
                  break;
                }
              } catch (e) {
                // Not found in this injector level, try parent
              }
              try {
                if (injector.viewContainerRef && injector.viewContainerRef.injector) {
                  injector = injector.viewContainerRef.injector;
                } else if (injector.parent) {
                  injector = injector.parent;
                } else {
                  break;
                }
              } catch (_) { break; }
              depth++;
            }
          } catch (e: any) {
            errors.push('NgRx DI scan: ' + (e.message || String(e)));
          }
        }
      }
    } catch (e: any) {
      errors.push('ng.probe scan: ' + (e.message || String(e)));
    }

    const result: Record<string, any> = {};
    const seenStates: Record<string, boolean> = {};
    stores.forEach(function (entry: { name: string; store: any }) {
      try {
        const state: any = entry.store.getState();
        const stateKey: string = Object.keys(state || {}).sort().join(',');
        if (seenStates[stateKey]) return;
        seenStates[stateKey] = true;
        result[entry.name] = {
          state: safeClone(state),
          type: 'ngrx-store',
        };
      } catch (e: any) {
        errors.push(entry.name + ': ' + (e.message || String(e)));
      }
    });

    return { stores: result, errors: errors };
  }

  function extractAngularSignals(): { signals: { name: string; component: string; type: string; state?: any }[]; errors: string[] } {
    const signals: { name: string; component: string; type: string; state?: any }[] = [];
    const errors: string[] = [];

    try {
      const ngAny: any = (window as any).ng;
      if (typeof ngAny !== 'undefined' && ngAny.probe) {
        const rootEl: Element = findRootComponent();
        const componentRef: any = ngAny.probe(rootEl);
        if (componentRef && componentRef.componentInstance) {
          const instance: any = componentRef.componentInstance;
          Object.keys(instance).forEach(function (key: string) {
            try {
              const val: any = instance[key];
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
    } catch (e: any) {
      errors.push('Signal extraction: ' + (e.message || String(e)));
    }

    // Scan window for signal-related globals
    try {
      Object.keys(window).forEach(function (key: string) {
        if (key.indexOf('__') === 0 || key.indexOf('webkit') === 0 || key.indexOf('on') === 0) return;
        try {
          const val: any = (window as any)[key];
          if (!val || typeof val !== 'object') return;
          if (val.__signal__ || (val.constructor && val.constructor.name && val.constructor.name.indexOf('Signal') !== -1)) {
            signals.push({ name: key, component: 'global', type: 'signal' });
          }
        } catch (_) { /* skip */ }
      });
    } catch (_) { /* skip */ }

    return { signals: signals, errors: errors };
  }

  function extractAngularRoutes(): { routes: { path: string; source: string; component?: string; lazy?: boolean; guards?: string[]; data?: any }[]; errors: string[] } {
    const routes: { path: string; source: string; component?: string; lazy?: boolean; guards?: string[]; data?: any }[] = [];
    const errors: string[] = [];

    // Method 1: ng.probe + Router DI
    try {
      const ngAny: any = (window as any).ng;
      if (typeof ngAny !== 'undefined' && ngAny.probe) {
        const rootEl: Element = findRootComponent();
        const componentRef: any = ngAny.probe(rootEl);
        if (componentRef) {
          let injector: any = componentRef.injector;
          let depth: number = 0;
          while (injector && depth < 15) {
            try {
              const router: any = injector.get && injector.get({ toString: function() { return 'Router'; } });
              if (router && router.config) {
                processRouteConfig(router.config, '', routes);
                break;
              }
            } catch (e) {
              // Not found at this level
            }
            try {
              if (injector.parent) {
                injector = injector.parent;
              } else {
                break;
              }
            } catch (_) { break; }
            depth++;
          }
        }
      }
    } catch (e: any) {
      errors.push('Router DI: ' + (e.message || String(e)));
    }

    // Method 2: Anchor-based fallback（含 hash 路由链接：#/xxx）
    try {
      const anchorRoutes: Record<string, boolean> = {};
      const pushAnchor = function (href: string | null): void {
        if (!href) return;
        let clean: string;
        if (href.charAt(0) === '#') {
          clean = href.slice(1).split('?')[0];
        } else {
          clean = href.split('?')[0].split('#')[0];
        }
        if (clean.length > 1 && !anchorRoutes[clean]) {
          anchorRoutes[clean] = true;
          routes.push({ path: clean, source: 'anchor href' });
        }
      };
      document.querySelectorAll('a[href^="/"], a[href^="#/"]').forEach(function (a: Element) {
        pushAnchor(a.getAttribute('href'));
      });
    } catch (_) { /* skip */ }

    if (routes.length > 100) routes.length = 100;
    return { routes: routes, errors: errors };
  }

  function processRouteConfig(config: any[], parentPath: string, routes: { path: string; source: string; component?: string; lazy?: boolean; guards?: string[]; data?: any }[]): void {
    if (!Array.isArray(config)) return;
    config.forEach(function (route: any) {
      if (!route || typeof route !== 'object') return;
      let fullPath: string = parentPath ? parentPath + '/' + (route.path || '') : route.path || '';
      if (fullPath.charAt(0) !== '/') fullPath = '/' + fullPath;
      if (fullPath === '//') fullPath = '/';
      // Normalize double slashes
      fullPath = fullPath.replace(/\/+/g, '/');

      const routeEntry: { path: string; source: string; component?: string; lazy?: boolean; guards?: string[]; data?: any } = {
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
        routeEntry.guards = route.canActivate.map(function (g: any) { return g.name || String(g); });
      }
      if (route.canDeactivate && route.canDeactivate.length > 0) {
        routeEntry.guards = (routeEntry.guards || []).concat(
          route.canDeactivate.map(function (g: any) { return g.name || String(g); })
        );
      }
      if (route.canMatch && route.canMatch.length > 0) {
        routeEntry.guards = (routeEntry.guards || []).concat(
          route.canMatch.map(function (g: any) { return g.name || String(g); })
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

  function extractApiEndpoints(): string[] {
    const endpoints: string[] = [];
    const seen: Record<string, boolean> = {};

    const urlPatterns: RegExp[] = [
      /['"`](\/(?:api|v[0-9]+|admin|system|user|auth|login|register|query|search|list|get|post|put|delete|patch|upload|download|config|setting|profile|account|role|permission|menu|dict|file|image|log|monitor|report|dashboard|health|status|info|version|token|session|captcha|common|public|static|resource|data|base|core|service|gateway|proxy|ws|graphql|rest)\/[^\s'"`)\]]{2,120})['"`]/gi,
    ];

    try {
      document.querySelectorAll('script:not([src])').forEach(function (s: any) {
        let text: string = s.textContent || '';
        if (text.length > 500000) text = text.substring(0, 500000);
        urlPatterns.forEach(function (pattern: RegExp) {
          let match: RegExpExecArray | null;
          pattern.lastIndex = 0;
          while ((match = pattern.exec(text)) !== null) {
            const url: string = match[1];
            if (!seen[url] && !url.startsWith('//') && url.length > 3) {
              seen[url] = true;
              endpoints.push(url);
            }
          }
        });
      });
    } catch (_) { /* skip */ }

    if (endpoints.length > 100) endpoints.length = 100;
    return endpoints;
  }

  // === Main execution ===
  const result: { stores: Record<string, any>; signals: { name: string; component: string }[]; routes: { path: string; source: string; component?: string; lazy?: boolean; guards?: string[]; data?: any }[]; apiEndpoints: string[]; errors: string[] } = {
    stores: {},
    signals: [],
    routes: [],
    apiEndpoints: [],
    errors: [],
  };

  // NgRx Stores
  try {
    const ngrxResult: { stores: Record<string, any>; errors: string[] } = extractNgrxStores();
    Object.keys(ngrxResult.stores).forEach(function (k: string) {
      result.stores[k] = ngrxResult.stores[k];
    });
    result.errors = result.errors.concat(ngrxResult.errors);
  } catch (e: any) {
    result.errors.push('NgRx extraction: ' + (e.message || String(e)));
  }

  // Angular Signals
  try {
    const signalResult: { signals: { name: string; component: string; type: string; state?: any }[]; errors: string[] } = extractAngularSignals();
    signalResult.signals.forEach(function (s: { name: string; component: string; type: string; state?: any }) {
      if (s.type === 'signal-store' && s.state) {
        result.stores['signal:' + s.name] = { state: s.state, type: 'signal-store' };
      } else {
        result.signals.push({ name: s.name, component: s.component });
      }
    });
    result.errors = result.errors.concat(signalResult.errors);
  } catch (e: any) {
    result.errors.push('Signal extraction: ' + (e.message || String(e)));
  }

  // Routes
  try {
    const routeResult: { routes: { path: string; source: string; component?: string; lazy?: boolean; guards?: string[]; data?: any }[]; errors: string[] } = extractAngularRoutes();
    result.routes = routeResult.routes;
    result.errors = result.errors.concat(routeResult.errors);
  } catch (e: any) {
    result.errors.push('Route extraction: ' + (e.message || String(e)));
  }

  // API Endpoints
  try {
    result.apiEndpoints = extractApiEndpoints();
  } catch (e: any) {
    result.errors.push('API endpoint extraction: ' + (e.message || String(e)));
  }

  window.postMessage(
    { __vk_angular_store: true, __vk_token: __vk_token, result: result },
    location.origin
  );
})();
