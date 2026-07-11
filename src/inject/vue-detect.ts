// 灵眸 - Vue Detect (Stealth Injection)
// This script is injected via <script> tag by content script, then removed.
(function () {
  'use strict';

  const __vk_token = document.currentScript
    ? (document.currentScript as HTMLScriptElement).dataset.vkToken || ''
    : '';

  const AUTH_KEY_RE =
    /^(?:requiresAuth|requireAuth|auth|authenticated|needLogin|loginRequired|permission|permissions|role|roles|admin|access|authority|authorize|whiteList|noAuth)$/i;
  const SENSITIVE_PATH_RE =
    /(?:admin|manage|dashboard|system|config|setting|permission|role|user|account|secret|token|debug|internal)/i;

  const info: {
    detected: boolean;
    version: string;
    router: boolean;
    store: boolean;
    routes: any[];
    guards: Record<string, number>;
    pageOrigin: string;
    routerInfo?: any;
  } = {
    detected: false,
    version: '',
    router: false,
    store: false,
    routes: [],
    guards: {},
    pageOrigin: location.origin,
  };

  function safeSerialize(obj: any): any {
    try {
      return JSON.parse(JSON.stringify(obj));
    } catch (e) {
      return null;
    }
  }

  function routeHasAuth(route: any): boolean {
    if (typeof route.beforeEnter === 'function') return true;
    if (route.meta && typeof route.meta === 'object') {
      const keys: string[] = Object.keys(route.meta);
      for (let i = 0; i < keys.length; i++) {
        if (AUTH_KEY_RE.test(keys[i]) && route.meta[keys[i]]) return true;
      }
    }
    return false;
  }

  function isSensitivePath(path: string | undefined, name: string | undefined): boolean {
    return SENSITIVE_PATH_RE.test(path || '') || SENSITIVE_PATH_RE.test(name || '');
  }

  function getGuardStats(router: any): Record<string, number> {
    const stats: Record<string, number> = {};
    if (Array.isArray(router.beforeGuards)) stats.beforeGuards = router.beforeGuards.length;
    if (Array.isArray(router.afterGuards)) stats.afterGuards = router.afterGuards.length;
    if (Array.isArray(router.beforeResolveGuards))
      stats.beforeResolveGuards = router.beforeResolveGuards.length;
    if (Array.isArray(router.beforeHooks)) stats.beforeHooks = router.beforeHooks.length;
    if (Array.isArray(router.afterHooks)) stats.afterHooks = router.afterHooks.length;
    if (Array.isArray(router.beforeResolveHooks))
      stats.beforeResolveHooks = router.beforeResolveHooks.length;
    return stats;
  }

  function normalizeRoute(r: any): any {
    let comps: string[] = [];
    if (r.components) {
      try {
        comps = Object.keys(r.components);
      } catch (e) {
        /* ignore */
      }
    } else if (r.component) {
      comps = ['default'];
    }
    return {
      path: r.path,
      name: r.name || '',
      meta: safeSerialize(r.meta) || {},
      children: [],
      hasAuth: routeHasAuth(r),
      sensitive: isSensitivePath(r.path, r.name),
      hasBeforeEnter: typeof r.beforeEnter === 'function',
      childCount: (r.children || []).length,
      componentKeys: comps,
    };
  }

  function buildRouteTree(routes: any[]): any[] {
    if (!routes || !Array.isArray(routes)) return [];
    return routes.map(function (r: any) {
      const node = normalizeRoute(r);
      if (r.children && r.children.length > 0) {
        node.children = buildRouteTree(r.children);
      }
      return node;
    });
  }

  function collectTreePaths(routes: any[], prefix: string): Record<string, boolean> {
    const paths: Record<string, boolean> = {};
    if (!routes) return paths;
    routes.forEach(function (r: any) {
      let p: string = r.path || '';
      if (p.charAt(0) !== '/' && prefix && prefix !== '/') {
        p = `${prefix}/${p}`;
      }
      if (r.children && r.children.length > 0) {
        const childPaths = collectTreePaths(r.children, p === '/' ? '/' : p);
        for (const k in childPaths) paths[k] = childPaths[k];
      }
      if (p) paths[p] = true;
    });
    return paths;
  }

  function addFlatRoutes(tree: any[], flatRoutes: any[]): void {
    const existingPaths = collectTreePaths(tree, '');
    flatRoutes.forEach(function (r: any) {
      if (r.path && !existingPaths[r.path]) {
        tree.push(normalizeRoute(r));
      }
    });
  }

  function getVue3Routes(router: any): any[] {
    if (!router) return [];
    const treeRoutes = safeSerialize(router.options && router.options.routes) || [];
    const tree = buildRouteTree(treeRoutes);
    if (typeof router.getRoutes === 'function') {
      addFlatRoutes(tree, router.getRoutes());
    }
    // Vue Router 4 fallback: history.matched
    if (tree.length === 0 && router.history && router.history.current) {
      try {
        const matched = router.history.current.matched || [];
        addFlatRoutes(
          tree,
          matched.map(function (r: any) {
            return r.record || r;
          })
        );
      } catch (e) {
        /* ignore */
      }
    }
    return tree;
  }

  function getRouterInfo(router: any): { base: string; mode: string } {
    if (!router) return { base: '/', mode: 'history' };
    let base = '/';
    let mode = 'history';
    try {
      base = router.options && router.options.base ? router.options.base : base;
    } catch (e) {
      /* ignore */
    }
    try {
      if (router.mode === 'hash' || router.mode === 'abstract') mode = router.mode;
      else if (
        router.options &&
        router.options.history &&
        typeof router.options.history.pushState === 'function'
      )
        mode = 'history';
      else if (typeof HTMLAnchorElement !== 'undefined') {
        try {
          const testA = document.createElement('a');
          testA.href = '/#/test';
          if (testA.hash) mode = 'hash';
        } catch (e) {
          /* ignore */
        }
      }
    } catch (e) {
      /* ignore */
    }
    return { base: base, mode: mode };
  }

  function getVue2Routes(router: any): any[] {
    if (!router) return [];
    const opts = router.options;
    const treeRoutes = opts ? safeSerialize(opts.routes) || [] : [];
    const tree = buildRouteTree(treeRoutes);
    // Vue Router 3.x
    if (typeof router.getRoutes === 'function') {
      addFlatRoutes(tree, router.getRoutes());
    }
    // Vue Router 2.x fallback: matcher.getRoutes()
    if (tree.length === 0 && router.matcher && typeof router.matcher.getRoutes === 'function') {
      try {
        const matcherRoutes = router.matcher.getRoutes();
        if (Array.isArray(matcherRoutes)) {
          addFlatRoutes(tree, matcherRoutes);
        }
      } catch (e) {
        /* ignore */
      }
    }
    // Vue Router 2.x fallback: history.current.matched
    if (tree.length === 0 && router.history && router.history.current) {
      try {
        const matched = router.history.current.matched || [];
        addFlatRoutes(
          tree,
          matched.map(function (r: any) {
            return r.record || r;
          })
        );
      } catch (e) {
        /* ignore */
      }
    }
    return tree;
  }

  function fillInfo(app: any, isVue3: boolean): void {
    info.detected = true;
    info.version = isVue3 ? app.version || '3.x' : app.constructor.version || '2.x';
    const router = isVue3 ? app.config.globalProperties.$router : app.$router;
    if (router) {
      info.router = true;
      info.routes = isVue3 ? getVue3Routes(router) : getVue2Routes(router);
      info.routerInfo = getRouterInfo(router);
      info.guards = getGuardStats(router);
    }
    if (isVue3) {
      const store = app.config.globalProperties.$pinia || app.config.globalProperties.$store;
      if (store) info.store = true;
    } else {
      if (app.$store) info.store = true;
    }
  }

  // Strategy 1: check common mount points
  const mountSelectors = ['#app', '[data-v-app]', '[id^="app"]', '#root', '#application', '#main'];
  for (let si = 0; si < mountSelectors.length; si++) {
    const el = document.querySelector(mountSelectors[si]);
    if (el && (el as any).__vue_app__) {
      fillInfo((el as any).__vue_app__, true);
      break;
    }
    if (el && (el as any).__vue__) {
      const vm = (el as any).__vue__.$root || (el as any).__vue__;
      fillInfo(vm, false);
      break;
    }
  }

  // Strategy 2: BFS scan (max 1000 nodes)
  if (!info.detected) {
    const bfsRoots: Element[] = document.body ? [document.body] : [document.documentElement];
    const visited = new Set<Element>();
    const queue: Element[] = bfsRoots.slice();
    let bfsCount = 0;
    while (queue.length > 0 && bfsCount < 1000) {
      const current = queue.shift()!;
      if (!current || visited.has(current)) continue;
      visited.add(current);
      bfsCount++;
      if ((current as any).__vue_app__) {
        fillInfo((current as any).__vue_app__, true);
        break;
      }
      if ((current as any).__vue__) {
        const vm = (current as any).__vue__.$root || (current as any).__vue__;
        fillInfo(vm, false);
        break;
      }
      const children = current.children;
      for (let ci = 0; ci < children.length; ci++) {
        queue.push(children[ci]);
      }
    }
  }

  // Strategy 3: global Vue check
  if (
    !info.detected &&
    typeof (window as any).Vue !== 'undefined' &&
    (window as any).Vue.version
  ) {
    info.detected = true;
    info.version = (window as any).Vue.version;
  }

  window.postMessage({ __vk_detect: true, __vk_token: __vk_token, result: info }, location.origin);
})();
