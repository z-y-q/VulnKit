// 灵眸 - Vue Detect (Stealth Injection)
// This script is injected via <script> tag by content script, then removed.
(function () {
  'use strict';

  const info = {
    detected: false,
    version: '',
    router: false,
    store: false,
    routes: [],
    pageOrigin: location.origin,
  };

  function safeSerialize(obj) {
    try {
      return JSON.parse(JSON.stringify(obj));
    } catch (e) {
      return null;
    }
  }

  function normalizeRoute(r) {
    return {
      path: r.path,
      name: r.name || '',
      meta: safeSerialize(r.meta) || {},
      children: [],
    };
  }

  function buildRouteTree(routes) {
    if (!routes || !Array.isArray(routes)) return [];
    return routes.map(function (r) {
      const node = normalizeRoute(r);
      if (r.children && r.children.length > 0) {
        node.children = buildRouteTree(r.children);
      }
      return node;
    });
  }

  function collectTreePaths(routes, prefix) {
    const paths = {};
    if (!routes) return paths;
    routes.forEach(function (r) {
      let p = r.path || '';
      if (p.charAt(0) !== '/' && prefix && prefix !== '/') {
        p = `${prefix}/${p}`;
      }
      if (r.children && r.children.length > 0) {
        const childPaths = collectTreePaths(r.children, p === '/' ? '/' : p);
        for (let k in childPaths) paths[k] = childPaths[k];
      }
      if (p) paths[p] = true;
    });
    return paths;
  }

  function addFlatRoutes(tree, flatRoutes) {
    const existingPaths = collectTreePaths(tree, '');
    flatRoutes.forEach(function (r) {
      if (r.path && !existingPaths[r.path]) {
        tree.push(normalizeRoute(r));
      }
    });
  }

  function getVue3Routes(router) {
    if (!router) return [];
    let treeRoutes = safeSerialize(router.options && router.options.routes) || [];
    let tree = buildRouteTree(treeRoutes);
    if (typeof router.getRoutes === 'function') {
      addFlatRoutes(tree, router.getRoutes());
    }
    // Vue Router 4 fallback: history.matched
    if (tree.length === 0 && router.history && router.history.current) {
      try {
        let matched = router.history.current.matched || [];
        addFlatRoutes(
          tree,
          matched.map(function (r) {
            return r.record || r;
          })
        );
      } catch (e) {
        /* ignore */
      }
    }
    return tree;
  }

  function getRouterInfo(router) {
    if (!router) return {};
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

  function getVue2Routes(router) {
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
          matched.map(function (r) {
            return r.record || r;
          })
        );
      } catch (e) {
        /* ignore */
      }
    }
    return tree;
  }

  function fillInfo(app, isVue3) {
    info.detected = true;
    info.version = isVue3 ? app.version || '3.x' : app.constructor.version || '2.x';
    const router = isVue3 ? app.config.globalProperties.$router : app.$router;
    if (router) {
      info.router = true;
      info.routes = isVue3 ? getVue3Routes(router) : getVue2Routes(router);
      info.routerInfo = getRouterInfo(router);
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
    if (el && el.__vue_app__) {
      fillInfo(el.__vue_app__, true);
      break;
    }
    if (el && el.__vue__) {
      let vm = el.__vue__.$root || el.__vue__;
      fillInfo(vm, false);
      break;
    }
  }

  // Strategy 2: BFS scan (max 1000 nodes)
  if (!info.detected) {
    const bfsRoots = document.body ? [document.body] : [document.documentElement];
    const visited = new Set();
    const queue = bfsRoots.slice();
    let bfsCount = 0;
    while (queue.length > 0 && bfsCount < 1000) {
      const current = queue.shift();
      if (!current || visited.has(current)) continue;
      visited.add(current);
      bfsCount++;
      if (current.__vue_app__) {
        fillInfo(current.__vue_app__, true);
        break;
      }
      if (current.__vue__) {
        const vm = current.__vue__.$root || current.__vue__;
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
  if (!info.detected && typeof window.Vue !== 'undefined' && window.Vue.version) {
    info.detected = true;
    info.version = window.Vue.version;
  }

  window.postMessage({ __vk_detect: true, result: info }, location.origin);
})();
