// 灵眸 - React Detection Inject Script
(function () {
  'use strict';
  if (window.__VK_REACT_DETECT_DONE__) return;
  window.__VK_REACT_DETECT_DONE__ = true;

  const result = {
    detected: false,
    version: '',
    metaframework: '',
    mode: '',
    stateManager: '',
    components: [],
    routes: [],
    signals: [],
  };

  // React DevTools hook
  if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
    result.detected = true;
    result.signals.push('React DevTools Global Hook');
    const renderers = window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers;
    if (renderers) {
      const versions = [];
      renderers.forEach(function (r, id) {
        if (r && r.version) versions.push(r.version);
      });
      if (versions.length > 0) result.version = versions.join(', ');
    }
  }

  // React Fiber on root element
  const rootEl =
    document.getElementById('root') ||
    document.getElementById('app') ||
    document.getElementById('__next');
  if (rootEl) {
    const fiberKey = Object.keys(rootEl).find(function (k) {
      return k.startsWith('__reactFiber$') || k.startsWith('__reactInternalInstance$');
    });
    if (fiberKey) {
      result.detected = true;
      result.signals.push(`React Fiber (${fiberKey})`);
    }
    const propsKey = Object.keys(rootEl).find(function (k) {
      return k.startsWith('__reactProps$');
    });
    if (propsKey) {
      result.detected = true;
      result.signals.push('React Props');
    }
  }

  // Legacy React attributes
  if (document.querySelector('[data-reactroot]')) {
    result.detected = true;
    result.signals.push('data-reactroot attribute');
  }
  if (document.querySelector('[data-reactid]')) {
    result.detected = true;
    result.signals.push('data-reactid attribute (React < 16)');
  }

  // Next.js
  if (window.__NEXT_DATA__) {
    result.metaframework = 'Next.js';
    result.detected = true;
    result.signals.push('__NEXT_DATA__');
    if (window.__NEXT_DATA__.buildId)
      result.signals.push(`Next.js Build: ${window.__NEXT_DATA__.buildId}`);
    if (window.__NEXT_DATA__.runtimeConfig) result.signals.push('Next.js Runtime Config');
  }
  if (document.querySelector('#__next')) {
    result.metaframework = result.metaframework || 'Next.js';
    result.detected = true;
    result.signals.push('#__next root element');
  }
  if (document.querySelector('[data-nextjs-route-announcer]')) {
    result.metaframework = result.metaframework || 'Next.js';
    result.detected = true;
    result.signals.push('data-nextjs-route-announcer');
  }

  // React Router
  const scripts = Array.from(document.querySelectorAll('script[src]'));
  const hasReactRouter = scripts.some(function (s) {
    return /react-router/i.test(s.src);
  });
  if (hasReactRouter) {
    result.signals.push('React Router detected');
  }

  // ReactDOM from script tags
  scripts.forEach(function (s) {
    if (/react-dom/i.test(s.src) && /(\d+\.\d+\.\d+)/.test(s.src)) {
      const m = s.src.match(/(\d+\.\d+\.\d+)/);
      if (m && !result.version) result.version = m[1];
    }
    if (/react\.production/i.test(s.src) || /react\.development/i.test(s.src)) {
      if (!result.version) {
        const m2 = s.src.match(/(\d+\.\d+\.\d+)/);
        if (m2) result.version = m2[1];
      }
    }
  });

  // Check for React in bundle (global)
  if (typeof React !== 'undefined' && React.version) {
    result.detected = true;
    if (!result.version) result.version = React.version;
    result.signals.push(`Global React object v${React.version}`);
  }
  if (typeof ReactDOM !== 'undefined' && ReactDOM.version) {
    result.detected = true;
    if (!result.version) result.version = ReactDOM.version;
  }

  // Dev/Prod mode detection
  let isDev = false;
  if (typeof React !== 'undefined' && React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED) {
    isDev = true;
  }
  scripts.forEach(function (s) {
    if (/react\.development/i.test(s.src)) isDev = true;
  });
  if (
    typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined' &&
    __REACT_DEVTOOLS_GLOBAL_HOOK__.renderers
  ) {
    try {
      const fiberRoot = rootEl ? rootEl[fiberKey] : null;
      if (fiberRoot && fiberRoot._debugInfo) isDev = true;
      if (fiberRoot && fiberRoot.memoizedState && fiberRoot.memoizedState.queue) isDev = true;
    } catch (e) {
      /* ignore */
    }
  }
  result.mode = isDev ? 'development' : 'production';
  if (isDev) result.signals.push('Development mode (security risk: verbose errors, source maps)');

  // State management detection
  if (
    typeof __REDUX_DEVTOOLS_EXTENSION__ !== 'undefined' ||
    typeof window.__store__ !== 'undefined'
  ) {
    result.stateManager = 'Redux';
    result.signals.push('Redux detected');
  }
  if (typeof window.__NEXT_REDUX_STORE__ !== 'undefined') {
    result.stateManager = 'Redux';
    result.signals.push('Redux (Next.js integration)');
  }
  if (typeof window.__ZUSTAND_DEVTOOLS__ !== 'undefined') {
    result.stateManager = result.stateManager ? `${result.stateManager} + Zustand` : 'Zustand';
    result.signals.push('Zustand detected');
  }
  if (typeof MobX !== 'undefined') {
    result.stateManager = result.stateManager ? `${result.stateManager} + MobX` : 'MobX';
    result.signals.push('MobX detected');
  }
  if (typeof Recoil !== 'undefined' || document.querySelector('[data-recoil-root]')) {
    result.stateManager = result.stateManager ? `${result.stateManager} + Recoil` : 'Recoil';
    result.signals.push('Recoil detected');
  }
  if (typeof jotai !== 'undefined' || typeof jotaiModule !== 'undefined') {
    result.stateManager = result.stateManager ? `${result.stateManager} + Jotai` : 'Jotai';
    result.signals.push('Jotai detected');
  }

  // Component tree extraction from Fiber
  const componentNames = [];
  function walkFiber(fiber, depth) {
    if (!fiber || depth > 8) return;
    const name = fiber.type
      ? typeof fiber.type === 'function'
        ? fiber.type.displayName || fiber.type.name
        : fiber.type
      : '';
    if (
      name &&
      name !== '' &&
      componentNames.indexOf(name) === -1 &&
      name.charAt(0) === name.charAt(0).toUpperCase() &&
      name.length > 1 &&
      name.length < 40
    ) {
      componentNames.push(name);
    }
    if (fiber.child) walkFiber(fiber.child, depth + 1);
    if (fiber.sibling) walkFiber(fiber.sibling, depth);
  }
  if (fiberKey && rootEl) {
    try {
      const fiberNode = rootEl[fiberKey];
      if (fiberNode && fiberNode.stateNode) {
        const _root = fiberNode.stateNode._reactRootContainer || fiberNode.stateNode;
        if (_root && _root._internalRoot) walkFiber(_root._internalRoot.current, 0);
      } else if (fiberNode) {
        walkFiber(fiberNode, 0);
      }
    } catch (e) {
      /* ignore */
    }
  }
  result.components = componentNames.slice(0, 30);

  // Next.js route extraction
  if (window.__NEXT_DATA__ && window.__NEXT_DATA__.page) {
    result.routes.push(window.__NEXT_DATA__.page);
  }
  if (window.__NEXT_DATA__ && window.__NEXT_DATA__.buildManifest) {
    const pages = Object.keys(window.__NEXT_DATA__.buildManifest.pages || {});
    pages.forEach(function (p) {
      if (p.charAt(0) === '/' && result.routes.indexOf(p) === -1) result.routes.push(p);
    });
    if (result.routes.length > 50) result.routes = result.routes.slice(0, 50);
  }
  // React Router route detection via router context
  if (typeof React !== 'undefined' && rootEl) {
    try {
      const allAnchors = document.querySelectorAll('a[href^="/"]');
      const routeSet = {};
      allAnchors.forEach(function (a) {
        const href = a.getAttribute('href');
        if (href && href.charAt(0) === '/' && href.length > 1 && !routeSet[href]) {
          const cleanPath = href.split('?')[0];
          if (cleanPath.length > 1 && !routeSet[cleanPath]) {
            routeSet[cleanPath] = true;
          }
        }
      });
      result.routes = result.routes.concat(Object.keys(routeSet)).slice(0, 50);
    } catch (e) {
      /* ignore */
    }
  }

  window.postMessage({ __vk_react_detect: true, result: result }, location.origin);
})();
