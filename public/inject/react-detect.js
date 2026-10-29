"use strict";
// 灵眸 - React Detection Inject Script
(function () {
    'use strict';
    // 检测为只读操作，不做一次性守卫：守卫会让二次注入早退、不回执，
    // bridge 端等到超时返回 null，面板误报「无法连接内容脚本」。
    const __vk_token = document.currentScript
        ? document.currentScript.dataset.vkToken || ''
        : '';
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
    const devtoolsHook = window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
    if (devtoolsHook) {
        result.detected = true;
        result.signals.push('React DevTools Global Hook');
        const renderers = devtoolsHook.renderers;
        if (renderers) {
            const versions = [];
            renderers.forEach(function (r, id) {
                if (r && r.version)
                    versions.push(r.version);
            });
            if (versions.length > 0)
                result.version = versions.join(', ');
        }
    }
    // React Fiber on root element
    // 修复：不限定固定 id（root/app/__next），root-master 等 umi/qiankun 容器也要能找到
    const candidateEls = [];
    const explicitIds = ['root', 'app', '__next', 'root-master', 'main', 'mainContainer', 'application'];
    for (let ei = 0; ei < explicitIds.length; ei++) {
        const el = document.getElementById(explicitIds[ei]);
        if (el && candidateEls.indexOf(el) === -1)
            candidateEls.push(el);
    }
    const prefixSelectors = ['[id^="root"]', '[id^="app"]', '[id^="main"]', '[data-reactroot]'];
    for (let pi = 0; pi < prefixSelectors.length; pi++) {
        document.querySelectorAll(prefixSelectors[pi]).forEach((el) => {
            if (candidateEls.indexOf(el) === -1)
                candidateEls.push(el);
        });
    }
    if (candidateEls.length === 0 && document.body) {
        // 兜底：扫描 body 前两层子树找带 React 内部键的容器
        const scan = [document.body];
        let sn = 0;
        while (scan.length > 0 && sn < 300) {
            const cur = scan.shift();
            sn++;
            const keys = Object.keys(cur);
            for (let ki = 0; ki < keys.length; ki++) {
                const k = keys[ki];
                if (k.indexOf('__reactFiber$') === 0 || k.indexOf('__reactContainer$') === 0 || k.indexOf('__reactInternalInstance$') === 0) {
                    candidateEls.push(cur);
                    break;
                }
            }
            for (let ci = 0; ci < cur.children.length; ci++)
                scan.push(cur.children[ci]);
        }
    }
    let rootEl;
    let fiberKey;
    for (let ci = 0; ci < candidateEls.length && !rootEl; ci++) {
        const keys = Object.keys(candidateEls[ci]);
        const fk = keys.find(function (k) {
            return k.startsWith('__reactFiber$') || k.startsWith('__reactContainer$') || k.startsWith('__reactInternalInstance$');
        });
        if (fk) {
            rootEl = candidateEls[ci];
            fiberKey = fk;
            result.detected = true;
            result.signals.push(`React Fiber (${fk})`);
        }
    }
    if (!rootEl) {
        for (const el of candidateEls) {
            const propsKey = Object.keys(el).find(function (k) {
                return k.startsWith('__reactProps$');
            });
            if (propsKey) {
                rootEl = el;
                result.detected = true;
                result.signals.push('React Props');
                break;
            }
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
    const nextData = window.__NEXT_DATA__;
    if (nextData) {
        result.metaframework = 'Next.js';
        result.detected = true;
        result.signals.push('__NEXT_DATA__');
        if (nextData.buildId)
            result.signals.push(`Next.js Build: ${nextData.buildId}`);
        if (nextData.runtimeConfig)
            result.signals.push('Next.js Runtime Config');
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
    // umi（含 qiankun 微前端主/子应用）：window.g_umi 由 umi 运行时注入
    const umiGlobal = window.g_umi;
    if (umiGlobal && umiGlobal.version) {
        result.metaframework = result.metaframework || `umi ${umiGlobal.version}`;
        result.detected = true;
        result.signals.push(`window.g_umi v${umiGlobal.version}`);
    }
    if (window.g_history && typeof window.g_history.push === 'function') {
        result.signals.push('window.g_history (umi router)');
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
            if (m && !result.version)
                result.version = m[1];
        }
        if (/react\.production/i.test(s.src) || /react\.development/i.test(s.src)) {
            if (!result.version) {
                const m2 = s.src.match(/(\d+\.\d+\.\d+)/);
                if (m2)
                    result.version = m2[1];
            }
        }
    });
    // Check for React in bundle (global)
    const ReactGlobal = window.React;
    if (typeof ReactGlobal !== 'undefined' && ReactGlobal.version) {
        result.detected = true;
        if (!result.version)
            result.version = ReactGlobal.version;
        result.signals.push(`Global React object v${ReactGlobal.version}`);
    }
    const ReactDOMGlobal = window.ReactDOM;
    if (typeof ReactDOMGlobal !== 'undefined' && ReactDOMGlobal.version) {
        result.detected = true;
        if (!result.version)
            result.version = ReactDOMGlobal.version;
    }
    // Dev/Prod mode detection
    let isDev = false;
    if (ReactGlobal && ReactGlobal.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED) {
        isDev = true;
    }
    scripts.forEach(function (s) {
        if (/react\.development/i.test(s.src))
            isDev = true;
    });
    if (devtoolsHook && devtoolsHook.renderers) {
        try {
            const fiberRoot = rootEl && fiberKey ? rootEl[fiberKey] : null;
            if (fiberRoot && fiberRoot._debugInfo)
                isDev = true;
            if (fiberRoot && fiberRoot.memoizedState && fiberRoot.memoizedState.queue)
                isDev = true;
        }
        catch (e) {
            /* ignore */
        }
    }
    result.mode = isDev ? 'development' : 'production';
    if (isDev)
        result.signals.push('Development mode (security risk: verbose errors, source maps)');
    // State management detection
    if (typeof window.__REDUX_DEVTOOLS_EXTENSION__ !== 'undefined' ||
        typeof window.__store__ !== 'undefined') {
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
    if (typeof window.MobX !== 'undefined') {
        result.stateManager = result.stateManager ? `${result.stateManager} + MobX` : 'MobX';
        result.signals.push('MobX detected');
    }
    if (typeof window.Recoil !== 'undefined' ||
        document.querySelector('[data-recoil-root]')) {
        result.stateManager = result.stateManager ? `${result.stateManager} + Recoil` : 'Recoil';
        result.signals.push('Recoil detected');
    }
    if (typeof window.jotai !== 'undefined' || typeof window.jotaiModule !== 'undefined') {
        result.stateManager = result.stateManager ? `${result.stateManager} + Jotai` : 'Jotai';
        result.signals.push('Jotai detected');
    }
    // Component tree extraction from Fiber
    const componentNames = [];
    function walkFiber(fiber, depth) {
        if (!fiber || depth > 8)
            return;
        const name = fiber.type
            ? typeof fiber.type === 'function'
                ? fiber.type.displayName || fiber.type.name
                : fiber.type
            : '';
        if (name &&
            name !== '' &&
            componentNames.indexOf(name) === -1 &&
            name.charAt(0) === name.charAt(0).toUpperCase() &&
            name.length > 1 &&
            name.length < 40) {
            componentNames.push(name);
        }
        if (fiber.child)
            walkFiber(fiber.child, depth + 1);
        if (fiber.sibling)
            walkFiber(fiber.sibling, depth);
    }
    if (fiberKey && rootEl) {
        try {
            const fiberNode = rootEl[fiberKey];
            if (fiberNode && fiberNode.stateNode) {
                const _root = fiberNode.stateNode._reactRootContainer || fiberNode.stateNode;
                if (_root && _root._internalRoot)
                    walkFiber(_root._internalRoot.current, 0);
            }
            else if (fiberNode) {
                walkFiber(fiberNode, 0);
            }
        }
        catch (e) {
            /* ignore */
        }
    }
    result.components = componentNames.slice(0, 30);
    // Next.js route extraction
    if (nextData && nextData.page) {
        result.routes.push(nextData.page);
    }
    if (nextData && nextData.buildManifest) {
        const pages = Object.keys(nextData.buildManifest.pages || {});
        pages.forEach(function (p) {
            if (p.charAt(0) === '/' && result.routes.indexOf(p) === -1)
                result.routes.push(p);
        });
        if (result.routes.length > 50)
            result.routes = result.routes.slice(0, 50);
    }
    // React Router route detection via router context
    if (ReactGlobal && rootEl) {
        try {
            const routeSet = {};
            const pushHref = function (href) {
                if (!href)
                    return;
                let clean;
                if (href.charAt(0) === '#') {
                    clean = href.slice(1).split('?')[0]; // hash 路由链接 #/xxx → /xxx
                }
                else if (href.charAt(0) === '/') {
                    clean = href.split('?')[0];
                }
                else {
                    return;
                }
                if (clean.length > 1 && !routeSet[clean]) {
                    routeSet[clean] = true;
                }
            };
            document.querySelectorAll('a[href^="/"], a[href^="#/"]').forEach(function (a) {
                pushHref(a.getAttribute('href'));
            });
            result.routes = result.routes.concat(Object.keys(routeSet)).slice(0, 50);
        }
        catch (e) {
            /* ignore */
        }
    }
    window.postMessage({ __vk_react_detect: true, __vk_token: __vk_token, result: result }, location.origin);
})();
