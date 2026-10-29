"use strict";
// 灵眸 - React Store/Router Explorer (MAIN world injection)
// Extracts Redux/Zustand store state, React Router routes, API endpoints
(function () {
    'use strict';
    const __vk_token = document.currentScript ? document.currentScript.dataset.vkToken || '' : '';
    function safeClone(obj, depth) {
        if (depth === undefined)
            depth = 0;
        if (obj === null || obj === undefined)
            return obj;
        if (typeof obj !== 'object')
            return obj;
        if (depth > 6)
            return '[Max Depth]';
        try {
            return JSON.parse(JSON.stringify(obj, function (key, value) {
                if (typeof value === 'function')
                    return '[Function]';
                if (value instanceof HTMLElement)
                    return '[HTMLElement: ' + (value.tagName || 'unknown') + ']';
                if (value instanceof Window)
                    return '[Window]';
                if (value instanceof Error)
                    return '[Error: ' + value.message + ']';
                if (typeof value === 'symbol')
                    return value.toString();
                if (typeof value === 'bigint')
                    return '[BigInt: ' + value.toString() + ']';
                if (value instanceof Promise)
                    return '[Promise]';
                if (value instanceof Map) {
                    try {
                        return { __type__: 'Map', size: value.size };
                    }
                    catch (_) {
                        return '[Map]';
                    }
                }
                if (value instanceof Set) {
                    try {
                        return { __type__: 'Set', size: value.size };
                    }
                    catch (_) {
                        return '[Set]';
                    }
                }
                if (value instanceof WeakMap || value instanceof WeakSet)
                    return '[WeakRef]';
                return value;
            }));
        }
        catch (e) {
            return String(obj);
        }
    }
    /** 疑似 React 根容器全集（显式 id → 前缀选择器 → body 前两层扫描兜底） */
    function findReactContainerEls() {
        const candidates = [];
        const explicitIds = ['root', 'app', '__next', 'root-master', 'main', 'mainContainer', 'application'];
        for (let ei = 0; ei < explicitIds.length; ei++) {
            const el = document.getElementById(explicitIds[ei]);
            if (el && candidates.indexOf(el) === -1)
                candidates.push(el);
        }
        const prefixSelectors = ['[id^="root"]', '[id^="app"]', '[id^="main"]', '[data-reactroot]'];
        for (let pi = 0; pi < prefixSelectors.length; pi++) {
            const els = document.querySelectorAll(prefixSelectors[pi]);
            for (let ei = 0; ei < els.length && ei < 10; ei++) {
                if (candidates.indexOf(els[ei]) === -1)
                    candidates.push(els[ei]);
            }
        }
        if (candidates.length === 0 && document.body) {
            // 兜底：扫描 body 前两层子树找带 React 内部键的容器
            const scan = [document.body];
            let sn = 0;
            while (scan.length > 0 && sn < 300) {
                const cur = scan.shift();
                sn++;
                Object.keys(cur).forEach(function (k) {
                    if ((k.indexOf('__reactFiber$') === 0 ||
                        k.indexOf('__reactContainer$') === 0 ||
                        k.indexOf('__reactInternalInstance$') === 0) &&
                        candidates.indexOf(cur) === -1) {
                        candidates.push(cur);
                    }
                });
                for (let ci = 0; ci < cur.children.length; ci++)
                    scan.push(cur.children[ci]);
            }
        }
        return candidates;
    }
    function getFiberRoot() {
        for (const rootEl of findReactContainerEls()) {
            const fiberKey = Object.keys(rootEl).find(function (k) {
                return (k.startsWith('__reactContainer$') ||
                    k.startsWith('__reactFiber$') ||
                    k.startsWith('__reactInternalInstance$'));
            });
            if (!fiberKey)
                continue;
            const fiberNode = rootEl[fiberKey];
            if (!fiberNode)
                continue;
            // 统一返回带 .current 的 FiberRoot（调用方用 fiberRoot.current 遍历）
            // React 18 createRoot：容器键 __reactContainer$ 指向 HostRoot fiber，其 stateNode 即 FiberRoot
            if (fiberKey.indexOf('__reactContainer$') === 0) {
                if (fiberNode.stateNode && fiberNode.stateNode.current)
                    return fiberNode.stateNode;
                continue;
            }
            if (fiberNode.stateNode && fiberNode.stateNode._reactRootContainer) {
                return fiberNode.stateNode._reactRootContainer._internalRoot;
            }
            if (fiberNode.stateNode && fiberNode.stateNode._internalRoot) {
                return fiberNode.stateNode._internalRoot;
            }
            if (fiberNode._internalRoot)
                return fiberNode._internalRoot;
            if (fiberNode.stateNode && fiberNode.stateNode.current)
                return fiberNode.stateNode;
            return fiberNode;
        }
        return null;
    }
    function walkFiberForStore(fiber, depth) {
        if (!fiber || depth > 30)
            return null;
        try {
            if (fiber.memoizedProps && fiber.memoizedProps.store) {
                const s = fiber.memoizedProps.store;
                if (s && typeof s.getState === 'function')
                    return s;
            }
            if (fiber.stateNode &&
                fiber.stateNode.store &&
                typeof fiber.stateNode.store.getState === 'function') {
                return fiber.stateNode.store;
            }
            if (fiber.type && fiber.type._context && fiber.stateNode) {
                const ctxValue = fiber.stateNode;
                if (ctxValue && typeof ctxValue.getState === 'function')
                    return ctxValue;
            }
        }
        catch (e) {
            /* skip */
        }
        const r = walkFiberForStore(fiber.child, depth + 1);
        if (r)
            return r;
        return walkFiberForStore(fiber.sibling, depth + 1);
    }
    function extractReduxStores() {
        const stores = [];
        const errors = [];
        // Method 1: Direct window globals
        if (window.__store__ && typeof window.__store__.getState === 'function') {
            stores.push({ name: 'window.__store__', store: window.__store__ });
        }
        if (window.__NEXT_REDUX_STORE__ && typeof window.__NEXT_REDUX_STORE__.getState === 'function') {
            stores.push({ name: '__NEXT_REDUX_STORE__', store: window.__NEXT_REDUX_STORE__ });
        }
        // Method 2: Fiber tree walk for Redux Provider
        try {
            const fiberRoot = getFiberRoot();
            if (fiberRoot) {
                const found = walkFiberForStore(fiberRoot.current || fiberRoot, 0);
                if (found)
                    stores.push({ name: 'fiber:ReduxProvider', store: found });
            }
        }
        catch (e) {
            errors.push('Redux fiber walk: ' + (e.message || String(e)));
        }
        // Method 3: __REDUX_DEVTOOLS_EXTENSION__ stores
        try {
            if (window.__REDUX_DEVTOOLS_EXTENSION__) {
                const devTools = window.__REDUX_DEVTOOLS_EXTENSION__;
                if (devTools._instances) {
                    devTools._instances.forEach(function (store, id) {
                        if (store && typeof store.getState === 'function') {
                            stores.push({ name: 'devtools-instance-' + id, store: store });
                        }
                    });
                }
            }
        }
        catch (e) {
            errors.push('Redux DevTools: ' + (e.message || String(e)));
        }
        const result = {};
        const seenStates = {};
        stores.forEach(function (entry) {
            try {
                const state = entry.store.getState();
                const stateKey = Object.keys(state || {})
                    .sort()
                    .join(',');
                if (seenStates[stateKey])
                    return;
                seenStates[stateKey] = true;
                result[entry.name] = {
                    state: safeClone(state),
                    type: 'redux',
                };
                // Extract action names from dispatch history if available
                try {
                    if (entry.store.dispatch && entry.store.getState) {
                        const thunkActions = [];
                        if (Array.isArray(entry.store._middleware)) {
                            entry.store._middleware.forEach(function (mw) {
                                if (typeof mw === 'function') {
                                    const src = mw.toString();
                                    thunkActions.push(src);
                                }
                            });
                        }
                    }
                }
                catch (_) {
                    /* no middleware access */
                }
            }
            catch (e) {
                errors.push(entry.name + ': ' + (e.message || String(e)));
            }
        });
        return { stores: result, errors: errors };
    }
    function extractZustandStores() {
        const result = {};
        const errors = [];
        try {
            if (window.__ZUSTAND_DEVTOOLS__ && window.__ZUSTAND_DEVTOOLS__.stores) {
                window.__ZUSTAND_DEVTOOLS__.stores.forEach(function (store, name) {
                    try {
                        const state = store.getState();
                        result[name || 'unnamed'] = {
                            state: safeClone(state),
                            type: 'zustand',
                        };
                    }
                    catch (e) {
                        errors.push('Zustand "' + name + '": ' + (e.message || String(e)));
                    }
                });
            }
        }
        catch (e) {
            errors.push('Zustand DevTools: ' + (e.message || String(e)));
        }
        // Fallback: scan window for common Zustand patterns
        try {
            const zustandKeys = Object.keys(window).filter(function (k) {
                if (k.startsWith('__') || k.startsWith('_') || k.startsWith('webkit') || k.startsWith('on'))
                    return false;
                try {
                    const v = window[k];
                    return (v &&
                        typeof v === 'object' &&
                        typeof v.getState === 'function' &&
                        typeof v.setState === 'function' &&
                        typeof v.subscribe === 'function');
                }
                catch (_) {
                    return false;
                }
            });
            zustandKeys.forEach(function (key) {
                if (result[key])
                    return;
                try {
                    const state = window[key].getState();
                    result[key] = {
                        state: safeClone(state),
                        type: 'zustand',
                    };
                }
                catch (_) {
                    /* skip */
                }
            });
        }
        catch (e) {
            errors.push('Zustand window scan: ' + (e.message || String(e)));
        }
        return { stores: result, errors: errors };
    }
    function extractJotaiAtoms() {
        const result = {};
        const atoms = [];
        // Strategy 1: __JOTAI_DEFAULT_STORE__ / __JOTAI_STORE__ on Fiber nodes
        try {
            for (const rootEl of findReactContainerEls()) {
                if (rootEl._reactRootContainer) {
                    const fiberKey = Object.keys(rootEl._reactRootContainer).find(function (k) {
                        return k.startsWith('__reactFiber$') || k.startsWith('__reactInternalInstance$');
                    });
                    if (fiberKey) {
                        walkFiberForJotai(rootEl._reactRootContainer[fiberKey], atoms, 0);
                    }
                }
                // React 18 createRoot 模式：容器上直接挂 __reactContainer$ / __reactFiber$ / __nextFiber$
                if (atoms.length === 0) {
                    const fiberKey2 = Object.keys(rootEl).find(function (k) {
                        return (k.startsWith('__reactContainer$') ||
                            k.startsWith('__reactFiber$') ||
                            k.startsWith('__nextFiber$') ||
                            k.startsWith('__reactInternalInstance$'));
                    });
                    if (fiberKey2) {
                        const f = rootEl[fiberKey2];
                        walkFiberForJotai(f.stateNode && f.stateNode.current ? f.stateNode.current : f, atoms, 0);
                    }
                }
                if (atoms.length > 0)
                    break;
            }
        }
        catch (_) {
            /* skip */
        }
        // Strategy 2: window.__JOTAI_DEFAULT_STORE__
        try {
            if (window.__JOTAI_DEFAULT_STORE__) {
                const store = window.__JOTAI_DEFAULT_STORE__;
                if (store.map instanceof Map) {
                    store.map.forEach(function (value, atom) {
                        const name = atom.debugLabel ||
                            (atom.key ? atom.key.substring(0, 60) : String(atom).substring(0, 60));
                        atoms.push({ name: name, value: safeClone(value) });
                    });
                }
            }
            if (window.__JOTAI_STORE__) {
                const store2 = window.__JOTAI_STORE__;
                if (store2.map instanceof Map) {
                    store2.map.forEach(function (value, atom) {
                        const name = atom.debugLabel ||
                            (atom.key ? atom.key.substring(0, 60) : String(atom).substring(0, 60));
                        atoms.push({ name: name, value: safeClone(value) });
                    });
                }
            }
        }
        catch (_) {
            /* skip */
        }
        // Strategy 3: useAtom hook memoizedState traversal on Fiber
        try {
            if (atoms.length === 0) {
                const allElements = document.querySelectorAll('*');
                for (let i = 0; i < Math.min(allElements.length, 200); i++) {
                    const el = allElements[i];
                    const fk = Object.keys(el).find(function (k) {
                        return k.startsWith('__reactFiber$');
                    });
                    if (fk) {
                        walkFiberForJotai(el[fk], atoms, 0);
                        if (atoms.length > 0)
                            break;
                    }
                }
            }
        }
        catch (_) {
            /* skip */
        }
        if (atoms.length > 0) {
            const state = {};
            atoms.forEach(function (a) {
                state[a.name] = a.value;
            });
            result['jotai'] = { state: state, type: 'jotai' };
        }
        return result;
    }
    function walkFiberForJotai(fiber, atoms, depth) {
        if (!fiber || depth > 8 || atoms.length > 50)
            return;
        try {
            let memoized = fiber.memoizedState;
            while (memoized) {
                if (memoized.queue && memoized.queue.lastRenderedState !== undefined) {
                    let name = '';
                    if (memoized.queue.lastRenderedState &&
                        typeof memoized.queue.lastRenderedState === 'object') {
                        const val = memoized.queue.lastRenderedState;
                        if (val.debugLabel) {
                            name = String(val.debugLabel);
                        }
                        else if (val.key) {
                            name = String(val.key).substring(0, 60);
                        }
                        else {
                            name = 'atom-' + atoms.length;
                        }
                        atoms.push({ name: name, value: safeClone(val.read !== undefined ? val.read : val) });
                    }
                }
                // Check for __JOTAI_STORE__ on the queue
                if (memoized.queue && memoized.queue.__JOTAI_STORE__) {
                    const js = memoized.queue.__JOTAI_STORE__;
                    if (js.map instanceof Map) {
                        js.map.forEach(function (v, atom) {
                            const n = atom.debugLabel || (atom.key ? atom.key.substring(0, 60) : 'atom-' + atoms.length);
                            atoms.push({ name: n, value: safeClone(v) });
                        });
                    }
                }
                memoized = memoized.next;
            }
        }
        catch (_) {
            /* skip */
        }
        walkFiberForJotai(fiber.child, atoms, depth + 1);
        walkFiberForJotai(fiber.sibling, atoms, depth + 1);
    }
    function extractRecoilState() {
        const result = {};
        // Strategy 1: __RECOIL_DEVTOOLS_GLOBAL_HOOK__
        try {
            const hook = window.__RECOIL_DEVTOOLS_GLOBAL_HOOK__;
            if (hook && hook.nodes) {
                const state = {};
                const atomKeys = Object.keys(hook.nodes);
                for (let i = 0; i < Math.min(atomKeys.length, 100); i++) {
                    const key = atomKeys[i];
                    try {
                        const node = hook.nodes[key];
                        const name = node && node.className ? node.className : key;
                        state[name] = safeClone(node);
                    }
                    catch (_) {
                        state[key] = { error: 'extraction failed' };
                    }
                }
                if (Object.keys(state).length > 0) {
                    result['recoil'] = { state: state, type: 'recoil', atomCount: atomKeys.length };
                }
            }
        }
        catch (_) {
            /* skip */
        }
        // Strategy 2: React fiber scan for Recoil_RecoilValue
        try {
            if (Object.keys(result).length === 0) {
                for (const rootEl of findReactContainerEls()) {
                    const fiberKey = Object.keys(rootEl).find(function (k) {
                        return (k.startsWith('__reactContainer$') ||
                            k.startsWith('__reactFiber$') ||
                            k.startsWith('__nextFiber$') ||
                            k.startsWith('__reactInternalInstance$'));
                    });
                    if (!fiberKey)
                        continue;
                    const f = rootEl[fiberKey];
                    const startFiber = f && f.stateNode && f.stateNode.current ? f.stateNode.current : f;
                    const recoilAtoms = [];
                    walkFiberForRecoil(startFiber, recoilAtoms, 0);
                    if (recoilAtoms.length > 0) {
                        const state2 = {};
                        recoilAtoms.forEach(function (a) {
                            state2[a.name] = a.value;
                        });
                        result['recoil'] = { state: state2, type: 'recoil', atomCount: recoilAtoms.length };
                        break;
                    }
                }
            }
        }
        catch (_) {
            /* skip */
        }
        return result;
    }
    function walkFiberForRecoil(fiber, atoms, depth) {
        if (!fiber || depth > 8 || atoms.length > 50)
            return;
        try {
            // Recoil stores state on the fiber in memoizedProps or memoizedState
            if (fiber.memoizedProps && fiber.memoizedProps.__recoilValue) {
                atoms.push({
                    name: String(fiber.memoizedProps.key || 'recoil-' + atoms.length),
                    value: safeClone(fiber.memoizedProps.defaultValue),
                });
            }
            // Check for RecoilRoot store in memoizedState
            if (fiber.stateNode && fiber.stateNode.storeState instanceof Map) {
                fiber.stateNode.storeState.forEach(function (v, k) {
                    atoms.push({ name: String(k), value: safeClone(v) });
                });
            }
        }
        catch (_) {
            /* skip */
        }
        walkFiberForRecoil(fiber.child, atoms, depth + 1);
        walkFiberForRecoil(fiber.sibling, atoms, depth + 1);
    }
    function extractRoutes() {
        const routes = [];
        const errors = [];
        // Next.js routes
        try {
            if (window.__NEXT_DATA__) {
                const nd = window.__NEXT_DATA__;
                if (nd.page)
                    routes.push({ path: nd.page, source: 'Next.js current page' });
                if (nd.buildManifest && nd.buildManifest.pages) {
                    Object.keys(nd.buildManifest.pages).forEach(function (p) {
                        if (p.charAt(0) === '/') {
                            routes.push({ path: p, source: 'Next.js buildManifest' });
                        }
                    });
                }
            }
        }
        catch (e) {
            errors.push('Next.js routes: ' + (e.message || String(e)));
        }
        // React Router: walk fiber tree for Route components / route configs
        try {
            const fiberRoot = getFiberRoot();
            if (fiberRoot) {
                const routePaths = {};
                /** 父链路径拼接（与 lib/analyzers/react-analyzer.ts joinReactPath 一致） */
                const joinPath = function (parent, segment, isIndex) {
                    if (isIndex || segment === undefined || segment === null || segment === '')
                        return parent || '/';
                    const seg = String(segment);
                    if (seg.charAt(0) === '/')
                        return seg;
                    if (seg === '*')
                        return parent === '/' || parent === '' ? '*' : parent + '/*';
                    if (!parent || parent === '/')
                        return '/' + seg;
                    return parent + '/' + seg;
                };
                /** 递归展开路由配置数组（含 children 嵌套，父链路径拼接） */
                const walkRouteArray = function (list, parent, source, depth) {
                    if (!Array.isArray(list) || depth > 10 || Object.keys(routePaths).length > 400)
                        return;
                    list.forEach(function (r) {
                        if (!r || typeof r !== 'object')
                            return;
                        const seg = typeof r.path === 'string' ? r.path : '';
                        const isIndex = r.index === true || seg === '';
                        const full = joinPath(parent, seg, isIndex);
                        if (!routePaths[full])
                            routePaths[full] = { path: full, source: source };
                        if (Array.isArray(r.children))
                            walkRouteArray(r.children, full, source, depth + 1);
                    });
                };
                function walkForRoutes(fiber, depth) {
                    if (!fiber || depth > 25)
                        return;
                    try {
                        const props = fiber.memoizedProps;
                        if (props && typeof props === 'object') {
                            if (props.path && typeof props.path === 'string') {
                                const p = props.path;
                                if (p.charAt(0) === '/' || p === '*') {
                                    routePaths[p] = routePaths[p] || { path: p, source: 'React Router (fiber)' };
                                    if (props.element)
                                        routePaths[p].hasElement = true;
                                }
                            }
                            // 路由配置数组挂在 props 上（react-router-config / umi 等）——递归含 children
                            if (Array.isArray(props.routes)) {
                                walkRouteArray(props.routes, '', 'React Router data router', 0);
                            }
                            // react-router 6.4+ data router：RouterProvider 的 router prop
                            if (props.router &&
                                typeof props.router === 'object' &&
                                Array.isArray(props.router.routes)) {
                                walkRouteArray(props.router.routes, '', 'React Router data router', 0);
                            }
                            // RouteContext：value.matches 携带已编译 route 记录
                            if (props.value && typeof props.value === 'object' && Array.isArray(props.value.matches)) {
                                props.value.matches.forEach(function (m) {
                                    const r = m && (m.route || m);
                                    if (r && typeof r.path === 'string' && !routePaths[r.path]) {
                                        routePaths[r.path] = { path: r.path, source: 'RouteContext' };
                                    }
                                });
                            }
                            // umi 微前端路由：{ path, microApp } 形状
                            if (typeof props.path === 'string' && props.microApp && typeof props.microApp === 'string') {
                                routePaths['microapp:' + props.microApp] = {
                                    path: props.path,
                                    source: 'micro-app: ' + props.microApp,
                                };
                            }
                        }
                    }
                    catch (_) {
                        /* skip */
                    }
                    walkForRoutes(fiber.child, depth + 1);
                    walkForRoutes(fiber.sibling, depth + 1);
                }
                walkForRoutes(fiberRoot.current || fiberRoot, 0);
                Object.values(routePaths).forEach(function (r) {
                    if (!routes.some(function (existing) {
                        return existing.path === r.path;
                    })) {
                        routes.push(r);
                    }
                });
            }
        }
        catch (e) {
            errors.push('React Router routes: ' + (e.message || String(e)));
        }
        // Anchor-based route discovery（含 hash 路由链接：移动 H5 底部导航全是 #/xxx）
        try {
            const anchorRoutes = {};
            const pushAnchor = function (raw) {
                if (!raw)
                    return;
                let clean;
                if (raw.charAt(0) === '#') {
                    // hash 路由：#/home/detail → /home/detail
                    clean = raw.slice(1).split('?')[0];
                }
                else {
                    clean = raw.split('?')[0].split('#')[0];
                }
                if (clean.length > 1 && clean.charAt(0) === '/' && !anchorRoutes[clean]) {
                    anchorRoutes[clean] = true;
                    routes.push({ path: clean, source: 'anchor href' });
                }
            };
            document.querySelectorAll('a[href^="/"]').forEach(function (a) {
                pushAnchor(a.getAttribute('href'));
            });
            document.querySelectorAll('a[href^="#/"]').forEach(function (a) {
                pushAnchor(a.getAttribute('href'));
            });
        }
        catch (_) {
            /* skip */
        }
        // Limit
        if (routes.length > 80)
            routes.length = 80;
        return { routes: routes, errors: errors };
    }
    function extractApiEndpoints() {
        const endpoints = [];
        const seen = {};
        // From Redux store: scan middleware/thunk action creators
        try {
            const fiberRoot = getFiberRoot();
            if (fiberRoot) {
                const store = walkFiberForStore(fiberRoot.current || fiberRoot, 0);
                if (store && store.dispatch) {
                    // Try to access the store's internal middleware chain
                    const srcList = [];
                    try {
                        if (store.__INITIAL_ACTION__)
                            srcList.push(JSON.stringify(store.__INITIAL_ACTION__));
                    }
                    catch (_) {
                        /* skip */
                    }
                }
            }
        }
        catch (_) {
            /* skip */
        }
        // Scan window globals for fetch/axios interceptors
        const urlPatterns = [
            /['"`](\/(?:api|v[0-9]+|admin|system|user|auth|login|register|query|search|list|get|post|put|delete|patch|upload|download|config|setting|profile|account|role|permission|menu|dict|file|image|log|monitor|report|dashboard|health|status|info|version|token|session|captcha|common|public|static|resource|data|base|core|service|gateway|proxy|ws|graphql|rest)\/[^\s'"`)\]]{2,120})['"`]/gi,
            /['"`]https?:\/\/[^\s'"`)\]]{10,200}['"`]/gi,
        ];
        // Scan all script contents for API patterns
        try {
            document.querySelectorAll('script:not([src])').forEach(function (s) {
                let text = s.textContent || '';
                if (text.length > 500000)
                    text = text.substring(0, 500000);
                urlPatterns.forEach(function (pattern) {
                    let match;
                    pattern.lastIndex = 0;
                    while ((match = pattern.exec(text)) !== null) {
                        const url = match[1];
                        if (!seen[url] && !url.startsWith('//') && url.length > 3) {
                            seen[url] = true;
                            endpoints.push(url);
                        }
                    }
                });
            });
        }
        catch (_) {
            /* skip */
        }
        // Scan Redux dispatch calls in inline scripts
        try {
            const dispatchPattern = /dispatch\s*\(\s*\w+\.(\w+)\s*\(/g;
            document.querySelectorAll('script:not([src])').forEach(function (s) {
                let text = s.textContent || '';
                if (text.length > 200000)
                    text = text.substring(0, 200000);
                let m;
                dispatchPattern.lastIndex = 0;
                while ((m = dispatchPattern.exec(text)) !== null) {
                    const actionName = m[1];
                    if (!seen['action:' + actionName]) {
                        seen['action:' + actionName] = true;
                        endpoints.push('[Action] ' + actionName);
                    }
                }
            });
        }
        catch (_) {
            /* skip */
        }
        if (endpoints.length > 100)
            endpoints.length = 100;
        return endpoints;
    }
    // === Main execution ===
    const result = {
        stores: {},
        routes: [],
        apiEndpoints: [],
        errors: [],
    };
    // Redux
    try {
        const reduxResult = extractReduxStores();
        Object.keys(reduxResult.stores).forEach(function (k) {
            result.stores[k] = reduxResult.stores[k];
        });
        result.errors = result.errors.concat(reduxResult.errors);
    }
    catch (e) {
        result.errors.push('Redux extraction: ' + (e.message || String(e)));
    }
    // Zustand
    try {
        const zustandResult = extractZustandStores();
        Object.keys(zustandResult.stores).forEach(function (k) {
            result.stores[k] = zustandResult.stores[k];
        });
        result.errors = result.errors.concat(zustandResult.errors);
    }
    catch (e) {
        result.errors.push('Zustand extraction: ' + (e.message || String(e)));
    }
    // Jotai
    try {
        const jotaiResult = extractJotaiAtoms();
        Object.keys(jotaiResult).forEach(function (k) {
            result.stores[k] = jotaiResult[k];
        });
    }
    catch (_) {
        /* skip */
    }
    // Recoil
    try {
        const recoilResult = extractRecoilState();
        Object.keys(recoilResult).forEach(function (k) {
            result.stores[k] = recoilResult[k];
        });
    }
    catch (_) {
        /* skip */
    }
    // Routes
    try {
        const routeResult = extractRoutes();
        result.routes = routeResult.routes;
        result.errors = result.errors.concat(routeResult.errors);
    }
    catch (e) {
        result.errors.push('Route extraction: ' + (e.message || String(e)));
    }
    // API Endpoints
    try {
        result.apiEndpoints = extractApiEndpoints();
    }
    catch (e) {
        result.errors.push('API endpoint extraction: ' + (e.message || String(e)));
    }
    window.postMessage({
        __vk_react_store: true,
        __vk_token: __vk_token,
        result: result,
    }, location.origin);
})();
