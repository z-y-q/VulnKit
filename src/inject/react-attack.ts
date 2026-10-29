/**
 * 灵眸 - React 攻击层注入脚本
 * MAIN world 运行，操作 React Router / umi 运行时：
 *   - routes:   深提取路由表（fiber routes 数组 / data router / RouteContext / JSX path /
 *               umi bundle 字面量兜底）+ qiankun 微应用清单 + umi 元信息
 *   - navigate: 按优先级选导航器跳转（data router.navigate → umi g_history →
 *               fiber history/navigator → hash → pushState）
 *   - jump:     一键绕过 + 跳转：吞掉登录/403 重定向 + 反弹重推（对抗鉴权 wrapper 踢回登录页）
 *   - restore:  还原被包装的导航器
 *
 * 通过 dataset.vkToken 读取一次性令牌，postMessage 回传结果。
 */
(async function () {
  const token: string = document.currentScript
    ? (document.currentScript as HTMLScriptElement).dataset.vkToken || ''
    : '';
  const action: string = document.currentScript
    ? (document.currentScript as HTMLScriptElement).dataset.vkAction || ''
    : '';
  const target: string = document.currentScript
    ? (document.currentScript as HTMLScriptElement).dataset.vkTarget || ''
    : '';

  /** 登录/403 类回退路径：jump 期间吞掉指向这些路径的重定向 */
  const LOGIN_REDIRECT_RE = /(?:^|\/)(login|signin|sign-in|sso-login|free-login|mobile-login|401|403|unauthorized|forbidden|no-auth)(?:$|[/?#])/i;

  function postResult(result: any) {
    window.postMessage({ __vk_react_attack: true, __vk_token: token, result }, location.origin);
  }

  // ====== 挂载容器发现（修复 root-master 等 umi/qiankun 容器识别不到的问题） ======

  function hasReactKey(el: Element): boolean {
    const keys = Object.keys(el);
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      if (
        k.indexOf('__reactFiber$') === 0 ||
        k.indexOf('__reactContainer$') === 0 ||
        k.indexOf('__reactInternalInstance$') === 0
      ) {
        return true;
      }
    }
    return false;
  }

  /** 返回全部疑似 React 根容器（显式 id → 前缀选择器 → body 后代扫描） */
  function findRootContainers(): HTMLElement[] {
    const found: HTMLElement[] = [];
    const push = (el: Element | null | undefined): void => {
      if (el && found.indexOf(el as HTMLElement) === -1 && hasReactKey(el)) found.push(el as HTMLElement);
    };
    const explicit = ['root', 'app', '__next', 'root-master', 'main', 'application'];
    for (let i = 0; i < explicit.length; i++) push(document.getElementById(explicit[i]));
    const selectors = ['[id^="root"]', '[id^="app"]', '[data-reactroot]', '[data-react-portal]'];
    for (let si = 0; si < selectors.length; si++) {
      const els = document.querySelectorAll(selectors[si]);
      for (let ei = 0; ei < els.length && ei < 10; ei++) push(els[ei]);
    }
    if (found.length === 0 && document.body) {
      // 兜底：扫描 body 前两层子树（qiankun 子应用容器多挂在这里）
      const scan: Element[] = [document.body];
      let n = 0;
      while (scan.length > 0 && n < 300) {
        const cur = scan.shift()!;
        n++;
        push(cur);
        for (let ci = 0; ci < cur.children.length; ci++) scan.push(cur.children[ci]);
      }
    }
    return found;
  }

  /** 从容器元素上取 fiber 节点（容器键 __reactContainer$ 直接是 fiber root） */
  function collectFibers(): any[] {
    const fibers: any[] = [];
    for (const el of findRootContainers()) {
      const keys = Object.keys(el);
      for (const k of keys) {
        if (k.indexOf('__reactContainer$') === 0) {
          // React 18 createRoot：容器键指向 HostRoot fiber
          const f = (el as any)[k];
          if (f) fibers.push(f.stateNode && f.stateNode.current ? f.stateNode.current : f);
        } else if (k.indexOf('__reactFiber$') === 0 || k.indexOf('__reactInternalInstance$') === 0) {
          const f = (el as any)[k];
          if (!f) continue;
          // React 16/17 legacy root：经 stateNode._internalRoot.current 取真正的根
          const legacy = f.stateNode && (f.stateNode._internalRoot || (f.stateNode._reactRootContainer && f.stateNode._reactRootContainer._internalRoot));
          fibers.push(legacy && legacy.current ? legacy.current : f);
        }
      }
    }
    return fibers;
  }

  // ====== fiber 遍历 ======

  function walkFiber(roots: any[], visit: (fiber: any) => void, maxNodes: number): void {
    const seen = new Set<any>();
    let count = 0;
    const stack: any[] = [];
    for (let i = roots.length - 1; i >= 0; i--) if (roots[i]) stack.push(roots[i]);
    while (stack.length > 0 && count < maxNodes) {
      const fiber = stack.pop();
      if (!fiber || seen.has(fiber)) continue;
      seen.add(fiber);
      count++;
      try {
        visit(fiber);
      } catch (e) {
        /* 单节点异常不中断遍历 */
      }
      if (fiber.child) stack.push(fiber.child);
      if (fiber.sibling) stack.push(fiber.sibling);
    }
  }

  // ====== 路径拼接（与 lib/analyzers/react-analyzer.ts joinReactPath 保持一致） ======

  function joinPath(parent: string, segment: string, isIndex?: boolean): string {
    if (isIndex || segment === undefined || segment === null || segment === '') return parent || '/';
    const seg = String(segment);
    if (seg.charAt(0) === '/') return seg;
    if (seg === '*') return parent === '/' || parent === '' ? '*' : parent + '/*';
    if (!parent || parent === '/') return '/' + seg;
    return parent + '/' + seg;
  }

  function isAuthKey(k: string): boolean {
    return /^(?:requiresAuth|requireAuth|auth|authenticated|needLogin|loginRequired|permission|permissions|role|roles|authority|access|private|isAdmin|admin|whiteList|noAuth)$/i.test(k);
  }

  function authKeysOf(node: any): string[] {
    const out: string[] = [];
    const pools = [node.handle, node.meta];
    for (const pool of pools) {
      if (pool && typeof pool === 'object') {
        for (const k of Object.keys(pool)) if (isAuthKey(k) && out.indexOf(k) === -1) out.push(k);
      }
    }
    return out;
  }

  // ====== 路由收集 ======

  interface RouteRow { path: string; component: string; source: string; authKeys: string[]; }

  function collectRoutesFromFiber(): { rows: RouteRow[]; fiberCount: number; dataRouter: any; historyLike: any } {
    const rows: RouteRow[] = [];
    const seen = new Set<string>();
    let fiberCount = 0;
    let dataRouter: any = null;
    let historyLike: any = null;

    const addRow = (path: string, component: string, source: string, authKeys: string[]): void => {
      if (!path) return;
      const key = path + '|' + source;
      if (seen.has(key)) return;
      seen.add(key);
      rows.push({ path, component: component || '', source, authKeys: authKeys || [] });
    };

    /** 递归展开 routes 数组（props.routes / router.routes），父链路径拼接 */
    const walkRouteArray = (list: any[], parent: string, source: string, depth: number): void => {
      if (!Array.isArray(list) || depth > 10 || rows.length > 400) return;
      for (const node of list) {
        if (!node || typeof node !== 'object') continue;
        const seg = typeof node.path === 'string' ? node.path : '';
        const isIndex = node.index === true || seg === '';
        const full = joinPath(parent, seg, isIndex);
        const comp =
          (typeof node.component === 'string' && node.component) ||
          (typeof node.element === 'object' && node.element && (node.element.type && (node.element.type.displayName || node.element.type.name) || '') ) ||
          '';
        addRow(full, comp, source, authKeysOf(node));
        if (Array.isArray(node.children)) walkRouteArray(node.children, full, source, depth + 1);
      }
    };

    const visit = (fiber: any): void => {
      fiberCount++;
      const props = fiber.memoizedProps;
      if (!props || typeof props !== 'object') return;

      // 1) data router（RouterProvider 的 router prop，react-router 6.4+）
      if (props.router && typeof props.router === 'object' && Array.isArray(props.router.routes)) {
        if (!dataRouter && typeof props.router.navigate === 'function') dataRouter = props.router;
        walkRouteArray(props.router.routes, '', 'data-router', 0);
      }
      // 2) 路由配置数组直接挂在 props 上（react-router-config / umi wrappers 等）
      if (Array.isArray(props.routes)) walkRouteArray(props.routes, '', 'fiber-props', 0);
      // 3) JSX <Route path>（v5/v6 手写路由）
      if (typeof props.path === 'string' && (props.path.charAt(0) === '/' || props.path === '*' || props.path.indexOf('/') > 0)) {
        addRow(props.path, '', 'jsx-route', authKeysOf(props));
      }
      // 4) RouteContext：value.matches 携带已编译 route 记录
      if (props.value && typeof props.value === 'object' && Array.isArray(props.value.matches)) {
        for (const match of props.value.matches) {
          const r = match && (match.route || match);
          if (r && typeof r.path === 'string') addRow(r.path, '', 'router-context', authKeysOf(r));
        }
      }
      // 5) 导航器（v5 Router history / v6 HistoryRouter navigator）
      if (!historyLike) {
        if (props.history && typeof props.history.push === 'function' && props.history.location) historyLike = props.history;
        else if (props.navigator && typeof props.navigator.push === 'function') historyLike = props.navigator;
      }
    };

    walkFiber(collectFibers(), visit, 4000);
    return { rows, fiberCount, dataRouter, historyLike };
  }

  // ====== umi 元信息 ======

  function umiInfo(): { version: string; historyMode: string; hasGlobalHistory: boolean } {
    const w = window as any;
    const version = w.g_umi && w.g_umi.version ? String(w.g_umi.version) : '';
    const hasGlobalHistory = !!(w.g_history && typeof w.g_history.push === 'function');
    let historyMode = '';
    if (hasGlobalHistory) {
      historyMode = location.href.indexOf('#') !== -1 && location.hash.charAt(1) === '/' ? 'hash' : 'browser';
    }
    return { version, historyMode, hasGlobalHistory };
  }

  // ====== bundle 字面量兜底（umi 4 路由配置闭包在模块内，fiber 不可达时启用） ======

  function isPlausibleRoutePath(p: string): boolean {
    if (!p || p.charAt(0) !== '/') return false;
    if (!/^[a-zA-Z0-9\-_/:*?.%~+[\]()$@,=&]{1,120}$/.test(p)) return false;
    return !/\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|json|html|map)$/i.test(p);
  }

  async function scanBundles(): Promise<{ paths: string[]; microApps: { path: string; microApp: string }[]; scripts: number }> {
    const scripts: string[] = [];
    document.querySelectorAll('script[src]').forEach((s: Element) => {
      const src = (s as HTMLScriptElement).src || '';
      try {
        const u = new URL(src, location.href);
        // 只扫同源脚本（跨源 fetch 会被 CORS 拦截，读不到内容）
        if (u.origin === location.origin && /\.js(\?|$)/.test(u.pathname)) scripts.push(u.href);
      } catch (e) {
        /* 非法 URL 跳过 */
      }
    });

    const paths = new Set<string>();
    const microApps: { path: string; microApp: string }[] = [];
    const microSeen = new Set<string>();
    let scanned = 0;

    for (const url of scripts.slice(0, 8)) {
      if (scanned >= 8 * 1024 * 1024) break;
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 8000);
        const res = await fetch(url, { credentials: 'omit', signal: ctrl.signal });
        clearTimeout(timer);
        const text = await res.text();
        scanned += text.length;

        const pathRe = /path\s*:\s*"([^"\s]{1,120})"/g;
        let m: RegExpExecArray | null;
        while ((m = pathRe.exec(text)) !== null) {
          if (isPlausibleRoutePath(m[1])) paths.add(m[1]);
          if (paths.size >= 500) break;
        }
        const microRe = /path\s*:\s*"([^"\s]+)"\s*,\s*microApp\s*:\s*"([^"]+)"|microApp\s*:\s*"([^"]+)"\s*,\s*path\s*:\s*"([^"\s]+)"/g;
        while ((m = microRe.exec(text)) !== null) {
          const p = m[1] || m[4];
          const app = m[2] || m[3];
          if (!p || !app) continue;
          const key = p + '|' + app;
          if (!microSeen.has(key)) {
            microSeen.add(key);
            microApps.push({ path: p, microApp: app });
          }
          if (microApps.length >= 50) break;
        }
      } catch (e) {
        /* 单个脚本失败跳过 */
      }
    }
    return { paths: Array.from(paths).sort(), microApps, scripts: scripts.length };
  }

  // ====== 锚点通道（含 hash 路由链接） ======

  function collectAnchorRoutes(): string[] {
    const out: string[] = [];
    const seen = new Set<string>();
    const push = function (raw: string | null): void {
      if (!raw) return;
      let clean: string;
      if (raw.charAt(0) === '#') {
        clean = raw.slice(1).split('?')[0]; // #/home/detail → /home/detail
      } else if (raw.charAt(0) === '/') {
        clean = raw.split('?')[0].split('#')[0];
      } else {
        return;
      }
      if (clean.length > 1 && !seen.has(clean)) {
        seen.add(clean);
        out.push(clean);
      }
    };
    document.querySelectorAll('a[href^="/"], a[href^="#/"]').forEach(function (a: Element) {
      push(a.getAttribute('href'));
    });
    return out.slice(0, 100);
  }

  // ====== 导航器解析与跳转 ======

  interface Navigator {
    via: string;
    push: (path: string) => void;
    currentPath: () => string;
  }

  /** 按优先级列出可用导航器 */
  function resolveNavigators(dataRouter: any, historyLike: any): Navigator[] {
    const out: Navigator[] = [];
    const w = window as any;

    if (dataRouter && typeof dataRouter.navigate === 'function') {
      out.push({
        via: 'data-router.navigate',
        push: (p: string) => dataRouter.navigate(p),
        currentPath: () => (dataRouter.state && dataRouter.state.location ? dataRouter.state.location.pathname : ''),
      });
    }
    if (w.g_history && typeof w.g_history.push === 'function') {
      out.push({
        via: 'umi.g_history',
        push: (p: string) => w.g_history.push(p),
        currentPath: () => (w.g_history.location ? w.g_history.location.pathname : ''),
      });
    }
    if (historyLike) {
      out.push({
        via: 'fiber.history',
        push: (p: string) => historyLike.push(p),
        currentPath: () => (historyLike.location ? historyLike.location.pathname : ''),
      });
    }
    // hash 兜底：hash 路由页面（URL 含 #/）直接改 hash 触发路由
    if (location.href.indexOf('#/') !== -1) {
      out.push({
        via: 'location.hash',
        push: (p: string) => {
          location.hash = '#' + p;
        },
        currentPath: () => {
          const h = location.hash.slice(1);
          return h.split('?')[0];
        },
      });
    }
    // pushState 兜底：browser 路由（含 qiankun 子应用路径前缀场景）
    out.push({
      via: 'history.pushState',
      push: (p: string) => {
        history.pushState(history.state, '', p);
        window.dispatchEvent(new PopStateEvent('popstate', { state: history.state }));
      },
      currentPath: () => location.pathname,
    });
    return out;
  }

  function primaryNavigator(nav: Navigator[]): Navigator {
    return nav[0];
  }

  function currentPathOf(nav: Navigator[]): string {
    for (const n of nav) {
      try {
        const p = n.currentPath();
        if (p) return p;
      } catch (e) {
        /* 下一个 */
      }
    }
    return location.pathname + location.hash;
  }

  // ====== 重定向吞噬（jump 用）：包装导航器，吞掉指向登录/403 的导航调用 ======

  const BACKUP_KEY = '__vk_react_backup_nav__';

  function installSwallow(keepPath: string): number {
    const w = window as any;
    w[BACKUP_KEY] = w[BACKUP_KEY] || {};
    let patched = 0;
    const swallow = (raw: string): boolean => {
      // 目标是登录类路径且非我们想去的路径 → 吞掉
      return LOGIN_REDIRECT_RE.test(raw || '') && raw !== keepPath;
    };
    if (w.g_history && !w.g_history.__vk_patched__) {
      const g = w.g_history;
      w[BACKUP_KEY].g_push = g.push;
      w[BACKUP_KEY].g_replace = g.replace;
      g.push = function (p: any) { if (!swallow(typeof p === 'string' ? p : p && p.pathname)) return w[BACKUP_KEY].g_push.apply(this, arguments); };
      g.replace = function (p: any) { if (!swallow(typeof p === 'string' ? p : p && p.pathname)) return w[BACKUP_KEY].g_replace.apply(this, arguments); };
      (g as any).__vk_patched__ = true;
      patched++;
    }
    const cachedRouter = (window as any).__vk_react_router_ref__;
    if (cachedRouter && typeof cachedRouter.navigate === 'function' && !cachedRouter.__vk_patched__) {
      const orig = cachedRouter.navigate.bind(cachedRouter);
      w[BACKUP_KEY].router_navigate = orig;
      cachedRouter.navigate = function (p: any) { const to = typeof p === 'string' ? p : p && p.pathname; if (!swallow(to)) return orig.apply(null, arguments as any); };
      (cachedRouter as any).__vk_patched__ = true;
      patched++;
    }
    // 原生 history API 兜底吞噬（鉴权 wrapper 直接调 window.history 的场景）
    if (!(window.history as any).__vk_patched__) {
      const h = window.history;
      w[BACKUP_KEY].native_push = h.pushState;
      w[BACKUP_KEY].native_replace = h.replaceState;
      h.pushState = function (state: any, title: string, url: string | URL | null) {
        const p = url == null ? '' : String(url);
        if (!swallow(p)) return w[BACKUP_KEY].native_push.apply(this, arguments as any);
      };
      h.replaceState = function (state: any, title: string, url: string | URL | null) {
        const p = url == null ? '' : String(url);
        if (!swallow(p)) return w[BACKUP_KEY].native_replace.apply(this, arguments as any);
      };
      (h as any).__vk_patched__ = true;
      patched++;
    }
    return patched;
  }

  function removeSwallow(): void {
    const w = window as any;
    const backup = w[BACKUP_KEY];
    if (!backup) return;
    if (w.g_history && w.g_history.__vk_patched__) {
      if (backup.g_push) w.g_history.push = backup.g_push;
      if (backup.g_replace) w.g_history.replace = backup.g_replace;
      w.g_history.__vk_patched__ = false;
    }
    if (backup.router_navigate) {
      // dataRouter 引用运行时重新解析（restore 独立调用时不再重新 fiber 遍历，直接查已缓存的标记对象）
      const cached = (w as any).__vk_react_router_ref__;
      if (cached && cached.__vk_patched__) {
        cached.navigate = backup.router_navigate;
        cached.__vk_patched__ = false;
      }
    }
    if ((window.history as any).__vk_patched__) {
      if (backup.native_push) window.history.pushState = backup.native_push;
      if (backup.native_replace) window.history.replaceState = backup.native_replace;
      (window.history as any).__vk_patched__ = false;
    }
    w[BACKUP_KEY] = null;
  }

  // ====== 主流程 ======

  try {
    // ---- routes：深提取 ----
    if (action === 'routes') {
      const fiber = collectRoutesFromFiber();
      (window as any).__vk_react_router_ref__ = fiber.dataRouter;
      const umi = umiInfo();
      const bundle = await scanBundles();
      postResult({
        success: true,
        routes: fiber.rows,
        fiberCount: fiber.fiberCount,
        bundlePaths: bundle.paths,
        microApps: bundle.microApps,
        anchorPaths: collectAnchorRoutes(),
        umi,
        navigators: resolveNavigators(fiber.dataRouter, fiber.historyLike).map((n) => n.via),
      });
      return;
    }

    // ---- navigate：普通跳转 ----
    if (action === 'navigate') {
      if (!target) {
        postResult({ success: false, error: '缺少目标路径' });
        return;
      }
      const fiber = collectRoutesFromFiber();
      (window as any).__vk_react_router_ref__ = fiber.dataRouter;
      const navs = resolveNavigators(fiber.dataRouter, fiber.historyLike);
      const primary = primaryNavigator(navs);
      primary.push(target);
      postResult({ success: true, path: target, via: primary.via });
      return;
    }

    // ---- jump：绕过重定向 + 跳转 + 反弹重推 ----
    if (action === 'jump') {
      if (!target) {
        postResult({ success: false, error: '缺少目标路径' });
        return;
      }
      const fiber = collectRoutesFromFiber();
      (window as any).__vk_react_router_ref__ = fiber.dataRouter;
      const navs = resolveNavigators(fiber.dataRouter, fiber.historyLike);
      const primary = primaryNavigator(navs);
      const patchedCount = installSwallow(target);
      primary.push(target);

      let bounces = 0;
      const maxBounces = 5;
      const startedAt = Date.now();
      const timer = setInterval(() => {
        const cur = currentPathOf(navs);
        const bouncedAway = LOGIN_REDIRECT_RE.test(cur) && !LOGIN_REDIRECT_RE.test(target);
        if (bouncedAway && bounces < maxBounces) {
          bounces++;
          primary.push(target);
        }
        if (Date.now() - startedAt > 5000 || (bounces >= maxBounces && bouncedAway)) {
          clearInterval(timer);
          removeSwallow();
          window.postMessage(
            { __vk_react_attack: true, __vk_token: token, result: { success: true, path: target, via: primary.via, bounces, autoRestored: true } },
            location.origin,
          );
        }
      }, 400);
      // 立即先回执，异步监视结果另行上报
      postResult({ success: true, path: target, via: primary.via, patched: patchedCount, watching: true });
      return;
    }

    // ---- restore：还原导航器 ----
    if (action === 'restore') {
      removeSwallow();
      postResult({ success: true });
      return;
    }

    postResult({ success: false, error: '未知操作: ' + action });
  } catch (e: any) {
    postResult({ success: false, error: String(e && e.message ? e.message : e) });
  }
})();
