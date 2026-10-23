<script lang="ts">
  // Vue 分析面板
  // 检测 Vue 框架、分析路由/守卫、探索 Vuex/Pinia Store
  import { onDestroy } from 'svelte';
  import { sendToContent } from '@/lib/core/messaging';
  import { getActiveTabUrl, getActiveTab, execInTab } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import { downloadBlob } from '@/lib/actions/download';
  import {
    MENU_KEYWORDS,
    classifyPermType,
    transformShowAll,
    transformAdmin,
    expandMenuIds,
    extractMenuPaths,
    isPathInMenu,
    injectRoutesIntoMenu,
    extractPathsFromJsContexts,
    extractKeywordsFromCapturedUrls,
    type PermCapture,
    type RoutePath,
  } from '@/lib/analyzers/vue-perm-engine';
  import { sendMessage } from '@/lib/core/messaging';
  import type { FetchResult } from '@/lib/types/messaging';
  import {
    type VueDetectResult,
    type VueRouteNode,
    type StoreExploreResult,
    type StoreTreeRow,
    countRouteStats,
    scorePermissionExposure,
    flattenStoreTree,
    isSensitiveEntry,
  } from '@/lib/analyzers/vue-analyzer';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import { createTaskController, IDLE, type TaskState } from '@/lib/tasks/task-controller';
  import { abortableDelay } from '@/lib/tasks/abortable-delay';

  // ===== 状态 =====
  let detecting = $state(false);
  let exploring = $state(false);
  let detectResult = $state<VueDetectResult | null>(null);
  let storeResult = $state<StoreExploreResult | null>(null);
  let routeFilter = $state('');
  let storeFilter = $state('');
  let expandedStores = $state<Set<string>>(new Set());
  let currentUrl = $state('');
  let bypassed = $state(false);
  let authDisabled = $state(false);
  let jumpTarget = $state('');

  // ===== 攻击层：守卫绕过 / 路由跳转 / 恢复 =====
  async function bypassGuards() {
    const r = await sendToContent({ type: 'VK_VUE_ATTACK', action: 'bypass' }) as any;
    if (r?.success) {
      bypassed = true;
      const g = r.guards ? Object.entries(r.guards).filter(([, n]) => (n as number) > 0).map(([k, n]) => `${k}:${n}`).join(' ') : '';
      toastStore.show(`已绕过守卫${g ? `（${g}）` : ''}，禁用 ${r.disabledMeta || 0} 项 auth meta`, 'success');
    } else {
      toastStore.show(`绕过失败: ${r?.error || '未知错误'}`, 'error');
    }
  }

  async function navigateRoute(path: string) {
    if (!path) return;
    const r = await sendToContent({ type: 'VK_VUE_ATTACK', action: 'navigate', target: path }) as any;
    if (r?.success) {
      toastStore.show(`已跳转 ${path}`, 'success');
    } else {
      toastStore.show(`跳转失败: ${r?.error || '未知错误'}`, 'error');
    }
  }

  async function restoreRuntime() {
    const r = await sendToContent({ type: 'VK_VUE_ATTACK', action: 'restore' }) as any;
    if (r?.success) {
      bypassed = false;
      authDisabled = false;
      toastStore.show('已恢复 Vue 运行时（守卫 + auth meta）', 'success');
    } else {
      toastStore.show(`恢复失败: ${r?.error || '未知错误'}`, 'error');
    }
  }

  async function disableAuth() {
    const r = await sendToContent({ type: 'VK_VUE_ATTACK', action: 'disableAuth' }) as any;
    if (r?.success) {
      authDisabled = true;
      toastStore.show(`已禁用 ${r.disabledMeta || 0} 项 auth meta（守卫未动，可恢复）`, 'success');
    } else {
      toastStore.show(`禁用鉴权失败: ${r?.error || '未知错误'}`, 'error');
    }
  }

  async function jumpToRoute(path: string) {
    if (!path) return;
    const r = await sendToContent({ type: 'VK_VUE_ATTACK', action: 'jump', target: path, timeout: 6000 }) as any;
    if (r?.success) {
      toastStore.show(`已跳转 ${path}（3 秒后自动恢复守卫）`, 'success');
    } else {
      toastStore.show(`跳转失败: ${r?.error || '未知错误'}`, 'error');
    }
  }

  // ===== 权限拦截层（v5 vue-perm 全套）=====
  let permActive = $state(false);
  let permCaptures = $state<PermCapture[]>([]);
  let permSelected = $state<number>(-1);
  let permEditor = $state('');
  let permRefreshTimer: ReturnType<typeof setInterval> | null = null;

  /** 安装 XHR/fetch 拦截器（MAIN world），捕获菜单/权限/角色 API 响应 */
  async function startPermIntercept() {
    const tab = await getActiveTab();
    if (!tab?.id) { toastStore.show('无法获取当前标签页', 'error'); return; }
    const status = await execInTab<string>(tab.id, function (MENU_KW: string[]) {
      if ((window as any).__VK_PERM__) { (window as any).__VK_PERM__.active = true; return 'already'; }
      const URL_MENU_PATTERNS = [
        /\/api\/.*menu/i, /\/api\/.*permission/i, /\/api\/.*role/i, /\/api\/.*user.*info/i,
        /\/api\/.*auth/i, /\/api\/.*nav/i, /\/menu(?:\/|$|[?#])/i, /\/permission(?:\/|$|[?#])/i,
        /\/getMenu/i, /\/getUserInfo/i, /\/getRouters/i, /\/getRoutes(?:\/|$|[?#])/i,
      ];
      const classifyResponse = (data: any, url: string) => {
        const urlLower = url.toLowerCase();
        try {
          const json = typeof data === 'string' ? JSON.parse(data) : data;
          if (json && typeof json === 'object' && !Array.isArray(json)) {
            const keys = Object.keys(json);
            for (const k of keys) if (/^(isadmin|admin|is_superuser|isvip|vip|role|isSuperAdmin|userType|user_type|level|grade)$/i.test(k)) return { type: 'role', subtype: 'special_zero' };
            for (const k2 of keys) for (let i = 0; i < MENU_KW.length; i++) if (k2.toLowerCase() === MENU_KW[i].toLowerCase()) return { type: 'menu', subtype: null };
          }
        } catch (e) { /* */ }
        if (/permission/i.test(urlLower)) return { type: 'permission', subtype: null };
        if (/role/i.test(urlLower)) return { type: 'role', subtype: null };
        if (/menu/i.test(urlLower)) return { type: 'menu', subtype: null };
        return { type: 'other', subtype: null };
      };
      const parseBody = (text: string) => {
        try {
          const json = JSON.parse(text);
          if (json && typeof json === 'object' && !Array.isArray(json)) {
            if (json.data !== undefined) return json.data;
            if (json.result !== undefined) return json.result;
            if (json.Data !== undefined) return json.Data;
          }
          return json;
        } catch (e) { return text; }
      };
      const captured: any[] = [];
      const pushCap = (url: string, type: string, subtype: any, data: any, rawText: string, method: string) => {
        captured.push({ url, type, subtype, data, rawText, size: rawText.length, timestamp: Date.now(), method });
      };
      const origFetch = window.fetch;
      window.fetch = function () {
        const args = arguments;
        return (origFetch as any).apply(this, args).then(function (response: any) {
          const P = (window as any).__VK_PERM__;
          if (P && P.active) {
            const url = typeof args[0] === 'string' ? args[0] : ((args[0] && args[0].url) || '');
            if (URL_MENU_PATTERNS.some((p) => p.test(url))) {
              const override = P._overrideData;
              if (override != null) {
                const ob = JSON.stringify(override);
                try { const info = classifyResponse(override, url); if (info.type !== 'other') pushCap(url, info.type, info.subtype, override, ob, 'fetch-override'); } catch (e) { /* */ }
                return new Response(ob, { status: response.status, statusText: response.statusText, headers: response.headers });
              }
              const cloned = response.clone();
              cloned.text().then((text: string) => { try { const parsed = parseBody(text); const info = classifyResponse(parsed, url); if (info.type !== 'other') pushCap(url, info.type, info.subtype, parsed, text, 'fetch'); } catch (e) { /* */ } }).catch(() => {});
            }
          }
          return response;
        });
      };
      const origOpen = XMLHttpRequest.prototype.open;
      const origSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.open = function (method: string, url: string) { (this as any).__perm_url = url; return (origOpen as any).apply(this, arguments as any); };
      XMLHttpRequest.prototype.send = function () {
        const self = this as any;
        const P = (window as any).__VK_PERM__;
        if (P && P.active && self.__perm_url) {
          const url = self.__perm_url;
          if (URL_MENU_PATTERNS.some((p) => p.test(url))) {
            self.addEventListener('readystatechange', function () {
              if (self.readyState === 4) {
                const override = P._overrideData;
                const originalText = self.responseText;
                if (override != null) {
                  try { const ob = JSON.stringify(override); Object.defineProperty(self, 'responseText', { value: ob, writable: true, configurable: true }); Object.defineProperty(self, 'response', { value: ob, writable: true, configurable: true }); } catch (e) { /* */ }
                }
                try {
                  const text = override != null ? JSON.stringify(override) : originalText;
                  if (!text) return;
                  const parsed = parseBody(text);
                  const info = classifyResponse(parsed, url);
                  if (info.type !== 'other') pushCap(url, info.type, info.subtype, parsed, text, override != null ? 'xhr-override' : 'xhr');
                } catch (e) { /* */ }
              }
            });
          }
        }
        return (origSend as any).apply(this, arguments as any);
      };
      (window as any).__VK_PERM__ = {
        active: true, captured,
        getCaptured: () => captured,
        clear: () => { captured.length = 0; },
        stop: function () { this.active = false; },
        start: function () { this.active = true; },
        _overrideData: null,
        setOverride: function (d: any) { this._overrideData = d; },
        _restore: function () { try { window.fetch = origFetch; XMLHttpRequest.prototype.open = origOpen; XMLHttpRequest.prototype.send = origSend; } catch (e) { /* */ } },
      };
      return 'injected';
    }, { world: 'MAIN', args: [MENU_KEYWORDS] });

    if (!status) { toastStore.show('拦截器安装失败（可能无权限）', 'error'); return; }
    permActive = true;
    // 立即读取已有 Store 数据
    await readPermStores();
    await refreshPermCaptured();
    // 5 秒轮询
    permRefreshTimer = setInterval(refreshPermCaptured, 5000);
    toastStore.show(status === 'already' ? '拦截已恢复，请操作页面或刷新' : '拦截已启动，请操作页面或刷新', 'success');
  }

  /** 读取 Pinia/Vuex/localStorage 中已有的菜单/权限数据 */
  async function readPermStores() {
    const tab = await getActiveTab();
    if (!tab?.id) return;
    await execInTab(tab.id, function (MENU_KW: string[]) {
      const P = (window as any).__VK_PERM__; if (!P) return;
      const classifyStr = (str: string, url: string) => {
        const u = (url || '').toLowerCase();
        if (/permission/i.test(u)) return 'permission';
        if (/role/i.test(u)) return 'role';
        if (/menu/i.test(u)) return 'menu';
        for (let i = 0; i < MENU_KW.length; i++) if (str.indexOf(MENU_KW[i]) !== -1) return 'menu';
        return 'other';
      };
      const tryAdd = (data: any, url: string) => {
        if (!data || typeof data === 'string') return;
        for (const c of P.captured) if (c.url === url && c.method === 'store-read') return;
        const str = JSON.stringify(data, (_k, v) => typeof v === 'function' || v instanceof HTMLElement || v instanceof RegExp ? null : v);
        const type = classifyStr(str, url);
        if (type !== 'other') P.captured.push({ url, type, subtype: null, data, rawText: str, size: str.length, timestamp: Date.now(), method: 'store-read' });
      };
      const appEl = document.querySelector('#app,[data-v-app],[id^="app"],#root,#application,#main') as any;
      if (appEl && appEl.__vue_app__) {
        const pinia = appEl.__vue_app__.config.globalProperties.$pinia;
        if (pinia && pinia._s) pinia._s.forEach((store: any, id: string) => {
          const state = store.$state;
          for (const key in state) if (/menu|permission|nav|route|sidebar/i.test(key) && (Array.isArray(state[key]) || (typeof state[key] === 'object' && state[key] !== null))) tryAdd(state[key], `pinia://${id}/${key}`);
        });
      }
      // §12.1：优化 Vuex 查找 — 先尝试常见 Vue 根元素，避免全 DOM 扫描
      let found = false;
      const vueRoots = ['#app', '[data-v-app]', '[id^="app"]', '#root', '#application', '#main'];
      for (const sel of vueRoots) {
        const root = document.querySelector(sel) as any;
        if (root && root.__vue__) {
          const vm = root.__vue__.$root || root.__vue__;
          if (vm.$store && vm.$store.state) {
            for (const key in vm.$store.state) if (/menu|permission|nav|route|sidebar/i.test(key)) tryAdd(vm.$store.state[key], `vuex://state/${key}`);
          }
          found = true;
          break;
        }
      }
      // 仅在常见根元素未找到时才全量扫描（批次缩小到 100 节点，减少单次阻塞）
      if (!found) {
        const allEls = document.querySelectorAll('*');
        const batchSize = 100;
        for (let i = 0; i < allEls.length && !found; i += batchSize) {
          const end = Math.min(i + batchSize, allEls.length);
          for (let j = i; j < end; j++) {
            const el = allEls[j] as any;
            if (el.__vue__) {
              const vm = el.__vue__.$root || el.__vue__;
              if (vm.$store && vm.$store.state) {
                for (const key in vm.$store.state) if (/menu|permission|nav|route|sidebar/i.test(key)) tryAdd(vm.$store.state[key], `vuex://state/${key}`);
              }
              found = true;
              break;
            }
          }
        }
      }
      const prefixes = ['menu', 'permission', 'routes', 'nav', 'sidebar'];
      for (let s = 0; s < localStorage.length; s++) { const k = localStorage.key(s); if (k) { for (const p of prefixes) if (k.toLowerCase().indexOf(p) !== -1) { try { tryAdd(JSON.parse(localStorage.getItem(k) || ''), `localStorage://${k}`); } catch (e) { /* */ } break; } } }
    }, { world: 'MAIN', args: [MENU_KEYWORDS] });
  }

  async function refreshPermCaptured() {
    const tab = await getActiveTab();
    if (!tab?.id) return;
    const items = await execInTab<PermCapture[]>(tab.id, function () {
      const P = (window as any).__VK_PERM__; return P ? P.getCaptured() : [];
    }, { world: 'MAIN' });
    if (Array.isArray(items) && items.length !== permCaptures.length) {
      permCaptures = items;
      // 首次捕获自动选中
      if (permSelected < 0 && items.length > 0) selectPerm(0);
    } else if (Array.isArray(items)) {
      permCaptures = items;
    }
  }

  async function stopPermIntercept() {
    if (permRefreshTimer) { clearInterval(permRefreshTimer); permRefreshTimer = null; }
    const tab = await getActiveTab();
    if (tab?.id) {
      // §2.2：stop 置 active=false 后必须 _restore 还原原生 fetch/XHR，并删除全局对象；
      // 否则页面 fetch/XHR 长期被 patch，且下次 start 会走 'already' 分支但 fetch 已是原生 → 拦截失效
      await execInTab(tab.id, function () {
        const P = (window as any).__VK_PERM__;
        if (P) { P.stop(); if (typeof P._restore === 'function') P._restore(); }
        try { delete (window as any).__VK_PERM__; } catch (e) { /* */ }
      }, { world: 'MAIN' });
    }
    permActive = false;
    toastStore.show('拦截已停止', 'info');
  }

  function selectPerm(idx: number) {
    permSelected = idx;
    const cap = permCaptures[idx];
    if (cap) permEditor = JSON.stringify(cap.data, null, 2);
  }

  function applyEditorTransform(fn: (d: unknown) => unknown, msg: string) {
    try {
      const data = JSON.parse(permEditor);
      permEditor = JSON.stringify(fn(data), null, 2);
      toastStore.show(msg, 'success');
    } catch { toastStore.show('JSON 解析失败', 'error'); }
  }

  /** 应用编辑器中的修改：setOverride + patch Pinia/Vuex/localStorage */
  async function applyPermOverride() {
    let modified: unknown;
    try { modified = JSON.parse(permEditor); } catch { toastStore.show('JSON 格式错误', 'error'); return; }
    const tab = await getActiveTab();
    if (!tab?.id) return;
    const result = await execInTab<{ success: boolean; storagePatchCount: number }>(tab.id, function (overrideData: any) {
      const P = (window as any).__VK_PERM__;
      if (!P) return { success: false, storagePatchCount: 0 };
      P.setOverride(overrideData);
      const patchDeepState = (state: any, override: any): boolean => {
        if (!state || typeof state !== 'object' || Array.isArray(state)) return false;
        for (const key in state) {
          if (!/menu|permission|route|nav|sidebar/i.test(key)) continue;
          const val = state[key];
          if (Array.isArray(val)) { try { val.splice(0, val.length); override.forEach((item: any) => val.push(item)); } catch (e) { state[key] = override; } return true; }
          if (val && typeof val === 'object' && !Array.isArray(val)) if (patchDeepState(val, override)) return true;
        }
        return false;
      };
      const appEl = document.querySelector('#app,[data-v-app],[id^="app"],#root,#application,#main') as any;
      if (appEl && appEl.__vue_app__) {
        const pinia = appEl.__vue_app__.config.globalProperties.$pinia;
        if (pinia && pinia._s) pinia._s.forEach((store: any) => {
          const state = store.$state;
          for (const key in state) {
            if (!/menu|permission|route|nav|sidebar/i.test(key)) continue;
            const val = state[key];
            if (Array.isArray(val)) { if (store.$patch) { const patch: any = {}; patch[key] = overrideData; store.$patch(patch); } else { state[key] = overrideData; } }
            else if (val && typeof val === 'object') patchDeepState(val, overrideData);
          }
        });
      }
      const allEls = document.querySelectorAll('*');
      for (let i = 0; i < allEls.length; i++) { const el = allEls[i] as any; if (el.__vue__) { const vm = el.__vue__.$root || el.__vue__; if (vm.$store && vm.$store.state) patchDeepState(vm.$store.state, overrideData); break; } }
      let cnt = 0;
      const prefixes = ['menu', 'permission', 'routes', 'nav', 'sidebar', 'role', 'auth'];
      for (const storage of [localStorage, sessionStorage]) {
        try { for (let si = 0; si < storage.length; si++) { const sKey = storage.key(si); if (!sKey) continue; if (!prefixes.some((p) => sKey.toLowerCase().indexOf(p) !== -1)) continue; try { const parsed = JSON.parse(storage.getItem(sKey) || ''); if (Array.isArray(parsed)) { storage.setItem(sKey, JSON.stringify(overrideData)); cnt++; } else if (parsed && typeof parsed === 'object') { let patched = false; for (const sk in parsed) if (/menu|permission|route|nav|sidebar/i.test(sk) && Array.isArray(parsed[sk])) { parsed[sk] = overrideData; patched = true; } if (patched) { storage.setItem(sKey, JSON.stringify(parsed)); cnt++; } } } catch (e) { /* */ } } } catch (e) { /* */ }
      }
      return { success: true, storagePatchCount: cnt };
    }, { world: 'MAIN', args: [modified] });
    if (!result?.success) { toastStore.show('拦截器未注入，请先启动权限拦截', 'error'); return; }
    let msg = '已应用修改（拦截器 + Vue 存储';
    if (result.storagePatchCount > 0) msg += ` + ${result.storagePatchCount} 个本地缓存`;
    msg += '）→ 刷新或点击菜单验证';
    toastStore.show(msg, 'success');
  }

  // ===== 路由对比 + 自动遍历（vue-compare）=====
  let hiddenRoutes = $state<RoutePath[]>([]);
  let visibleRoutes = $state<RoutePath[]>([]);
  let traverseLog = $state<{ idx: number; path: string; ok: boolean }[]>([]);
  let traverseDelay = $state(2500);

  // §5.1：路由遍历接入 TaskController（可取消 signal + 进度上报 + dispose 统一）
  const traverseCtrl = createTaskController<{ routes: RoutePath[]; tabId: number }, void>({
    run: async (input, ctx) => {
      const { routes, tabId } = input;
      traverseLog = [];
      ctx.reportProgress({ total: routes.length, completed: 0, phase: '路由遍历' });
      for (let i = 0; i < routes.length; i++) {
        if (ctx.signal.aborted) break;
        const path = routes[i].path;
        const res = await execInTab<{ ok: boolean }>(tabId, function (p: string) {
          const appEl = document.querySelector('#app,[data-v-app],[id^="app"],#root,#application,#main') as any;
          let router: any = null;
          if (appEl && appEl.__vue_app__) router = appEl.__vue_app__.config.globalProperties.$router;
          else { const els = document.querySelectorAll('*'); for (let i = 0; i < els.length; i++) { const el = els[i] as any; if (el.__vue__) { const vm = el.__vue__.$root || el.__vue__; if (vm.$router) { router = vm.$router; break; } } } }
          if (router) { try { router.push(p); return { ok: true }; } catch (e) { return { ok: false }; } }
          return { ok: false };
        }, { world: 'MAIN', args: [path] });
        if (!ctx.isCurrent()) return; // 旧 run，丢弃回写
        traverseLog = [...traverseLog, { idx: i + 1, path, ok: !!res?.ok }];
        ctx.reportProgress({ completed: i + 1, phase: `遍历路由 (${i + 1}/${routes.length})` });
        if (i < routes.length - 1 && !ctx.signal.aborted) {
          try { await abortableDelay(traverseDelay, ctx.signal); }
          catch { break; } // 取消：退出循环，走 cancelled（非 failed）
        }
      }
    },
  }, { centerPanel: 'vue', centerLabel: 'Vue 路由遍历' });

  let traverseState = $state<TaskState>({ ...IDLE });
  $effect(() => traverseCtrl.state.subscribe((v: TaskState) => { traverseState = v; }));
  let traverseActive = $derived(traverseState.status === 'running' || traverseState.status === 'paused' || traverseState.status === 'validating');

  /** 从页面 Vue Router 提取全部路由（MAIN world） */
  async function getPageRoutes(): Promise<RoutePath[]> {
    const tab = await getActiveTab();
    if (!tab?.id) return [];
    return (await execInTab<RoutePath[]>(tab.id, function () {
      const routes: any[] = []; const seen: any = {};
      const extract = (rts: any[], prefix: string) => rts.forEach((r: any) => {
        const cp = r.path || '/'; let path: string;
        if (cp.charAt(0) === '/') path = cp;
        else if (prefix === '' || prefix === '/') path = '/' + cp;
        else path = prefix + '/' + cp;
        if (r.path && r.path !== '*' && !seen[path]) { seen[path] = true; routes.push({ path, name: r.name || '' }); }
        if (r.children) extract(r.children, path === '/' ? '/' : path);
      });
      const getAndExtract = (router: any) => {
        if (!router) return;
        if (typeof router.getRoutes === 'function') router.getRoutes().forEach((r: any) => { if (r.path && r.path !== '*' && !seen[r.path]) { seen[r.path] = true; routes.push({ path: r.path, name: r.name || '' }); } });
        else if (router.options && router.options.routes) extract(router.options.routes, '');
      };
      const appEl = document.querySelector('#app,[data-v-app],[id^="app"],#root,#application,#main') as any;
      if (appEl && appEl.__vue_app__) getAndExtract(appEl.__vue_app__.config.globalProperties.$router);
      else { const els = document.querySelectorAll('*'); for (let i = 0; i < els.length; i++) { const el = els[i] as any; if (el.__vue__) { const vm = el.__vue__.$root || el.__vue__; getAndExtract(vm.$router); if (routes.length > 0) break; } } }
      return routes;
    }, { world: 'MAIN' })) || [];
  }

  /** 对比页面路由 vs 已捕获菜单数据，找出隐藏路由 */
  async function compareRoutesAndMenu() {
    const routeList = await getPageRoutes();
    if (routeList.length === 0) { toastStore.show('未检测到路由，请先「检测 Vue」', 'warning'); return; }
    // 从权限捕获数据提取菜单路径
    const menuPaths = new Set<string>();
    for (const cap of permCaptures) extractMenuPaths(cap.data, menuPaths);
    hiddenRoutes = routeList.filter(r => !isPathInMenu(r.path, menuPaths));
    visibleRoutes = routeList.filter(r => isPathInMenu(r.path, menuPaths));
    if (permCaptures.length === 0) toastStore.show('未捕获菜单数据，建议先启动权限拦截并刷新页面', 'info');
    else toastStore.show(`路由 ${routeList.length} 条，隐藏 ${hiddenRoutes.length} 条`, hiddenRoutes.length ? 'warning' : 'success');
    await saveFindings();
  }

  /** 把隐藏路由注入当前编辑器 JSON */
  function injectHiddenToEditor() {
    if (hiddenRoutes.length === 0) { toastStore.show('无隐藏路由，请先「路由对比」', 'warning'); return; }
    if (!permEditor) { toastStore.show('请先选择一条捕获数据', 'warning'); return; }
    const { text, injected } = injectRoutesIntoMenu(permEditor, hiddenRoutes);
    permEditor = text;
    toastStore.show(`已注入 ${injected} 条隐藏路由到菜单数据`, 'success');
  }

  /** 自动遍历隐藏路由（router.push 逐条，TaskController 接管可取消/进度） */
  async function startTraverse(hiddenOnly: boolean) {
    const routes = hiddenOnly ? hiddenRoutes : await getPageRoutes();
    if (routes.length === 0) { toastStore.show(hiddenOnly ? '无隐藏路由，请先「路由对比」' : '未检测到路由', 'warning'); return; }
    const tab = await getActiveTab();
    if (!tab?.id) { toastStore.show('无法获取标签页', 'error'); return; }
    try {
      const r = await traverseCtrl.start({ routes, tabId: tab.id });
      if (r.status === 'succeeded') toastStore.show(`遍历完成，共 ${routes.length} 条`, 'success');
    } catch { /* failed：actionable error 已由 task-center/UI 反馈 */ }
  }

  function stopTraverse() { traverseCtrl.cancel(); }

  // §2.2：组件卸载时清残留定时器并恢复页面 fetch/XHR（不写组件状态，避免卸载后更新警告）
  onDestroy(() => {
    if (permRefreshTimer) { clearInterval(permRefreshTimer); permRefreshTimer = null; }
    traverseCtrl.dispose();
    if (!permActive) return;
    getActiveTab().then((tab) => {
      if (!tab?.id) return;
      execInTab(tab.id, function () {
        const P = (window as any).__VK_PERM__;
        if (P) { P.stop(); if (typeof P._restore === 'function') P._restore(); }
        try { delete (window as any).__VK_PERM__; } catch (e) { /* */ }
      }, { world: 'MAIN' }).catch(() => { /* 标签已关或无权限 */ });
    }).catch(() => { /* */ });
  });

  // ===== JS 搜索（vue-jssearch）=====
  let jsKeyword = $state('');
  let jsMatches = $state<{ source: string; line: number; context: string }[]>([]);
  let jsFoundPaths = $state<string[]>([]);
  let jsSearching = $state(false);

  async function searchJs(keyword?: string) {
    const kw = (keyword ?? jsKeyword).trim();
    if (kw.length < 2) { toastStore.show('请输入至少 2 个字符', 'warning'); return; }
    jsSearching = true; jsKeyword = kw;
    const tab = await getActiveTab();
    if (!tab?.id) { jsSearching = false; return; }
    // 内联脚本 + 外部 JS URL 列表
    const inline = await execInTab<{ matches: any[]; extUrls: string[] }>(tab.id, function (k: string) {
      const matches: any[] = []; const seen: any = {};
      const scripts = document.querySelectorAll('script:not([src])');
      for (let i = 0; i < scripts.length; i++) {
        const text = scripts[i].textContent || '';
        if (text.indexOf(k) === -1) continue;
        const lines = text.split('\n');
        for (let j = 0; j < lines.length && matches.length < 50; j++) {
          let idx = lines[j].indexOf(k);
          while (idx !== -1 && matches.length < 50) {
            const start = Math.max(0, idx - 40), end = Math.min(lines[j].length, idx + k.length + 60);
            const context = lines[j].substring(start, end).replace(/^\S*\s*/, '');
            const key = i + ':' + idx;
            if (!seen[key]) { seen[key] = true; matches.push({ source: '(inline #' + (i + 1) + ')', line: j + 1, context }); }
            idx = lines[j].indexOf(k, idx + 1);
          }
        }
      }
      const extUrls: string[] = [];
      document.querySelectorAll('script[src]').forEach((s: any) => extUrls.push(s.src));
      return { matches, extUrls };
    }, { world: 'ISOLATED', args: [kw] });
    const matchList = inline?.matches || [];
    const extUrls = inline?.extUrls || [];
    // 并发抓取外部 JS 搜索
    const contents = await Promise.allSettled(extUrls.slice(0, 20).map(u => sendMessage({ type: 'FETCH_URL', url: u, tailOnly: false })));
    for (let b = 0; b < contents.length && matchList.length < 50; b++) {
      const settled = contents[b];
      if (settled.status !== 'fulfilled') continue;
      const res = settled.value as FetchResult<string>;
      if (!res?.success) continue;
      const text = res.data; if (!text || text.indexOf(kw) === -1) continue;
      let shortUrl = extUrls[b]; if (shortUrl.length > 60) shortUrl = '...' + shortUrl.substring(shortUrl.length - 57);
      const lines = text.split('\n');
      for (let j = 0; j < lines.length && matchList.length < 50; j++) {
        let idx = lines[j].indexOf(kw);
        while (idx !== -1 && matchList.length < 50) {
          const start = Math.max(0, idx - 40), end = Math.min(lines[j].length, idx + kw.length + 60);
          matchList.push({ source: shortUrl, line: j + 1, context: lines[j].substring(start, end).replace(/^\S*\s*/, '') });
          idx = lines[j].indexOf(kw, idx + 1);
        }
      }
    }
    jsMatches = matchList;
    jsFoundPaths = extractPathsFromJsContexts(matchList.map(m => m.context));
    jsSearching = false;
    toastStore.show(`找到 ${matchList.length} 处匹配，提取 ${jsFoundPaths.length} 条路径`, matchList.length ? 'success' : 'info');
  }

  /** 把 JS 提取的路径注入当前编辑器 */
  function injectJsPathsToEditor() {
    if (jsFoundPaths.length === 0) { toastStore.show('未找到 JS 路径，请先搜索', 'warning'); return; }
    if (!permEditor) { toastStore.show('请先选择一条捕获数据', 'warning'); return; }
    const routes: RoutePath[] = jsFoundPaths.map(p => ({ path: p, name: p }));
    const { text, injected } = injectRoutesIntoMenu(permEditor, routes);
    permEditor = text;
    toastStore.show(`已注入 ${injected} 条 JS 路径到菜单数据`, 'success');
  }

  /** zero-open 自动搜索：menu → routes → 从 URL 提取关键词 */
  async function autoSearchZeroOpen() {
    jsSearching = true; let allContexts: string[] = [];
    await searchJs('menu'); allContexts = allContexts.concat(jsMatches.map(m => m.context));
    await searchJs('routes'); allContexts = allContexts.concat(jsMatches.map(m => m.context));
    const urlKws = extractKeywordsFromCapturedUrls(permCaptures);
    for (const kw of urlKws) {
      if (allContexts.length >= 50) break;
      if (/^(menu|routes|route|permission)$/i.test(kw)) continue;
      await searchJs(kw); allContexts = allContexts.concat(jsMatches.map(m => m.context));
    }
    jsMatches = allContexts.slice(0, 50).map((c, i) => ({ source: '(auto)', line: i + 1, context: c }));
    jsFoundPaths = extractPathsFromJsContexts(allContexts);
    jsSearching = false;
    toastStore.show(jsFoundPaths.length ? `提取 ${jsFoundPaths.length} 条路径，可注入菜单` : '未提取到路径', jsFoundPaths.length ? 'success' : 'warning');
  }

  // 自动填充当前 URL
  $effect(() => {
    getActiveTabUrl().then(u => { if (u) currentUrl = u; });
  });

  // ===== 检测 Vue =====
  async function detectVue() {
    detecting = true;
    detectResult = null;
    storeResult = null;

    const data = await sendToContent({ type: 'VK_VUE_DETECT' });

    if (!data || !(data as VueDetectResult).detected) {
      detectResult = null;
      detecting = false;
      toastStore.show(
        data ? '未检测到 Vue 框架' : '无法连接内容脚本（请刷新页面后重试）',
        data ? 'warning' : 'error',
      );
      return;
    }

    detectResult = data as VueDetectResult;
    detecting = false;
    toastStore.show(`检测到 Vue ${(data as VueDetectResult).version}`, 'success');
    await saveFindings();
  }

  // ===== 探索 Store =====
  async function exploreStore() {
    exploring = true;
    storeResult = null;

    const data = await sendToContent({ type: 'VK_VUE_STORE_EXPLORE' });

    if (!data || !(data as StoreExploreResult).store) {
      storeResult = null;
      exploring = false;
      toastStore.show(
        data ? '未检测到 Vuex/Pinia Store' : '无法连接内容脚本',
        data ? 'warning' : 'error',
      );
      return;
    }

    storeResult = data as StoreExploreResult;
    exploring = false;
    const frameworks = (data as StoreExploreResult).store.frameworks || [];
    const storeCount = Object.keys((data as StoreExploreResult).store.stores || {}).length;
    toastStore.show(`${frameworks.join(', ')} | ${storeCount} 个 Store`, 'success');
  }

  // ===== Findings 导出 =====
  /** 基于当前扫描结果生成安全发现（对齐 v5 vk-vue getFindings） */
  function getFindings(): ScanFinding[] {
    const findings: ScanFinding[] = [];
    if (!detectResult || !detectResult.detected) return findings;
    if (detectResult.version) {
      findings.push({ severity: 'info', title: 'Vue 版本泄露', detail: '检测到 Vue ' + detectResult.version, url: currentUrl });
    }
    if (detectResult.store) {
      findings.push({ severity: 'low', title: 'Vuex/Pinia Store 已启用', detail: '前端状态管理暴露，可能泄露业务数据结构', url: currentUrl });
    }
    if (hiddenRoutes.length > 0) {
      findings.push({ severity: 'high', title: '隐藏路由发现', detail: '路由中存在但菜单未显示的 ' + hiddenRoutes.length + ' 个页面', url: currentUrl });
    }
    // 权限拦截发现
    let zeroCount = 0;
    let roleCount = 0;
    for (const cap of permCaptures) {
      const cls = classifyPermType(cap.data);
      if (cls.type === 'special-zero') zeroCount++;
      if (cls.type === 'role-active') roleCount++;
    }
    if (zeroCount > 0) {
      findings.push({ severity: 'critical', title: '零权限 API 可达', detail: '发现 ' + zeroCount + ' 个返回空权限的接口，可能存在越权', url: currentUrl });
    }
    if (roleCount > 0) {
      findings.push({ severity: 'medium', title: '角色控制字段检测', detail: '发现 ' + roleCount + ' 个接口返回角色控制字段（isAdmin/role 等）', url: currentUrl });
    }
    return findings;
  }

  /** 将 findings 保存到扫描历史 */
  async function saveFindings() {
    const findings = getFindings();
    if (findings.length > 0 && currentUrl) {
      await scanHistoryStore.addScan({ url: currentUrl, module: 'vue', findings });
    }
  }

  // ===== 路由过滤 =====
  let filteredRoutes = $derived<VueRouteNode[]>(
    !detectResult?.routes || !routeFilter
      ? detectResult?.routes || []
      : filterNodes(detectResult.routes, routeFilter.toLowerCase()),
  );

  function filterNodes(routes: VueRouteNode[], keyword: string): VueRouteNode[] {
    return routes.filter(r => {
      const pathMatch = r.path.toLowerCase().includes(keyword);
      const nameMatch = r.name?.toLowerCase().includes(keyword) || false;
      if (pathMatch || nameMatch) return true;
      if (r.children?.length) return filterNodes(r.children, keyword).length > 0;
      return false;
    }).map(r => ({
      ...r,
      children: r.children?.length ? filterNodes(r.children, keyword) : [],
    }));
  }

  // ===== Store 展开/收起 =====
  function toggleStore(storeId: string) {
    if (expandedStores.has(storeId)) {
      expandedStores.delete(storeId);
    } else {
      expandedStores.add(storeId);
    }
    expandedStores = new Set(expandedStores); // trigger reactivity
  }

  // ===== 复制/导出 =====
  function copyDetectJson() {
    if (!detectResult) return;
    navigator.clipboard.writeText(JSON.stringify(detectResult, null, 2)).then(() => {
      toastStore.show('已复制检测结果', 'success');
    });
  }

  function copyStoreJson() {
    if (!storeResult) return;
    navigator.clipboard.writeText(JSON.stringify(storeResult, null, 2)).then(() => {
      toastStore.show('已复制 Store 数据', 'success');
    });
  }

  function exportReport() {
    if (!detectResult) return;
    const report = {
      timestamp: new Date().toISOString(),
      url: currentUrl,
      detect: detectResult,
      store: storeResult ? storeResult.store : undefined,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    downloadBlob(blob, `vue-analysis-${Date.now()}.json`);
    toastStore.show('报告已导出', 'success');
  }

  // ===== 辅助 =====
  function severityColor(sensitive: boolean): string {
    return sensitive ? 'text-red-500 dark:text-red-400' : '';
  }
</script>

<div class="space-y-3">
  <!-- 当前 URL -->
  <div class="card p-2 text-xs text-gray-500">
    <b>目标:</b> <span class="font-mono break-all">{currentUrl || '未获取'}</span>
  </div>

  <!-- 检测区域 -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div class="text-sm font-medium">Vue 检测</div>
      <button
        class="btn btn-sm btn-primary"
        disabled={detecting}
        onclick={detectVue}
      >
        {detecting ? '检测中...' : '检测 Vue'}
      </button>
    </div>

    {#if detectResult}
      <!-- 基本信息 -->
      <div class="space-y-1 text-xs">
        <div class="flex items-center gap-2">
          <span class="text-gray-500 w-20 shrink-0">版本</span>
          <span class="badge badge-ok">Vue {detectResult.version}</span>
        </div>
        <div class="flex items-center gap-2">
          <span class="text-gray-500 w-20 shrink-0">Router</span>
          {#if detectResult.router}
            <span class="badge badge-ok">
              已检测 ({detectResult.routerInfo?.mode || '?'} 模式)
            </span>
          {:else}
            <span class="text-gray-500">未检测到</span>
          {/if}
        </div>
        {#if detectResult.routerInfo}
          <div class="flex items-center gap-2">
            <span class="text-gray-500 w-20 shrink-0">Base Path</span>
            <span class="font-mono">{detectResult.routerInfo.base || '/'}</span>
          </div>
        {/if}
        <div class="flex items-center gap-2">
          <span class="text-gray-500 w-20 shrink-0">Store</span>
          {#if detectResult.store}
            <span class="badge badge-warn">已检测</span>
          {:else}
            <span class="text-gray-500">未检测到</span>
          {/if}
        </div>
      </div>

      <!-- 路由统计 -->
      {#if detectResult.router && detectResult.routes.length > 0}
        {@const stats = countRouteStats(detectResult.routes)}
        {@const exposure = scorePermissionExposure(stats)}
        <div class="space-y-1 text-xs mt-2">
          <div class="flex items-center gap-2 flex-wrap">
            <span>总计 {stats.total} 条路由</span>
            {#if stats.authCount > 0}
              <span class="badge badge-auth">需认证 {stats.authCount}</span>
            {/if}
            {#if stats.sensitiveCount > 0}
              <span class="badge badge-sensitive">敏感路径 {stats.sensitiveCount}</span>
            {/if}
            {#if stats.beforeEnterCount > 0}
              <span class="badge badge-enter">beforeEnter {stats.beforeEnterCount}</span>
            {/if}
          </div>
          {#if exposure > 0}
            <div class="text-yellow-600 dark:text-yellow-500">
              权限暴露评分: {exposure}/100
            </div>
          {/if}
        </div>

        <!-- 全局守卫 -->
        {#if detectResult.guards && Object.keys(detectResult.guards).length > 0}
          <div class="space-y-0.5 text-xs mt-1">
            <span class="text-gray-500">全局守卫:</span>
            {#each Object.entries(detectResult.guards) as [guardName, count]}
              <span class="badge">{guardName}({count})</span>
            {/each}
          </div>
        {/if}

        <!-- 攻击层操作 -->
        <div class="flex items-center gap-1.5 mt-2 flex-wrap">
          {#if !bypassed}
            <button class="btn btn-xs btn-danger" onclick={bypassGuards} title="清空所有导航守卫 + 禁用路由 auth meta（备份可恢复）">
              ⚔️ 绕过守卫
            </button>
          {:else}
            <button class="btn btn-xs btn-success" onclick={restoreRuntime}>↩️ 恢复运行时</button>
          {/if}
          {#if !authDisabled}
            <button class="btn btn-xs" onclick={disableAuth} title="仅禁用路由 auth meta，不清空导航守卫（备份可恢复）">
              🔓 禁用鉴权
            </button>
          {/if}
          {#if bypassed}
            <span class="text-xs text-amber-600 dark:text-amber-400">守卫已绕过，现在可跳转受保护路由</span>
          {/if}
          {#if authDisabled && !bypassed}
            <span class="text-xs text-blue-600 dark:text-blue-400">auth meta 已禁用</span>
          {/if}
        </div>

        <!-- 一键跳转 -->
        {#if detectResult.routes.length > 0}
          <div class="mt-2 space-y-1">
            <div class="flex items-center gap-1">
              <input
                class="input text-xs flex-1"
                placeholder="输入路径或从下方路由列表点击..."
                bind:value={jumpTarget}
                onkeydown={(e) => e.key === 'Enter' && jumpToRoute(jumpTarget)}
              />
              <button class="btn btn-xs btn-primary" onclick={() => jumpToRoute(jumpTarget)} disabled={!jumpTarget}>
                一键跳转
              </button>
            </div>
            <div class="text-xs text-gray-500">绕过守卫 + 导航 + 3 秒后自动恢复（不影响现有守卫状态）</div>
          </div>
        {/if}

        <!-- 路由过滤 + 树 -->
        <div class="mt-2">
          <div class="flex items-center gap-1 mb-1">
            <input
              class="input text-xs flex-1"
              placeholder="过滤路由..."
              bind:value={routeFilter}
            />
            <span class="text-xs text-gray-500 whitespace-nowrap">
              {detectResult.routes.length} 条
            </span>
          </div>
          <div class="space-y-0.5 max-h-80 overflow-y-auto">
            {#each filteredRoutes as route (route.path)}
              {@render routeNode(route, 0)}
            {/each}
          </div>
        </div>

        <!-- 操作按钮 -->
        <div class="flex gap-1 mt-2">
          <button class="btn btn-sm flex-1" onclick={copyDetectJson}>复制 JSON</button>
          <button class="btn btn-sm flex-1" onclick={exportReport}>导出报告</button>
        </div>
      {/if}
    {/if}
  </div>

  <!-- 权限拦截层（vue-perm）-->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div class="text-sm font-medium">权限拦截 <span class="text-xs text-gray-500 font-normal">（拦截菜单/角色 API → 分类 → 变换 → 覆盖）</span></div>
      {#if !permActive}
        <button class="btn btn-sm btn-danger" onclick={startPermIntercept}>🪝 启动拦截</button>
      {:else}
        <button class="btn btn-sm btn-ghost" onclick={stopPermIntercept}>⏹ 停止</button>
      {/if}
    </div>

    {#if permCaptures.length > 0}
      <div class="text-xs text-gray-500">捕获 {permCaptures.length} 条（菜单/角色/权限 API + Store 读取）</div>
      <div class="space-y-1 max-h-40 overflow-y-auto">
        {#each permCaptures as cap, idx}
          {@const cls = classifyPermType(cap.data)}
          <button
            class="w-full text-left flex items-center gap-2 px-2 py-1 rounded text-xs {permSelected === idx ? 'bg-primary/10 ring-1 ring-primary/30' : 'hover:bg-gray-100 dark:hover:bg-gray-800'}"
            onclick={() => selectPerm(idx)}
          >
            <span class="badge text-xs shrink-0 {cap.type === 'menu' ? 'bg-blue-50 text-blue-700 ring-1 ring-inset ring-blue-200 dark:bg-blue-900/30 dark:text-blue-300 dark:ring-blue-800/60' : cap.type === 'role' ? 'bg-amber-50 text-amber-700 ring-1 ring-inset ring-amber-200 dark:bg-amber-900/30 dark:text-amber-300 dark:ring-amber-800/60' : 'bg-gray-500 text-white'}">{cap.type}</span>
            <span class="font-mono truncate flex-1 {cls.cssClass}" title={cap.url}>{cap.url}</span>
            <span class="text-gray-500 shrink-0">{(cap.size / 1024).toFixed(1)}KB</span>
          </button>
        {/each}
      </div>
    {:else if permActive}
      <div class="text-xs text-gray-500">拦截中... 请操作页面触发菜单 API，或刷新页面</div>
    {:else}
      <div class="text-xs text-gray-500">启动后自动 hook XHR/fetch，捕获 /getRouters、/getMenu、/getUserInfo 等响应</div>
    {/if}

    {#if permSelected >= 0 && permCaptures[permSelected]}
      {@const sel = permCaptures[permSelected]}
      {@const cls = classifyPermType(sel.data)}
      <!-- 分类 + 建议 -->
      <div class="text-xs px-2 py-1 rounded bg-gray-50 dark:bg-gray-900 {cls.cssClass}">
        🏷️ {cls.label}
      </div>

      <!-- 动态建议：基于分类类型高亮推荐操作（对齐 v5 showPermSuggestions） -->
      {#if cls.type === 'full-open'}
        <div class="text-xs text-blue-500">💡 建议：点击「全部显示」展开所有被隐藏的菜单</div>
      {:else if cls.type === 'semi-open'}
        <div class="text-xs text-amber-500">💡 建议：菜单只返回了部分，使用「路由对比」发现缺失的隐藏菜单</div>
      {:else if cls.type === 'zero-open'}
        <div class="text-xs text-red-500">💡 建议：菜单返回为空，点击「自动」搜索 JS 源码中的路由定义</div>
      {:else if cls.type === 'special-zero'}
        <div class="text-xs text-red-500">💡 建议：检测到角色控制字段为 0/false，点击「提权至管理员」修改</div>
      {:else if cls.type === 'menuid-limit'}
        <div class="text-xs text-amber-500">💡 建议：菜单受 menuIds 限制，点击「展开 menuIds」扩大范围</div>
      {/if}

      <!-- 变换按钮 -->
      <div class="flex gap-1 flex-wrap">
        <button class="btn btn-xs {cls.type === 'full-open' ? 'btn-primary' : ''}" onclick={() => applyEditorTransform(transformShowAll, '已将所有 isshow/display 改为显示')}>全部显示</button>
        <button class="btn btn-xs {cls.type === 'special-zero' ? 'btn-danger ring-2 ring-red-400' : 'btn-danger'}" onclick={() => applyEditorTransform(transformAdmin, '已提权：角色/管理员字段已修改')}>提权至管理员</button>
        <button class="btn btn-xs {cls.type === 'menuid-limit' ? 'btn-primary' : ''}" onclick={() => applyEditorTransform(expandMenuIds, '已展开菜单ID范围')}>展开 menuIds</button>
      </div>

      <!-- JSON 编辑器 -->
      <textarea class="input font-mono text-xs" rows="8" bind:value={permEditor}></textarea>

      <div class="flex gap-1">
        <button class="btn btn-sm btn-primary flex-1" onclick={applyPermOverride}>⚡ 应用覆盖（拦截器 + Store + 缓存）</button>
      </div>
      <div class="text-xs text-gray-500">编辑 JSON 后点「应用覆盖」，再刷新页面或点击菜单验证是否生效</div>
    {/if}
  </div>

  <!-- 路由对比 + 自动遍历（vue-compare）-->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div class="text-sm font-medium">路由对比 <span class="text-xs text-gray-500 font-normal">（发现菜单未显示的隐藏路由）</span></div>
      <div class="flex gap-1 items-center">
        <button class="btn btn-xs btn-primary" onclick={compareRoutesAndMenu}>对比</button>
        {#if !traverseActive}
          <button class="btn btn-xs" onclick={() => startTraverse(true)} title="逐条 router.push 隐藏路由">遍历隐藏</button>
        {:else}
          <button class="btn btn-xs btn-danger" onclick={stopTraverse}>停止</button>
        {/if}
        <label class="text-xs text-gray-500 flex items-center gap-1" title="每条路由间隔毫秒数">间隔
          <input type="number" class="input text-xs w-16" min="500" max="10000" step="500" bind:value={traverseDelay} />
          ms
        </label>
      </div>
    </div>
    {#if hiddenRoutes.length > 0 || visibleRoutes.length > 0}
      <div class="text-xs text-gray-500">路由 {hiddenRoutes.length + visibleRoutes.length} 条 · 隐藏 <span class="text-red-500">{hiddenRoutes.length}</span> · 已显示 {visibleRoutes.length}</div>
      {#if hiddenRoutes.length > 0}
        <button class="btn btn-xs btn-danger w-full" onclick={injectHiddenToEditor}>注入 {hiddenRoutes.length} 条隐藏路由到权限编辑器</button>
        <div class="space-y-0.5 max-h-32 overflow-y-auto">
          {#each hiddenRoutes as r}
            <div class="text-xs"><span class="text-red-500">[隐]</span> <span class="font-mono">{r.path}</span> {#if r.name}<span class="text-gray-500">{r.name}</span>{/if}</div>
          {/each}
        </div>
      {/if}
      {#if traverseLog.length > 0}
        <div class="text-xs text-gray-500 mt-1">遍历日志</div>
        <div class="space-y-0.5 max-h-32 overflow-y-auto">
          {#each traverseLog as log}
            <div class="text-xs font-mono">{log.idx}. {log.ok ? '✓' : '✗'} {log.path}</div>
          {/each}
        </div>
      {/if}
    {:else}
      <div class="text-xs text-gray-500">点击「对比」找出路由存在但菜单未显示的隐藏路由（需先检测 Vue + 启动权限拦截捕获菜单）</div>
    {/if}
  </div>

  <!-- JS 搜索（vue-jssearch）-->
  <div class="card p-3 space-y-2">
    <div class="text-sm font-medium">JS 源码搜索 <span class="text-xs text-gray-500 font-normal">（搜索菜单/路由定义，提取路径）</span></div>
    <div class="flex gap-1">
      <input class="input text-xs flex-1" placeholder="关键词（如 menu / routes / 业务名）" bind:value={jsKeyword} onkeydown={(e) => e.key === 'Enter' && searchJs()} />
      <button class="btn btn-xs btn-primary" onclick={() => searchJs()} disabled={jsSearching}>{jsSearching ? '...' : '搜索'}</button>
      <button class="btn btn-xs" onclick={autoSearchZeroOpen} disabled={jsSearching} title="自动搜索 menu→routes→URL关键词，用于 zero-open">自动</button>
    </div>
    {#if jsMatches.length > 0}
      <div class="text-xs text-gray-500">{jsMatches.length} 处匹配 · 提取 {jsFoundPaths.length} 条路径</div>
      {#if jsFoundPaths.length > 0}
        <button class="btn btn-xs btn-danger w-full" onclick={injectJsPathsToEditor}>注入 {jsFoundPaths.length} 条 JS 路径到权限编辑器</button>
      {/if}
      <div class="space-y-1 max-h-40 overflow-y-auto">
        {#each jsMatches.slice(0, 30) as m}
          <div class="text-xs">
            <div class="text-gray-500">{m.source} : line {m.line}</div>
            <div class="font-mono text-gray-600 dark:text-gray-300 break-all bg-gray-50 dark:bg-gray-900 px-1.5 py-0.5 rounded">{m.context}</div>
          </div>
        {/each}
      </div>
    {/if}
  </div>

  <!-- Store 探索 -->
  {#if detectResult?.store}
    <div class="card p-3 space-y-2">
      <div class="flex items-center justify-between">
        <div class="text-sm font-medium">Store 探索</div>
        <button
          class="btn btn-sm btn-primary"
          disabled={exploring}
          onclick={exploreStore}
        >
          {exploring ? '探索中...' : '探索 Store'}
        </button>
      </div>

      {#if storeResult}
        <!-- Store 框架标签 -->
        <div class="flex gap-1 flex-wrap text-xs">
          {#each (storeResult.store.frameworks || []) as fw}
            <span class="badge badge-ok">{fw}</span>
          {/each}
          {#if storeResult.store.errors?.length > 0}
            <span class="badge badge-sensitive">
              错误: {storeResult.store.errors.join('; ')}
            </span>
          {/if}
        </div>

        <!-- Store 列表 -->
        {#each Object.entries(storeResult.store.stores || {}) as [storeId, storeData]}
          {@const isExpanded = expandedStores.has(storeId)}
          <div class="card p-2 space-y-1 text-xs">
            <div
              class="flex items-center gap-2 cursor-pointer"
              role="button"
              tabindex="0"
              onclick={() => toggleStore(storeId)}
              onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleStore(storeId); } }}
            >
              <span class="text-gray-500">{isExpanded ? '▼' : '▶'}</span>
              <span class="font-semibold">{storeId}</span>
              <span class="badge">{storeData.type || 'unknown'}</span>
            </div>

            {#if isExpanded}
              <!-- Vuex extra info -->
              {#if storeData.type === 'vuex' && 'getters' in storeData}
                {@const vuex = storeData as any}
                {#if vuex.getters?.length > 0}
                  <div class="flex gap-1 flex-wrap">
                    {#each vuex.getters as g}
                      <span class="badge text-blue-600 dark:text-blue-400">{g}</span>
                    {/each}
                  </div>
                {/if}
                {#if vuex.mutations?.length > 0}
                  <div class="flex gap-1 flex-wrap">
                    {#each vuex.mutations as m}
                      <span class="badge text-yellow-600 dark:text-yellow-500">{m}</span>
                    {/each}
                  </div>
                {/if}
                {#if vuex.actions?.length > 0}
                  <div class="flex gap-1 flex-wrap">
                    {#each vuex.actions as a}
                      <span class="badge text-purple-600 dark:text-purple-400">{a}</span>
                    {/each}
                  </div>
                {/if}
              {/if}

              <!-- Store State 树 -->
              {#if storeData.state && typeof storeData.state === 'object'}
                {@const rows = flattenStoreTree(storeData.state).filter(r =>
                  !storeFilter || r.path.toLowerCase().includes(storeFilter.toLowerCase()) || r.key.toLowerCase().includes(storeFilter.toLowerCase())
                )}
                <input
                  class="input text-xs w-full"
                  placeholder="过滤 State..."
                  bind:value={storeFilter}
                />
                <div class="max-h-60 overflow-y-auto">
                  {#each rows as row}
                    <div
                      class="flex items-baseline gap-1 py-0.5 border-b border-gray-100 dark:border-gray-800"
                      style="padding-left: {row.depth * 16}px"
                    >
                      <span class="font-mono text-gray-600 dark:text-gray-500 w-32 shrink-0 truncate">{row.key}</span>
                      <span class="text-gray-500 w-12 shrink-0">{row.type}</span>
                      <span class="font-mono break-all flex-1 {row.sensitive ? 'text-red-500 dark:text-red-400' : 'text-gray-700 dark:text-gray-300'}">{row.valuePreview}</span>
                      {#if row.sensitive}
                        <span class="text-red-500 dark:text-red-400 text-[10px] shrink-0">SENSITIVE</span>
                      {/if}
                    </div>
                  {/each}
                </div>
              {/if}
            {/if}
          </div>
        {/each}

        <!-- API 端点 -->
        {#if storeResult.actions?.apiEndpoints?.length > 0}
          <div class="space-y-1 text-xs">
            <div class="text-xs font-medium">API 端点 ({storeResult.actions.apiEndpoints.length})</div>
            <div class="space-y-0.5">
              {#each storeResult.actions.apiEndpoints as ep}
                <div class="flex items-center gap-1">
                  <code class="font-mono text-xs break-all flex-1">{ep}</code>
                  <button
                    class="btn btn-sm text-[10px] shrink-0"
                    onclick={() => {
                      navigator.clipboard.writeText(ep);
                      toastStore.show('已复制: ' + ep, 'success');
                    }}
                  >
                    复制
                  </button>
                </div>
              {/each}
            </div>
          </div>
        {/if}

        <!-- 自定义指令 -->
        {#if storeResult.directives?.length > 0}
          <div class="space-y-1 text-xs">
            <div class="text-xs font-medium">自定义指令 ({storeResult.directives.length})</div>
            {#each storeResult.directives as dir}
              <div class="flex items-center gap-2">
                <span class="font-mono">{dir.name}</span>
                <span class="text-gray-500">{dir.count} 次</span>
                {#if dir.examples?.length > 0}
                  <span class="text-gray-500 truncate">{dir.examples[0]}</span>
                {/if}
              </div>
            {/each}
          </div>
        {/if}

        <!-- Store 操作 -->
        <div class="flex gap-1">
          <button class="btn btn-sm flex-1" onclick={copyStoreJson}>复制 Store JSON</button>
        </div>
      {/if}
    </div>
  {/if}
</div>

<!-- 递归渲染路由节点 -->
{#snippet routeNode(route: VueRouteNode, depth: number)}
  <div
    class="flex items-center gap-1 flex-wrap text-xs py-0.5 border-b border-gray-100 dark:border-gray-800"
    style="padding-left: {depth * 16}px"
  >
    <span class="font-mono {severityColor(route.sensitive)}">{route.path}</span>
    {#if route.name}
      <span class="text-gray-500">{route.name}</span>
    {/if}
    {#if route.hasAuth}
      <span class="badge badge-auth">auth</span>
    {/if}
    {#if route.sensitive}
      <span class="badge badge-sensitive">sensitive</span>
    {/if}
    {#if route.hasBeforeEnter}
      <span class="badge badge-enter">beforeEnter</span>
    {/if}
    {#if route.childCount > 0}
      <span class="badge">{route.childCount} sub</span>
    {/if}
    {#if route.path && route.path !== '/'}
      <button
        class="ml-auto text-[10px] text-blue-500 hover:text-blue-700 dark:text-blue-400 shrink-0"
        title="普通跳转（建议先绕过守卫）"
        onclick={() => navigateRoute(route.path)}
      >跳转</button>
      <button
        class="text-[10px] text-orange-500 hover:text-orange-700 dark:text-orange-400 shrink-0"
        title="一键跳转（绕过+导航+自动恢复）"
        onclick={() => jumpToRoute(route.path)}
      >⚡</button>
    {/if}
  </div>
  {#if route.children?.length > 0}
    {#each route.children as child (child.path)}
      {@render routeNode(child, depth + 1)}
    {/each}
  {/if}
{/snippet}
