<script lang="ts">
  // RuoYi 路由分析面板
  // 流程：注册 Hook → 监听 VK_RUOYI_HOOK_EVENT → 实时显示捕获的路由/请求
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl, getActiveTab, execInTab } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import { downloadBlob } from '@/lib/actions/download';
  import { scanSettingsStore } from '@/stores/settings';
  import { getAppVersion } from '@/lib/core/app-version';
  import type { ProbeResult, FetchResult } from '@/lib/types/messaging';
  import { runConcurrent } from '@/lib/core/concurrency';
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import { copyText } from '@/lib/actions/clipboard';
  import { toCsv } from '@/lib/actions/serializers';
  import {
    type HookEvent,
    type CapturedRequest,
    type ClassifiedRoute,
    type RuoYiCveEntry,
    matchCvesByVersion,
    getAllCves,
    classifyRoute,
    getSensitiveRoutes,
    aggregateHookEvents,
    classifyRequest,
    classifyStatus,
    statusColor,
    cveSeverityLabel,
    cveSeverityColor,
    routeCategoryLabel,
    extractPathsFromRouterData,
  } from '@/lib/analyzers/ruoyi-analyzer';
  import { RUOYI_KNOWN_ROUTES, CLOUD_KNOWN_ROUTES } from '@/lib/data/ruoyi-mar-dict';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';

  // —— 状态 ——
  let hookActive = $state(false);
  let registering = $state(false);
  let events = $state<HookEvent[]>([]);
  let capturedRequests = $state<CapturedRequest[]>([]);
  let detectedVersion = $state('');
  let detectedVariant = $state('');
  let matchedCves = $state<RuoYiCveEntry[]>([]);
  let sensitiveRoutes = $state<ClassifiedRoute[]>([]);
  let statusText = $state('');
  let showCvePanel = $state(false);
  let activeSubTab = $state<'routes' | 'api' | 'cve'>('routes');

  // API 流量过滤
  let apiFilter = $state('');
  let apiStatusFilter = $state<'all' | '2xx' | '3xx' | '4xx' | '5xx' | 'err'>('all');
  // Nacos 实例详情：serviceName → 实例列表
  let nacosInstances = $state<Record<string, { ip: string; port: number; healthy: boolean }[]>>({});
  let nacosLoading = $state<string | null>(null);
  // 路由树视图开关
  let routeTreeMode = $state(false);

  // —— 派生数据 ——
  let routerEvents = $derived(
    events.filter((e) => e.event === 'routers_captured'),
  );
  let userInfoEvents = $derived(
    events.filter((e) => e.event === 'userinfo_captured'),
  );
  let totalEvents = $derived(events.length);
  let totalRequests = $derived(capturedRequests.length);

  let aggregated = $derived(aggregateHookEvents(events));

  // API 流量过滤（URL 关键词 + 状态码）
  let filteredRequests = $derived.by(() => {
    let list = capturedRequests;
    if (apiStatusFilter !== 'all') {
      list = list.filter((r) => {
        const s = r.status;
        if (apiStatusFilter === 'err') return s === 0;
        if (s === 0) return false;
        const prefix = apiStatusFilter;
        return String(s).startsWith(prefix[0]);
      });
    }
    if (apiFilter.trim()) {
      const q = apiFilter.toLowerCase();
      list = list.filter((r) => r.url.toLowerCase().includes(q) || r.method.toLowerCase().includes(q));
    }
    return list;
  });

  // 路由按前缀分组树（/system/user → system > user）
  interface RouteTreeNode {
    name: string;
    children?: RouteTreeNode[];
    leaf?: string;
  }
  let routeTree = $derived.by(() => {
    const root: RouteTreeNode = { name: '', children: [] };
    const getNode = (parts: string[], create: boolean): RouteTreeNode | null => {
      let node: RouteTreeNode = root;
      for (const p of parts) {
        node.children = node.children || [];
        let next = node.children.find(c => c.name === p);
        if (!next && create) {
          next = { name: p, children: [] };
          node.children.push(next);
        }
        if (!next) return null;
        node = next;
      }
      return node;
    };
    for (const r of sensitiveRoutes) {
      const parts = r.path.split('/').filter(Boolean);
      if (parts.length === 0) continue;
      const node = getNode(parts, true);
      if (node) node.leaf = r.title || r.category;
    }
    return root.children || [];
  });

  // —— 监听器注册/清理 ——
  $effect(() => {
    if (!hookActive) return;

    const listener = (
      msg: { type: string; event?: string; augmented?: unknown; injected?: unknown },
      _sender: unknown,
    ) => {
      if (msg.type === 'VK_RUOYI_HOOK_EVENT' && msg.event) {
        const hookEvent: HookEvent = {
          event: msg.event,
          augmented: msg.augmented,
          injected: msg.injected,
          timestamp: Date.now(),
        };
        events = [...events, hookEvent];

        // 如果是 API 请求类型的日志，分类后追加
        if (msg.event === 'api_request' && msg.augmented) {
          const aug = msg.augmented as { url?: string; method?: string; status?: number; time?: string };
          if (aug.url) {
            const req: CapturedRequest = {
              url: aug.url,
              method: aug.method || 'GET',
              status: aug.status || 0,
              time: aug.time || '',
              category: classifyRequest(aug.url),
            };
            capturedRequests = [...capturedRequests, req];
            // 自动分类新路由
            const classified = classifyRoute(aug.url);
            if (classified.category !== 'normal' && classified.category !== 'auth') {
              if (!sensitiveRoutes.some((r) => r.path === classified.path)) {
                sensitiveRoutes = [...sensitiveRoutes, classified];
              }
            }
          }
        }
      }
    };

    browser.runtime.onMessage.addListener(listener);
    return () => {
      browser.runtime.onMessage.removeListener(listener);
    };
  });

  // —— Hook 注册/注销 ——
  async function registerHook() {
    registering = true;
    statusText = '正在注册 Hook...';
    events = [];
    capturedRequests = [];
    detectedVersion = '';
    detectedVariant = '';
    matchedCves = [];
    sensitiveRoutes = [];

    try {
      const tabUrl = await getActiveTabUrl();
      if (!tabUrl) {
        toastStore.show('无法获取当前标签页 URL', 'error');
        statusText = '';
        registering = false;
        return;
      }

      const origin = new URL(tabUrl).origin;
      const r = await sendMessage({ type: 'REGISTER_RUOYI_HOOK', origin });
      if (r.success) {
        hookActive = true;
        statusText = 'Hook 已注册，正在监听...';
        toastStore.show('Hook 已注册，刷新页面或浏览以捕获路由', 'success');
      } else {
        statusText = '';
        toastStore.show(`注册失败: ${r.error || '未知错误'}`, 'error');
      }
    } catch (e: any) {
      statusText = '';
      toastStore.show(`注册失败: ${e.message || '未知错误'}`, 'error');
    } finally {
      registering = false;
    }
  }

  async function unregisterHook() {
    try {
      await sendMessage({ type: 'UNREGISTER_RUOYI_HOOK' });
      hookActive = false;
      statusText = 'Hook 已停止';
      toastStore.show('Hook 已注销', 'info');
    } catch (e: any) {
      toastStore.show(`注销失败: ${e.message}`, 'error');
    }
  }

  // —— CVE 查询 ——
  function lookupCves() {
    if (detectedVersion) {
      matchedCves = matchCvesByVersion(detectedVersion);
    } else {
      matchedCves = getAllCves();
    }
    showCvePanel = true;
  }

  // ===== 框架检测（detect）+ Gateway/Nacos 探测 + 批量路由探测 =====
  let detectEvidence = $state<string[]>([]);
  let detecting = $state(false);
  let gatewayRoutes = $state<{ uri: string; predicate: string }[]>([]);
  let nacosServices = $state<string[]>([]);
  let probeResults = $state<{ path: string; status: number; cls: string }[]>([]);
  let probing = $state(false);
  let probeScanned = $state(0);
  // 批量探测高级选项（对齐 v5：方法 + 跟随重定向）
  let probeMethod = $state<'GET' | 'POST' | 'OPTIONS'>('GET');
  let probeFollowRedirect = $state(false);

  /** 检测 RuoYi 框架（MAIN world，30+ 特征维度）→ variant/version/evidence */
  async function detectRuoYi() {
    const tab = await getActiveTab();
    if (!tab?.id) { toastStore.show('无法获取标签页', 'error'); return; }
    detecting = true; detectEvidence = [];
    const result = await execInTab<{ isRuoYi: boolean; variant: string; version: string; evidence: string[] }>(tab.id, function () {
      const evidence: string[] = []; let variant = ''; let version = '';
      const scripts = Array.from(document.querySelectorAll('script[src]')) as HTMLScriptElement[];
      const srcs = scripts.map(s => s.src || '');
      srcs.forEach(src => {
        if (/\/request\.js/i.test(src)) evidence.push('script:request.js');
        if (/\/auth\.js/i.test(src)) evidence.push('script:auth.js');
        if (/\/permission\.js/i.test(src)) evidence.push('script:permission.js');
        if (/\/ruoyi/i.test(src)) evidence.push('script:ruoyi');
        if (/\/router\/index\.js/i.test(src)) evidence.push('script:router/index.js');
        if (/\/store\/modules\/(user|permission|app)\.js/i.test(src)) evidence.push('script:store');
        if (/\/gateway\/js\//i.test(src)) { variant = variant || 'cloud'; evidence.push('script:gateway'); }
        if (/\/uni\.js|\/manifest\.js/i.test(src)) { variant = variant || 'app'; evidence.push('script:uni-app'); }
      });
      if (document.querySelector('.app-container') && document.querySelector('.sidebar-container')) evidence.push('layout:ruoyi-sidebar');
      if (document.querySelector('.fixed-header') && document.querySelector('.sidebar-logo-container')) { variant = variant || 'vue'; evidence.push('layout:ruoyi-vue'); }
      const title = document.title || '';
      if (/若依|RuoYi|管理系统/i.test(title)) evidence.push('title:若依/RuoYi');
      const w = window as any;
      const hasEl = !!w.ELEMENT || !!w.ElPlus || !!document.querySelector('[class*="el-"]');
      if (hasEl) evidence.push('ui:element');
      if (w.ELEMENT) { version = (w.ELEMENT.version || '').replace(/^[^0-9]*/, '') || ''; if (version) evidence.push('version:element-ui-' + version); }
      if (w.ElPlus) { version = (w.ElPlus.version || '').replace(/^[^0-9]*/, '') || version; if (w.ElPlus.version) evidence.push('version:element-plus'); }
      if (w.Vue) { const vv = w.Vue.version; if (vv) evidence.push('version:vue-' + vv); if (/^3\./.test(vv)) variant = variant || 'vue3'; else if (/^2\./.test(vv)) variant = variant || 'vue'; }
      if (w.__CONFIG__) evidence.push('global:__CONFIG__');
      if (w.__APP_BASE_API__) evidence.push('global:__APP_BASE_API__');
      const cookies = document.cookie || '';
      if (/Admin-Token/i.test(cookies)) evidence.push('cookie:Admin-Token');
      if (/token=|JSESSIONID/i.test(cookies)) evidence.push('cookie:session-token');
      const metaGen = document.querySelector('meta[name="generator"]') as HTMLMetaElement | null;
      if (metaGen && /ruoyi/i.test(metaGen.content || '')) evidence.push('meta:generator-ruoyi');
      const isRuoYi = evidence.length >= 2 || /若依|RuoYi/i.test(title) || !!metaGen && /ruoyi/i.test(metaGen.content || '');
      return { isRuoYi, variant: variant || 'unknown', version, evidence };
    }, { world: 'MAIN' });
    detecting = false;
    if (!result) { toastStore.show('检测失败（可能无权限）', 'error'); return; }
    detectEvidence = result.evidence;
    detectedVariant = result.variant;
    detectedVersion = result.version;
    if (result.isRuoYi) toastStore.show(`检测到 RuoYi（${result.variant}${result.version ? ' / ' + result.version : ''}）`, 'success');
    else toastStore.show('未检测到 RuoYi 特征（可手动注册 Hook）', 'info');
    await saveFindings();
  }

  /** 探测 Gateway 路由 + Nacos 服务发现 + Actuator（云版若依）*/
  async function probeCloudEndpoints() {
    const tabUrl = await getActiveTabUrl();
    if (!tabUrl) { toastStore.show('无法获取 URL', 'error'); return; }
    const origin = new URL(tabUrl).origin;
    gatewayRoutes = []; nacosServices = [];
    // Gateway 路由
    for (const p of ['/actuator/gateway/routes', '/gateway/routes']) {
      try {
        const res = await sendMessage({ type: 'FETCH_PROBE', url: origin + p, method: 'GET', timeout: 8000 }) as ProbeResult;
        if (res?.status === 200 && res.body) {
          try {
            const arr = JSON.parse(res.body);
            if (Array.isArray(arr)) {
              gatewayRoutes = arr.map((r: any) => ({ uri: r.route_definition?.uri || r.uri || r.route_id || '', predicate: Array.isArray(r.route_definition?.predicates) ? r.route_definition.predicates.map((x: any) => x._genkey_ || JSON.stringify(x)).join(', ') : '' }));
              if (gatewayRoutes.length > 0) { toastStore.show(`发现 ${gatewayRoutes.length} 条 Gateway 路由`, 'success'); break; }
            }
          } catch { /* ignore */ }
        }
      } catch { /* ignore */ }
    }
    // Nacos 服务列表
    try {
      const res = await sendMessage({ type: 'FETCH_PROBE', url: origin + '/nacos/v1/ns/service/list?pageNo=1&pageSize=100', method: 'GET', timeout: 8000 }) as ProbeResult;
      if (res?.status === 200 && res.body) {
        try { const j = JSON.parse(res.body); if (Array.isArray(j.data)) { nacosServices = j.data; if (nacosServices.length > 0) toastStore.show(`Nacos 暴露 ${nacosServices.length} 个服务`, 'warning'); } } catch { /* */ }
      }
    } catch { /* ignore */ }
    if (gatewayRoutes.length === 0 && nacosServices.length === 0) toastStore.show('未发现 Gateway/Nacos 暴露（可能非云版或需认证）', 'info');
    await saveFindings();
  }

  /** 查询单个 Nacos 服务的实例列表（IP:port/健康状态） */
  async function fetchNacosInstances(serviceName: string) {
    if (nacosInstances[serviceName]) {
      // 已加载则折叠
      const next = { ...nacosInstances };
      delete next[serviceName];
      nacosInstances = next;
      return;
    }
    const tabUrl = await getActiveTabUrl();
    if (!tabUrl) return;
    const origin = new URL(tabUrl).origin;
    nacosLoading = serviceName;
    try {
      const res = await sendMessage({
        type: 'FETCH_PROBE',
        url: origin + '/nacos/v1/ns/instance/list?serviceName=' + encodeURIComponent(serviceName),
        method: 'GET',
        timeout: 8000,
      }) as ProbeResult;
      if (res?.status === 200 && res.body) {
        const j = JSON.parse(res.body);
        const hosts = (j.hosts || []) as any[];
        const insts = hosts.map((h) => ({ ip: h.ip || '-', port: h.port || 0, healthy: h.healthy !== false }));
        nacosInstances = { ...nacosInstances, [serviceName]: insts };
        toastStore.show(`${serviceName}: ${insts.length} 个实例`, insts.length ? 'success' : 'info');
      } else {
        toastStore.show(`${serviceName}: 无法获取实例`, 'info');
      }
    } catch {
      toastStore.show(`${serviceName}: 查询失败`, 'error');
    } finally {
      nacosLoading = null;
    }
  }

  /** 批量探测所有已知路由（admin/monitor/tool/cloud）的可达性 */
  async function batchProbeRoutes() {
    probing = true; probeResults = []; probeScanned = 0;
    const tabUrl = await getActiveTabUrl();
    if (!tabUrl) { probing = false; return; }
    const origin = new URL(tabUrl).origin;
    // 用引擎里所有已知路由 + 已捕获路由
    const known = ['/', ...getSensitiveRoutes(sensitiveRoutes).map(r => r.path)];
    const paths = [...new Set(known.filter(Boolean))];
    await runConcurrent(paths.map(p => async () => {
      try {
        const res = await sendMessage({ type: 'FETCH_PROBE', url: origin + p, method: probeMethod, followRedirect: probeFollowRedirect, timeout: 6000 }) as ProbeResult;
        const st = res?.status ?? 0;
        probeResults = [...probeResults, { path: p, status: st, cls: classifyStatus(st) }];
      } catch {
        probeResults = [...probeResults, { path: p, status: 0, cls: 'error' }];
      }
      probeScanned++;
    }), async (t) => { await t(); }, { concurrency: $scanSettingsStore.concurrency });
    probing = false;
    const found = probeResults.filter(r => r.status !== 0 && r.status !== 404).length;
    toastStore.show(`探测完成，${found}/${paths.length} 可达`, found > 0 ? 'success' : 'info');
  }

  /** MaR：从内联 + 外部 JS 扫描动态路由定义（path:'/xxx' / component:'views/xxx'）*/
  let jsDiscoveredRoutes = $state<{ path: string; source: string }[]>([]);
  let scanningJs = $state(false);

  async function scanJsRoutes() {
    scanningJs = true; jsDiscoveredRoutes = [];
    const tab = await getActiveTab();
    if (!tab?.id) { scanningJs = false; return; }
    // 内联脚本扫描 + 收集外部 JS URL（独立于 hook 是否注册）
    const inline = await execInTab<{ discovered: { path: string; source: string }[]; extUrls: string[] }>(tab.id, function () {
      const discovered: any[] = []; const seen: any = {};
      const routePattern = /path\s*:\s*['"`](\/[a-zA-Z0-9_\-\/]+)['"`]/g;
      const pathPattern = /['"`](\/[a-zA-Z0-9_\-]+(?:\/[a-zA-Z0-9_\-]+){1,})['"`]/g;
      const skipRe = /\/api\/|\.js$|\.css$|\.(png|jpg|svg|ico|woff|ttf)|\/login$|\/index$/i;
      const scan = (text: string, source: string) => {
        let m: RegExpExecArray | null;
        routePattern.lastIndex = 0;
        while ((m = routePattern.exec(text)) !== null) { const p = m[1]; if (!skipRe.test(p) && p.length >= 4 && !seen[p]) { seen[p] = true; discovered.push({ path: p, source }); } }
        pathPattern.lastIndex = 0;
        while ((m = pathPattern.exec(text)) !== null) { const p = m[1]; if (!skipRe.test(p) && p.length >= 5 && !seen[p]) { seen[p] = true; discovered.push({ path: p, source }); } }
      };
      document.querySelectorAll('script:not([src])').forEach(function (s, i) { const t = s.textContent || ''; if (t.length < 500000) scan(t, 'inline#' + (i + 1)); });
      const extUrls: string[] = [];
      document.querySelectorAll('script[src]').forEach(function (s: any) { extUrls.push(s.src); });
      return { discovered, extUrls };
    }, { world: 'MAIN' });
    const found = [...(inline?.discovered || [])];
    const extUrls = inline?.extUrls || [];
    // 抓取外部 JS 扫描
    // §5.1：外部 JS 抓取改 runConcurrent（并发限流 + 一致性，替代 Promise.allSettled 一次性全发）
    const seen = new Set(found.map(f => f.path));
    await runConcurrent(
      extUrls.slice(0, 20),
      async (u: string) => {
        let res: FetchResult<string>;
        try { res = await sendMessage({ type: 'FETCH_URL', url: u }) as FetchResult<string>; }
        catch { return; }
        if (!res?.success || !res.data) return;
        const text = res.data;
        let label = u; if (label.length > 40) label = '...' + label.slice(-37);
        const routeRe = /path\s*:\s*['"`](\/[a-zA-Z0-9_\-\/]+)['"`]/g;
        let m: RegExpExecArray | null;
        while ((m = routeRe.exec(text)) !== null) {
          const p = m[1];
          if (/\/api\/|\.js$|\.css$|\.(png|jpg|svg|ico)/i.test(p) || p.length < 4 || seen.has(p)) continue;
          seen.add(p); found.push({ path: p, source: label });
        }
      },
      { concurrency: $scanSettingsStore.concurrency },
    );
    jsDiscoveredRoutes = found;
    // 合并到 sensitiveRoutes（去重）
    let added = 0;
    for (const r of found) {
      if (r.path && !sensitiveRoutes.some(s => s.path === r.path)) {
        sensitiveRoutes = [...sensitiveRoutes, classifyRoute(r.path)];
        added++;
      }
    }
    scanningJs = false;
    toastStore.show(`JS 扫描发现 ${found.length} 条路径，新增 ${added} 条`, found.length ? 'success' : 'info');
  }

  // ===== MaR 字典扫描：叠加 RuoYi 标准路由 + 云端路由字典，批量探测 =====
  let marRoutes = $state<{ path: string; title: string; status: number | null; source: string }[]>([]);
  let marScanning = $state(false);
  let marScanned = $state(0);
  let marTotal = $state(0);

  /** MaR 字典扫描：合并已知路由字典 + JS 扫描结果 + 批量 HTTP 探测 */
  async function marDictionaryScan() {
    marScanning = true; marScanned = 0;
    const tabUrl = await getActiveTabUrl();
    if (!tabUrl) { marScanning = false; toastStore.show('无法获取 URL', 'error'); return; }
    const origin = new URL(tabUrl).origin;

    // 1. 收集已知路由路径（字典 + 已发现的 JS 路由）
    const seen = new Set(sensitiveRoutes.map(r => r.path));
    const routes: { path: string; title: string; status: number | null; source: string }[] = [];

    // RuoYi 标准字典
    for (const kr of RUOYI_KNOWN_ROUTES) {
      if (!seen.has(kr.path)) {
        seen.add(kr.path);
        routes.push({ path: kr.path, title: kr.title, status: null, source: 'RuoYi标准' });
      }
    }

    // 云版字典（始终加入，用于探测）
    const isCloud = detectedVariant === 'cloud' || detectedVariant === 'microservice';
    for (const cr of CLOUD_KNOWN_ROUTES) {
      if (!seen.has(cr.path) && (isCloud || cr.path.startsWith('/actuator') || cr.path.startsWith('/nacos') || cr.path.startsWith('/swagger') || cr.path.startsWith('/v2/api') || cr.path.startsWith('/v3/api') || cr.path.startsWith('/doc.html'))) {
        seen.add(cr.path);
        routes.push({ path: cr.path, title: cr.title, status: null, source: '云端字典' });
      }
    }

    // 已有 JS 扫描结果中尚未发现的
    for (const jr of jsDiscoveredRoutes) {
      if (!seen.has(jr.path)) {
        seen.add(jr.path);
        routes.push({ path: jr.path, title: '', status: null, source: 'JS扫描' });
      }
    }

    // Hook 捕获的路由
    for (const sr of sensitiveRoutes) {
      if (!seen.has(sr.path)) {
        seen.add(sr.path);
        routes.push({ path: sr.path, title: sr.title || '', status: null, source: 'Hook捕获' });
      }
    }

    marRoutes = routes;
    marTotal = routes.length;

    // 2. 批量探测（HEAD，并发 10）
    const CONCURRENCY = 10;
    let cancelled = false;
    await runConcurrent(
      routes.map(r => () => async () => {
        if (cancelled) return;
        try {
          const probe = await sendMessage({ type: 'FETCH_HEADER_PROBE', url: origin + r.path, timeout: 5000 }) as ProbeResult;
          r.status = probe?.status || 0;
        } catch { r.status = 0; }
        marScanned++;
      }),
      async (task) => { await task(); },
      { concurrency: CONCURRENCY, cancelled: () => cancelled },
    );

    // 3. 统计结果
    const alive = routes.filter(r => r.status && r.status >= 200 && r.status < 400);
    const hidden = alive.filter(r => r.status && !sensitiveRoutes.some(s => s.path === r.path));
    // 合并存活路由到 sensitiveRoutes
    let added = 0;
    for (const r of alive) {
      if (r.status && !sensitiveRoutes.some(s => s.path === r.path)) {
        sensitiveRoutes = [...sensitiveRoutes, classifyRoute(r.path)];
        added++;
      }
    }
    marScanning = false;
    const msg = `字典扫描完成：${alive.length}/${routes.length} 存活` + (hidden.length > 0 ? `，${hidden.length} 个隐藏路由` : '') + (added > 0 ? `，新增 ${added}` : '');
    toastStore.show(msg, alive.length > 0 ? 'success' : 'info');
    await saveFindings();
  }

  /** curl 导出（带 Admin-Token 认证头） */
  async function exportCurl() {
    const tab = await getActiveTab();
    if (!tab?.id) { toastStore.show('无法获取标签页', 'error'); return; }
    const tabUrl = await getActiveTabUrl();
    if (!tabUrl) return;

    // 从页面获取 Admin-Token
    const token = await execInTab<string | null>(tab.id, function () {
      const cookies = document.cookie || '';
      const m = cookies.match(/Admin-Token=([^;]+)/i);
      return m ? m[1] : null;
    }, { world: 'MAIN' });

    const origin = new URL(tabUrl).origin;
    const paths = marRoutes.filter(r => r.status && r.status >= 200 && r.status < 400).map(r => r.path);
    if (paths.length === 0) {
      toastStore.show('没有可导出的路由（先运行字典扫描）', 'warning');
      return;
    }

    const lines = paths.map(p => {
      const cmd = `curl -s -X GET '${origin}${p}'`;
      return token ? `${cmd} \\\n  -H 'Authorization: Bearer ${token}'` : cmd;
    });
    copyText(lines.join('\n\n'), `已复制 ${paths.length} 条 curl 命令${token ? '（含 Admin-Token）' : ''}`);
  }

  // —— 导出序列化器（敏感路由）——
  function ruoyiCsv(items: ClassifiedRoute[]): string {
    return toCsv([['path', 'category', 'title'], ...items.map(r => [r.path, r.category, r.title])]);
  }
  function ruoyiJson(items: ClassifiedRoute[]): string {
    return JSON.stringify({
      version: detectedVersion, variant: detectedVariant,
      sensitiveRoutes: items.map(r => ({ path: r.path, category: r.category, title: r.title })),
      matchedCves: matchedCves.map(c => ({ id: c.id, title: c.title, severity: c.severity, affected: c.affected })),
    }, null, 2);
  }
  function ruoyiText(items: ClassifiedRoute[]): string {
    return items.map(r => `[${r.category}] ${r.path}${r.title ? ' — ' + r.title : ''}`).join('\n');
  }

  /** 导出 HTML 报告（对齐 v5 exportHtmlReport）—— 自包含、可离线查看 */
  function exportHtml() {
    const esc = (s: string) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
    const sevColor = (s: string) => s === 'critical' ? '#dc2626' : s === 'high' ? '#ea580c' : s === 'medium' ? '#ca8a04' : '#6b7280';
    const rows = (items: any[], render: (x: any) => string) => items.length ? items.map(render).join('') : '<tr><td colspan="99" style="color:#999;text-align:center;padding:12px">无</td></tr>';

    const cveRows = rows(matchedCves, c => `<tr><td><span style="color:${sevColor(c.severity)};font-weight:bold">${esc(c.id)}</span></td><td>${esc(c.severity)}</td><td>${esc(c.title)}</td><td>${esc(c.affected || '')}</td></tr>`);
    const routeRows = rows(sensitiveRoutes, r => `<tr><td><code>${esc(r.path)}</code></td><td>${esc(r.category)}</td><td>${esc(r.title || '')}</td></tr>`);
    const gwRows = rows(gatewayRoutes, g => `<tr><td><code>${esc(g.uri)}</code></td><td>${esc(g.predicate)}</td></tr>`);
    const marAlive = marRoutes.filter(r => r.status && r.status >= 200 && r.status < 400);
    const marRows = rows(marAlive, r => `<tr><td><span style="color:#16a34a">${r.status}</span></td><td><code>${esc(r.path)}</code></td><td>${esc(r.title || '')}</td><td>${esc(r.source)}</td></tr>`);

    const html = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><title>RuoYi 安全报告</title>
<style>body{font-family:-apple-system,sans-serif;max-width:960px;margin:20px auto;padding:0 16px;color:#1f2937}
h1{border-bottom:2px solid #2563eb;padding-bottom:8px}h2{margin-top:28px;color:#374151}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px}
th,td{border:1px solid #e5e7eb;padding:6px 8px;text-align:left}
th{background:#f9fafb}code{background:#f3f4f6;padding:1px 4px;border-radius:3px;font-size:12px}
.meta{background:#eff6ff;padding:12px 16px;border-radius:8px;margin:12px 0;font-size:13px}
.summary{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.card{flex:1;min-width:120px;background:#f9fafb;padding:12px;border-radius:8px;text-align:center}
.card .num{font-size:24px;font-weight:bold;color:#2563eb}</style></head>
<body><h1>🔒 RuoYi 安全分析报告</h1>
<div class="meta">生成时间: ${new Date().toLocaleString('zh-CN')}<br>变体: <b>${esc(detectedVariant || 'unknown')}</b>${detectedVersion ? ' · 版本: <b>' + esc(detectedVersion) + '</b>' : ''}</div>
<div class="summary">
  <div class="card"><div class="num">${sensitiveRoutes.length}</div>敏感路由</div>
  <div class="card"><div class="num">${matchedCves.length}</div>CVE 匹配</div>
  <div class="card"><div class="num">${marAlive.length}</div>MaR 存活</div>
  <div class="card"><div class="num">${gatewayRoutes.length}</div>Gateway 路由</div>
  <div class="card"><div class="num">${nacosServices.length}</div>Nacos 服务</div>
</div>
${matchedCves.length > 0 ? `<h2>⚠️ CVE 漏洞匹配（${matchedCves.length}）</h2><table><thead><tr><th>ID</th><th>级别</th><th>标题</th><th>影响版本</th></tr></thead><tbody>${cveRows}</tbody></table>` : ''}
${sensitiveRoutes.length > 0 ? `<h2>🛣️ 敏感路由（${sensitiveRoutes.length}）</h2><table><thead><tr><th>路径</th><th>分类</th><th>标题</th></tr></thead><tbody>${routeRows}</tbody></table>` : ''}
${marAlive.length > 0 ? `<h2>🔍 MaR 字典扫描存活（${marAlive.length}）</h2><table><thead><tr><th>状态</th><th>路径</th><th>标题</th><th>来源</th></tr></thead><tbody>${marRows}</tbody></table>` : ''}
${gatewayRoutes.length > 0 ? `<h2>🌐 Gateway 路由（${gatewayRoutes.length}）</h2><table><thead><tr><th>URI</th><th>谓词</th></tr></thead><tbody>${gwRows}</tbody></table>` : ''}
${nacosServices.length > 0 ? `<h2>☁️ Nacos 服务（${nacosServices.length}）</h2><div>${nacosServices.map(s => `<span style="display:inline-block;background:#fef2f2;color:#dc2626;padding:2px 8px;border-radius:4px;margin:2px;font-size:12px">${esc(s)}</span>`).join('')}</div>` : ''}
<hr><p style="color:#9ca3af;font-size:12px;text-align:center">灵眸 v${getAppVersion()} RuoYi 分析报告</p>
</body></html>`;

    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    downloadBlob(blob, `ruoyi-report-${Date.now()}.html`);
    toastStore.show('HTML 报告已导出', 'success');
  }
  function severityBadge(severity: string): string {
    if (severity === 'critical') return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400';
    if (severity === 'high') return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400';
    if (severity === 'medium') return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400';
    return 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400';
  }

  // ===== Findings 导出 =====
  /** 基于当前扫描结果生成安全发现（对齐 v5 vk-ruoyi getFindings） */
  function getFindings(): ScanFinding[] {
    const findings: ScanFinding[] = [];
    if (!detectedVariant || detectedVariant === 'unknown') return findings;

    findings.push({ severity: 'info', title: '若依框架检测', detail: '变体: ' + detectedVariant });

    if (nacosServices.length > 0) {
      findings.push({ severity: 'critical', title: 'Nacos 服务发现暴露', detail: '暴露 ' + nacosServices.length + ' 个微服务: ' + nacosServices.slice(0, 5).join(', ') });
    }
    if (gatewayRoutes.length > 0) {
      findings.push({ severity: 'high', title: 'Spring Cloud Gateway 路由暴露', detail: '发现 ' + gatewayRoutes.length + ' 条网关路由规则' });
    }
    if (sensitiveRoutes.length > 0) {
      findings.push({ severity: 'high', title: '敏感路由发现', detail: '发现 ' + sensitiveRoutes.length + ' 个敏感路由（认证/文件/配置等）' });
    }
    if (marRoutes.length > 0) {
      const hiddenMar = marRoutes.filter(r => r.status !== null && r.status >= 200 && r.status < 400);
      if (hiddenMar.length > 0) {
        findings.push({ severity: 'high', title: '若依隐藏路由发现', detail: 'MAR 扫描发现 ' + hiddenMar.length + ' 个隐藏/动态路由' });
      }
    }
    if (jsDiscoveredRoutes.length > 0) {
      findings.push({ severity: 'medium', title: '未注册路由发现', detail: 'JS 分析发现 ' + jsDiscoveredRoutes.length + ' 条不在路由表中的路径' });
    }

    // CVE 匹配
    const allCves = detectedVersion ? matchCvesByVersion(detectedVersion) : getAllCves();
    const criticalCves = allCves.filter(c => c.severity === 'critical');
    const highCves = allCves.filter(c => c.severity === 'high');
    if (criticalCves.length > 0) {
      findings.push({ severity: 'critical', title: '若依严重漏洞 (' + criticalCves.length + ' 个)', detail: criticalCves.map(c => c.id + ': ' + c.title).join('; ') });
    }
    if (highCves.length > 0) {
      findings.push({ severity: 'high', title: '若依高危漏洞 (' + highCves.length + ' 个)', detail: highCves.map(c => c.id + ': ' + c.title).join('; ') });
    }

    return findings;
  }

  /** 将 findings 保存到扫描历史 */
  async function saveFindings() {
    const tabUrl = await getActiveTabUrl();
    if (!tabUrl) return;
    const findings = getFindings();
    if (findings.length > 0) {
      await scanHistoryStore.addScan({ url: tabUrl, module: 'ruoyi', findings });
    }
  }
</script>

<div class="space-y-3">
  <!-- 框架检测 + 云端探测 -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div class="text-sm font-medium">框架检测 <span class="text-xs text-gray-400 font-normal">（30+ 特征维度）</span></div>
      <div class="flex gap-1">
        <button class="btn btn-sm btn-primary" onclick={detectRuoYi} disabled={detecting}>{detecting ? '检测中...' : '检测'}</button>
        <button class="btn btn-sm" onclick={scanJsRoutes} disabled={scanningJs}>{scanningJs ? '扫描中...' : 'JS扫路由'}</button>
        <button class="btn btn-sm" onclick={probeCloudEndpoints}>Gateway/Nacos</button>
        <button class="btn btn-sm" onclick={batchProbeRoutes} disabled={probing}>{probing ? `探测中(${probeScanned})` : '批量探测'}</button>
        <button class="btn btn-sm btn-warning" onclick={marDictionaryScan} disabled={marScanning}>{marScanning ? `MaR扫描(${marScanned}/${marTotal})` : 'MaR字典扫描'}</button>
        <button class="btn btn-sm" onclick={exportCurl}>curl导出</button>
      </div>
    </div>

    {#if detectedVariant && detectedVariant !== 'unknown'}
      <div class="flex items-center gap-2 text-xs">
        <span class="badge bg-blue-50 text-blue-700 ring-1 ring-inset ring-blue-200 dark:bg-blue-900/30 dark:text-blue-300 dark:ring-blue-800/60">{detectedVariant}</span>
        {#if detectedVersion}<span class="badge bg-gray-200 dark:bg-gray-700">{detectedVersion}</span>{/if}
      </div>
    {/if}

    {#if detectEvidence.length > 0}
      <div class="flex flex-wrap gap-1">
        {#each detectEvidence as ev}
          <span class="badge text-xs bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 font-mono">{ev}</span>
        {/each}
      </div>
    {/if}

    {#if gatewayRoutes.length > 0}
      <div class="text-xs font-medium text-amber-600 dark:text-amber-400">Gateway 路由（{gatewayRoutes.length}）</div>
      <div class="space-y-0.5 max-h-32 overflow-y-auto">
        {#each gatewayRoutes.slice(0, 30) as gr}
          <div class="text-xs font-mono truncate"><span class="text-green-600 dark:text-green-400">{gr.uri}</span> <span class="text-gray-400">{gr.predicate}</span></div>
        {/each}
      </div>
    {/if}

    {#if nacosServices.length > 0}
      <div class="text-xs font-medium text-red-600 dark:text-red-400">Nacos 服务（{nacosServices.length}，点击查看实例）</div>
      <div class="flex flex-wrap gap-1">
        {#each nacosServices as ns}
          <button
            class="badge text-xs cursor-pointer {nacosInstances[ns] ? 'bg-red-50 text-red-700 ring-1 ring-inset ring-red-200 dark:bg-red-900/30 dark:text-red-300 dark:ring-red-800/60' : 'bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300'}"
            onclick={() => fetchNacosInstances(ns)}
            disabled={nacosLoading === ns}
          >
            {nacosLoading === ns ? '⏳' : '▸'} {ns}
            {#if nacosInstances[ns]}<span class="ml-1 opacity-75">({nacosInstances[ns].length})</span>{/if}
          </button>
        {/each}
      </div>
      <!-- 展开的实例列表 -->
      {#each Object.keys(nacosInstances) as svc}
        {#if nacosInstances[svc]?.length}
          <div class="ml-2 mt-1 border-l-2 border-red-300 dark:border-red-700 pl-2 space-y-0.5">
            {#each nacosInstances[svc] as inst}
              <div class="text-xs font-mono flex items-center gap-2">
                <span class="w-2 h-2 rounded-full {inst.healthy ? 'bg-green-500' : 'bg-red-500'}"></span>
                <span class="text-gray-700 dark:text-gray-300">{inst.ip}:{inst.port}</span>
                <span class="text-gray-400">{inst.healthy ? 'healthy' : 'unhealthy'}</span>
              </div>
            {/each}
          </div>
        {/if}
      {/each}
    {/if}

    {#if probeResults.length > 0 || probing}
      <div class="flex items-center gap-2 text-xs flex-wrap">
        <span class="text-gray-500">方法:</span>
        {#each ['GET', 'POST', 'OPTIONS'] as m}
          <label class="flex items-center gap-0.5 cursor-pointer">
            <input type="radio" name="probeMethod" value={m} bind:group={probeMethod} disabled={probing} class="accent-blue-500" />
            <span class="text-gray-600 dark:text-gray-300">{m}</span>
          </label>
        {/each}
        <label class="flex items-center gap-0.5 cursor-pointer ml-2">
          <input type="checkbox" bind:checked={probeFollowRedirect} disabled={probing} class="accent-blue-500" />
          <span class="text-gray-600 dark:text-gray-300">跟随重定向</span>
        </label>
      </div>
    {/if}

    {#if probeResults.length > 0}
      <div class="text-xs font-medium text-gray-500">批量探测（{probeResults.length}）</div>
      <div class="space-y-0.5 max-h-32 overflow-y-auto">
        {#each probeResults as pr}
          <div class="text-xs font-mono flex items-center gap-2">
            <span class="badge {statusColor(pr.cls)} w-12 shrink-0">{pr.status || 'ERR'}</span>
            <span class="truncate">{pr.path}</span>
          </div>
        {/each}
      </div>
    {/if}

    {#if jsDiscoveredRoutes.length > 0}
      <div class="text-xs font-medium text-blue-600 dark:text-blue-400">JS 扫描路由（{jsDiscoveredRoutes.length}）</div>
      <div class="space-y-0.5 max-h-32 overflow-y-auto">
        {#each jsDiscoveredRoutes.slice(0, 40) as jr}
          <div class="text-xs font-mono"><span class="text-gray-400">{jr.source}</span> <span class="text-blue-600 dark:text-blue-400">{jr.path}</span></div>
        {/each}
      </div>
    {/if}

    {#if marRoutes.length > 0}
      {@const marAlive = marRoutes.filter(r => r.status && r.status >= 200 && r.status < 400)}
      {@const marHidden = marAlive.filter(r => !sensitiveRoutes.some(s => s.path !== r.path) || jsDiscoveredRoutes.some(j => j.path !== r.path))}
      <div class="text-xs font-medium text-orange-600 dark:text-orange-400">
        MaR 字典扫描（{marAlive.length}/{marRoutes.length} 存活{#if marHidden.length > 0}，{marHidden.length} 隐藏{/if}）
      </div>
      <div class="space-y-0.5 max-h-40 overflow-y-auto">
        {#each marRoutes.filter(r => r.status && r.status >= 200 && r.status < 400).slice(0, 50) as mr}
          <div class="text-xs font-mono flex items-center gap-2">
            <span class="badge bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300 w-8 shrink-0 text-center">{mr.status}</span>
            <span class="truncate text-green-700 dark:text-green-400">{mr.path}</span>
            {#if mr.title}<span class="text-gray-400 shrink-0">{mr.title}</span>{/if}
          </div>
        {/each}
      </div>
    {/if}

  </div>

  <!-- Hook 控制 -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div>
        <div class="text-sm font-medium">RuoYi 路由 Hook</div>
        <div class="text-xs text-gray-500">
          {hookActive
            ? `Hook 运行中 — 已捕获 ${totalEvents} 个事件`
            : '注册 Hook 以监听 RuoYi 路由/API 流量'}
        </div>
      </div>
      <div class="flex gap-1">
        {#if hookActive}
          <button class="btn btn-sm" onclick={unregisterHook}>停止</button>
        {:else}
          <button
            class="btn btn-sm btn-primary"
            disabled={registering}
            onclick={registerHook}
          >
            {registering ? '注册中...' : '注册 Hook'}
          </button>
        {/if}
      </div>
    </div>

    {#if statusText}
      <div class="text-xs text-gray-500">{statusText}</div>
    {/if}

    <!-- 状态摘要 -->
    {#if hookActive && aggregated.routerCaptured}
      <div class="flex gap-2 flex-wrap text-xs">
        {#if aggregated.routerCaptured}
          <span class="badge bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400">
            路由已捕获
          </span>
        {/if}
        {#if aggregated.userinfoCaptured}
          <span class="badge bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400">
            UserInfo 已捕获
          </span>
        {/if}
        {#if aggregated.hookRestored}
          <span class="badge bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400">
            Hook 已恢复
          </span>
        {/if}
        {#if aggregated.augmentCount > 0}
          <span class="badge bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400">
            增强注入: {aggregated.augmentCount}
          </span>
        {/if}
        {#if totalRequests > 0}
          <span class="badge bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300">
            API 请求: {totalRequests}
          </span>
        {/if}
      </div>
    {/if}
  </div>

  <!-- 子标签切换 -->
  {#if hookActive && (totalEvents > 0 || totalRequests > 0)}
    <div class="flex gap-1">
      <button
        class="btn btn-sm {activeSubTab === 'routes' ? 'btn-primary' : ''}"
        onclick={() => (activeSubTab = 'routes')}
      >
        路由 ({sensitiveRoutes.length})
      </button>
      <button
        class="btn btn-sm {activeSubTab === 'api' ? 'btn-primary' : ''}"
        onclick={() => (activeSubTab = 'api')}
      >
        API ({totalRequests})
      </button>
      <button
        class="btn btn-sm {activeSubTab === 'cve' ? 'btn-primary' : ''}"
        onclick={() => { activeSubTab = 'cve'; lookupCves(); }}
      >
        CVE ({matchedCves.length})
      </button>
    </div>
  {/if}

  <!-- 路由面板 -->
  {#if activeSubTab === 'routes'}
    {#if sensitiveRoutes.length > 0}
      <div class="flex items-center justify-end mb-1">
        <button
          class="btn btn-sm"
          onclick={() => (routeTreeMode = !routeTreeMode)}
          title="切换树/列表视图"
        >
          {routeTreeMode ? '🗂️ 树视图' : '📋 列表视图'}
        </button>
      </div>

      {#if routeTreeMode}
        <!-- 树视图：按路径前缀分组 -->
        <div class="card p-2 space-y-0.5 max-h-96 overflow-y-auto text-xs font-mono">
          {#snippet renderNode(node: RouteTreeNode, depth: number)}
            {#if node.children && node.children.length > 0}
              <details open style="margin-left: {depth * 12}px;">
                <summary class="cursor-pointer text-gray-700 dark:text-gray-300 select-none">
                  <span class="text-blue-500">📁 /{node.name}</span>
                  {#if node.leaf}<span class="text-gray-400 ml-1">({node.leaf})</span>{/if}
                </summary>
                {#each node.children as child}
                  {@render renderNode(child, depth + 1)}
                {/each}
              </details>
            {:else}
              <div style="margin-left: {(depth + 1) * 12}px;" class="text-green-600 dark:text-green-400">
                /{node.name}
                {#if node.leaf}<span class="text-gray-400 ml-1">({node.leaf})</span>{/if}
              </div>
            {/if}
          {/snippet}
          {#each routeTree as node}
            {@render renderNode(node, 0)}
          {/each}
        </div>
      {:else}
        <!-- 列表视图 -->
        <div class="space-y-1">
          {#each sensitiveRoutes as route}
            <div class="card p-2 flex items-center gap-2">
              <span class="badge {severityBadge(route.category === 'admin' ? 'high' : route.category === 'cloud' ? 'medium' : 'low')}">
                {routeCategoryLabel(route.category)}
              </span>
              <span class="text-xs font-mono flex-1 break-all">{route.path}</span>
              {#if route.title}
                <span class="text-xs text-gray-400">{route.title}</span>
              {/if}
            </div>
          {/each}
        </div>
      {/if}

      <div class="flex gap-1">
        <ExportMenu items={sensitiveRoutes} module="ruoyi-routes" serializers={{ json: ruoyiJson, csv: ruoyiCsv, text: ruoyiText }} copySerialize={ruoyiText} />
        <button class="btn btn-sm flex-1" onclick={exportHtml}>HTML 报告</button>
      </div>
    {:else if hookActive}
      <div class="card p-3 text-center">
        <div class="text-xs text-gray-400">
          刷新目标页面或浏览功能以捕获路由
        </div>
      </div>
    {/if}
  {/if}

  <!-- API 流量面板 -->
  {#if activeSubTab === 'api' && totalRequests > 0}
    <!-- 过滤工具栏 -->
    <div class="card p-2 space-y-2">
      <input
        class="input text-xs"
        placeholder="过滤 URL / 方法 关键词..."
        bind:value={apiFilter}
      />
      <div class="flex gap-1 flex-wrap">
        {#each [['all', '全部'], ['2xx', '2xx'], ['3xx', '3xx'], ['4xx', '4xx'], ['5xx', '5xx'], ['err', '错误']] as [key, label]}
          <button
            class="badge text-xs cursor-pointer {apiStatusFilter === key ? 'bg-primary text-white' : 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-300'}"
            onclick={() => (apiStatusFilter = key as typeof apiStatusFilter)}
          >{label}</button>
        {/each}
        <span class="text-xs text-gray-400 ml-auto self-center">{filteredRequests.length} / {totalRequests}</span>
      </div>
    </div>
    <div class="space-y-1">
      {#each filteredRequests.slice(-50).reverse() as req}
        <div class="card p-2 flex items-center gap-2 text-xs">
          <span class="font-mono font-bold w-16 shrink-0 {statusColor(classifyStatus(req.status))}">
            {req.method}
          </span>
          <span class="font-mono w-8 shrink-0 {statusColor(classifyStatus(req.status))}">
            {req.status || '-'}
          </span>
          <span class="font-mono flex-1 break-all truncate">{req.url}</span>
          <span class="text-gray-400 shrink-0">{req.time}</span>
        </div>
      {/each}
    </div>
  {:else if activeSubTab === 'api' && hookActive}
    <div class="card p-3 text-center">
      <div class="text-xs text-gray-400">
        等待 API 请求捕获...
      </div>
    </div>
  {/if}

  <!-- CVE 面板 -->
  {#if activeSubTab === 'cve'}
    <div class="space-y-1">
      {#if detectedVersion}
        <div class="card p-2 text-xs">
          <span class="text-gray-500">检测版本:</span>
          <span class="font-mono font-bold ml-1">{detectedVersion}</span>
          {#if detectedVariant}
            <span class="badge bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 ml-2">
              {detectedVariant}
            </span>
          {/if}
        </div>
      {/if}

      {#if matchedCves.length > 0}
        {#each matchedCves as cve}
          <div class="card p-3 space-y-1">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="badge {severityBadge(cve.severity)}">
                {cveSeverityLabel(cve.severity).toUpperCase()}
              </span>
              <span class="text-xs font-bold {cveSeverityColor(cve.severity)}">{cve.id}</span>
            </div>
            <div class="text-xs font-medium">{cve.title}</div>
            <div class="text-xs text-gray-500">{cve.description}</div>
            <div class="text-xs text-gray-400">
              影响版本: {cve.affected.join(', ')}
            </div>
            {#if cve.refs && cve.refs.length > 0}
              <div class="flex gap-1">
                {#each cve.refs as ref}
                  <a
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    class="text-xs text-blue-500 hover:text-blue-400 underline"
                  >
                    NVD
                  </a>
                {/each}
              </div>
            {/if}
          </div>
        {/each}
      {:else}
        <div class="card p-3 text-center">
          <div class="text-sm">未找到已知 CVE</div>
          <div class="text-xs text-gray-400 mt-1">
            未检测到版本信息或该版本暂无已知漏洞
          </div>
        </div>
      {/if}
    </div>
  {/if}

  <!-- 未激活时的提示 -->
  {#if !hookActive && totalEvents === 0}
    <div class="card p-3 text-center space-y-1">
      <div class="text-sm">RuoYi 路由分析</div>
      <div class="text-xs text-gray-400">
        注册 Hook 后将自动捕获 RuoYi 框架的动态路由、API 请求等流量数据，
        并匹配已知 CVE 漏洞库进行安全评估。
      </div>
    </div>
  {/if}
</div>
