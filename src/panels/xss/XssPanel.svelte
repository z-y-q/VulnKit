<script lang="ts">
  // XSS 扫描面板（对齐 v5 完整能力）
  // 三大区块：① 反射扫描（参数×payload）② 注入点管理（采集/筛选/批量）③ DOM Sink 静态分析
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl, getActiveTab, execInTab } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore } from '@/stores/ui';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import { scanSettingsStore } from '@/stores/settings';
  import { runConcurrent } from '@/lib/core/concurrency';
  import { compareSeverity } from '@/lib/types/severity';
  import UrlInput from '@/components/scanner/UrlInput.svelte';
  import ScanProgress from '@/components/scanner/ScanProgress.svelte';
  import SeverityBadge from '@/components/scanner/SeverityBadge.svelte';
  import { copyText as clipboardCopy } from '@/lib/actions/clipboard';
  import ResultToolbar from '@/components/results/ResultToolbar.svelte';
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import { type ResultAdapter, type ResultQuery } from '@/lib/results/result-adapter';
  import { downloadText, buildFilename } from '@/lib/actions/download';
  import { toCsv } from '@/lib/actions/serializers';
  import type { ProbeResult } from '@/lib/types/messaging';
  import {
    buildPayloadsForContext,
    detectContext,
    findReflection,
    isSanitized,
    assessSeverity,
    severityLabel,
    analyzeSinkLine,
    XSS_MARKERS,
    REFLECTION_PROBE,
    XSS_SORT_FNS,
    type XssFinding,
    type XssContext,
    type XssSeverity,
    type SinkMatch,
  } from '@/lib/scanners/xss-engine';

  // ===== 注入点（结构化，带来源/URL/method）=====
  type ParamSource = 'url' | 'link' | 'form' | 'ajax';
  interface InjectPoint {
    id: string;          // 去重键: source|url|param|method
    source: ParamSource;
    url: string;         // 该注入点的基础 URL
    param: string;
    method: 'GET' | 'POST';
    selected: boolean;
  }

  const SOURCE_LABEL: Record<ParamSource, string> = {
    url: 'URL', link: '链接', form: '表单', ajax: 'AJAX',
  };
  const SOURCE_CLASS: Record<ParamSource, string> = {
    url: 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300',
    link: 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300',
    form: 'bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300',
    ajax: 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300',
  };

  // ===== 状态 =====
  let targetUrl = $state('');
  let scanning = $state(false);
  let scanned = $state(0);
  let total = $state(0);
  let findings = $state<XssFinding[]>([]);
  let query = $state<ResultQuery>({ search: '', filters: {}, sort: { key: 'severity', direction: 'asc' } });
  let customPayload = $state('');
  let useCustom = $state(false);
  let useHarvest = $state(true);
  let usePost = $state(false);
  let encoding = $state<'none' | 'url' | 'html' | 'base64'>('none');
  let cancelled = $state(false);

  // 注入点管理
  let points = $state<InjectPoint[]>([]);
  let pointFilter = $state<ParamSource | 'all'>('all');
  let pointSearch = $state('');
  let pointSort = $state<'source' | 'url' | 'param'>('source');

  // AJAX 拦截
  let capturedAjax = $state<{ url: string; method: string; params: string[] }[]>([]);
  let intercepting = $state(false);
  let interceptMsg = $state('');

  // DOM Sink 分析
  let sinkLoading = $state(false);
  let sinks = $state<(SinkMatch & { recommended: string[] })[]>([]);

  $effect(() => {
    getActiveTabUrl().then(u => {
      if (u) targetUrl = u;
    });
  });

  // ===== 派生：结果（统一 ResultAdapter，供 ResultToolbar/ExportMenu 消费）=====
  const xssAdapter: ResultAdapter<XssFinding> = {
    apply(items, q) {
      let list = items;
      if (q.filters.scope?.includes('vuln')) list = list.filter((f) => f.reflected && !f.sanitized);
      const kw = q.search.trim().toLowerCase();
      if (kw) list = list.filter((f) => xssAdapter.getSearchText(f).toLowerCase().includes(kw));
      return [...list].sort((a, b) => {
        if (q.sort.key === 'param') return a.param.localeCompare(b.param);
        if (q.sort.key === 'context') return a.context.localeCompare(b.context);
        return compareSeverity(a.severity, b.severity);
      });
    },
    getSearchText(f) {
      return `${f.param} ${f.payload} ${f.context} ${f.evidence ?? ''}`;
    },
    getId(f) {
      return f.param + f.payload + f.context;
    },
  };

  let filteredFindings = $derived(xssAdapter.apply(findings, query));
  let vulnOnly = $derived(query.filters.scope?.includes('vuln') ?? false);
  function toggleVuln() {
    query.filters = vulnOnly ? {} : { scope: ['vuln'] };
  }

  let vulnCount = $derived(findings.filter((f) => f.reflected && !f.sanitized).length);
  let reflectedCount = $derived(findings.filter((f) => f.reflected).length);

  // ===== 派生：注入点视图 =====
  let filteredPoints = $derived.by(() => {
    let list = points;
    if (pointFilter !== 'all') list = list.filter(p => p.source === pointFilter);
    if (pointSearch.trim()) {
      const q = pointSearch.toLowerCase();
      list = list.filter(p => p.param.toLowerCase().includes(q) || p.url.toLowerCase().includes(q));
    }
    return [...list].sort((a, b) => {
      if (pointSort === 'url') return a.url.localeCompare(b.url);
      if (pointSort === 'param') return a.param.localeCompare(b.param);
      return a.source.localeCompare(b.source);
    });
  });

  const CTX_LABELS: Record<XssContext, string> = {
    html: 'HTML 文本', attr: '属性', script: 'Script', url: 'URL', style: 'Style',
  };

  // ===== Findings 持久化 =====
  function mapToFindings(fs: XssFinding[]): ScanFinding[] {
    return fs
      .filter(f => f.reflected && !f.sanitized)
      .map(f => ({
        title: `XSS [${f.param}] (${f.context})`,
        severity: f.severity,
        detail: f.payload,
        evidence: f.evidence,
        url: targetUrl,
      }));
  }

  // ===== 编码 =====
  function encodePayload(payload: string, enc: typeof encoding): string {
    if (enc === 'none') return payload;
    if (enc === 'url') return encodeURIComponent(payload);
    if (enc === 'html') {
      return payload.replace(/[&<>"'/]/g, (c) =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;', '/': '&#x2F;' }[c]!),
      );
    }
    if (enc === 'base64') {
      try { return btoa(unescape(encodeURIComponent(payload))); } catch { return payload; }
    }
    return payload;
  }

  // ===== 注入点采集 =====
  function makeId(source: ParamSource, url: string, param: string, method: string): string {
    return `${source}|${url}|${param}|${method}`;
  }

  function urlQueryParams(url: string): string[] {
    try {
      const u = new URL(url);
      return Array.from(new Set(u.searchParams.keys()));
    } catch { return []; }
  }

  /** 从当前页面 DOM 采集 link + form 注入点（MAIN world）*/
  async function harvestDomPoints(): Promise<InjectPoint[]> {
    const tab = await getActiveTab();
    if (!tab?.id) return [];
    const raw = await execInTab<{ source: string; url: string; param: string; method: string }[]>(tab.id, function () {
      const out: { source: string; url: string; param: string; method: string }[] = [];
      const seen = new Set<string>();
      const push = (s: string, url: string, p: string, m: string) => {
        const k = s + '|' + url + '|' + p + '|' + m;
        if (seen.has(k) || p.length > 40) return;
        seen.add(k); out.push({ source: s, url: url, param: p, method: m });
      };
      // 链接
      document.querySelectorAll('a[href]').forEach(function (el) {
        try {
          const u = new URL((el as HTMLAnchorElement).href, location.href);
          if (u.origin !== location.origin) return;
          u.searchParams.forEach(function (_v: string, k: string) { push('link', u.origin + u.pathname, k, 'GET'); });
        } catch (e) { /* */ }
      });
      // 表单
      document.querySelectorAll('form').forEach(function (f) {
        let action = f.action || location.href;
        try { action = new URL(action, location.href).href; } catch (e) { /* */ }
        const method = (f.method || 'get').toUpperCase() === 'POST' ? 'POST' : 'GET';
        f.querySelectorAll('input[name],textarea[name],select[name]').forEach(function (el) {
          const n = (el as HTMLInputElement).name;
          if (n) push('form', action, n, method);
        });
      });
      return out;
    }, { world: 'MAIN' });
    return (raw || []).map(r => ({
      id: makeId(r.source as ParamSource, r.url, r.param, r.method),
      source: r.source as ParamSource, url: r.url, param: r.param,
      method: r.method as 'GET' | 'POST', selected: true,
    }));
  }

  /** 采集注入点：URL query + (可选 DOM 收割) + AJAX 已捕获 */
  async function collectPoints(): Promise<InjectPoint[]> {
    const v = validateProbeUrl(targetUrl);
    const baseOk = !('error' in v);
    const out: InjectPoint[] = [];
    const seen = new Set<string>();
    const add = (p: InjectPoint) => { if (!seen.has(p.id)) { seen.add(p.id); out.push(p); } };

    // 1) 当前 URL query（来源 url）
    if (baseOk) {
      let baseUrl: string;
      try { baseUrl = new URL(targetUrl).origin + new URL(targetUrl).pathname; } catch { baseUrl = targetUrl; }
      for (const param of urlQueryParams(targetUrl)) {
        add({ id: makeId('url', baseUrl, param, 'GET'), source: 'url', url: baseUrl, param, method: 'GET', selected: true });
      }
    }
    // 2) DOM 收割
    if (useHarvest) for (const p of await harvestDomPoints()) add(p);
    // 3) AJAX 拦截捕获
    for (const cap of capturedAjax) {
      let baseUrl: string;
      try { const u = new URL(cap.url, targetUrl); baseUrl = u.origin + u.pathname; } catch { baseUrl = cap.url; }
      const method = cap.method.toUpperCase() === 'POST' ? 'POST' : 'GET';
      for (const param of cap.params) {
        add({ id: makeId('ajax', baseUrl, param, method), source: 'ajax', url: baseUrl, param, method, selected: true });
      }
    }
    return out;
  }

  /** 显式采集并填入注入点列表 */
  async function harvestPoints() {
    const collected = await collectPoints();
    if (collected.length === 0) {
      toastStore.show('未采集到注入点（开启 DOM 收割或 AJAX 拦截可获取更多）', 'warning');
      return;
    }
    // 合并已存在点（保留已有选中状态）
    const prev = new Map(points.map(p => [p.id, p]));
    points = collected.map(p => prev.get(p.id) ?? p);
    toastStore.show(`采集到 ${points.length} 个注入点`, 'success');
  }

  function clearPoints() { points = []; }
  function toggleAll(selected: boolean) { points = points.map(p => ({ ...p, selected })); }
  let allSelected = $derived(points.length > 0 && points.every(p => p.selected));

  // ===== AJAX 拦截器（MAIN world hook XHR/fetch）=====
  async function installAjaxIntercept(): Promise<boolean> {
    const tab = await getActiveTab();
    if (!tab?.id) return false;
    const ok = await execInTab<boolean>(tab.id, function () {
      const w = window as any;
      if (w.__vkXssIntActive) return true;
      w.__vkXssInt = [];
      const extractParams = (url: string, body?: string): string[] => {
        const ps: string[] = [];
        try { const u = new URL(url, location.href); u.searchParams.forEach((_v: string, k: string) => { if (k.length <= 40) ps.push(k); }); } catch (e) { /* */ }
        if (body) {
          if (/^[a-z]/i.test(body)) {
            try { new URLSearchParams(body).forEach((_v: string, k: string) => { if (k.length <= 40) ps.push(k); }); } catch (e) { /* */ }
          }
          if (body.trim().startsWith('{') || body.trim().startsWith('[')) {
            try {
              const walk = (obj: any, prefix = '') => {
                if (!obj || typeof obj !== 'object') return;
                for (const k of Object.keys(obj)) {
                  const v = obj[k];
                  if (typeof v === 'string' || typeof v === 'number') { if (k.length <= 40) ps.push(prefix ? prefix + '.' + k : k); }
                  else if (typeof v === 'object') walk(v, prefix ? prefix + '.' + k : k);
                }
              };
              walk(JSON.parse(body));
            } catch (e) { /* */ }
          }
        }
        return ps;
      };
      const origFetch = w.fetch;
      w.fetch = function (input: any, init?: any) {
        try {
          const url = typeof input === 'string' ? input : (input && input.url) || '';
          const body = init && init.body ? String(init.body) : '';
          const ps = extractParams(url, body);
          if (ps.length) w.__vkXssInt.push({ url, method: (init && init.method) || 'GET', params: ps });
        } catch (e) { /* */ }
        return origFetch.apply(this, arguments);
      };
      const OrigOpen = XMLHttpRequest.prototype.open;
      const OrigSend = XMLHttpRequest.prototype.send;
      let curUrl = '', curMethod = 'GET';
      XMLHttpRequest.prototype.open = function (method: string, url: string) {
        curMethod = method; curUrl = url;
        return OrigOpen.apply(this, arguments as any);
      };
      XMLHttpRequest.prototype.send = function (body?: any) {
        try {
          const ps = extractParams(curUrl, body ? String(body) : '');
          if (ps.length) w.__vkXssInt.push({ url: curUrl, method: curMethod, params: ps });
        } catch (e) { /* */ }
        return OrigSend.apply(this, arguments as any);
      };
      w.__vkXssIntActive = true;
      w.__vkXssRestore = function () {
        try { w.fetch = origFetch; XMLHttpRequest.prototype.open = OrigOpen; XMLHttpRequest.prototype.send = OrigSend; w.__vkXssIntActive = false; } catch (e) { /* */ }
      };
      return true;
    }, { world: 'MAIN' });
    return ok === true;
  }

  async function collectAjaxIntercept(): Promise<{ url: string; method: string; params: string[] }[]> {
    const tab = await getActiveTab();
    if (!tab?.id) return [];
    const data = await execInTab<{ url: string; method: string; params: string[] }[]>(tab.id, function () {
      const w = window as any;
      const captured = (w.__vkXssInt || []).slice();
      if (typeof w.__vkXssRestore === 'function') w.__vkXssRestore();
      return captured;
    }, { world: 'MAIN' });
    return Array.isArray(data) ? data : [];
  }

  async function runIntercept() {
    if (intercepting) return;
    const ok = await installAjaxIntercept();
    if (!ok) { toastStore.show('拦截器安装失败（可能无权限）', 'error'); return; }
    intercepting = true;
    interceptMsg = '拦截中... 请操作页面触发 AJAX（8 秒后自动采集）';
    let remaining = 8;
    const timer = setInterval(() => {
      remaining--;
      if (remaining > 0) interceptMsg = `拦截中... 请操作页面触发 AJAX（${remaining} 秒后采集）`;
    }, 1000);
    setTimeout(async () => {
      clearInterval(timer);
      const data = await collectAjaxIntercept();
      intercepting = false;
      capturedAjax = data;
      const n = data.reduce((s, e) => s + e.params.length, 0);
      interceptMsg = n
        ? `已捕获 ${data.length} 个请求 / ${n} 个参数（将并入采集）`
        : '未捕获到 AJAX 参数（页面可能未发起请求）';
      toastStore.show(`捕获 ${n} 个参数`, n ? 'success' : 'info');
    }, 8000);
  }

  function clearIntercept() { capturedAjax = []; interceptMsg = ''; }

  // ===== 探测 =====
  function buildTestUrl(baseUrl: string, param: string, payload: string): string {
    try {
      const u = new URL(baseUrl);
      u.searchParams.set(param, payload);
      return u.href;
    } catch { return ''; }
  }

  async function probeSingle(
    point: InjectPoint,
    payload: string,
  ): Promise<XssFinding | null> {
    try {
      const enc = encodePayload(payload, encoding);
      let probeUrl = point.url;
      let postBody: string | undefined;
      if (point.method === 'POST') {
        postBody = `${encodeURIComponent(point.param)}=${encodeURIComponent(enc)}`;
      } else {
        probeUrl = buildTestUrl(point.url, point.param, enc);
        if (!probeUrl) return null;
      }
      const res = await sendMessage({
        type: 'FETCH_PROBE',
        url: probeUrl,
        method: point.method,
        body: postBody,
        headers: point.method === 'POST' ? { 'Content-Type': 'application/x-www-form-urlencoded' } : undefined,
        includeBody: true,
        timeout: $scanSettingsStore.requestTimeoutMs,
      });
      const r = res as ProbeResult;
      const body = r.body ?? '';

      // marker：优先用金丝雀，否则用 payload 本身
      let marker = payload;
      for (const m of XSS_MARKERS) {
        if (payload.includes(m)) { marker = m; break; }
      }

      const refl = findReflection(body, marker);
      const sanitized = isSanitized(body, payload);
      const ctx = refl.found ? refl.context : detectContext(body.substring(0, 500));
      const sev = assessSeverity(ctx, refl.found, sanitized);

      return {
        param: point.param,
        payload,
        context: ctx,
        reflected: refl.found,
        sanitized,
        severity: sev,
        evidence: refl.found ? refl.surrounding : undefined,
      };
    } catch {
      return null;
    }
  }

  async function probeReflection(
    point: InjectPoint,
  ): Promise<{ reflected: boolean; context: XssContext }> {
    try {
      let probeUrl = point.url;
      let body: string | undefined;
      if (point.method === 'POST') {
        body = `${encodeURIComponent(point.param)}=${encodeURIComponent(REFLECTION_PROBE)}`;
      } else {
        const u = new URL(point.url);
        u.searchParams.set(point.param, REFLECTION_PROBE);
        probeUrl = u.href;
      }
      const res = await sendMessage({
        type: 'FETCH_PROBE',
        url: probeUrl,
        method: point.method,
        body,
        headers: point.method === 'POST' ? { 'Content-Type': 'application/x-www-form-urlencoded' } : undefined,
        includeBody: true,
        timeout: $scanSettingsStore.requestTimeoutMs,
      });
      const r = res as ProbeResult;
      const refl = findReflection(r.body ?? '', REFLECTION_PROBE);
      return { reflected: refl.found, context: refl.context };
    } catch {
      return { reflected: false, context: 'html' };
    }
  }

  // ===== 主扫描 =====
  async function scan() {
    const v = validateProbeUrl(targetUrl);
    if ('error' in v) {
      toastStore.show('请输入合法的 http(s) URL', 'error');
      return;
    }

    // 注入点：优先使用列表中选中的；列表为空则现场采集
    let activePoints: InjectPoint[];
    if (points.length > 0) {
      activePoints = points.filter(p => p.selected);
      if (activePoints.length === 0) {
        toastStore.show('请至少勾选一个注入点', 'warning');
        return;
      }
    } else {
      activePoints = await collectPoints();
      // 同步回填列表
      points = activePoints;
    }

    if (activePoints.length === 0) {
      toastStore.show('未发现注入点（可点击「采集注入点」或开启 DOM 收割）', 'warning');
      return;
    }

    scanning = true;
    findings = [];
    scanned = 0;
    cancelled = false;

    let payloads: string[];
    if (useCustom && customPayload.trim()) {
      payloads = customPayload.split('\n').map(s => s.trim()).filter(Boolean);
    } else {
      const allPayloads = new Set<string>();
      for (const ctx of ['html', 'attr', 'script', 'url', 'style'] as XssContext[]) {
        for (const p of buildPayloadsForContext(ctx)) allPayloads.add(p);
      }
      payloads = [...allPayloads];
    }

    // Phase 1: 反射快速过滤
    let reflectedPoints: InjectPoint[] = [];
    if (!useCustom) {
      const probeResults = new Set<string>();
      await runConcurrent(activePoints, async (pt) => {
        const r = await probeReflection(pt);
        if (r.reflected) probeResults.add(pt.id);
        scanned++;
      }, { concurrency: $scanSettingsStore.concurrency, cancelled: () => cancelled });

      reflectedPoints = activePoints.filter(p => probeResults.has(p.id));
      if (reflectedPoints.length === 0) {
        scanning = false;
        toastStore.show(`${activePoints.length} 个注入点均无反射`, 'success');
        return;
      }
    } else {
      reflectedPoints = activePoints;
    }

    // Phase 2: 反射点 × payload
    const tasks: (() => Promise<XssFinding | null>)[] = [];
    for (const pt of reflectedPoints) {
      for (const payload of payloads) {
        tasks.push(() => probeSingle(pt, payload));
      }
    }

    total = tasks.length;
    scanned = 0;
    const collected: XssFinding[] = [];
    await runConcurrent(tasks, async (task) => {
      const r = await task();
      if (r) collected.push(r);
      scanned++;
    }, { concurrency: $scanSettingsStore.concurrency, cancelled: () => cancelled });

    findings = collected.sort(XSS_SORT_FNS.severity);
    scanning = false;

    if (cancelled) { toastStore.show('扫描已取消', 'info'); return; }

    try {
      await scanHistoryStore.addScan({ url: targetUrl, module: 'xssscan', findings: mapToFindings(findings) });
    } catch { /* store failure must not break scan */ }

    if (vulnCount > 0) {
      toastStore.show(`发现 ${vulnCount} 个潜在 XSS 点（${reflectedCount} 个反射）`, 'warning');
    } else if (reflectedCount > 0) {
      toastStore.show(`${reflectedCount} 个参数存在反射，但已被净化`, 'success');
    } else {
      toastStore.show(`XSS 检测完成，未发现漏洞（${total} 个测试）`, 'success');
    }
  }

  function cancel() { cancelled = true; }

  // ===== DOM Sink 静态分析 =====
  async function analyzeSinks() {
    const tab = await getActiveTab();
    if (!tab?.id) { toastStore.show('无可用标签页', 'error'); return; }
    sinkLoading = true;
    sinks = [];
    const lines = await execInTab<{ code: string; source: string }[]>(tab.id, function () {
      const out: { code: string; source: string }[] = [];
      const MAX = 2000;
      // inline script
      document.querySelectorAll('script:not([src])').forEach(function (s) {
        const text = s.textContent || '';
        text.split('\n').forEach(function (line) {
          const t = line.trim();
          if (t.length < 5 || /^return\b/.test(t)) return;
          out.push({ code: t, source: 'inline' });
        });
      });
      // external script src
      document.querySelectorAll('script[src]').forEach(function (s) {
        out.push({ code: 'script src=' + (s as HTMLScriptElement).src, source: 'external' });
      });
      // event-attr
      const els = document.querySelectorAll('*');
      let n = 0;
      els.forEach(function (el) {
        if (n++ > MAX) return;
        for (const attr of Array.from((el as Element).attributes)) {
          if (/^on[a-z]+$/i.test(attr.name) && attr.value) {
            out.push({ code: attr.name + '=' + attr.value, source: 'event-attr' });
          }
        }
      });
      // js-href
      document.querySelectorAll('a[href^="javascript:"]').forEach(function (el) {
        out.push({ code: 'href=' + (el as HTMLAnchorElement).href, source: 'js-href' });
      });
      return out;
    }, { world: 'MAIN' });

    const matches: (SinkMatch & { recommended: string[] })[] = [];
    for (const { code, source } of lines || []) {
      const m = analyzeSinkLine(code, source);
      if (m) {
        // 推荐上下文 payload
        const rec: string[] = [];
        const seen = new Set<string>();
        for (const ctx of m.contexts) {
          const ctxKey = ctx as XssContext;
          if (['innerHTML', 'outerHTML', 'documentWrite', 'insertAdjacentHTML'].includes(ctx)) {
            for (const p of buildPayloadsForContext('html')) if (!seen.has(p)) { seen.add(p); rec.push(p); }
          } else if (ctx === 'attribute') {
            for (const p of buildPayloadsForContext('attr')) if (!seen.has(p)) { seen.add(p); rec.push(p); }
          } else if (ctx === 'eval' || ctx === 'scriptSrc' || ctx === 'script-src') {
            for (const p of buildPayloadsForContext('script')) if (!seen.has(p)) { seen.add(p); rec.push(p); }
          }
        }
        matches.push({ ...m, recommended: rec.slice(0, 3) });
      }
    }
    // 按 score 降序
    matches.sort((a, b) => b.score - a.score);
    sinks = matches;
    sinkLoading = false;
    if (matches.length === 0) {
      toastStore.show('未发现高危 DOM Sink', 'info');
    } else {
      toastStore.show(`发现 ${matches.length} 个 DOM Sink`, 'warning');
      // 写入 findings
      try {
        const sinkFindings: ScanFinding[] = matches
          .filter(m => m.severity === 'critical' || m.severity === 'high')
          .slice(0, 20)
          .map(m => ({
            title: `DOM Sink [${m.contexts.join(',')}] (${m.source})`,
            severity: m.severity,
            detail: m.code.slice(0, 200),
            url: targetUrl,
          }));
        if (sinkFindings.length) {
          await scanHistoryStore.addScan({ url: targetUrl, module: 'xssscan', findings: sinkFindings });
        }
      } catch { /* */ }
    }
  }

  function clearSinks() { sinks = []; }

  // ===== 单条复制 =====
  async function copyFinding(f: XssFinding) {
    const text = [
      `Param: ${f.param}`, `Payload: ${f.payload}`,
      `Context: ${CTX_LABELS[f.context] ?? f.context}`, `Severity: ${severityLabel(f.severity)}`,
      `Reflected: ${f.reflected}`, `Sanitized: ${f.sanitized}`,
      f.evidence ? `Evidence: ${f.evidence}` : '',
    ].filter(Boolean).join('\n');
    await clipboardCopy(text, '已复制到剪贴板');
  }

  async function copyText(text: string, msg = '已复制') {
    await clipboardCopy(text, msg);
  }

  // ===== 批量导出 =====
  function downloadBlob(content: string, filename: string, type: string) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function exportPointsCsv() {
    if (points.length === 0) { toastStore.show('无注入点', 'warning'); return; }
    const rows: string[][] = [['Source', 'URL', 'Param', 'Method']];
    for (const p of points) rows.push([p.source, p.url, p.param, p.method]);
    downloadText(toCsv(rows), buildFilename('xss-points', 'csv'), 'text/csv');
    toastStore.show('注入点 CSV 已导出', 'success');
  }

  // —— 导出/复制序列化器（作用于当前筛选 filteredFindings，展示/导出同源 §6.1）——
  function xssCsv(items: XssFinding[]): string {
    return toCsv([
      ['Severity', 'Param', 'URL', 'Payload', 'Context', 'Reflected', 'Sanitized'],
      ...items.map((f) => [f.severity, f.param, targetUrl, f.payload, f.context, String(f.reflected), String(f.sanitized)]),
    ]);
  }
  function xssMd(items: XssFinding[]): string {
    const header = '| URL | Parameter | Context | Severity | Payload |';
    const sep = '|---|---|---|---|---|';
    const body = items
      .map((f) => `| ${targetUrl} | ${f.param} | ${f.context} | ${f.severity} | \`${f.payload.replace(/\|/g, '\\|')}\` |`)
      .join('\n');
    return `# XSS Findings\n\n${header}\n${sep}\n${body}`;
  }
  function xssText(items: XssFinding[]): string {
    const lines = [`XSS Findings @ ${targetUrl}`, `发现: ${items.length}`, ''];
    for (const f of items) {
      lines.push(`[${f.severity}] ${f.param} (${f.context})`);
      lines.push(`  Payload: ${f.payload}`);
      if (f.evidence) lines.push(`  Evidence: ${f.evidence}`);
    }
    return lines.join('\n');
  }

  function copyAllUrls() {
    if (points.length === 0) { toastStore.show('无注入点', 'warning'); return; }
    const lines: string[] = [];
    for (const p of points) {
      if (p.method === 'POST') {
        lines.push(`[POST] ${p.url}\n  参数: ${p.param}=<payload>`);
      } else {
        const u = buildTestUrl(p.url, p.param, 'XSS');
        lines.push(u);
      }
    }
    copyText(lines.join('\n'), '已复制全部 URL');
  }

  async function batchOpen() {
    const selected = points.filter(p => p.selected);
    if (selected.length === 0) { toastStore.show('请勾选注入点', 'warning'); return; }
    if (selected.length > 20) { toastStore.show('一次最多打开 20 个', 'warning'); return; }
    for (const p of selected) {
      const url = p.method === 'GET' ? buildTestUrl(p.url, p.param, REFLECTION_PROBE) : p.url;
      try { window.open(url, '_blank'); } catch { /* */ }
    }
    toastStore.show(`已打开 ${selected.length} 个测试 URL`, 'success');
  }

  /** 批量验证：在真实浏览器标签页中打开勾选的 GET 注入点，DOM 级检测探针是否反射（绕过 fetch 与浏览器差异）*/
  let verifying = $state(false);
  let verifyResults = $state<{ url: string; param: string; reflected: boolean }[]>([]);
  async function batchVerify() {
    const selected = points.filter(p => p.selected && p.method === 'GET');
    if (selected.length === 0) { toastStore.show('请勾选 GET 注入点（浏览器验证仅支持 GET）', 'warning'); return; }
    if (selected.length > 10) { toastStore.show('一次最多验证 10 个', 'warning'); return; }
    verifying = true; verifyResults = [];
    toastStore.show(`正在打开 ${selected.length} 个页面并验证反射...`, 'info');
    const tabs: { p: typeof selected[number]; tabId: number }[] = [];
    for (const p of selected) {
      try {
        const tab = await browser.tabs.create({ url: buildTestUrl(p.url, p.param, REFLECTION_PROBE), active: false });
        if (tab?.id) tabs.push({ p, tabId: tab.id });
      } catch { /* */ }
    }
    // 等待页面加载渲染
    await new Promise(r => setTimeout(r, 3000));
    for (const { p, tabId } of tabs) {
      let reflected = false;
      try {
        reflected = !!(await execInTab<boolean>(tabId, (mk: string) => {
          return document.documentElement.outerHTML.includes(mk);
        }, { world: 'MAIN', args: [REFLECTION_PROBE] }));
      } catch { /* 标签已关或无权限 */ }
      verifyResults = [...verifyResults, { url: p.url, param: p.param, reflected }];
      try { await browser.tabs.remove(tabId); } catch { /* */ }
    }
    verifying = false;
    const hits = verifyResults.filter(r => r.reflected).length;
    toastStore.show(`DOM 验证完成：${hits}/${verifyResults.length} 反射`, hits ? 'warning' : 'info');
  }

  async function sendToConsole() {
    if (findings.length === 0) { toastStore.show('无扫描结果', 'warning'); return; }
    const tab = await getActiveTab();
    if (!tab?.id) return;
    const data = findings.map(f => ({
      param: f.param, payload: f.payload, context: f.context,
      severity: f.severity, reflected: f.reflected, sanitized: f.sanitized,
    }));
    await execInTab(tab.id, function (ds: any[]) {
      try {
        console.group('%c[灵眸] XSS 扫描结果', 'color:#e74c3c;font-weight:bold');
        console.table(ds);
        console.groupEnd();
      } catch (e) { /* */ }
    }, { world: 'MAIN', args: [data] });
    toastStore.show(`已发送 ${data.length} 条到页面 Console`, 'success');
  }

  function generatePoc() {
    const vulns = findings.filter(f => f.reflected && !f.sanitized);
    if (vulns.length === 0) { toastStore.show('无可用漏洞生成 PoC', 'warning'); return; }
    const now = new Date();
    const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!));
    const crit = vulns.filter(f => f.severity === 'critical').length;
    const high = vulns.filter(f => f.severity === 'high').length;
    const cards = vulns.map((f, i) => {
      const testUrl = buildTestUrl(targetUrl, f.param, f.payload);
      return `<div class="card sev-${f.severity}">
        <div class="card-h"><span class="num">#${i + 1}</span>
        <span class="param">${esc(f.param)}</span>
        <span class="badge sev-${f.severity}">${f.severity}</span></div>
        <div class="row"><span>Context</span><b>${esc(f.context)}</b></div>
        <div class="row"><span>Payload</span><code>${esc(f.payload)}</code></div>
        ${f.evidence ? `<div class="row"><span>Evidence</span><code class="ev">${esc(f.evidence)}</code></div>` : ''}
        <div class="row"><span>Test URL</span><a href="${esc(testUrl)}" target="_blank">打开测试 ↗</a></div>
      </div>`;
    }).join('\n');
    const html = `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>XSS PoC Report — 灵眸</title>
<style>
  body{font-family:-apple-system,system-ui,sans-serif;max-width:980px;margin:0 auto;padding:24px;color:#222;background:#f7f8fa}
  h1{font-size:20px;margin:0 0 4px} .meta{color:#888;font-size:13px;margin-bottom:18px}
  .summary{display:flex;gap:12px;margin-bottom:20px}
  .stat{flex:1;background:#fff;border-radius:8px;padding:14px;text-align:center;border:1px solid #eee}
  .stat .n{font-size:28px;font-weight:700} .stat .l{font-size:12px;color:#888}
  .card{background:#fff;border-radius:8px;padding:14px 16px;margin-bottom:12px;border-left:4px solid #888}
  .sev-critical{border-color:#7f1d1d}.sev-high{border-color:#dc2626}.sev-medium{border-color:#f59e0b}.sev-low{border-color:#10b981}
  .card-h{display:flex;align-items:center;gap:10px;margin-bottom:8px}
  .num{color:#aaa;font-size:13px}.param{font-weight:600;font-family:monospace;flex:1}
  .badge{font-size:11px;padding:2px 8px;border-radius:10px;color:#fff;text-transform:uppercase}
  .badge.sev-critical{background:#7f1d1d}.badge.sev-high{background:#dc2626}.badge.sev-medium{background:#f59e0b}.badge.sev-low{background:#10b981}
  .row{font-size:13px;margin:4px 0}.row span{color:#888;display:inline-block;width:80px}
  code{font-family:monospace;background:#f1f3f5;padding:1px 6px;border-radius:3px;word-break:break-all}
  .ev{display:block;margin-top:2px;max-height:60px;overflow:hidden}
  a{color:#2563eb}
</style></head><body>
<h1>XSS PoC Report</h1>
<div class="meta">生成时间: ${now.toLocaleString('zh-CN')} · 目标: ${esc(targetUrl)} · Generated by 灵眸 (LingMou)</div>
<div class="summary">
  <div class="stat"><div class="n" style="color:#7f1d1d">${crit}</div><div class="l">Critical</div></div>
  <div class="stat"><div class="n" style="color:#dc2626">${high}</div><div class="l">High</div></div>
  <div class="stat"><div class="n">${vulns.length}</div><div class="l">Total</div></div>
</div>
${cards}
</body></html>`;
    downloadBlob(html, `xss-poc-${now.toISOString().slice(0, 10)}.html`, 'text/html');
    toastStore.show('PoC HTML 报告已生成', 'success');
  }
</script>

<div class="space-y-3">
  <!-- 输入 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <UrlInput bind:value={targetUrl} {scanning} buttonText="检测" onscan={scan} recordTarget />
      {#if scanning}
        <button class="btn btn-sm btn-danger shrink-0" onclick={cancel}>取消</button>
      {/if}
    </div>

    <div class="flex items-center gap-3 text-xs flex-wrap">
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={useHarvest} disabled={scanning} class="accent-blue-500" />
        <span>DOM 收割</span>
      </label>
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={usePost} disabled={scanning} class="accent-blue-500" />
        <span>测试 POST</span>
      </label>
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={useCustom} disabled={scanning} class="accent-blue-500" />
        <span>自定义 Payload</span>
      </label>
      <label class="flex items-center gap-1 cursor-pointer">
        <span class="text-gray-500">编码</span>
        <select class="input text-xs w-24 py-0.5" bind:value={encoding} disabled={scanning}>
          <option value="none">无</option>
          <option value="url">URL 编码</option>
          <option value="html">HTML 编码</option>
          <option value="base64">Base64</option>
        </select>
      </label>
    </div>

    <!-- AJAX 拦截器 -->
    <div class="card p-2 space-y-1 text-xs">
      <div class="flex items-center gap-2">
        <span class="text-gray-500 shrink-0">AJAX 拦截</span>
        {#if !intercepting}
          <button class="btn btn-xs btn-primary" onclick={runIntercept}>🪝 开始拦截</button>
        {:else}
          <button class="btn btn-xs btn-danger" disabled>拦截中...</button>
        {/if}
        {#if capturedAjax.length > 0}
          <span class="badge bg-blue-500 text-white">已捕获 {capturedAjax.length} 请求</span>
          <button class="text-xs text-gray-400 hover:text-primary ml-auto" onclick={clearIntercept}>清除</button>
        {/if}
      </div>
      {#if interceptMsg}
        <div class="text-blue-600 dark:text-blue-400">{interceptMsg}</div>
      {:else}
        <div class="text-gray-400">hook XHR/fetch，捕获 SPA 动态 API 的 URL/JSON body 参数</div>
      {/if}
    </div>

    {#if useCustom}
      <textarea
        class="input w-full text-sm font-mono"
        rows="2"
        placeholder="输入自定义 XSS payload（每行一个）"
        bind:value={customPayload}
      ></textarea>
    {:else}
      <div class="text-xs text-gray-400">自动提取注入点，使用反射探针 + 上下文 payload 并发检测</div>
    {/if}

    <ScanProgress {scanned} {total} {scanning} label="XSS 检测" />
  </div>

  <!-- 注入点管理 -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div class="text-sm font-medium">注入点管理 <span class="text-xs text-gray-400">({points.length > 0 ? points.filter(p => p.selected).length + '/' + points.length : '未采集'})</span></div>
      <div class="flex gap-1">
        <button class="btn btn-sm btn-primary" onclick={harvestPoints} disabled={scanning}>采集注入点</button>
        <button class="btn btn-sm" onclick={copyAllUrls} disabled={points.length === 0}>复制 URL</button>
        <button class="btn btn-sm" onclick={batchOpen} disabled={points.length === 0}>批量打开</button>
        <button class="btn btn-sm" onclick={batchVerify} disabled={points.length === 0 || verifying}>{verifying ? '验证中...' : '批量验证'}</button>
        <button class="btn btn-sm" onclick={exportPointsCsv} disabled={points.length === 0}>导出 CSV</button>
        <button class="btn btn-sm" onclick={clearPoints} disabled={points.length === 0}>清空</button>
      </div>
    </div>

    {#if points.length > 0}
      <!-- 来源筛选 + 搜索 + 排序 + 全选 -->
      <div class="flex items-center gap-2 text-xs flex-wrap">
        {#each ['all', 'url', 'link', 'form', 'ajax'] as sf}
          <button
            class="badge {pointFilter === sf ? 'bg-primary text-white' : 'bg-gray-200 dark:bg-gray-700'}"
            onclick={() => (pointFilter = sf as ParamSource | 'all')}
          >
            {sf === 'all' ? '全部' : SOURCE_LABEL[sf as ParamSource]}
          </button>
        {/each}
        <input class="input text-xs flex-1 min-w-24" placeholder="搜索 URL/参数..." bind:value={pointSearch} />
        <select class="input text-xs w-20" bind:value={pointSort}>
          <option value="source">来源</option>
          <option value="url">URL</option>
          <option value="param">参数</option>
        </select>
        <button class="btn btn-xs" onclick={() => toggleAll(!allSelected)}>
          {allSelected ? '取消全选' : '全选'}
        </button>
      </div>

      <!-- 注入点列表 -->
      <div class="space-y-1 max-h-52 overflow-y-auto">
        {#each filteredPoints as p (p.id)}
          <div class="flex items-center gap-2 text-xs p-1.5 rounded hover:bg-gray-50 dark:hover:bg-gray-800">
            <input type="checkbox" bind:checked={p.selected} class="accent-blue-500 shrink-0" />
            <span class="badge text-xs shrink-0 {SOURCE_CLASS[p.source]}">{SOURCE_LABEL[p.source]}</span>
            <span class="badge text-xs shrink-0 {p.method === 'POST' ? 'bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300' : 'bg-gray-100 dark:bg-gray-700'}">{p.method}</span>
            <span class="font-mono text-red-500 dark:text-red-400 shrink-0">{p.param}</span>
            <span class="text-gray-400 truncate flex-1" title={p.url}>{p.url}</span>
            <button
              class="text-gray-400 hover:text-primary shrink-0"
              onclick={() => copyText(p.method === 'GET' ? buildTestUrl(p.url, p.param, REFLECTION_PROBE) : p.url, '已复制')}
              title="复制测试 URL"
            >📋</button>
          </div>
        {/each}
      </div>

      {#if verifyResults.length > 0}
        <div class="card p-2 space-y-1">
          <div class="text-xs font-medium text-gray-500">DOM 验证结果（{verifyResults.filter(r => r.reflected).length}/{verifyResults.length} 反射）</div>
          <div class="space-y-0.5 max-h-32 overflow-y-auto">
            {#each verifyResults as r (r.url + r.param)}
              <div class="text-xs flex items-center gap-2">
                <span class="badge text-xs shrink-0 {r.reflected ? 'bg-red-500 text-white' : 'bg-gray-300 dark:bg-gray-700'}">{r.reflected ? '反射' : '未反射'}</span>
                <span class="font-mono text-red-500 dark:text-red-400 shrink-0">{r.param}</span>
                <span class="text-gray-400 truncate" title={r.url}>{r.url}</span>
              </div>
            {/each}
          </div>
        </div>
      {/if}
    {:else}
      <div class="text-xs text-gray-400">点击「采集注入点」从当前 URL、页面链接/表单、AJAX 捕获中提取注入点</div>
    {/if}
  </div>

  <!-- 工具栏：ResultToolbar 包裹 漏洞筛选 / 排序 / PoC·Console / 导出 -->
  {#if findings.length > 0}
    <ResultToolbar {query} total={findings.length} shown={filteredFindings.length} searchPlaceholder="搜索参数/payload...">
      <button
        class="badge cursor-pointer {vulnOnly ? 'bg-red-500 text-white' : 'bg-gray-200 dark:bg-gray-700'}"
        aria-pressed={vulnOnly}
        onclick={toggleVuln}
      >
        漏洞 {vulnCount}
      </button>
      <span class="badge bg-blue-500 text-white">反射 {reflectedCount}</span>
      <select
        class="input text-xs w-24"
        value={query.sort.key}
        onchange={(e) => { query.sort.key = (e.currentTarget as HTMLSelectElement).value; }}
        aria-label="排序"
      >
        <option value="severity">按严重性</option>
        <option value="param">按参数</option>
        <option value="context">按上下文</option>
      </select>
      <button class="btn btn-xs btn-danger" onclick={generatePoc}>📄 PoC</button>
      <button class="btn btn-xs" onclick={sendToConsole}>Console</button>
      <ExportMenu items={filteredFindings} module="xss" serializers={{ csv: xssCsv, markdown: xssMd, text: xssText }} />
    </ResultToolbar>
  {/if}

  <!-- 结果 -->
  {#if filteredFindings.length > 0}
    <div class="space-y-1.5">
      {#each filteredFindings as f (f.param + f.payload + f.context)}
        <div class="card p-2.5 space-y-1">
          <div class="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={f.severity} />
            <span class="badge text-xs bg-gray-200 dark:bg-gray-700">{f.param}</span>
            <span class="badge text-xs bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300">
              {CTX_LABELS[f.context] ?? f.context}
            </span>
            {#if f.reflected}
              <span class="badge text-xs bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300">反射</span>
            {/if}
            {#if f.sanitized}
              <span class="badge text-xs bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300">已净化</span>
            {/if}
            <button class="ml-auto text-xs text-gray-400 hover:text-primary" onclick={() => copyFinding(f)}>复制</button>
          </div>
          <div class="text-xs font-mono text-gray-600 dark:text-gray-300 break-all max-h-16 overflow-hidden">{f.payload}</div>
          {#if f.evidence}
            <div class="text-xs text-gray-400 break-all max-h-10 overflow-hidden font-mono">{f.evidence}</div>
          {/if}
        </div>
      {/each}
    </div>
  {:else if !scanning && findings.length === 0 && scanned > 0}
    <div class="text-center text-gray-400 text-sm py-8">未发现 XSS 漏洞</div>
  {/if}

  <!-- DOM Sink 分析 -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div class="text-sm font-medium">DOM Sink 静态分析</div>
      <div class="flex gap-1">
        <button class="btn btn-sm btn-danger" onclick={analyzeSinks} disabled={sinkLoading}>
          {sinkLoading ? '分析中...' : '分析 DOM 汇点'}
        </button>
        <button class="btn btn-sm" onclick={clearSinks} disabled={sinks.length === 0}>清空</button>
      </div>
    </div>
    <div class="text-xs text-gray-400">扫描页面内联脚本/外部脚本/事件属性/javascript: 链接中的危险 Sink（innerHTML/eval/document.write 等），评分 + 推荐上下文 payload</div>

    {#if sinks.length > 0}
      <div class="space-y-1.5 max-h-80 overflow-y-auto">
        {#each sinks as s, i (i)}
          <div class="card p-2 space-y-1">
            <div class="flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={s.severity} />
              <span class="badge text-xs bg-gray-200 dark:bg-gray-700">评分 {s.score}/10</span>
              <span class="badge text-xs bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300">{s.source}</span>
              {#each s.contexts as c}
                <span class="badge text-xs bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300">{c}</span>
              {/each}
              {#each s.sanitizers as san}
                <span class="badge text-xs bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300">🛡 {san}</span>
              {/each}
            </div>
            <div class="text-xs font-mono text-gray-600 dark:text-gray-300 break-all max-h-14 overflow-hidden">{s.code}</div>
            {#if s.recommended.length > 0}
              <div class="flex items-center gap-1 flex-wrap">
                <span class="text-xs text-gray-400">推荐:</span>
                {#each s.recommended as rec}
                  <button
                    class="badge text-xs font-mono bg-yellow-50 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300 hover:bg-yellow-100 cursor-pointer"
                    onclick={() => copyText(rec, 'Payload 已复制')}
                  >{rec.length > 40 ? rec.slice(0, 40) + '...' : rec}</button>
                {/each}
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {:else if !sinkLoading}
      <div class="text-xs text-gray-400 text-center py-4">点击「分析 DOM 汇点」检测 DOM XSS 危险 sink</div>
    {/if}
  </div>

  {#if !scanning && findings.length === 0 && scanned === 0 && sinks.length === 0}
    <div class="text-center text-gray-400 text-sm py-4">
      输入目标 URL → 采集注入点 → 检测反射；或直接「分析 DOM 汇点」
    </div>
  {/if}
</div>
