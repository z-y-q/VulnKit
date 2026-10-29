<script lang="ts">
  // SQLi 报错注入扫描面板
  // 流程：采集注入点（URL 参数 + 表单字段）→ 每点取基线 → 报错 payload 矩阵探测 → 基线对比确认
  // 仅做报错注入（无误报、无合规风险）；时间盲注（SLEEP）/ 布尔盲注留后续阶段
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl, getActiveTab, execInTab } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore, autoRunStore } from '@/stores/ui';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import { scanSettingsStore } from '@/stores/settings';
  import { runConcurrent } from '@/lib/core/concurrency';
  import UrlInput from '@/components/scanner/UrlInput.svelte';
  import ScanProgress from '@/components/scanner/ScanProgress.svelte';
  import EmptyState from '@/components/scanner/EmptyState.svelte';
  import SeverityBadge from '@/components/scanner/SeverityBadge.svelte';
  import ResultToolbar from '@/components/results/ResultToolbar.svelte';
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import ErrorState from '@/components/feedback/ErrorState.svelte';
  import DetailDrawer from '@/components/results/DetailDrawer.svelte';
  import { createTaskController, IDLE, type TaskState } from '@/lib/tasks/task-controller';
  import { toCsv, toMarkdownTable } from '@/lib/actions/serializers';
  import { type ResultAdapter, type ResultQuery } from '@/lib/results/result-adapter';
  import type { DetailField, DetailHandoffAction } from '@/components/results/detail-drawer-utils';
  import type { ProbeResult } from '@/lib/types/messaging';
  import {
    SQLI_ERROR_PAYLOADS,
    isNewSqlError,
    assessSqliSeverity,
    sqlSeverityLabel,
    dbLabel,
    SQLI_SORT_FNS,
    buildBooleanBlindPair,
    analyzeBooleanBlind,
    type SqliFinding,
  } from '@/lib/scanners/sqli-engine';

  // ===== 注入点 =====
  type ParamSource = 'url' | 'form' | 'header';
  interface InjectPoint {
    id: string; // 去重键: source|url|param|method
    source: ParamSource;
    url: string;
    param: string;
    method: 'GET' | 'POST';
    /** URL 参数的原始值（布尔盲注构造恒真/恒假变体用） */
    originalValue?: string;
  }

  /** HTTP 头注入点：日志型注入（Referer/XFF 入库回显）的高频入口 */
  const HEADER_INJECT_POINTS = ['Referer', 'X-Forwarded-For', 'User-Agent'] as const;

  // ===== 状态 =====
  let targetUrl = $state('');
  let findings = $state<SqliFinding[]>([]);
  let pointCount = $state(0);
  let query = $state<ResultQuery>({ search: '', filters: {}, sort: { key: 'severity', direction: 'asc' } });
  // 布尔盲注（恒真/恒假响应差异对比）：请求为正常语义变体，风险与普通访问相当
  let useBooleanBlind = $state(true);

  const adapter: ResultAdapter<SqliFinding> = {
    apply(items, q) {
      let list = items;
      const kw = q.search.trim().toLowerCase();
      if (kw) list = list.filter((i) => adapter.getSearchText(i).toLowerCase().includes(kw));
      return [...list].sort((a, b) => {
        if (q.sort.key === 'param') return a.param.localeCompare(b.param);
        if (q.sort.key === 'db') return a.db.localeCompare(b.db);
        return SQLI_SORT_FNS.severity(a, b);
      });
    },
    getSearchText(i) {
      return `${i.param} ${i.payload} ${i.db} ${dbLabel(i.db)} ${i.method} ${i.source} ${i.url} ${i.evidence}`;
    },
    getId(i) {
      return i.url + i.param + i.method + i.payload;
    },
  };

  let filtered = $derived(adapter.apply(findings, query));

  // 详情抽屉索引（基于当前筛选集）；结果集变化时关闭，避免索引错位
  let detailIndex = $state<number | null>(null);
  $effect(() => {
    void filtered;
    detailIndex = null;
  });

  $effect(() => {
    getActiveTabUrl().then((u) => {
      if (u) targetUrl = u;
    });
  });

  // ===== 注入点采集（URL 参数 + 表单字段）=====
  async function collectPoints(): Promise<InjectPoint[]> {
    const v = validateProbeUrl(targetUrl);
    if ('error' in v) return [];
    const base = v.parsed;
    const pts: InjectPoint[] = [];
    const baseUrl = base.origin + base.pathname;

    // 1. URL query params (GET)——记录原始值供布尔盲注使用
    base.searchParams.forEach((v, k) => {
      pts.push({ id: `url|${baseUrl}|${k}|GET`, source: 'url', url: baseUrl, param: k, method: 'GET', originalValue: v });
    });

    // 1.5 HTTP 头注入点（GET，头值带 payload，URL 不变）
    for (const h of HEADER_INJECT_POINTS) {
      pts.push({ id: `header|${baseUrl}|${h}|GET`, source: 'header', url: baseUrl, param: h, method: 'GET' });
    }

    // 2. 表单字段（execInTab 注入；仅当当前 tab 同源时，避免跨站注入）
    const tab = await getActiveTab();
    if (tab?.id && tab.url) {
      let sameOrigin = false;
      try {
        sameOrigin = new URL(tab.url).origin === base.origin;
      } catch {
        /* ignore */
      }
      if (sameOrigin) {
        try {
          const fp = await execInTab<{ url: string; param: string; method: string }[]>(tab.id, function () {
            const out: { url: string; param: string; method: string }[] = [];
            document.querySelectorAll('form').forEach(function (f) {
              const actionAttr = f.getAttribute('action') || location.href;
              let url = location.href;
              try {
                url = new URL(actionAttr, location.href).href;
              } catch (e) {
                /* keep location.href */
              }
              const method = (f.getAttribute('method') || 'get').toLowerCase() === 'post' ? 'POST' : 'GET';
              f.querySelectorAll('input[name],textarea[name],select[name]').forEach(function (el) {
                const name = (el as HTMLInputElement).name;
                if (name) out.push({ url, param: name, method });
              });
            });
            return out;
          });
          for (const f of fp ?? []) {
            pts.push({
              id: `form|${f.url}|${f.param}|${f.method}`,
              source: 'form',
              url: f.url,
              param: f.param,
              method: f.method === 'POST' ? 'POST' : 'GET',
            });
          }
        } catch {
          /* execInTab 失败（跨页 / 无注入权限），仅靠 URL 参数 */
        }
      }
    }

    // 去重（按 id）
    const seen = new Set<string>();
    return pts.filter((p) => (seen.has(p.id) ? false : (seen.add(p.id), true)));
  }

  // ===== 探测 =====
  interface ProbeOutcome {
    body: string;
    status: number;
  }

  /** 统一探测：url/form 点改参数值，header 点改请求头值 */
  async function probePointValue(pt: InjectPoint, value: string): Promise<ProbeOutcome> {
    let url = pt.url;
    let body: string | undefined;
    let headers: Record<string, string> | undefined;
    if (pt.source === 'header') {
      headers = { [pt.param]: value };
    } else if (pt.method === 'POST') {
      body = `${encodeURIComponent(pt.param)}=${encodeURIComponent(value)}`;
      headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    } else {
      try {
        const u = new URL(pt.url);
        u.searchParams.set(pt.param, value);
        url = u.href;
      } catch {
        return { body: '', status: 0 };
      }
    }
    try {
      const res = await sendMessage({
        type: 'FETCH_PROBE',
        url,
        method: pt.method === 'POST' ? 'POST' : 'GET',
        body,
        headers,
        includeBody: true,
        timeout: $scanSettingsStore.requestTimeoutMs,
      });
      const r = res as ProbeResult;
      return { body: r.body ?? '', status: r.status ?? 0 };
    } catch {
      return { body: '', status: 0 };
    }
  }

  async function fetchBody(pt: InjectPoint, value: string): Promise<string> {
    return (await probePointValue(pt, value)).body;
  }

  async function probePoint(pt: InjectPoint, payload: string, baseline: string): Promise<SqliFinding | null> {
    const payloadBody = await fetchBody(pt, payload);
    const hit = isNewSqlError(payloadBody, baseline);
    if (!hit.found) return null;
    return {
      param: pt.param,
      payload,
      db: hit.db,
      evidence: hit.evidence,
      url: pt.url,
      method: pt.method,
      source: pt.source,
      severity: assessSqliSeverity(hit.db),
    };
  }

  // ===== TaskController 接管扫描状态机 =====
  const controller = createTaskController<{ url: string }, SqliFinding[]>(
    {
      validate: (input) => {
        const v = validateProbeUrl(input.url);
        if ('error' in v) throw new Error('请输入合法的 http(s) URL');
      },
      run: async (input, ctx) => {
        const v = validateProbeUrl(input.url);
        if ('error' in v) throw new Error('无效的目标 URL');

        // 采集注入点
        const points = await collectPoints();
        if (ctx.signal.aborted) return [];
        pointCount = points.length;
        if (points.length === 0) {
          findings = [];
          toastStore.show('未发现注入点（URL 无参数且未采集到表单字段）', 'warning');
          return [];
        }
        const payloads = SQLI_ERROR_PAYLOADS.map((p) => p.payload);

        // Phase 1：每点取基线（无 payload 的正常响应）—— 基线对比防误报的关键
        const baselines = new Map<string, string>();
        ctx.reportProgress({ phase: '基线采集', total: points.length, completed: 0 });
        let p1 = 0;
        await runConcurrent(
          points,
          async (pt) => {
            if (ctx.signal.aborted) return;
            baselines.set(pt.id, await fetchBody(pt, ''));
            p1++;
            ctx.reportProgress({ completed: p1 });
          },
          { concurrency: $scanSettingsStore.concurrency, cancelled: () => ctx.signal.aborted },
        );
        if (ctx.signal.aborted) {
          findings = [];
          return [];
        }

        // Phase 2：注入点 × payload 矩阵
        const tasks: (() => Promise<SqliFinding | null>)[] = [];
        for (const pt of points) {
          const base = baselines.get(pt.id) ?? '';
          for (const payload of payloads) {
            tasks.push(() => probePoint(pt, payload, base));
          }
        }
        ctx.reportProgress({ phase: '报错注入探测', total: tasks.length, completed: 0 });
        const collected: SqliFinding[] = [];
        let p2 = 0;
        await runConcurrent(
          tasks,
          async (task) => {
            if (ctx.signal.aborted) return;
            const r = await task();
            if (r) collected.push(r);
            p2++;
            ctx.reportProgress({ completed: p2 });
          },
          { concurrency: $scanSettingsStore.concurrency, cancelled: () => ctx.signal.aborted },
        );

        const sorted = collected.sort(SQLI_SORT_FNS.severity);

        // Phase 3：布尔盲注（仅 URL 参数点，需原始值构造恒真/恒假变体）
        if (useBooleanBlind && !ctx.signal.aborted) {
          const blindPoints = points.filter((p) => p.source === 'url' && p.originalValue !== undefined);
          if (blindPoints.length > 0) {
            ctx.reportProgress({ phase: '布尔盲注探测', total: blindPoints.length, completed: 0 });
            let p3 = 0;
            const blindFindings: SqliFinding[] = [];
            await runConcurrent(
              blindPoints,
              async (pt) => {
                if (ctx.signal.aborted) return;
                const pair = buildBooleanBlindPair(pt.originalValue!);
                const [truthyRes, falsyRes] = await Promise.all([
                  probePointValue(pt, pair.truthy),
                  probePointValue(pt, pair.falsy),
                ]);
                // 两个响应都拿到且均为 200 才参与对比（错误页走报错注入通道）
                if (truthyRes.body && falsyRes.body && truthyRes.status === 200 && falsyRes.status === 200) {
                  const baseline = baselines.get(pt.id) ?? '';
                  const r = analyzeBooleanBlind(baseline.length, truthyRes.body.length, falsyRes.body.length);
                  if (r.suspected) {
                    blindFindings.push({
                      param: pt.param,
                      payload: `${pair.truthy}  /  ${pair.falsy}`,
                      db: 'unknown',
                      evidence: `布尔盲注（${pair.desc}）：恒真 ${truthyRes.body.length}B / 恒假 ${falsyRes.body.length}B，长度差 ${r.lengthDiff}B（占比 ${(r.ratio * 100).toFixed(1)}%）`,
                      url: pt.url,
                      method: pt.method,
                      source: pt.source,
                      severity: 'medium',
                    });
                  }
                }
                p3++;
                ctx.reportProgress({ completed: p3 });
              },
              { concurrency: $scanSettingsStore.concurrency, cancelled: () => ctx.signal.aborted },
            );
            collected.push(...blindFindings);
          }
        }

        findings = collected.sort(SQLI_SORT_FNS.severity);
        try {
          await scanHistoryStore.addScan({ url: input.url, module: 'sqliscan', findings: mapToFindings(findings) });
        } catch {
          /* store failure must not break scan */
        }
        return findings;
      },
    },
    { centerPanel: 'sqliscan', centerLabel: 'SQLi 检测' },
  );

  let cs = $state<TaskState>({ ...IDLE });
  $effect(() => controller.state.subscribe((v: TaskState) => { cs = v; }));
  let scanning = $derived(cs.status === 'running' || cs.status === 'paused' || cs.status === 'validating');

  async function handleScan() {
    const r = await controller.start({ url: targetUrl });
    if (r.status === 'succeeded') {
      if (findings.length > 0) {
        toastStore.show(`发现 ${findings.length} 处疑似 SQL 注入（报错）`, 'warning');
      } else {
        toastStore.show(`SQLi 检测完成，未发现报错注入（${pointCount} 个注入点）`, 'success');
      }
    } else if (r.status === 'cancelled') {
      toastStore.show('扫描已取消', 'info');
    }
  }

  // 一键操作（右键菜单 / Popup）：命中本面板则自动扫描
  $effect(() => {
    const sig = $autoRunStore;
    if (sig && sig.panel === 'sqliscan') {
      autoRunStore.clear();
      if (sig.url) targetUrl = sig.url;
      handleScan();
    }
  });

  // ===== scan-history 序列化 =====
  function mapToFindings(fs: SqliFinding[]): ScanFinding[] {
    return fs.map((f) => ({
      title: `SQLi 报错注入 [${f.method}] ${f.param}`,
      severity: f.severity as ScanFinding['severity'],
      detail: `${dbLabel(f.db)} · payload: ${f.payload}`,
      evidence: f.evidence,
      url: f.url,
    }));
  }

  // ===== 导出序列化器（作用于当前筛选 filtered）=====
  function sqliCsv(items: SqliFinding[]): string {
    return toCsv([
      ['severity', 'param', 'method', 'db', 'payload', 'url'],
      ...items.map((i) => [i.severity, i.param, i.method, dbLabel(i.db), i.payload, i.url]),
    ]);
  }
  function sqliMd(items: SqliFinding[]): string {
    return toMarkdownTable(
      ['风险', '参数', '方法', '数据库', 'Payload'],
      items.map((i) => [sqlSeverityLabel(i.severity), i.param, i.method, dbLabel(i.db), i.payload]),
    );
  }
  function sqliText(items: SqliFinding[]): string {
    const lines = [`# SQLi 报错注入扫描结果`, ``, `**目标:** ${targetUrl}`, ``, `## 发现 (${items.length})`];
    for (const i of items) {
      lines.push(`- **[${sqlSeverityLabel(i.severity)}]** ${i.param} [${i.method}] ${dbLabel(i.db)} ${i.url}`);
      lines.push(`  - Payload: \`${i.payload}\``);
      if (i.evidence) lines.push(`  - 证据: ${i.evidence}`);
    }
    return lines.join('\n');
  }

  // ===== DetailDrawer 字段 / 证据 / handoff =====
  function sqliFields(i: SqliFinding): DetailField[] {
    return [
      { label: '参数', value: i.param, mono: true },
      { label: '方法', value: i.method },
      { label: '来源', value: i.source === 'form' ? '表单' : i.source === 'header' ? '请求头' : 'URL 参数' },
      { label: '数据库', value: dbLabel(i.db) },
      { label: 'URL', value: i.url, mono: true },
      { label: 'Payload', value: i.payload, mono: true },
    ];
  }
  function sqliEvidence(i: SqliFinding): string {
    return i.evidence || '（无错误片段）';
  }
  const sqliActions: DetailHandoffAction<SqliFinding>[] = [
    { label: '在 XSS 中打开', targetPanel: 'xss', build: (i) => ({ payload: { targetUrl: i.url }, summary: `XSS 测 ${i.param}` }) },
    { label: '在 目录扫描 中打开', targetPanel: 'fuzz', build: (i) => ({ payload: { targetUrl: i.url }, summary: '目录扫描' }) },
  ];
</script>

<div class="space-y-3">
  <!-- 输入 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <UrlInput bind:value={targetUrl} scanning={scanning} buttonText="扫描" onscan={handleScan} recordTarget />
      {#if scanning}
        <button class="btn btn-sm btn-danger shrink-0" onclick={() => controller.cancel()} disabled={!cs.canCancel}>取消</button>
      {/if}
    </div>
    <div class="flex items-center gap-2 flex-wrap text-xs text-gray-500">
      <span>报错注入 + 布尔盲注：URL 参数/HTTP 头/表单字段 × {SQLI_ERROR_PAYLOADS.length} payload，基线对比防误报</span>
      <label class="flex items-center gap-1 cursor-pointer" title="恒真/恒假响应差异对比，请求为正常语义变体">
        <input type="checkbox" class="checkbox checkbox-xs" bind:checked={useBooleanBlind} />
        布尔盲注
      </label>
    </div>
    <ScanProgress scanned={cs.completed} total={cs.total ?? 0} scanning={scanning} phase={cs.phase} label="SQLi 探测" />
  </div>

  <!-- 工具栏 -->
  {#if findings.length > 0}
    <ResultToolbar {query} total={findings.length} shown={filtered.length} searchPlaceholder="搜索参数/payload/DB...">
      <span class="badge bg-red-50 text-red-700 ring-1 ring-inset ring-red-200 dark:bg-red-900/30 dark:text-red-300 dark:ring-red-800/60">命中 {findings.length}</span>
      <select
        class="input text-xs w-24"
        value={query.sort.key}
        onchange={(e) => {
          query.sort.key = (e.currentTarget as HTMLSelectElement).value;
        }}
        aria-label="排序"
      >
        <option value="severity">按风险</option>
        <option value="param">按参数</option>
        <option value="db">按数据库</option>
      </select>
      <ExportMenu items={filtered} module="sqliscan" serializers={{ csv: sqliCsv, markdown: sqliMd, text: sqliText }} />
    </ResultToolbar>
  {/if}

  <!-- 结果 -->
  {#if filtered.length > 0}
    <div class="space-y-2">
      {#each filtered as f, i (f.url + f.param + f.method + f.payload)}
        <div
          class="card p-2.5 space-y-1.5 cursor-pointer hover:border-primary transition-colors vk-pop-in"
          style="animation-delay: {Math.min(i, 12) * 30}ms"
          role="button"
          tabindex="0"
          aria-label="查看 SQLi 详情"
          onclick={() => (detailIndex = i)}
          onkeydown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              detailIndex = i;
            }
          }}
        >
          <div class="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={f.severity} />
            <span class="badge text-xs bg-gray-200 dark:bg-gray-700">{f.source === 'form' ? '表单' : f.source === 'header' ? '请求头' : 'URL'}</span>
            <span class="text-xs font-mono text-gray-700 dark:text-gray-300">{f.param}</span>
            <span class="badge text-xs bg-gray-200 dark:bg-gray-700">{f.method}</span>
            <span class="badge text-xs bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300">{dbLabel(f.db)}</span>
          </div>
          <div class="text-xs font-mono text-gray-600 dark:text-gray-300 break-all">{f.url}</div>
          <div class="text-xs">
            <span class="text-gray-500">Payload:</span>
            <code class="font-mono break-all text-red-600 dark:text-red-400">{f.payload}</code>
          </div>
          {#if f.evidence}
            <div class="text-xs text-gray-500 dark:text-gray-500 break-all bg-gray-50 dark:bg-gray-800/50 p-1.5 rounded">
              {f.evidence}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {:else if cs.status === 'failed'}
    <ErrorState error={cs.error!} onRetry={handleScan} />
  {:else if !scanning && cs.completed > 0 && findings.length === 0}
    <EmptyState message={`未发现报错注入（已检测 ${pointCount} 个注入点）`} icon="✅" />
  {:else if !scanning}
    <EmptyState
      message="输入目标 URL，点击「扫描」开始 SQL 报错注入检测"
      hint="自动采集 URL 参数与表单字段，基线对比防误报"
      icon="💉"
    />
  {/if}

  <!-- 详情抽屉 -->
  <DetailDrawer
    items={filtered}
    index={detailIndex}
    onclose={() => (detailIndex = null)}
    onnavigate={(idx) => (detailIndex = idx)}
    sourcePanel="sqliscan"
    sourceLabel="SQLi 检测"
    moduleLabel="SQLi"
    title={(i) => `${i.param} [${i.method}]`}
    severity={(i) => i.severity}
    target={(i) => i.url}
    fields={sqliFields}
    evidence={sqliEvidence}
    actions={sqliActions}
  />
</div>
