<script lang="ts">
  // 目录扫描面板 — 灵眸 v7.3
  // 流程：选字典 → 拼路径 → 并发探测 → 内容分析 → 排序渲染
  // v7.3：统一 TaskController（暂停/取消/partial）+ ResultToolbar（搜索/筛选/排序/计数）
  //      + ExportMenu（规范文件名）+ copyText（修复未 await）
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore, autoRunStore } from '@/stores/ui';
  import { confirmStore } from '@/stores/confirm';

  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import { scanSettingsStore } from '@/stores/settings';
  import { analysisContextStore } from '@/stores/analysis-context';
  import { runConcurrent } from '@/lib/core/concurrency';
  import UrlInput from '@/components/scanner/UrlInput.svelte';
  import ScanProgress from '@/components/scanner/ScanProgress.svelte';
  import EmptyState from '@/components/scanner/EmptyState.svelte';
  import ErrorState from '@/components/feedback/ErrorState.svelte';
  import ResultToolbar from '@/components/results/ResultToolbar.svelte';
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import { copyText } from '@/lib/actions/clipboard';
  import { downloadText, buildFilename } from '@/lib/actions/download';
  import { toCsv, toMarkdownTable } from '@/lib/actions/serializers';
  import { createTaskController, IDLE, type TaskState } from '@/lib/tasks/task-controller';
  import { EMPTY_QUERY, type ResultAdapter, type ResultQuery } from '@/lib/results/result-adapter';
  import type { ProbeResult } from '@/lib/types/messaging';
  import {
    analyzeContent,
    extractContentLength,
    getWordlist,
    getWordlistKeys,
    isFoundStatus,
    gradeSeverity,
    markDuplicates,
    type FuzzResult,
  } from '@/lib/scanners/fuzz-engine';

  let targetUrl = $state('');
  let wordlistKey = $state<ReturnType<typeof getWordlistKeys>[number]>('common');
  let results = $state<FuzzResult[]>([]);
  let customPaths = $state('');
  let query = $state<ResultQuery>({ search: '', filters: {}, sort: { key: 'status', direction: 'desc' } });

  const wordlistKeys = getWordlistKeys();

  // —— TaskController 接管扫描状态机（替代 scanning/cancelled/paused）——
  type FuzzInput = { targetUrl: string; wordlistKey: typeof wordlistKey; customPaths: string };
  const controller = createTaskController<FuzzInput, FuzzResult[]>(
    {
      validate: (input) => {
        const v = validateProbeUrl(input.targetUrl);
        if ('error' in v) throw new Error('请输入合法的 http(s) URL');
      },
      run: async (input, ctx) => {
        const v = validateProbeUrl(input.targetUrl);
        if ('error' in v) throw new Error('无效的目标 URL');
        const base = v.parsed.origin + v.parsed.pathname.replace(/[?#].*$/, '');
        const baseUrl = base.endsWith('/') ? base : base + '/';

        let paths = getWordlist(input.wordlistKey);
        if (input.customPaths.trim()) {
          paths = [...new Set([...input.customPaths.split(/\r?\n/).map(p => p.trim()).filter(Boolean), ...paths])];
        }
        ctx.reportProgress({ total: paths.length, completed: 0, phase: '目录扫描' });

        const collected: FuzzResult[] = [];
        let scanned = 0;
        await runConcurrent(paths, async (path) => {
          if (ctx.signal.aborted) return;
          const cleanPath = path.replace(/^\/+/, '');
          const r = await probeSmart(baseUrl, cleanPath);
          if (r) collected.push(r);
          scanned++;
          ctx.reportProgress({ completed: scanned });
        }, { concurrency: $scanSettingsStore.concurrency, cancelled: () => ctx.signal.aborted, paused: ctx.isPaused });

        // 去重（软 404 标记）+ 严重级别评估
        markDuplicates(collected);
        for (const r of collected) {
          if (!r.severity) r.severity = gradeSeverity(r);
        }
        results = collected;
        return collected;
      },
    },
    { canPause: true, centerPanel: 'fuzz', centerLabel: '目录扫描' },
  );

  let cs = $state<TaskState>({ ...IDLE });
  $effect(() => controller.state.subscribe((v: TaskState) => { cs = v; }));
  let archiving = $derived(cs.status === 'running' || cs.status === 'paused' || cs.status === 'validating');

  $effect(() => {
    getActiveTabUrl().then(u => { if (u) targetUrl = u; });
  });

  // 一键操作（右键菜单 / Popup）：命中本面板则自动填充并扫描
  $effect(() => {
    const sig = $autoRunStore;
    if (sig && sig.panel === 'fuzz') {
      autoRunStore.clear();
      if (sig.url) targetUrl = sig.url;
      handleScan();
    }
  });

  // 消费跨面板 handoff（paths 来自 Wayback；targetUrl 由 UrlInput 统一回填）
  $effect(() => {
    analysisContextStore.consumePayload('fuzz', 'paths').then((p) => {
      if (p) customPaths = p;
    }).catch(() => { /* ignore */ });
  });

  // —— ResultAdapter：把 foundOnly/statusFilter/sortBy/search 统一为 query 协议 ——
  const fuzzResultAdapter: ResultAdapter<FuzzResult> = {
    apply(items, q) {
      let list = items;
      const statusSel = q.filters.status?.[0];
      if (statusSel != null && statusSel !== '') {
        const code = Number(statusSel);
        list = list.filter(r => r.status === code);
      } else {
        list = list.filter(r => isFoundStatus(r.status)); // 默认仅有效
      }
      const kw = q.search.trim().toLowerCase();
      if (kw) list = list.filter(r => fuzzResultAdapter.getSearchText(r).toLowerCase().includes(kw));
      const fns: Record<string, (a: FuzzResult, b: FuzzResult) => number> = {
        status: (a, b) => a.status - b.status,
        size: (a, b) => b.size - a.size,
        time: (a, b) => b.time - a.time,
      };
      return [...list].sort(fns[q.sort.key] ?? fns.status);
    },
    getSearchText(r) {
      return `${r.path} ${r.url} ${(r.analysis?.tags ?? []).join(' ')}`;
    },
    getId(r) { return r.url; },
  };

  let filtered = $derived(fuzzResultAdapter.apply(results, query));
  let uniqueStatusCodes = $derived.by(() => {
    const codes = new Set<number>();
    for (const r of results) if (r.status > 0) codes.add(r.status);
    return [...codes].sort((a, b) => a - b);
  });
  let statusSel = $derived(query.filters.status?.[0] ?? '');

  const SENSITIVE_TAGS = new Set(['敏感信息', 'WAF', '管理界面']);

  function mapToFindings(rs: FuzzResult[]): ScanFinding[] {
    return rs
      .filter(r => isFoundStatus(r.status))
      .map(r => {
        const tags = r.analysis?.tags ?? [];
        const hasSensitive = tags.some(t => SENSITIVE_TAGS.has(t));
        return {
          title: `${r.path} [${r.status}]`,
          severity: (hasSensitive ? 'medium' : 'info') as ScanFinding['severity'],
          detail: tags.join(', ') || undefined,
          url: r.url,
        };
      });
  }

  function statusColor(s: number): string {
    if (s >= 200 && s < 300) return 'text-green-600 dark:text-green-400';
    if (s >= 300 && s < 400) return 'text-blue-600 dark:text-blue-400';
    if (s === 401 || s === 403 || s === 405) return 'text-yellow-600 dark:text-yellow-400';
    if (s === 404) return 'text-gray-500';
    if (s >= 500) return 'text-red-600 dark:text-red-400';
    return 'text-gray-500';
  }

  async function probe(baseUrl: string, path: string, method: string): Promise<FuzzResult | null> {
    const u = new URL(path, baseUrl).href;
    const start = Date.now();
    try {
      const res = await sendMessage({
        type: 'FETCH_PROBE',
        url: u,
        method,
        timeout: $scanSettingsStore.requestTimeoutMs,
      });
      const r = res as ProbeResult;
      const size = extractContentLength(r.headers) || (r.body ? r.body.length : 0);
      const analysis = method === 'GET' ? analyzeContent(r.body) : null;
      return { path, url: u, status: r.status || 0, size, time: Date.now() - start, method, analysis };
    } catch {
      return null;
    }
  }

  /** HEAD 优先策略：先发 HEAD（省带宽），仅在 405/501 或 HEAD 无有效状态时回退 GET。 */
  async function probeSmart(baseUrl: string, path: string): Promise<FuzzResult | null> {
    const head = await probe(baseUrl, path, 'HEAD');
    if (head && head.status !== 0 && head.status !== 405 && head.status !== 501) {
      head.severity = gradeSeverity(head);
      return head;
    }
    const get = await probe(baseUrl, path, 'GET');
    if (get) get.severity = gradeSeverity(get);
    return get;
  }

  async function handleScan() {
    const confirmed = await confirmStore.ask({
      title: '目录扫描',
      message: '目录扫描将向目标发送批量路径探测请求，请确认目标在授权范围内。',
      confirmLabel: '开始扫描',
      variant: 'danger',
    });
    if (!confirmed) return;
    try {
      const r = await controller.start({ targetUrl, wordlistKey, customPaths });
      if (r.status === 'succeeded') {
        const list = r.result ?? [];
        try {
          await scanHistoryStore.addScan({ url: targetUrl, module: 'fuzz', findings: mapToFindings(list) });
        } catch { /* store failure must not break scan */ }
        const found = list.filter(r => isFoundStatus(r.status)).length;
        toastStore.show(`扫描完成，发现 ${found} 个有效路径（共 ${list.length}）`, found > 0 ? 'warning' : 'success');
      } else if (r.status === 'cancelled') {
        const scanned = results.length;
        toastStore.show(scanned > 0 ? `扫描已取消（已扫描 ${scanned} 项）` : '扫描已取消', 'info');
      }
    } catch {
      // failed：cs.error 驱动 ErrorState
    }
  }

  // —— 导出/复制序列化器（作用于当前筛选 filtered）——
  function fuzzCsv(items: FuzzResult[]): string {
    return toCsv([['path', 'url', 'status', 'size', 'method'], ...items.map(r => [r.path, r.url, r.status, r.size, r.method])]);
  }
  function fuzzTxt(items: FuzzResult[]): string {
    const found = items.filter(r => r.status > 0 && r.status !== 404);
    const lines = ['目录扫描报告', '==================', '目标: ' + targetUrl, '字典: ' + wordlistKey, '发现: ' + found.length, ''];
    for (const e of found) {
      lines.push(`[${e.status}] ${e.path} (${e.size}B, ${e.time}ms${e.method === 'GET' ? ', GET' : ''})`);
      if (e.analysis?.title) lines.push('  Title: ' + e.analysis.title);
      if (e.analysis?.tags?.length) lines.push('  Tags: ' + e.analysis.tags.join(', '));
    }
    return lines.join('\n');
  }
  function fuzzMd(items: FuzzResult[]): string {
    const found = items.filter(r => r.status > 0 && r.status !== 404);
    return toMarkdownTable(['Path', 'Status', 'Size', 'Time'], found.map(e => [e.path, e.status, e.size, e.time]));
  }
  function fuzzCopyText(items: FuzzResult[]): string {
    const found = items.filter(r => r.status > 0 && r.status !== 404);
    const lines = [`目录扫描 @ ${targetUrl}`, `字典: ${wordlistKey}`, `发现: ${found.length}`, ''];
    for (const e of found) lines.push(`[${e.status}] ${e.path} (${e.size}B, ${e.time}ms)`);
    return lines.join('\n');
  }
  async function copyCurl() {
    if (filtered.length === 0) { toastStore.show('没有可复制的结果', 'warning'); return; }
    const found = filtered.filter(r => r.status > 0 && r.status !== 404);
    if (found.length === 0) { toastStore.show('没有有效结果', 'warning'); return; }
    const cmds = found.map(r => `curl -I -s "${r.url}"`).join('\n');
    await copyText(cmds, `已复制 ${found.length} 条 cURL`);
  }

  function setStatusFilter(code: number | null) {
    query.filters = { ...query.filters, status: code == null ? [] : [String(code)] };
  }
  function resetQuery() {
    query.search = '';
    query.filters = {};
    query.sort = { key: 'status', direction: 'desc' };
  }
</script>

<div class="space-y-3">
  <!-- 输入 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <UrlInput bind:value={targetUrl} scanning={archiving} buttonText="扫描" onscan={handleScan} recordTarget />
      {#if archiving}
        <button class="btn btn-sm btn-danger shrink-0" onclick={() => controller.cancel()} disabled={!cs.canCancel}>取消</button>
        {#if cs.status === 'paused'}
          <button class="btn btn-sm btn-primary shrink-0" onclick={() => controller.resume()}>继续</button>
        {:else}
          <button class="btn btn-sm shrink-0" onclick={() => controller.pause()} disabled={!cs.canPause}>暂停</button>
        {/if}
      {/if}
    </div>
    <div class="flex items-center gap-2 text-xs">
      <span class="text-gray-500">字典:</span>
      <select class="input text-xs flex-1" bind:value={wordlistKey}>
        {#each wordlistKeys as k}
          <option value={k}>{k} ({getWordlist(k).length})</option>
        {/each}
      </select>
    </div>
    <details class="text-xs">
      <summary class="cursor-pointer text-gray-500">自定义路径（每行一个，合并到字典）</summary>
      <textarea class="input w-full mt-1 font-mono" rows="3" placeholder="/admin&#10;/test&#10;/backup.zip" bind:value={customPaths}></textarea>
    </details>
    <ScanProgress scanned={cs.completed} total={cs.total ?? 0} scanning={archiving} phase={cs.phase} label="目录扫描" />
    {#if cs.status === 'failed' && cs.error}
      <ErrorState error={cs.error} onRetry={handleScan} />
    {/if}
  </div>

  <!-- 工具栏 -->
  {#if results.length > 0}
    <!-- 状态码过滤 -->
    <div class="flex flex-wrap items-center gap-1.5 text-xs">
      <button
        class="badge cursor-pointer {statusSel === '' ? 'bg-blue-600 text-white' : 'bg-gray-200 dark:bg-gray-700'}"
        aria-pressed={statusSel === ''}
        onclick={() => setStatusFilter(null)}
      >
        有效
      </button>
      {#each uniqueStatusCodes as code}
        <button
          class="badge cursor-pointer {statusSel === String(code) ? 'bg-blue-600 text-white' : 'bg-gray-200 dark:bg-gray-700'}"
          aria-pressed={statusSel === String(code)}
          onclick={() => setStatusFilter(statusSel === String(code) ? null : code)}
        >
          {code}
        </button>
      {/each}
    </div>
    <ResultToolbar {query} total={results.length} shown={filtered.length} searchPlaceholder="搜索路径/标签...">
      <select
        class="input text-xs w-24"
        value={query.sort.key}
        onchange={(e) => { query.sort.key = e.currentTarget.value; }}
        aria-label="排序"
      >
        <option value="status">按状态码</option>
        <option value="size">按大小</option>
        <option value="time">按耗时</option>
      </select>
      <button class="btn btn-sm" onclick={copyCurl} title="复制 cURL 命令">cURL</button>
      <ExportMenu
        items={filtered}
        module="fuzz"
        serializers={{ csv: fuzzCsv, text: fuzzTxt, markdown: fuzzMd }}
        copySerialize={fuzzCopyText}
      />
    </ResultToolbar>
  {/if}

  <!-- 结果 -->
  {#if filtered.length > 0}
    <div class="space-y-1">
      {#each filtered as r (r.url)}
        <div class="card p-2 flex items-center gap-2">
          <span class="badge text-xs {statusColor(r.status)} w-12 justify-center">{r.status || '-'}</span>
          <div class="flex-1 min-w-0">
            <div class="text-xs font-mono text-gray-700 dark:text-gray-200 truncate">{r.path}</div>
            {#if r.analysis?.tags?.length}
              <div class="flex flex-wrap gap-1 mt-0.5">
                {#each r.analysis.tags as tag}
                  <span class="badge text-xs bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300">{tag}</span>
                {/each}
              </div>
            {/if}
          </div>
          <span class="text-xs text-gray-500 shrink-0">{r.size}B</span>
          <span class="text-xs text-gray-500 shrink-0">{r.time}ms</span>
        </div>
      {/each}
    </div>
  {:else if !archiving && results.length === 0 && cs.completed > 0}
    <EmptyState message="未发现有效路径" icon="🔍" />
  {:else if !archiving && results.length === 0}
    <EmptyState
      message="选择字典，扫描目标站点的目录与敏感文件"
      hint="支持自定义路径，合并到所选字典中"
      icon="📂"
    />
  {/if}
</div>
