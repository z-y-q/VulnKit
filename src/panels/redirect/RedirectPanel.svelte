<script lang="ts">
  // 开放重定向检测面板
  // 流程：构建 参数 × 协议变体 测试 URL → 不跟随重定向探测 → 引擎判定 → 渲染
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore, autoRunStore } from '@/stores/ui';
  import { confirmStore } from '@/stores/confirm';

  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import { scanSettingsStore } from '@/stores/settings';
  import { runConcurrent } from '@/lib/core/concurrency';
  import UrlInput from '@/components/scanner/UrlInput.svelte';
  import ScanProgress from '@/components/scanner/ScanProgress.svelte';
  import EmptyState from '@/components/scanner/EmptyState.svelte';
  import ResultToolbar from '@/components/results/ResultToolbar.svelte';
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import ErrorState from '@/components/feedback/ErrorState.svelte';
  import { createTaskController, IDLE, type TaskState } from '@/lib/tasks/task-controller';
  import { toCsv, toMarkdownTable } from '@/lib/actions/serializers';
  import { type ResultAdapter, type ResultQuery } from '@/lib/results/result-adapter';
  import type { ProbeResult } from '@/lib/types/messaging';
  import {
    buildTestUrls,
    isRedirectVulnerable,
    PROTOCOL_VARIANTS,
    REDIRECT_PAYLOADS,
    type RedirectResult,
  } from '@/lib/scanners/redirect-engine';

  let targetUrl = $state('');
  let results = $state<RedirectResult[]>([]);
  let query = $state<ResultQuery>({ search: '', filters: {}, sort: { key: 'vuln', direction: 'asc' } });

  $effect(() => {
    getActiveTabUrl().then(u => {
      if (u) targetUrl = u;
    });
  });

  // —— TaskController 接管扫描状态机 ——
  const controller = createTaskController<{ url: string }, RedirectResult[]>({
    validate: (input) => {
      const v = validateProbeUrl(input.url);
      if ('error' in v) throw new Error('请输入合法的 http(s) URL');
    },
    run: async (input, ctx) => {
      const v = validateProbeUrl(input.url);
      if ('error' in v) throw new Error('无效的目标 URL');
      const tests = buildTestUrls(v.parsed.origin + v.parsed.pathname);
      ctx.reportProgress({ total: tests.length, completed: 0, phase: '重定向检测' });
      const collected: RedirectResult[] = [];
      let scanCount = 0;
      await runConcurrent(tests, async (t) => {
        const r = await probe(t.url);
        if (r) collected.push({ ...r, param: t.param, variant: t.variant });
        scanCount++;
        ctx.reportProgress({ completed: scanCount });
      }, { concurrency: $scanSettingsStore.concurrency, cancelled: () => ctx.signal.aborted });
      // 漏洞优先排序
      results = collected.sort((a, b) => {
        if (a.status !== b.status) return a.status === 'vulnerable' ? -1 : 1;
        return a.param.localeCompare(b.param);
      });
      try {
        await scanHistoryStore.addScan({ url: input.url, module: 'redirect', findings: mapToFindings(results) });
      } catch { /* store failure must not break scan */ }
      return results;
    },
  }, { centerPanel: 'redirect', centerLabel: '重定向检测' });

  let cs = $state<TaskState>({ ...IDLE });
  $effect(() => controller.state.subscribe((v: TaskState) => { cs = v; }));
  let archiving = $derived(cs.status === 'running' || cs.status === 'paused' || cs.status === 'validating');

  async function handleScan() {
    const confirmed = await confirmStore.ask({
      title: '重定向检测',
      message: '重定向检测将向目标发送跳转探测请求，请确认目标在授权范围内。',
      confirmLabel: '开始扫描',
      variant: 'danger',
    });
    if (!confirmed) return;
    const r = await controller.start({ url: targetUrl });
    if (r.status === 'succeeded') {
      const vuln = results.filter(r => r.status === 'vulnerable').length;
      if (vuln > 0) {
        toastStore.show(`发现 ${vuln} 个开放重定向点`, 'warning');
      } else {
        toastStore.show(`检测完成，未发现开放重定向（${cs.total} 个测试）`, 'success');
      }
    } else if (r.status === 'cancelled') {
      toastStore.show('扫描已取消', 'info');
    }
  }

  // 一键操作（右键链接 → 重定向检测）：命中本面板则自动扫描
  $effect(() => {
    const sig = $autoRunStore;
    if (sig && sig.panel === 'redirect') {
      autoRunStore.clear();
      if (sig.url) targetUrl = sig.url;
      handleScan();
    }
  });

  // ===== 派生：结果（统一 ResultAdapter，供 ResultToolbar/ExportMenu 消费）=====
  const redirectAdapter: ResultAdapter<RedirectResult> = {
    apply(items, q) {
      let list = items;
      if (q.filters.scope?.includes('vuln')) list = list.filter((r) => r.status === 'vulnerable');
      const kw = q.search.trim().toLowerCase();
      if (kw) list = list.filter((r) => redirectAdapter.getSearchText(r).toLowerCase().includes(kw));
      return [...list].sort((a, b) => {
        if (a.status !== b.status) return a.status === 'vulnerable' ? -1 : 1;
        return a.param.localeCompare(b.param);
      });
    },
    getSearchText(r) {
      return `${r.param} ${r.variant} ${r.url} ${r.status}`;
    },
    getId(r) {
      return r.url;
    },
  };

  let filtered = $derived(redirectAdapter.apply(results, query));
  let vulnOnly = $derived(query.filters.scope?.includes('vuln') ?? false);
  function toggleVuln() {
    query.filters = vulnOnly ? {} : { scope: ['vuln'] };
  }
  let vulnCount = $derived(results.filter((r) => r.status === 'vulnerable').length);

  function mapToFindings(results: RedirectResult[]): ScanFinding[] {
    return results
      .filter(r => r.status === 'vulnerable')
      .map(r => ({
        title: `开放重定向 [${r.param}]`,
        severity: 'high' as const,
        detail: r.variant,
        evidence: r.evidence,
        url: r.url,
      }));
  }

  async function probe(url: string): Promise<RedirectResult | null> {
    try {
      const res = await sendMessage({
        type: 'FETCH_PROBE',
        url,
        method: 'GET',
        followRedirect: false,
        timeout: $scanSettingsStore.requestTimeoutMs,
      });
      const r = res as ProbeResult;
      const resp = {
        status: r.status,
        headers: r.headers,
        url: r.url,
        redirected: r.redirected,
        body: r.body,
      };
      const vulnerable = isRedirectVulnerable(resp, '');
      const location =
        (r.headers && (r.headers['location'] || r.headers['Location'])) || r.url || '';
      return {
        param: '',
        variant: '',
        url,
        status: vulnerable ? 'vulnerable' : 'safe',
        statusCode: r.status || 0,
        evidence: vulnerable ? `Location → ${location}` : undefined,
      };
    } catch {
      return null;
    }
  }

  // —— 导出/复制序列化器（作用于当前筛选 filtered，展示/导出同源 §6.1）——
  function redirectCsv(items: RedirectResult[]): string {
    return toCsv([
      ['param', 'variant', 'url', 'status', 'statusCode'],
      ...items.map((r) => [r.param, r.variant, r.url, r.status, r.statusCode]),
    ]);
  }
  function redirectText(items: RedirectResult[]): string {
    return items
      .map((r) => `[${r.status}] ${r.param} (${r.variant}) [${r.statusCode}]\n  ${r.url}`)
      .join('\n\n');
  }
  function redirectMd(items: RedirectResult[]): string {
    return toMarkdownTable(
      ['参数', '协议变体', '状态', '状态码', 'URL'],
      items.map((r) => [r.param, r.variant, r.status, r.statusCode, r.url]),
    );
  }
</script>

<div class="space-y-3">
  <!-- 输入 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <UrlInput bind:value={targetUrl} scanning={archiving} buttonText="检测" onscan={handleScan} />
      {#if archiving}
        <button class="btn btn-sm btn-danger shrink-0" onclick={() => controller.cancel()} disabled={!cs.canCancel}>取消</button>
      {/if}
    </div>
    <div class="text-xs text-gray-500">
      {REDIRECT_PAYLOADS.length} 个参数 × {PROTOCOL_VARIANTS.length} 个协议变体 = {REDIRECT_PAYLOADS.length * PROTOCOL_VARIANTS.length} 个测试
    </div>
    <ScanProgress scanned={cs.completed} total={cs.total ?? 0} scanning={archiving} phase={cs.phase} label="重定向检测" />
  </div>

  <!-- 工具栏：ResultToolbar 包裹 漏洞筛选 / 导出 -->
  {#if results.length > 0}
    <ResultToolbar {query} total={results.length} shown={filtered.length} searchPlaceholder="搜索参数/URL...">
      <button
        class="badge cursor-pointer {vulnOnly ? 'bg-red-50 text-red-700 ring-1 ring-inset ring-red-200 dark:bg-red-900/30 dark:text-red-300 dark:ring-red-800/60' : 'bg-gray-100 text-gray-500 dark:bg-gray-700/50 dark:text-gray-500'}"
        aria-pressed={vulnOnly}
        onclick={toggleVuln}
      >
        漏洞 {vulnCount}
      </button>
      <ExportMenu items={filtered} module="redirect" serializers={{ csv: redirectCsv, text: redirectText, markdown: redirectMd }} />
    </ResultToolbar>
  {/if}

  <!-- 结果 -->
  {#if filtered.length > 0}
    <div class="space-y-1.5">
      {#each filtered as r (r.url)}
        <div class="card p-2.5 space-y-1">
          <div class="flex items-center gap-2">
            <span class="badge text-xs {r.status === 'vulnerable' ? 'bg-red-50 text-red-700 ring-1 ring-inset ring-red-200 dark:bg-red-900/30 dark:text-red-300 dark:ring-red-800/60' : 'bg-gray-100 text-gray-500 dark:bg-gray-700/50 dark:text-gray-500'}">
              {r.status === 'vulnerable' ? '漏洞' : '安全'}
            </span>
            <span class="badge text-xs bg-gray-200 dark:bg-gray-700">{r.param}</span>
            {#if r.statusCode}
              <span class="badge text-xs bg-gray-200 dark:bg-gray-700">{r.statusCode}</span>
            {/if}
          </div>
          <div class="text-xs font-mono text-gray-600 dark:text-gray-300 break-all">{r.variant}</div>
          {#if r.evidence}
            <div class="text-xs text-red-600 dark:text-red-400 break-all">⚠ {r.evidence}</div>
          {/if}
        </div>
      {/each}
    </div>
  {:else if cs.status === 'failed'}
    <ErrorState error={cs.error!} onRetry={handleScan} />
  {:else if !archiving && results.length === 0 && cs.completed > 0}
    <EmptyState message="未发现开放重定向" icon="✅" />
  {:else if !archiving}
    <EmptyState
      message="输入目标 URL，检测开放重定向漏洞（参数注入测试）"
      hint="{REDIRECT_PAYLOADS.length} 个参数 × {PROTOCOL_VARIANTS.length} 个协议变体"
      icon="🔀"
    />
  {/if}
</div>
