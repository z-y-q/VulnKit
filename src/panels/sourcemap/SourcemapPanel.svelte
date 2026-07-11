<script lang="ts">
  // Source Map 检测面板 — 灵眸 v6.0
  // 流程：检测构建工具 + JS Bundle → 并发抓取 → 解析 Source Map → 敏感文件分析 → 渲染结果
  import { sendToContent, sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import UrlInput from '@/components/scanner/UrlInput.svelte';
  import ScanProgress from '@/components/scanner/ScanProgress.svelte';
  import EmptyState from '@/components/scanner/EmptyState.svelte';
  import SeverityBadge from '@/components/scanner/SeverityBadge.svelte';
  import FilterBar from '@/components/scanner/FilterBar.svelte';
  import type { FetchResult } from '@/lib/types/messaging';
  import { scanSettingsStore } from '@/stores/settings';
  import { runConcurrent } from '@/lib/core/concurrency';
  import {
    extractScriptUrls,
    extractInlineSourceMapHints,
    extractSourceMapUrl,
    parseSourceMap,
    classifySources,
    hasSourceContent,
    assessRisk,
    severityLabel,
    type DetectResult,
    type SourceMapResult,
  } from '@/lib/analyzers/sourcemap-analyzer';

  type Phase = 'idle' | 'detecting' | 'detected' | 'scanning' | 'done';

  let targetUrl = $state('');
  let phase = $state<Phase>('idle');
  let detectResult = $state<DetectResult | null>(null);
  let bundleUrls = $state<string[]>([]);
  let inlineMapHints = $state<string[]>([]);
  let results = $state<SourceMapResult[]>([]);
  let scanned = $state(0);
  let total = $state(0);
  let filter = $state<'all' | 'vuln'>('all');
  let cancelled = $state(false);

  const CONCURRENCY = $derived($scanSettingsStore.concurrency);
  const MAX_SCRIPTS = 50;
  const FETCH_TIMEOUT = $derived($scanSettingsStore.requestTimeoutMs);

  $effect(() => {
    getActiveTabUrl().then(u => {
      if (u) targetUrl = u;
    });
  });

  let filteredResults = $derived.by(() => {
    if (filter === 'vuln') {
      return results.filter(r => {
        const sev = assessRisk(r);
        return sev === 'critical' || sev === 'high' || sev === 'medium';
      });
    }
    return results;
  });

  let vulnCount = $derived(
    results.filter(r => {
      const sev = assessRisk(r);
      return sev === 'critical' || sev === 'high' || sev === 'medium';
    }).length,
  );

  let leakCount = $derived(results.filter(r => r.hasContentLeak).length);
  let mapCount = $derived(results.filter(r => r.mapUrl !== null).length);

  /** Phase 1: 检测构建工具 + 收集 JS Bundle */
  async function detect() {
    if (!targetUrl || !/^https?:\/\//.test(targetUrl)) {
      toastStore.show('请输入合法的 http(s) URL', 'error');
      return;
    }

    phase = 'detecting';
    detectResult = null;
    bundleUrls = [];
    inlineMapHints = [];
    results = [];

    // 1. 构建工具检测
    const dt = await sendToContent({ type: 'VK_SOURCEMAP_DETECT' });
    if (dt && typeof dt === 'object' && 'tool' in (dt as any)) {
      detectResult = dt as DetectResult;
    }

    // 2. 抓取页面 HTML 提取 script[src]
    try {
      const pageRes = await sendMessage({
        type: 'FETCH_URL',
        url: targetUrl,
        timeout: FETCH_TIMEOUT,
      }) as FetchResult<string>;

      if (pageRes.success && pageRes.data) {
        const html = pageRes.data;
        const scriptUrls = extractScriptUrls(html, targetUrl);
        const inlineHints = extractInlineSourceMapHints(html, targetUrl);
        // 去重合并
        const seen = new Set<string>();
        const merged: string[] = [];
        for (const u of [...scriptUrls, ...inlineHints]) {
          if (!seen.has(u)) {
            seen.add(u);
            merged.push(u);
          }
        }
        bundleUrls = merged.slice(0, MAX_SCRIPTS);
        inlineMapHints = inlineHints;
      }
    } catch {
      // 页面抓取失败，仅依赖检测到的构建工具信息
    }

    phase = 'detected';

    if (detectResult?.tool) {
      const toolLabel = detectResult.tool.toUpperCase();
      toastStore.show(
        `检测到 ${toolLabel}，发现 ${bundleUrls.length} 个 JS Bundle`,
        'success',
      );
    } else {
      toastStore.show(
        `未识别构建工具，发现 ${bundleUrls.length} 个 JS Bundle`,
        bundleUrls.length > 0 ? 'warning' : 'info',
      );
    }
  }

  /** Phase 2: 并发抓取 Bundle → 提取 Source Map → 分析 */
  async function scan() {
    if (bundleUrls.length === 0) {
      toastStore.show('未检测到 JS Bundle，请先点击「检测」', 'error');
      return;
    }

    phase = 'scanning';
    cancelled = false;
    results = [];
    scanned = 0;

    // 合并待扫描的 URL：Bundle URLs + 已知 inline sourceMappingURL hints
    const urlsToScan = bundleUrls.slice(0, MAX_SCRIPTS);
    total = urlsToScan.length;
    const collected: SourceMapResult[] = [];

    // 任务队列
    const tasks = urlsToScan.map(
      (url) => (): Promise<SourceMapResult> => scanBundle(url),
    );

    await runConcurrent(tasks, async (task) => {
      collected.push(await task());
      scanned++;
    }, { concurrency: CONCURRENCY, cancelled: () => cancelled });

    if (cancelled) {
      results = collected;
      phase = 'done';
      toastStore.show('扫描已取消', 'info');
      return;
    }

    results = collected;
    phase = 'done';

    if (vulnCount > 0) {
      toastStore.show(
        `发现 ${mapCount} 个 Source Map，${vulnCount} 个风险项，${leakCount} 个源码泄露`,
        'warning',
      );
    } else if (mapCount > 0) {
      toastStore.show(
        `发现 ${mapCount} 个 Source Map（${leakCount} 个含源码泄露）`,
        'info',
      );
    } else {
      toastStore.show('未发现 Source Map 文件', 'success');
    }
  }

  /** 扫描单个 Bundle：抓取 JS → 查找 sourceMappingURL → 抓取 .map → 解析分析 */
  async function scanBundle(bundleUrl: string): Promise<SourceMapResult> {
    // 1. 抓取 JS Bundle
    const jsRes = await sendMessage({
      type: 'FETCH_URL',
      url: bundleUrl,
      timeout: FETCH_TIMEOUT,
    }) as FetchResult<string>;

    if (!jsRes.success || !jsRes.data) {
      return {
        bundleUrl,
        mapUrl: null,
        info: null,
        sourceCount: 0,
        sensitiveFiles: [],
        hasContentLeak: false,
        error: 'JS Bundle 抓取失败',
      };
    }

    // 2. 提取 sourceMappingURL
    const mapUrl = extractSourceMapUrl(jsRes.data, bundleUrl);
    if (!mapUrl) {
      return {
        bundleUrl,
        mapUrl: null,
        info: null,
        sourceCount: 0,
        sensitiveFiles: [],
        hasContentLeak: false,
      };
    }

    // 3. 抓取 Source Map
    const mapRes = await sendMessage({
      type: 'FETCH_URL',
      url: mapUrl,
      timeout: FETCH_TIMEOUT,
    }) as FetchResult<string>;

    if (!mapRes.success || !mapRes.data) {
      return {
        bundleUrl,
        mapUrl,
        info: null,
        sourceCount: 0,
        sensitiveFiles: [],
        hasContentLeak: false,
        error: 'Source Map 抓取失败',
      };
    }

    // 4. 解析 Source Map
    const info = parseSourceMap(mapRes.data);
    if (!info) {
      return {
        bundleUrl,
        mapUrl,
        info: null,
        sourceCount: 0,
        sensitiveFiles: [],
        hasContentLeak: false,
        error: 'Source Map 解析失败',
      };
    }

    // 5. 分类源文件
    const { all, sensitive } = classifySources(info.sources);
    const contentLeak = hasSourceContent(info);

    return {
      bundleUrl,
      mapUrl,
      info,
      sourceCount: all.length,
      sensitiveFiles: sensitive,
      hasContentLeak: contentLeak,
    };
  }

  function cancel() { cancelled = true; }

  /** 复制单条结果 */
  function copyResult(r: SourceMapResult) {
    const lines = [
      `Bundle: ${r.bundleUrl}`,
      `Source Map: ${r.mapUrl || '(无)'}`,
      `源文件数: ${r.sourceCount}`,
      `敏感文件: ${r.sensitiveFiles.length > 0 ? r.sensitiveFiles.join(', ') : '(无)'}`,
      `源码泄露: ${r.hasContentLeak ? '是' : '否'}`,
    ];
    if (r.error) lines.push(`错误: ${r.error}`);
    navigator.clipboard.writeText(lines.join('\n'));
    toastStore.show('已复制到剪贴板', 'success');
  }

  /** 导出所有结果为 CSV */
  function exportResults() {
    const rows = [
      ['bundle_url', 'map_url', 'source_count', 'sensitive_count', 'sensitive_files', 'content_leak', 'severity'],
    ];
    for (const r of filteredResults) {
      const sev = severityLabel(assessRisk(r));
      rows.push([
        r.bundleUrl,
        r.mapUrl || '',
        String(r.sourceCount),
        String(r.sensitiveFiles.length),
        r.sensitiveFiles.join('; '),
        r.hasContentLeak ? 'yes' : 'no',
        sev,
      ]);
    }
    const csv = rows.map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'sourcemap-results.csv';
    a.click();
    URL.revokeObjectURL(a.href);
    toastStore.show(`已导出 ${filteredResults.length} 条结果`, 'success');
  }

  /** 短路径展示（截取最后一段） */
  function shortUrl(url: string): string {
    try {
      const u = new URL(url);
      const path = u.pathname;
      const parts = path.split('/').filter(Boolean);
      if (parts.length > 2) return '.../' + parts.slice(-2).join('/');
      return path || u.host;
    } catch {
      return url.length > 40 ? '...' + url.slice(-37) : url;
    }
  }
</script>

<div class="space-y-3">
  <!-- 输入 -->
  <div class="card p-3 space-y-2">
    <UrlInput bind:value={targetUrl} scanning={phase === 'detecting' || phase === 'scanning'} buttonText="检测" scanningText="检测中..." onscan={detect} />

    <!-- 构建工具信息 -->
    {#if detectResult}
      <div class="text-xs text-gray-400">
        {#if detectResult.tool}
          <span class="badge bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300">
            {detectResult.tool.toUpperCase()}
          </span>
          {#if detectResult.version}
            <span class="badge bg-gray-200 dark:bg-gray-700 ml-1">v{detectResult.version}</span>
          {/if}
          {#if detectResult.features.length > 0}
            {#each detectResult.features as f}
              <span class="badge bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300 ml-1">{f}</span>
            {/each}
          {/if}
        {:else}
          <span class="text-gray-400">未识别构建工具</span>
        {/if}
        <span class="ml-1">{bundleUrls.length} 个 JS Bundle</span>
      </div>
    {/if}

    <!-- 检测到 Bundle 后显示扫描按钮 -->
    {#if phase === 'detected' || phase === 'scanning' || phase === 'done'}
      <div class="flex gap-1">
        <button
          class="btn btn-sm btn-primary flex-1"
          disabled={phase === 'scanning'}
          onclick={scan}
        >
          {phase === 'scanning' ? '扫描中...' : `扫描 ${bundleUrls.length} 个 Bundle`}
        </button>
        {#if phase === 'scanning'}
          <button class="btn btn-sm btn-danger shrink-0" onclick={cancel}>取消</button>
        {/if}
      </div>
    {/if}

    <!-- 进度条 -->
    <ScanProgress {scanned} {total} scanning={phase === 'detecting' || phase === 'scanning'} label="Bundle 扫描" />
  </div>

  <!-- 统计栏 -->
  {#if results.length > 0}
    <FilterBar
      active={filter}
      options={[
        { key: 'all', label: '全部', count: results.length, color: 'bg-primary text-white' },
        { key: 'vuln', label: '风险', count: vulnCount, color: 'bg-red-500 text-white' },
      ]}
      onchange={(k) => (filter = k as 'all' | 'vuln')}
    >
      <span class="badge bg-green-500 text-white">Map {mapCount}</span>
      <span class="badge bg-orange-500 text-white">泄露 {leakCount}</span>
      <button class="btn btn-sm" onclick={exportResults}>导出</button>
    </FilterBar>
  {/if}

  <!-- 结果列表 -->
  {#if filteredResults.length > 0}
    <div class="space-y-2">
      {#each filteredResults as r (r.bundleUrl)}
        {@const sev = assessRisk(r)}
        <div class="card p-2.5 space-y-1.5">
          <div class="flex items-center gap-2">
            <SeverityBadge severity={sev} />
            {#if r.mapUrl}
              <span class="badge text-xs bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300">MAP</span>
            {/if}
            {#if r.hasContentLeak}
              <span class="badge text-xs bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300">源码泄露</span>
            {/if}
            <span class="badge text-xs bg-gray-200 dark:bg-gray-700">{r.sourceCount} 文件</span>
            <button
              class="ml-auto text-xs text-gray-400 hover:text-primary"
              onclick={() => copyResult(r)}
            >
              复制
            </button>
          </div>
          <div class="text-xs font-mono text-gray-600 dark:text-gray-300 truncate" title={r.bundleUrl}>
            {shortUrl(r.bundleUrl)}
          </div>
          {#if r.mapUrl}
            <div class="text-xs font-mono text-gray-400 truncate" title={r.mapUrl}>
              .map: {shortUrl(r.mapUrl)}
            </div>
          {/if}
          {#if r.error}
            <div class="text-xs text-red-500">{r.error}</div>
          {/if}
          {#if r.sensitiveFiles.length > 0}
            <div class="flex flex-wrap gap-1 mt-0.5">
              {#each r.sensitiveFiles.slice(0, 8) as f}
                <span class="badge text-xs bg-red-50 text-red-600 dark:bg-red-950 dark:text-red-400" title={f}>
                  {f.split('/').pop() || f}
                </span>
              {/each}
              {#if r.sensitiveFiles.length > 8}
                <span class="badge text-xs bg-gray-200 dark:bg-gray-700">+{r.sensitiveFiles.length - 8}</span>
              {/if}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {:else if phase === 'done' && results.length === 0}
    <EmptyState message="未发现 Source Map 文件" icon="✅" />
  {:else if phase === 'idle'}
    <EmptyState message="输入目标 URL，点击「检测」发现 JS Bundle 和 Source Map 文件" icon="🔍" />
  {/if}
</div>
