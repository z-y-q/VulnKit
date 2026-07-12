<script lang="ts">
  // 目录扫描面板 — 灵眸 v6.0
  // 流程：选字典 → 拼路径 → 并发探测 → 内容分析 → 排序渲染
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore } from '@/stores/ui';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import { scanSettingsStore } from '@/stores/settings';
  import { runConcurrent } from '@/lib/core/concurrency';
  import UrlInput from '@/components/scanner/UrlInput.svelte';
  import ScanProgress from '@/components/scanner/ScanProgress.svelte';
  import EmptyState from '@/components/scanner/EmptyState.svelte';
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
  let scanning = $state(false);
  let scanned = $state(0);
  let total = $state(0);
  let results = $state<FuzzResult[]>([]);
  let foundOnly = $state(true);
  let sortBy = $state<'status' | 'size' | 'time'>('status');
  let customPaths = $state('');
  let cancelled = $state(false);
  let paused = $state(false);
  let statusFilter = $state<number | null>(null);

  const wordlistKeys = getWordlistKeys();

  $effect(() => {
    getActiveTabUrl().then(u => {
      if (u) targetUrl = u;
    });
  });

  // 消费来自其他面板（如 Wayback 历史档案）发送的路径
  $effect(() => {
    browser.storage.local.get('lingmou:fuzz-pending').then((res) => {
      const pending = res?.['lingmou:fuzz-pending'] as string | undefined;
      if (pending) {
        customPaths = pending;
        browser.storage.local.remove('lingmou:fuzz-pending');
      }
    }).catch(() => { /* ignore */ });
  });

  let filtered = $derived.by(() => {
    let list = results;
    if (statusFilter !== null) {
      list = list.filter(r => r.status === statusFilter);
    } else if (foundOnly) {
      list = list.filter(r => isFoundStatus(r.status));
    }
    const fns: Record<string, (a: FuzzResult, b: FuzzResult) => number> = {
      status: (a, b) => a.status - b.status,
      size: (a, b) => b.size - a.size,
      time: (a, b) => a.time - b.time,
    };
    return [...list].sort(fns[sortBy]);
  });

  let uniqueStatusCodes = $derived.by(() => {
    const codes = new Set<number>();
    for (const r of results) {
      if (r.status > 0) codes.add(r.status);
    }
    return [...codes].sort((a, b) => a - b);
  });

  const SENSITIVE_TAGS = new Set(['敏感信息', 'WAF', '管理界面']);

  function mapToFindings(results: FuzzResult[]): ScanFinding[] {
    return results
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
    if (s === 404) return 'text-gray-400';
    if (s >= 500) return 'text-red-600 dark:text-red-400';
    return 'text-gray-500';
  }

  async function probe(path: string, method: string): Promise<FuzzResult | null> {
    const u = new URL(path, targetUrl).href;
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
      return {
        path,
        url: u,
        status: r.status || 0,
        size,
        time: Date.now() - start,
        method,
        analysis,
      };
    } catch {
      return null;
    }
  }

  /**
   * HEAD 优先策略：先发 HEAD（省带宽），仅在 405/501 或 HEAD 无有效状态时回退 GET。
   * GET 才做内容分析（识别备份/SQL/配置等）。
   */
  async function probeSmart(path: string): Promise<FuzzResult | null> {
    const head = await probe(path, 'HEAD');
    if (head && head.status !== 0 && head.status !== 405 && head.status !== 501) {
      head.severity = gradeSeverity(head);
      return head;
    }
    // 回退 GET（需要 body 做内容分析）
    const get = await probe(path, 'GET');
    if (get) get.severity = gradeSeverity(get);
    return get;
  }

  async function scan() {
    const v = validateProbeUrl(targetUrl);
    if ('error' in v) {
      toastStore.show('请输入合法的 http(s) URL', 'error');
      return;
    }
    // 规整 base：去 query/hash，保证以 / 结尾
    const base = v.parsed.origin + v.parsed.pathname.replace(/[?#].*$/, '');
    const baseUrl = base.endsWith('/') ? base : base + '/';

    scanning = true;
    results = [];
    scanned = 0;
    cancelled = false;
    paused = false;
    statusFilter = null;

    let paths = getWordlist(wordlistKey);
    if (customPaths.trim()) {
      paths = [...new Set([...customPaths.split(/\r?\n/).map(p => p.trim()).filter(Boolean), ...paths])];
    }
    total = paths.length;
    const collected: FuzzResult[] = [];

    await runConcurrent(paths, async (path) => {
      const cleanPath = path.replace(/^\/+/, '');
      const r = await probeSmart(cleanPath);
      if (r) collected.push(r);
      scanned++;
    }, { concurrency: $scanSettingsStore.concurrency, cancelled: () => cancelled, paused: () => paused });

    // 去重（软 404 标记）+ 严重级别评估
    markDuplicates(collected);
    for (const r of collected) {
      if (!r.severity) r.severity = gradeSeverity(r);
    }
    results = collected;
    scanning = false;

    if (cancelled) {
      toastStore.show('扫描已取消', 'info');
      return;
    }

    try {
      await scanHistoryStore.addScan({ url: targetUrl, module: 'fuzz', findings: mapToFindings(results) });
    } catch { /* store failure must not break scan */ }

    const found = collected.filter(r => isFoundStatus(r.status)).length;
    toastStore.show(`扫描完成，发现 ${found} 个有效路径（共 ${total}）`, found > 0 ? 'warning' : 'success');
  }

  function cancel() { cancelled = true; paused = false; }

  function togglePause() { paused = !paused; }

  function exportResults() {
    const rows = [['path', 'url', 'status', 'size', 'method']];
    for (const r of filtered) rows.push([r.path, r.url, String(r.status), String(r.size), r.method]);
    const csv = rows.map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = 'fuzz-results.csv';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function exportTxt() {
    if (filtered.length === 0) return;
    const found = filtered.filter(r => r.status > 0 && r.status !== 404);
    const lines = [
      '目录扫描报告',
      '==================',
      '目标: ' + targetUrl,
      '字典: ' + wordlistKey,
      '发现: ' + found.length,
      '',
    ];
    for (const e of found) {
      lines.push(`[${e.status}] ${e.path} (${e.size}B, ${e.time}ms${e.method === 'GET' ? ', GET' : ''})`);
      if (e.analysis?.title) lines.push('  Title: ' + e.analysis.title);
      if (e.analysis?.tags?.length) lines.push('  Tags: ' + e.analysis.tags.join(', '));
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'fuzz-report.txt';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    toastStore.show('TXT 报告已导出', 'success');
  }

  function copyMarkdown() {
    if (filtered.length === 0) {
      toastStore.show('没有可复制的结果', 'warning');
      return;
    }
    const found = filtered.filter(r => r.status > 0 && r.status !== 404);
    if (found.length === 0) {
      toastStore.show('没有有效结果', 'warning');
      return;
    }
    const lines = ['| Path | Status | Size | Time |', '| --- | --- | --- | --- |'];
    for (const e of found) {
      lines.push(`| ${e.path} | ${e.status} | ${e.size} | ${e.time} |`);
    }
    navigator.clipboard.writeText(lines.join('\n'));
    toastStore.show('已复制 Markdown 表格', 'success');
  }

  function copyResults() {
    if (filtered.length === 0) {
      toastStore.show('没有可复制的结果', 'warning');
      return;
    }
    const found = filtered.filter(r => r.status > 0 && r.status !== 404);
    if (found.length === 0) {
      toastStore.show('没有有效结果', 'warning');
      return;
    }
    const lines = [`目录扫描 @ ${targetUrl}`, `字典: ${wordlistKey}`, `发现: ${found.length}`, ''];
    for (const e of found) {
      lines.push(`[${e.status}] ${e.path} (${e.size}B, ${e.time}ms)`);
    }
    navigator.clipboard.writeText(lines.join('\n'));
    toastStore.show('已复制纯文本', 'success');
  }

  function copyCurl() {
    if (filtered.length === 0) {
      toastStore.show('没有可复制的结果', 'warning');
      return;
    }
    const found = filtered.filter(r => r.status > 0 && r.status !== 404);
    if (found.length === 0) {
      toastStore.show('没有有效结果', 'warning');
      return;
    }
    const cmds = found.map(r => `curl -I -s "${r.url}"`).join('\n');
    navigator.clipboard.writeText(cmds);
    toastStore.show('已复制 cURL 命令', 'success');
  }
</script>

<div class="space-y-3">
  <!-- 输入 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <UrlInput bind:value={targetUrl} {scanning} buttonText="扫描" onscan={scan} />
      {#if scanning}
        <button class="btn btn-sm btn-danger shrink-0" onclick={cancel}>取消</button>
        <button
          class="btn btn-sm shrink-0"
          class:btn-primary={paused}
          onclick={togglePause}
        >
          {paused ? '继续' : '暂停'}
        </button>
      {/if}
    </div>
    <div class="flex items-center gap-2 text-xs">
      <span class="text-gray-400">字典:</span>
      <select class="input text-xs flex-1" bind:value={wordlistKey}>
        {#each wordlistKeys as k}
          <option value={k}>{k} ({getWordlist(k).length})</option>
        {/each}
      </select>
    </div>
    <details class="text-xs">
      <summary class="cursor-pointer text-gray-400">自定义路径（每行一个，合并到字典）</summary>
      <textarea class="input w-full mt-1 font-mono" rows="3" placeholder="/admin&#10;/test&#10;/backup.zip" bind:value={customPaths}></textarea>
    </details>
    <ScanProgress {scanned} {total} {scanning} label="目录扫描" />
  </div>

  <!-- 工具栏 -->
  {#if results.length > 0}
    <!-- 状态码过滤 -->
    <div class="flex flex-wrap items-center gap-1.5 text-xs">
      <button
        class="badge cursor-pointer {statusFilter === null ? 'bg-blue-600 text-white' : 'bg-gray-200 dark:bg-gray-700'}"
        onclick={() => statusFilter = null}
      >
        有效
      </button>
      {#each uniqueStatusCodes as code}
        <button
          class="badge cursor-pointer {statusFilter === code ? 'bg-blue-600 text-white' : 'bg-gray-200 dark:bg-gray-700'}"
          onclick={() => statusFilter = statusFilter === code ? null : code}
        >
          {code}
        </button>
      {/each}
    </div>
    <div class="flex items-center gap-2 text-xs">
      <span>{filtered.length} 条</span>
      <select class="input text-xs w-24 ml-auto" bind:value={sortBy}>
        <option value="status">按状态码</option>
        <option value="size">按大小</option>
        <option value="time">按耗时</option>
      </select>
      <button class="btn btn-sm" onclick={copyResults} title="复制纯文本">复制</button>
      <button class="btn btn-sm" onclick={exportResults} title="导出 CSV">CSV</button>
      <button class="btn btn-sm" onclick={exportTxt} title="导出 TXT">TXT</button>
      <button class="btn btn-sm" onclick={copyMarkdown} title="复制 Markdown">MD</button>
      <button class="btn btn-sm" onclick={copyCurl} title="复制 cURL">cURL</button>
    </div>
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
          <span class="text-xs text-gray-400 shrink-0">{r.size}B</span>
          <span class="text-xs text-gray-400 shrink-0">{r.time}ms</span>
        </div>
      {/each}
    </div>
  {:else if !scanning && results.length === 0 && scanned > 0}
    <EmptyState message="未发现有效路径" icon="🔍" />
  {:else if !scanning}
    <EmptyState
      message="选择字典，扫描目标站点的目录与敏感文件"
      hint="支持自定义路径，合并到所选字典中"
      icon="📂"
    />
  {/if}
</div>
