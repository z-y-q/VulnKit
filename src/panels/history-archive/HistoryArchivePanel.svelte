<script lang="ts">
  // Wayback Machine 历史档案面板
  // 通过 CDX API 查询目标的 Web Archive 历史快照（URL/状态码/MIME/时间）。
  // 注意：这是新的"历史档案"面板，与本地扫描历史（HistoryPanel）不同。对齐 v5 vk-history.js。
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore } from '@/stores/ui';
  import { analysisContextStore } from '@/stores/analysis-context';
  import type { FetchResult } from '@/lib/types/messaging';
  import UrlInput from '@/components/scanner/UrlInput.svelte';
  import EmptyState from '@/components/scanner/EmptyState.svelte';

  let targetUrl = $state('');
  let querying = $state(false);
  let matchType = $state<'domain' | 'host' | 'exact' | 'prefix' | 'suffix'>('domain');
  let fromYear = $state('');
  let toYear = $state('');
  let typeFilter = $state(''); // php/asp/jsp/空
  let results = $state<{ timestamp: string; url: string; status: string; mime: string }[]>([]);
  let cancelled = $state(false);

  $effect(() => { getActiveTabUrl().then(u => { if (u) targetUrl = u; }); });

  /** 提取查询目标（domain 或完整 URL，按 matchType） */
  function queryTarget(): string {
    const v = validateProbeUrl(targetUrl);
    const base = 'error' in v ? targetUrl.trim() : v.parsed.hostname;
    return base;
  }

  function buildCdxUrl(): string {
    const target = queryTarget();
    const fields = 'timestamp,original,statuscode,mimetype';
    let url = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(target)}&collapse=urlkey&matchType=${matchType}&output=json&fl=${fields}&limit=2000`;
    if (fromYear.trim()) url += `&from=${fromYear.trim()}`;
    if (toYear.trim()) url += `&to=${toYear.trim()}`;
    if (typeFilter.trim()) url += `&filter=original:.*\\.${typeFilter.trim()}($|\\?.*)`;
    return url;
  }

  function parseCdxJson(jsonText: string) {
    try {
      const data = JSON.parse(jsonText);
      if (!Array.isArray(data) || data.length < 2) return [];
      // 首行为字段名
      const items: { timestamp: string; url: string; status: string; mime: string }[] = [];
      for (let i = 1; i < data.length; i++) {
        const row = data[i];
        items.push({
          timestamp: String(row[0] || ''),
          url: String(row[1] || ''),
          status: String(row[2] || ''),
          mime: String(row[3] || ''),
        });
      }
      return items;
    } catch { return []; }
  }

  async function query() {
    if (!targetUrl.trim()) { toastStore.show('请输入目标', 'warning'); return; }
    querying = true; results = []; cancelled = false;
    try {
      const cdxUrl = buildCdxUrl();
      const res = await sendMessage({ type: 'FETCH_URL', url: cdxUrl }) as FetchResult<string>;
      if (!res?.success || !res.data) { toastStore.show('CDX 查询失败（可能无历史记录或网络受限）', 'warning'); querying = false; return; }
      const items = parseCdxJson(res.data);
      results = items;
      toastStore.show(`找到 ${items.length} 条历史快照`, items.length ? 'success' : 'info');
    } catch (e: any) {
      toastStore.show('查询出错: ' + (e.message || ''), 'error');
    } finally {
      querying = false;
    }
  }

  function fmtTs(ts: string): string {
    // CDX 时间戳格式 YYYYMMDDhhmmss
    if (ts.length < 8) return ts;
    return `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}${ts.length >= 10 ? ' ' + ts.slice(8, 10) + ':' + ts.slice(10, 12) : ''}`;
  }

  function statusClass(s: string): string {
    const n = parseInt(s, 10);
    if (n >= 200 && n < 300) return 'text-green-600 dark:text-green-400';
    if (n >= 300 && n < 400) return 'text-blue-600 dark:text-blue-400';
    if (n === 404) return 'text-gray-400';
    if (n >= 400) return 'text-red-500';
    return 'text-gray-500';
  }

  function snapshotUrl(ts: string, url: string): string {
    return `https://web.archive.org/web/${ts}/${url}`;
  }

  function copyAll() {
    if (!results.length) return;
    navigator.clipboard.writeText(results.map(r => r.url).join('\n')).then(() =>
      toastStore.show(`已复制 ${results.length} 个 URL`, 'success'));
  }

  function exportTxt() {
    if (!results.length) { toastStore.show('无结果', 'warning'); return; }
    const lines = results.map(r => `${fmtTs(r.timestamp)}  [${r.status}]  ${r.url}`);
    const blob = new Blob([`# Wayback 历史快照 @ ${queryTarget()}\n` + lines.join('\n')], { type: 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `wayback-${queryTarget()}-${Date.now()}.txt`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    toastStore.show('TXT 已导出', 'success');
  }

  /** 发送到 URL 多开面板 */
  async function sendToMultiUrl() {
    if (!results.length) { toastStore.show('无结果', 'warning'); return; }
    const text = results.map(r => snapshotUrl(r.timestamp, r.url)).join('\n');
    await analysisContextStore.handoff({
      sourcePanel: 'history-archive', sourceLabel: 'Wayback',
      targetPanel: 'multiurl', payload: { text }, summary: `${results.length} 条历史快照`,
    });
  }

  /** 发送到目录扫描：从历史 URL 提取路径作为字典 */
  async function sendToFuzz() {
    if (!results.length) { toastStore.show('无结果', 'warning'); return; }
    const paths = new Set<string>();
    for (const r of results) {
      try {
        const u = new URL(r.url);
        const p = u.pathname;
        if (p && p !== '/') paths.add(p);
        // 也把文件名部分（去扩展名的目录）纳入
      } catch { /* ignore */ }
    }
    if (!paths.size) { toastStore.show('未能从历史 URL 提取路径', 'warning'); return; }
    await analysisContextStore.handoff({
      sourcePanel: 'history-archive', sourceLabel: 'Wayback',
      targetPanel: 'fuzz', payload: { paths: [...paths].join('\n') }, summary: `${paths.size} 条路径`,
    });
  }

  function calendarLink(): string {
    const t = queryTarget();
    return `https://web.archive.org/web/*/${encodeURIComponent(t)}/*`;
  }
</script>

<div class="space-y-3">
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <UrlInput bind:value={targetUrl} buttonText="查询历史" onscan={query} />
    </div>
    <div class="flex items-center gap-2 text-xs flex-wrap">
      <span class="text-gray-400">匹配:</span>
      <select class="input text-xs w-24" bind:value={matchType}>
        <option value="domain">整个域名</option>
        <option value="host">单主机</option>
        <option value="exact">精确URL</option>
        <option value="prefix">前缀</option>
        <option value="suffix">后缀</option>
      </select>
      <input class="input text-xs w-20" placeholder="from(年)" bind:value={fromYear} />
      <input class="input text-xs w-20" placeholder="to(年)" bind:value={toYear} />
      <input class="input text-xs w-20" placeholder="类型(php/asp)" bind:value={typeFilter} />
    </div>
    <div class="text-xs text-gray-400">通过 CDX API 查询 Wayback Machine 历史快照，发现已下线页面/旧接口/敏感文件存档</div>
  </div>

  {#if results.length > 0}
    <div class="card p-2 flex items-center gap-2 text-xs">
      <span>共 {results.length} 条</span>
      <button class="btn btn-xs" onclick={copyAll}>复制</button>
      <button class="btn btn-xs" onclick={exportTxt}>导出</button>
      <button class="btn btn-xs" onclick={sendToMultiUrl}>→多开</button>
      <button class="btn btn-xs" onclick={sendToFuzz}>→目录扫描</button>
      <a href={calendarLink()} target="_blank" class="btn btn-xs ml-auto">Wayback 日历</a>
    </div>
    <div class="card p-2 space-y-0.5 max-h-[28rem] overflow-y-auto">
      {#each results as r (r.timestamp + r.url)}
        <div class="text-xs py-1 border-b border-gray-100 dark:border-gray-800 last:border-0 flex items-center gap-2">
          <span class="font-mono text-gray-400 shrink-0">{fmtTs(r.timestamp)}</span>
          <span class="font-mono shrink-0 w-10 {statusClass(r.status)}">{r.status}</span>
          <a href={snapshotUrl(r.timestamp, r.url)} target="_blank" class="font-mono text-blue-500 hover:underline truncate flex-1" title={r.url}>{r.url}</a>
        </div>
      {/each}
    </div>
  {:else if !querying}
    <EmptyState message="输入目标，查询 Wayback Machine 历史快照" hint="发现已下线页面、旧版接口、备份文件存档" icon="📜" />
  {/if}
</div>
