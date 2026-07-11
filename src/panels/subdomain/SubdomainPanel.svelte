<script lang="ts">
  // 子域名枚举面板 — 灵眸 v6.0
  // 流程：自动填充 URL → 提取根域 → 词表生成 → DNS 并发解析 → 结果渲染
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore } from '@/stores/ui';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import type { DnsResolveResult } from '@/lib/types/messaging';
  import {
    SUBDOMAIN_WORDLIST,
    extractRootDomain,
    buildSubdomainCandidates,
    analyzeDnsResult,
    dedupAliveResults,
    buildStats,
    type SubdomainResult,
  } from '@/lib/scanners/subdomain-engine';

  let targetUrl = $state('');
  let scanning = $state(false);
  let scanned = $state(0);
  let total = $state(0);
  let results = $state<SubdomainResult[]>([]);
  let searchQuery = $state('');
  let sortBy = $state<'name' | 'ips'>('name');

  $effect(() => {
    getActiveTabUrl().then(u => {
      if (u) targetUrl = u;
    });
  });

  let filteredResults = $derived.by(() => {
    let list = dedupAliveResults(results);
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(r => r.subdomain.toLowerCase().includes(q));
    }
    if (sortBy === 'name') {
      list.sort((a, b) => a.subdomain.localeCompare(b.subdomain));
    } else {
      list.sort((a, b) => b.ips.length - a.ips.length);
    }
    return list;
  });

  let stats = $derived(buildStats(results, 0));
  let elapsed = $state(0);

  async function resolveOne(hostname: string): Promise<SubdomainResult> {
    try {
      const res = await sendMessage({ type: 'FETCH_DNS_RESOLVE', hostname }) as DnsResolveResult;
      return analyzeDnsResult(hostname, res);
    } catch {
      return { subdomain: hostname, ips: [], records: [], status: 'dead' };
    }
  }

  function mapSubdomainsToFindings(alive: SubdomainResult[]): ScanFinding[] {
    return alive.map(r => ({
      title: `子域名: ${r.subdomain}`,
      severity: 'info' as const,
      detail: `IPs: ${r.ips.join(', ')}`,
      evidence: r.cname || undefined,
      url: `https://${r.subdomain}`,
    }));
  }

  async function scan() {
    const v = validateProbeUrl(targetUrl);
    if ('error' in v) {
      toastStore.show('请输入合法的 http(s) URL', 'error');
      return;
    }

    const rootDomain = extractRootDomain(v.parsed.hostname);
    const candidates = buildSubdomainCandidates(rootDomain);

    scanning = true;
    results = [];
    scanned = 0;
    total = candidates.length;
    const startMs = Date.now();
    elapsed = 0;

    const CONCURRENCY = 8;
    let idx = 0;

    async function worker() {
      while (idx < candidates.length) {
        const cur = idx++;
        const r = await resolveOne(candidates[cur].full);
        results.push(r);
        scanned++;
        elapsed = Date.now() - startMs;
      }
    }

    await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));
    elapsed = Date.now() - startMs;
    scanning = false;

    const aliveCount = results.filter(r => r.status === 'alive').length;
    if (aliveCount > 0) {
      toastStore.show(`发现 ${aliveCount} 个存活子域名（共 ${total} 候选）`, 'warning');
    } else {
      toastStore.show(`枚举完成，未发现存活子域名（${total} 候选）`, 'success');
    }

    // 发布到扫描历史
    try {
      const alive = results.filter(r => r.status === 'alive');
      await scanHistoryStore.addScan({
        url: targetUrl,
        module: 'subdomain',
        findings: mapSubdomainsToFindings(alive),
      });
    } catch { /* store failure must not break scan */ }
  }

  function copyAll() {
    if (filteredResults.length === 0) {
      toastStore.show('没有可复制的结果', 'warning');
      return;
    }
    const text = filteredResults.map(r => r.subdomain).join('\n');
    navigator.clipboard.writeText(text);
    toastStore.show(`已复制 ${filteredResults.length} 个子域名`, 'success');
  }

  function exportCsv() {
    if (filteredResults.length === 0) return;
    const rows = [['subdomain', 'ips', 'cname', 'record_count']];
    for (const r of filteredResults) {
      rows.push([r.subdomain, r.ips.join(';'), r.cname || '', String(r.records.length)]);
    }
    const csv = rows.map(row => row.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'subdomains.csv';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function copyRow(r: SubdomainResult) {
    const text = [
      `Subdomain: ${r.subdomain}`,
      `IPs: ${r.ips.join(', ') || '(无)'}`,
      `CNAME: ${r.cname || '(无)'}`,
      `Records: ${r.records.map(rec => `${rec.type}: ${rec.data}`).join(', ') || '(无)'}`,
    ].join('\n');
    navigator.clipboard.writeText(text);
    toastStore.show(`已复制: ${r.subdomain}`, 'success');
  }

  function formatElapsed(ms: number): string {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  }
</script>

<div class="space-y-3">
  <!-- 输入 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <input class="input flex-1 text-sm" placeholder="目标 URL (https://...)" bind:value={targetUrl} />
      <button class="btn btn-sm btn-primary" disabled={scanning || !targetUrl} onclick={scan}>
        {scanning ? '枚举中...' : '枚举'}
      </button>
    </div>
    <div class="flex items-center gap-2 text-xs text-gray-400">
      <span>词表: {SUBDOMAIN_WORDLIST.length} 条</span>
      <span>·</span>
      <span>并发: 8</span>
    </div>
    {#if scanning}
      <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5 overflow-hidden">
        <div class="bg-primary h-full transition-all" style="width: {total ? (scanned / total) * 100 : 0}%"></div>
      </div>
      <div class="text-xs text-gray-400">
        {scanned} / {total} · {formatElapsed(elapsed)}
      </div>
    {/if}
  </div>

  <!-- 工具栏 -->
  {#if results.length > 0}
    <div class="flex items-center gap-2 text-xs">
      <span class="badge bg-green-500 text-white">存活 {stats.alive}</span>
      <span class="badge bg-gray-200 dark:bg-gray-700">总计 {stats.total}</span>
      <span class="text-gray-400">·</span>
      <span>{filteredResults.length} 条</span>
      <input
        class="input text-xs flex-1 ml-2"
        placeholder="搜索子域名..."
        bind:value={searchQuery}
      />
      <select class="input text-xs w-20" bind:value={sortBy}>
        <option value="name">按名称</option>
        <option value="ips">按 IP 数</option>
      </select>
      <button class="btn btn-sm" onclick={copyAll}>复制</button>
      <button class="btn btn-sm" onclick={exportCsv}>导出</button>
    </div>
  {/if}

  <!-- 结果 -->
  {#if filteredResults.length > 0}
    <div class="space-y-1">
      {#each filteredResults as r (r.subdomain)}
        <div class="card p-2 flex items-center gap-2">
          <span class="badge text-xs bg-green-600 text-white w-8 justify-center shrink-0">
            {r.ips.length}
          </span>
          <div class="flex-1 min-w-0">
            <div class="text-xs font-mono text-gray-700 dark:text-gray-200 truncate">{r.subdomain}</div>
            {#if r.ips.length > 0}
              <div class="text-xs text-gray-400 truncate">{r.ips.join(', ')}</div>
            {/if}
            {#if r.cname}
              <div class="text-xs text-blue-500 dark:text-blue-400 truncate">
                CNAME: {r.cname}
              </div>
            {/if}
          </div>
          <span class="badge text-xs bg-gray-200 dark:bg-gray-700 shrink-0">
            {r.records.length}
          </span>
          <button
            class="ml-auto text-xs text-gray-400 hover:text-primary shrink-0"
            onclick={() => copyRow(r)}
          >
            复制
          </button>
        </div>
      {/each}
    </div>
  {:else if !scanning && results.length === 0 && scanned > 0}
    <div class="text-center text-gray-400 text-sm py-8">未发现存活子域名</div>
  {:else if !scanning}
    <div class="text-center text-gray-400 text-sm py-8">
      输入目标 URL，点击「枚举」开始 DNS 子域名扫描
    </div>
  {/if}
</div>
