<script lang="ts">
  // 开放重定向检测面板 — 灵眸 v6.0
  // 流程：构建 参数 × 协议变体 测试 URL → 不跟随重定向探测 → 引擎判定 → 渲染
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore } from '@/stores/ui';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import type { ProbeResult } from '@/lib/types/messaging';
  import {
    buildTestUrls,
    isRedirectVulnerable,
    PROTOCOL_VARIANTS,
    REDIRECT_PAYLOADS,
    type RedirectResult,
  } from '@/lib/scanners/redirect-engine';

  let targetUrl = $state('');
  let scanning = $state(false);
  let scanned = $state(0);
  let total = $state(0);
  let results = $state<RedirectResult[]>([]);
  let filter = $state<'all' | 'vuln'>('all');

  $effect(() => {
    getActiveTabUrl().then(u => {
      if (u) targetUrl = u;
    });
  });

  let filtered = $derived(filter === 'vuln' ? results.filter(r => r.status === 'vulnerable') : results);
  let vulnCount = $derived(results.filter(r => r.status === 'vulnerable').length);

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
        timeout: 8000,
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

  async function scan() {
    const v = validateProbeUrl(targetUrl);
    if ('error' in v) {
      toastStore.show('请输入合法的 http(s) URL', 'error');
      return;
    }
    scanning = true;
    results = [];
    scanned = 0;

    const tests = buildTestUrls(v.parsed.origin + v.parsed.pathname);
    total = tests.length;
    const collected: RedirectResult[] = [];

    const CONCURRENCY = 8;
    let idx = 0;
    async function worker() {
      while (idx < tests.length) {
        const cur = idx++;
        const t = tests[cur];
        const r = await probe(t.url);
        if (r) collected.push({ ...r, param: t.param, variant: t.variant });
        scanned++;
      }
    }
    await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));

    // 漏洞优先
    results = collected.sort((a, b) => {
      if (a.status !== b.status) return a.status === 'vulnerable' ? -1 : 1;
      return a.param.localeCompare(b.param);
    });
    scanning = false;

    try {
      await scanHistoryStore.addScan({ url: targetUrl, module: 'redirect', findings: mapToFindings(results) });
    } catch { /* store failure must not break scan */ }

    if (vulnCount > 0) {
      toastStore.show(`发现 ${vulnCount} 个开放重定向点`, 'warning');
    } else {
      toastStore.show(`检测完成，未发现开放重定向（${total} 个测试）`, 'success');
    }
  }
</script>

<div class="space-y-3">
  <!-- 输入 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <input class="input flex-1 text-sm" placeholder="目标 URL (https://...)" bind:value={targetUrl} />
      <button class="btn btn-sm btn-primary" disabled={scanning || !targetUrl} onclick={scan}>
        {scanning ? '扫描中...' : '检测'}
      </button>
    </div>
    <div class="text-xs text-gray-400">
      {REDIRECT_PAYLOADS.length} 个参数 × {PROTOCOL_VARIANTS.length} 个协议变体 = {REDIRECT_PAYLOADS.length * PROTOCOL_VARIANTS.length} 个测试
    </div>
    {#if scanning}
      <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5 overflow-hidden">
        <div class="bg-primary h-full transition-all" style="width: {total ? (scanned / total) * 100 : 0}%"></div>
      </div>
      <div class="text-xs text-gray-400">{scanned} / {total}</div>
    {/if}
  </div>

  <!-- 统计 -->
  {#if results.length > 0}
    <div class="flex gap-2 text-xs">
      <button
        class="badge {filter === 'all' ? 'bg-primary text-white' : 'bg-gray-200 dark:bg-gray-700'}"
        onclick={() => (filter = 'all')}>全部 {results.length}</button>
      <button
        class="badge {filter === 'vuln' ? 'bg-red-500 text-white' : 'bg-gray-200 dark:bg-gray-700'}"
        onclick={() => (filter = 'vuln')}>漏洞 {vulnCount}</button>
    </div>
  {/if}

  <!-- 结果 -->
  {#if filtered.length > 0}
    <div class="space-y-1.5">
      {#each filtered as r (r.url)}
        <div class="card p-2.5 space-y-1">
          <div class="flex items-center gap-2">
            <span class="badge text-xs {r.status === 'vulnerable' ? 'bg-red-500 text-white' : 'bg-gray-400 text-white'}">
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
  {:else if !scanning && results.length === 0 && scanned > 0}
    <div class="text-center text-gray-400 text-sm py-8">未发现开放重定向</div>
  {:else if !scanning}
    <div class="text-center text-gray-400 text-sm py-8">
      输入目标 URL，检测开放重定向漏洞（参数注入测试）
    </div>
  {/if}
</div>
