<script lang="ts">
  // 开放重定向检测面板 — 灵眸 v6.0
  // 流程：构建 参数 × 协议变体 测试 URL → 不跟随重定向探测 → 引擎判定 → 渲染
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore } from '@/stores/ui';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import { scanSettingsStore } from '@/stores/settings';
  import UrlInput from '@/components/scanner/UrlInput.svelte';
  import ScanProgress from '@/components/scanner/ScanProgress.svelte';
  import EmptyState from '@/components/scanner/EmptyState.svelte';
  import FilterBar from '@/components/scanner/FilterBar.svelte';
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
  let cancelled = $state(false);
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

  async function scan() {
    const v = validateProbeUrl(targetUrl);
    if ('error' in v) {
      toastStore.show('请输入合法的 http(s) URL', 'error');
      return;
    }
    scanning = true;
    cancelled = false;
    results = [];
    scanned = 0;

    const tests = buildTestUrls(v.parsed.origin + v.parsed.pathname);
    total = tests.length;
    const collected: RedirectResult[] = [];

    const CONCURRENCY = $scanSettingsStore.concurrency;
    let idx = 0;
    async function worker() {
      while (idx < tests.length) {
        if (cancelled) return;
        const cur = idx++;
        const t = tests[cur];
        const r = await probe(t.url);
        if (r) collected.push({ ...r, param: t.param, variant: t.variant });
        scanned++;
      }
    }
    await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));

    if (cancelled) {
      scanning = false;
      toastStore.show('扫描已取消', 'info');
      return;
    }

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

  function cancel() { cancelled = true; }
</script>

<div class="space-y-3">
  <!-- 输入 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <UrlInput bind:value={targetUrl} {scanning} buttonText="检测" onscan={scan} />
      {#if scanning}
        <button class="btn btn-sm btn-danger shrink-0" onclick={cancel}>取消</button>
      {/if}
    </div>
    <div class="text-xs text-gray-400">
      {REDIRECT_PAYLOADS.length} 个参数 × {PROTOCOL_VARIANTS.length} 个协议变体 = {REDIRECT_PAYLOADS.length * PROTOCOL_VARIANTS.length} 个测试
    </div>
    <ScanProgress {scanned} {total} {scanning} label="重定向检测" />
  </div>

  <!-- 统计 -->
  {#if results.length > 0}
    <FilterBar
      active={filter}
      options={[
        { key: 'all', label: '全部', count: results.length, color: 'bg-primary text-white' },
        { key: 'vuln', label: '漏洞', count: vulnCount, color: 'bg-red-500 text-white' },
      ]}
      onchange={(k) => (filter = k as 'all' | 'vuln')}
    />
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
    <EmptyState message="未发现开放重定向" icon="✅" />
  {:else if !scanning}
    <EmptyState
      message="输入目标 URL，检测开放重定向漏洞（参数注入测试）"
      hint="{REDIRECT_PAYLOADS.length} 个参数 × {PROTOCOL_VARIANTS.length} 个协议变体"
      icon="🔀"
    />
  {/if}
</div>
