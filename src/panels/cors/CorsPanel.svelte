<script lang="ts">
  // CORS 检测面板 — 灵眸 v6.0
  // 流程：自动填充 URL → 端点 × Origin 变体并发探测 → 引擎分析 → 按风险排序渲染
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore } from '@/stores/ui';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import { scanSettingsStore } from '@/stores/settings';
  import { runConcurrent } from '@/lib/core/concurrency';
  import { compareSeverity } from '@/lib/types/severity';
  import UrlInput from '@/components/scanner/UrlInput.svelte';
  import ScanProgress from '@/components/scanner/ScanProgress.svelte';
  import EmptyState from '@/components/scanner/EmptyState.svelte';
  import SeverityBadge from '@/components/scanner/SeverityBadge.svelte';
  import FilterBar from '@/components/scanner/FilterBar.svelte';
  import type { ProbeResult } from '@/lib/types/messaging';
  import {
    analyzeResults,
    buildDynamicOrigins,
    DEFAULT_CORS_ENDPOINTS,
    ORIGIN_VARIANTS,
    severityLabel,
    type CorsEndpoint,
    type CorsIssue,
    type OriginVariant,
    type CorsProbeResult,
  } from '@/lib/scanners/cors-engine';

  let targetUrl = $state('');
  let scanning = $state(false);
  let scanned = $state(0);
  let total = $state(0);
  let issues = $state<CorsIssue[]>([]);
  let safeCount = $state(0);
  let useDynamic = $state(true);
  let cancelled = $state(false);
  let sortBy = $state<'risk' | 'url'>('risk');
  let filter = $state<'all' | 'vuln'>('all');

  $effect(() => {
    getActiveTabUrl().then(u => {
      if (u) targetUrl = u;
    });
  });

  let sortedIssues = $derived.by(() => {
    const list = filter === 'vuln' ? issues.filter(i => i.severity !== 'safe') : issues;
    return [...list].sort((a, b) => {
      if (sortBy === 'url') return (a.url || '').localeCompare(b.url || '');
      return compareSeverity(a.severity, b.severity);
    });
  });

  let vulnCount = $derived(issues.filter(i => i.severity !== 'safe').length);

  async function probeOne(
    url: string,
    method: string,
    endpoint: CorsEndpoint,
    origin: OriginVariant,
  ): Promise<CorsProbeResult | null> {
    try {
      const res = await sendMessage({
        type: 'FETCH_CORS_PROBE',
        url,
        method,
        headers: { Origin: origin.value },
        credentials: 'include',
        timeout: $scanSettingsStore.requestTimeoutMs,
      });
      const r = res as ProbeResult;
      return {
        url,
        method,
        endpoint,
        origin,
        response: {
          status: r.status,
          type: r.type as string | undefined,
          headers: r.headers,
        },
      };
    } catch {
      return null;
    }
  }

  const CORS_SEV_MAP: Record<string, ScanFinding['severity']> = {
    critical: 'critical',
    danger: 'high',
    warning: 'medium',
    info: 'info',
  };

  function mapToFindings(issues: CorsIssue[]): ScanFinding[] {
    return issues
      .filter(i => i.severity !== 'safe' && i.severity in CORS_SEV_MAP)
      .map(i => ({
        title: `CORS ${i.endpoint.label} [${i.method}]`,
        severity: CORS_SEV_MAP[i.severity],
        detail: i.findings.join('; '),
        evidence: i.acao ? `ACAO=${i.acao}` : undefined,
        url: i.url,
      }));
  }

  async function scan() {
    const v = validateProbeUrl(targetUrl);
    if ('error' in v) {
      toastStore.show('请输入合法的 http(s) URL', 'error');
      return;
    }
    scanning = true;
    cancelled = false;
    issues = [];
    safeCount = 0;
    scanned = 0;

    const base = v.parsed;
    const origins: OriginVariant[] = [...ORIGIN_VARIANTS];
    if (useDynamic) origins.push(...buildDynamicOrigins(base.hostname));

    const endpoints = DEFAULT_CORS_ENDPOINTS;
    // 每个 endpoint × origin 探测 GET + OPTIONS
    const tasks: (() => Promise<CorsProbeResult | null>)[] = [];
    for (const ep of endpoints) {
      const u = new URL(ep.path, base.origin).href;
      for (const origin of origins) {
        tasks.push(() => probeOne(u, 'GET', ep, origin));
        tasks.push(() => probeOne(u, 'OPTIONS', ep, origin));
      }
    }

    total = tasks.length;
    const results: CorsProbeResult[] = [];
    await runConcurrent(tasks, async (task) => {
      const r = await task();
      if (r) results.push(r);
      scanned++;
    }, { concurrency: $scanSettingsStore.concurrency, cancelled: () => cancelled });

    if (cancelled) {
      scanning = false;
      toastStore.show('扫描已取消', 'info');
      return;
    }

    const analyzed = analyzeResults(results);
    issues = analyzed.issues;
    safeCount = analyzed.safeCount;
    scanning = false;

    try {
      await scanHistoryStore.addScan({ url: targetUrl, module: 'cors', findings: mapToFindings(issues) });
    } catch { /* store failure must not break scan */ }

    if (vulnCount > 0) {
      toastStore.show(`发现 ${vulnCount} 个 CORS 风险点`, 'warning');
    } else {
      toastStore.show(`CORS 检测完成，未发现风险（${safeCount} 安全）`, 'success');
    }
  }

  function cancel() { cancelled = true; }

  function copyIssue(issue: CorsIssue) {
    const text = [
      `URL: ${issue.url}`,
      `Method: ${issue.method}`,
      `Severity: ${severityLabel(issue.severity)}`,
      `ACAO: ${issue.acao || '(无)'}`,
      `ACAC: ${issue.acac || '(无)'}`,
      `Findings:`,
      ...issue.findings.map(f => `  - ${f}`),
    ].join('\n');
    navigator.clipboard.writeText(text);
    toastStore.show('已复制到剪贴板', 'success');
  }
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
    <div class="flex items-center gap-3 text-xs">
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={useDynamic} />
        <span>动态混淆 Origin</span>
      </label>
      <span class="text-gray-400">端点: {DEFAULT_CORS_ENDPOINTS.length} · Origin: {ORIGIN_VARIANTS.length}{useDynamic ? '+动态' : ''}</span>
    </div>
    <ScanProgress {scanned} {total} {scanning} label="CORS 探测" />
  </div>

  <!-- 统计/筛选 -->
  {#if issues.length > 0}
    <FilterBar
      active={filter}
      options={[
        { key: 'all', label: '全部', count: issues.length, color: 'bg-primary text-white' },
        { key: 'vuln', label: '风险', count: vulnCount, color: 'bg-red-500 text-white' },
      ]}
      onchange={(k) => (filter = k as 'all' | 'vuln')}
    >
      <span class="badge bg-green-500 text-white">安全 {safeCount}</span>
      <select class="input text-xs w-24" bind:value={sortBy}>
        <option value="risk">按风险</option>
        <option value="url">按 URL</option>
      </select>
    </FilterBar>
  {/if}

  <!-- 结果 -->
  {#if sortedIssues.length > 0}
    <div class="space-y-2">
      {#each sortedIssues as issue (issue.url + issue.method + issue.origin.value)}
        <div class="card p-2.5 space-y-1.5">
          <div class="flex items-center gap-2">
            <SeverityBadge severity={issue.severity} />
            <span class="text-xs text-gray-400">{issue.endpoint.label}</span>
            <span class="badge text-xs bg-gray-200 dark:bg-gray-700">{issue.method}</span>
            {#if issue.statusCode}
              <span class="badge text-xs bg-gray-200 dark:bg-gray-700">{issue.statusCode}</span>
            {/if}
            <button class="ml-auto text-xs text-gray-400 hover:text-primary" onclick={() => copyIssue(issue)}>复制</button>
          </div>
          <div class="text-xs font-mono text-gray-600 dark:text-gray-300 break-all">{issue.url}</div>
          <div class="text-xs text-gray-400">Origin: {issue.origin.value}</div>
          {#if issue.acao}
            <div class="text-xs">ACAO: <span class="font-mono text-blue-600 dark:text-blue-400">{issue.acao}</span>
              {#if issue.acac}<span class="ml-2 text-red-500">ACAC: {issue.acac}</span>{/if}
            </div>
          {/if}
          <ul class="text-xs space-y-0.5 pl-3">
            {#each issue.findings as f}
              <li class="text-gray-500 dark:text-gray-400">• {f}</li>
            {/each}
          </ul>
        </div>
      {/each}
    </div>
  {:else if !scanning && issues.length === 0 && scanned > 0}
    <EmptyState message="未检测到 CORS 配置" icon="✅" />
  {:else if !scanning}
    <EmptyState
      message="输入目标 URL，点击「检测」开始 CORS 跨域配置扫描"
      hint="支持 6 端点 × 多 Origin × GET/OPTIONS 组合探测"
      icon="🔗"
    />
  {/if}
</div>
