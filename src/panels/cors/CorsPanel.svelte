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
  // HTTP 方法开关（v5 支持多方法测试）
  let methods = $state({ GET: true, OPTIONS: true, POST: false, PUT: false, DELETE: false });
  // 已验证的 issue（Credential 双探针）key -> 验证结果
  let verifiedMap = $state<Record<string, string>>({});

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

  /**
   * Credential 双探针验证（v5 verifyCredentials）：
   * 对 Origin 反射 + ACAC:true 的 critical issue，再用 credentials:'omit' 重探，
   * 若 ACAO 仍反射该 Origin → 确认服务器无视凭证模式盲目反射，漏洞可利用。
   */
  async function verifyCredential(issue: CorsIssue) {
    const key = issue.url + issue.method + issue.origin.value;
    verifiedMap = { ...verifiedMap, [key]: '验证中...' };
    try {
      // omit 模式重探
      const res = await sendMessage({
        type: 'FETCH_CORS_PROBE',
        url: issue.url,
        method: issue.method,
        headers: { Origin: issue.origin.value },
        credentials: 'omit',
        timeout: $scanSettingsStore.requestTimeoutMs,
      });
      const r = res as ProbeResult;
      const acao = r.headers?.['access-control-allow-origin'] || '';
      const acac = r.headers?.['access-control-allow-credentials'] || '';
      if (acao === issue.origin.value) {
        const credNote = acac.toLowerCase() === 'true'
          ? '凭证模式下 ACAC:true — 浏览器允许跨域携带 Cookie 读取响应，漏洞可利用'
          : 'Origin 反射与凭证模式无关，但未开启 ACAC，仅可读取公开数据';
        verifiedMap = { ...verifiedMap, [key]: `✅ 已确认：${credNote}` };
      } else if (acao === '*') {
        verifiedMap = { ...verifiedMap, [key]: '⚠️ omit 模式返回 ACAO:* （通配）' };
      } else {
        verifiedMap = { ...verifiedMap, [key]: '❌ omit 模式未反射 Origin，include 模式可能误报' };
      }
    } catch {
      verifiedMap = { ...verifiedMap, [key]: '验证请求失败' };
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
    verifiedMap = {};

    const base = v.parsed;
    const origins: OriginVariant[] = [...ORIGIN_VARIANTS];
    if (useDynamic) origins.push(...buildDynamicOrigins(base.hostname));

    const endpoints = DEFAULT_CORS_ENDPOINTS;
    const activeMethods = (Object.keys(methods) as (keyof typeof methods)[]).filter(m => methods[m]);
    // 每个 endpoint × origin × 启用方法 探测
    const tasks: (() => Promise<CorsProbeResult | null>)[] = [];
    for (const ep of endpoints) {
      const u = new URL(ep.path, base.origin).href;
      for (const origin of origins) {
        for (const m of activeMethods) {
          tasks.push(() => probeOne(u, m, ep, origin));
        }
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

  function copyAll() {
    if (sortedIssues.length === 0) { toastStore.show('没有可复制的结果', 'warning'); return; }
    const lines = [`# CORS 扫描结果`, ``, `**目标:** ${targetUrl}`, ``, `## 发现 (${sortedIssues.length})`];
    for (const i of sortedIssues) {
      lines.push(`- **[${severityLabel(i.severity)}]** ${i.endpoint.label} [${i.method}] ${i.url}`);
      if (i.acao) lines.push(`  - ACAO: \`${i.acao}\`${i.acac ? ` · ACAC: ${i.acac}` : ''}`);
      for (const f of i.findings) lines.push(`  - ${f}`);
    }
    navigator.clipboard.writeText(lines.join('\n'));
    toastStore.show('已复制全部结果', 'success');
  }

  function copyMarkdown() {
    if (sortedIssues.length === 0) { toastStore.show('没有可复制的结果', 'warning'); return; }
    const lines = ['| 风险 | 端点 | 方法 | URL | ACAO | ACAC |', '|------|------|------|-----|------|------|'];
    for (const i of sortedIssues) {
      lines.push(`| ${severityLabel(i.severity)} | ${i.endpoint.label} | ${i.method} | ${i.url} | ${i.acao || '-'} | ${i.acac || '-'} |`);
    }
    navigator.clipboard.writeText(lines.join('\n'));
    toastStore.show('Markdown 已复制', 'success');
  }

  function exportJson() {
    if (sortedIssues.length === 0) { toastStore.show('没有可导出的结果', 'warning'); return; }
    const data = { url: targetUrl, safeCount, issues: sortedIssues };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = `cors-scan-${Date.now()}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toastStore.show('结果已导出', 'success');
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
    <div class="flex items-center gap-3 text-xs flex-wrap">
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={useDynamic} disabled={scanning} class="accent-blue-500" />
        <span>动态混淆 Origin</span>
      </label>
      <span class="text-gray-400 shrink-0">方法:</span>
      {#each ['GET', 'OPTIONS', 'POST', 'PUT', 'DELETE'] as m}
        <label class="flex items-center gap-0.5 cursor-pointer">
          <input type="checkbox" bind:checked={methods[m as keyof typeof methods]} disabled={scanning} class="accent-blue-500" />
          <span class="text-gray-600 dark:text-gray-300">{m}</span>
        </label>
      {/each}
    </div>
    <div class="text-xs text-gray-400">端点: {DEFAULT_CORS_ENDPOINTS.length} · Origin: {ORIGIN_VARIANTS.length}{useDynamic ? '+动态' : ''}</div>
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
      <button class="btn btn-sm" onclick={copyAll}>复制</button>
      <button class="btn btn-sm" onclick={copyMarkdown}>MD</button>
      <button class="btn btn-sm" onclick={exportJson}>导出</button>
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
            <div class="ml-auto flex items-center gap-1">
              {#if issue.severity === 'critical' || issue.severity === 'danger'}
                <button
                  class="text-xs text-blue-500 hover:text-blue-700 dark:text-blue-400"
                  onclick={() => verifyCredential(issue)}
                >
                  验证
                </button>
              {/if}
              <button class="text-xs text-gray-400 hover:text-primary" onclick={() => copyIssue(issue)}>复制</button>
            </div>
          </div>
          {#if verifiedMap[issue.url + issue.method + issue.origin.value]}
            <div class="text-xs px-2 py-1 rounded bg-blue-50 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300">{verifiedMap[issue.url + issue.method + issue.origin.value]}</div>
          {/if}
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
