<script lang="ts">
  // CORS 检测面板
  // 流程：自动填充 URL → 端点 × Origin 变体并发探测 → 引擎分析 → 按风险排序渲染
  // 结果区统一：ResultToolbar（搜索/筛选/排序/计数）+ ExportMenu（规范文件名，修未 await）
  //             + DetailDrawer（详情 + 跨面板 handoff：在 XSS / 安全头 中打开）
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore, autoRunStore } from '@/stores/ui';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import { scanSettingsStore } from '@/stores/settings';
  import { runConcurrent } from '@/lib/core/concurrency';
  import { compareSeverity } from '@/lib/types/severity';
  import UrlInput from '@/components/scanner/UrlInput.svelte';
  import ScanProgress from '@/components/scanner/ScanProgress.svelte';
  import EmptyState from '@/components/scanner/EmptyState.svelte';
  import SeverityBadge from '@/components/scanner/SeverityBadge.svelte';
  import ResultToolbar from '@/components/results/ResultToolbar.svelte';
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import DetailDrawer from '@/components/results/DetailDrawer.svelte';
  import { toCsv, toMarkdownTable } from '@/lib/actions/serializers';
  import { type ResultAdapter, type ResultQuery } from '@/lib/results/result-adapter';
  import type { DetailField, DetailHandoffAction } from '@/components/results/detail-drawer-utils';
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
  // HTTP 方法开关（v5 支持多方法测试）
  let methods = $state({ GET: true, OPTIONS: true, POST: false, PUT: false, DELETE: false });
  // 已验证的 issue（Credential 双探针）key -> 验证结果
  let verifiedMap = $state<Record<string, string>>({});

  // 结果查询：搜索 + 「仅风险」筛选 + 排序，统一 ResultToolbar/ExportMenu/DetailDrawer 消费
  let query = $state<ResultQuery>({ search: '', filters: {}, sort: { key: 'risk', direction: 'asc' } });

  const corsAdapter: ResultAdapter<CorsIssue> = {
    apply(items, q) {
      let list = items;
      if (q.filters.scope?.includes('vuln')) list = list.filter((i) => i.severity !== 'safe');
      const kw = q.search.trim().toLowerCase();
      if (kw) list = list.filter((i) => corsAdapter.getSearchText(i).toLowerCase().includes(kw));
      return [...list].sort((a, b) => {
        if (q.sort.key === 'url') return (a.url || '').localeCompare(b.url || '');
        return compareSeverity(a.severity, b.severity);
      });
    },
    getSearchText(i) {
      return `${i.url} ${i.method} ${i.endpoint.label} ${i.origin.value} ${i.acao} ${i.findings.join(' ')}`;
    },
    getId(i) {
      return i.url + i.method + i.origin.value;
    },
  };

  let filteredIssues = $derived(corsAdapter.apply(issues, query));
  let vulnCount = $derived(issues.filter((i) => i.severity !== 'safe').length);
  let vulnOnly = $derived(query.filters.scope?.includes('vuln') ?? false);

  function toggleVuln() {
    query.filters = vulnOnly ? {} : { scope: ['vuln'] };
  }

  // 详情抽屉索引（基于当前筛选集）；结果集变化（搜索/筛选/新扫描）时关闭，避免索引错位
  let detailIndex = $state<number | null>(null);
  $effect(() => {
    void filteredIssues;
    detailIndex = null;
  });

  $effect(() => {
    getActiveTabUrl().then((u) => {
      if (u) targetUrl = u;
    });
  });

  // 一键操作（右键菜单 / Popup）：命中本面板则自动扫描
  $effect(() => {
    const sig = $autoRunStore;
    if (sig && sig.panel === 'cors') {
      autoRunStore.clear();
      if (sig.url) targetUrl = sig.url;
      scan();
    }
  });

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
        const credNote =
          acac.toLowerCase() === 'true'
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
      .filter((i) => i.severity !== 'safe' && i.severity in CORS_SEV_MAP)
      .map((i) => ({
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
    const activeMethods = (Object.keys(methods) as (keyof typeof methods)[]).filter((m) => methods[m]);
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
    await runConcurrent(
      tasks,
      async (task) => {
        const r = await task();
        if (r) results.push(r);
        scanned++;
      },
      { concurrency: $scanSettingsStore.concurrency, cancelled: () => cancelled },
    );

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
    } catch {
      /* store failure must not break scan */
    }

    if (vulnCount > 0) {
      toastStore.show(`发现 ${vulnCount} 个 CORS 风险点`, 'warning');
    } else {
      toastStore.show(`CORS 检测完成，未发现风险（${safeCount} 安全）`, 'success');
    }
  }

  function cancel() {
    cancelled = true;
  }

  // —— 导出/复制序列化器（作用于当前筛选 filteredIssues）——
  function corsCsv(items: CorsIssue[]): string {
    return toCsv([
      ['severity', 'endpoint', 'method', 'url', 'origin', 'acao', 'acac', 'status'],
      ...items.map((i) => [
        i.severity,
        i.endpoint.label,
        i.method,
        i.url,
        i.origin.value,
        i.acao,
        i.acac,
        i.statusCode,
      ]),
    ]);
  }
  function corsMd(items: CorsIssue[]): string {
    return toMarkdownTable(
      ['风险', '端点', '方法', 'URL', 'ACAO', 'ACAC'],
      items.map((i) => [
        severityLabel(i.severity),
        i.endpoint.label,
        i.method,
        i.url,
        i.acao || '-',
        i.acac || '-',
      ]),
    );
  }
  function corsText(items: CorsIssue[]): string {
    const lines = [`# CORS 扫描结果`, ``, `**目标:** ${targetUrl}`, ``, `## 发现 (${items.length})`];
    for (const i of items) {
      lines.push(`- **[${severityLabel(i.severity)}]** ${i.endpoint.label} [${i.method}] ${i.url}`);
      if (i.acao) lines.push(`  - ACAO: \`${i.acao}\`${i.acac ? ` · ACAC: ${i.acac}` : ''}`);
      for (const f of i.findings) lines.push(`  - ${f}`);
    }
    return lines.join('\n');
  }

  // —— DetailDrawer 字段 / 证据 / handoff 动作 ——
  function corsFields(i: CorsIssue): DetailField[] {
    const f: DetailField[] = [
      { label: 'URL', value: i.url, mono: true },
      { label: '方法', value: i.method },
      { label: '端点', value: i.endpoint.label },
      { label: 'Origin', value: i.origin.value, mono: true },
      { label: 'ACAO', value: i.acao || '—', mono: true },
      { label: 'ACAC', value: i.acac || '—' },
    ];
    if (i.statusCode) f.push({ label: '状态码', value: String(i.statusCode) });
    if (i.acam) f.push({ label: 'ACAM', value: i.acam, mono: true });
    if (i.acah) f.push({ label: 'ACAH', value: i.acah, mono: true });
    return f;
  }
  function corsEvidence(i: CorsIssue): string {
    return i.findings.length ? i.findings.map((x) => `• ${x}`).join('\n') : '（无）';
  }
  const corsActions: DetailHandoffAction<CorsIssue>[] = [
    {
      label: '在 XSS 中打开',
      targetPanel: 'xss',
      build: (i) => ({ payload: { targetUrl: i.url }, summary: `XSS 测 ${i.endpoint.label}` }),
    },
    {
      label: '在 安全头 中检测',
      targetPanel: 'headers',
      build: (i) => ({ payload: { targetUrl: i.url }, summary: `安全头 ${i.endpoint.label}` }),
    },
  ];
</script>

<div class="space-y-3">
  <!-- 输入 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <UrlInput bind:value={targetUrl} {scanning} buttonText="检测" onscan={scan} recordTarget />
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
          <input
            type="checkbox"
            bind:checked={methods[m as keyof typeof methods]}
            disabled={scanning}
            class="accent-blue-500"
          />
          <span class="text-gray-600 dark:text-gray-300">{m}</span>
        </label>
      {/each}
    </div>
    <div class="text-xs text-gray-400">
      端点: {DEFAULT_CORS_ENDPOINTS.length} · Origin: {ORIGIN_VARIANTS.length}{useDynamic ? '+动态' : ''}
    </div>
    <ScanProgress {scanned} {total} {scanning} label="CORS 探测" />
  </div>

  <!-- 工具栏：ResultToolbar（搜索 + 计数 + 清除）包裹「仅风险」筛选 / 排序 / 导出 -->
  {#if issues.length > 0}
    <ResultToolbar {query} total={issues.length} shown={filteredIssues.length} searchPlaceholder="搜索 URL/端点/ACAO...">
      <button
        class="badge cursor-pointer {vulnOnly
          ? 'bg-red-500 text-white'
          : 'bg-gray-200 dark:bg-gray-700'}"
        aria-pressed={vulnOnly}
        onclick={toggleVuln}
      >
        仅风险 {vulnCount}
      </button>
      <span class="badge bg-green-500 text-white">安全 {safeCount}</span>
      <select
        class="input text-xs w-24"
        value={query.sort.key}
        onchange={(e) => {
          query.sort.key = (e.currentTarget as HTMLSelectElement).value;
        }}
        aria-label="排序"
      >
        <option value="risk">按风险</option>
        <option value="url">按 URL</option>
      </select>
      <ExportMenu
        items={filteredIssues}
        module="cors"
        serializers={{ csv: corsCsv, markdown: corsMd, text: corsText }}
      />
    </ResultToolbar>
  {/if}

  <!-- 结果 -->
  {#if filteredIssues.length > 0}
    <div class="space-y-2">
      {#each filteredIssues as issue, i (issue.url + issue.method + issue.origin.value)}
        <div
          class="card p-2.5 space-y-1.5 cursor-pointer hover:border-primary transition-colors"
          role="button"
          tabindex="0"
          aria-label="查看 CORS 详情"
          onclick={() => (detailIndex = i)}
          onkeydown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              detailIndex = i;
            }
          }}
        >
          <div class="flex items-center gap-2">
            <SeverityBadge severity={issue.severity} />
            <span class="text-xs text-gray-400">{issue.endpoint.label}</span>
            <span class="badge text-xs bg-gray-200 dark:bg-gray-700">{issue.method}</span>
            {#if issue.statusCode}
              <span class="badge text-xs bg-gray-200 dark:bg-gray-700">{issue.statusCode}</span>
            {/if}
            {#if issue.severity === 'critical' || issue.severity === 'danger'}
              <button
                class="ml-auto text-xs text-blue-500 hover:text-blue-700 dark:text-blue-400"
                onclick={(e) => {
                  e.stopPropagation();
                  verifyCredential(issue);
                }}
              >
                验证
              </button>
            {/if}
          </div>
          {#if verifiedMap[issue.url + issue.method + issue.origin.value]}
            <div class="text-xs px-2 py-1 rounded bg-blue-50 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300">
              {verifiedMap[issue.url + issue.method + issue.origin.value]}
            </div>
          {/if}
          <div class="text-xs font-mono text-gray-600 dark:text-gray-300 break-all">{issue.url}</div>
          <div class="text-xs text-gray-400">Origin: {issue.origin.value}</div>
          {#if issue.acao}
            <div class="text-xs">
              ACAO: <span class="font-mono text-blue-600 dark:text-blue-400">{issue.acao}</span>
              {#if issue.acac}<span class="ml-2 text-red-500">ACAC: {issue.acac}</span>{/if}
            </div>
          {/if}
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

  <!-- 详情抽屉 -->
  <DetailDrawer
    items={filteredIssues}
    index={detailIndex}
    onclose={() => (detailIndex = null)}
    onnavigate={(idx) => (detailIndex = idx)}
    sourcePanel="cors"
    sourceLabel="CORS 检测"
    moduleLabel="CORS"
    title={(i) => `${i.endpoint.label} [${i.method}]`}
    severity={(i) => i.severity}
    target={(i) => i.url}
    fields={corsFields}
    evidence={corsEvidence}
    actions={corsActions}
  >
    {#snippet children(i)}
      {#if i.severity === 'critical' || i.severity === 'danger'}
        <div class="flex items-center gap-2">
          <button class="btn btn-xs btn-primary" onclick={() => verifyCredential(i)}>验证凭证反射</button>
          <span class="text-xs text-gray-400">omit 模式重探，确认是否无视凭证盲目反射</span>
        </div>
      {/if}
      {#if verifiedMap[i.url + i.method + i.origin.value]}
        <div
          class="text-xs px-2 py-1.5 rounded bg-blue-50 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300"
        >
          {verifiedMap[i.url + i.method + i.origin.value]}
        </div>
      {/if}
    {/snippet}
  </DetailDrawer>
</div>
