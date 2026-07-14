<script lang="ts">
  // GraphQL 安全检测面板
  // 流程：自动填充 URL → 常见路径探测 → 安全测试并发 → 引擎分析 → 排序渲染
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore } from '@/stores/ui';
  import type { ProbeResult } from '@/lib/types/messaging';
  import {
    COMMON_GRAPHQL_PATHS,
    GRAPHQL_PROBES,
    INTROSPECTION_QUERIES,
    SEVERITY_ORDER,
    analyzeGraphqlResponse,
    extractSchemaInfo,
    isGraphqlEndpoint,
    severityLabel,
    type GraphqlEndpoint,
    type GraphqlFinding,
    type GraphqlProbe,
    type GraphqlSchemaInfo,
  } from '@/lib/scanners/graphql-engine';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import { scanSettingsStore } from '@/stores/settings';
  import { runConcurrent } from '@/lib/core/concurrency';
  import UrlInput from '@/components/scanner/UrlInput.svelte';
  import ScanProgress from '@/components/scanner/ScanProgress.svelte';
  import EmptyState from '@/components/scanner/EmptyState.svelte';
  import SeverityBadge from '@/components/scanner/SeverityBadge.svelte';
  import ResultToolbar from '@/components/results/ResultToolbar.svelte';
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import { copyText } from '@/lib/actions/clipboard';
  import { type ResultAdapter, type ResultQuery } from '@/lib/results/result-adapter';

  let targetUrl = $state('');
  let scanning = $state(false);
  let scanned = $state(0);
  let total = $state(0);
  let phase = $state('');
  let endpoints = $state<GraphqlEndpoint[]>([]);
  let schemaInfo = $state<GraphqlSchemaInfo | null>(null);
  let findings = $state<GraphqlFinding[]>([]);
  let batchSupported = $state(false);
  let suggestionsEnabled = $state(false);
  let query = $state<ResultQuery>({ search: '', filters: {}, sort: { key: 'severity', direction: 'asc' } });
  let showSchema = $state(false);
  let customPath = $state('');
  let cancelled = $state(false);

  $effect(() => {
    getActiveTabUrl().then(u => {
      if (u) targetUrl = u;
    });
  });

  // ===== 派生：结果（统一 ResultAdapter，供 ResultToolbar/ExportMenu 消费）=====
  const graphqlAdapter: ResultAdapter<GraphqlFinding> = {
    apply(items, q) {
      let list = items;
      if (q.filters.scope?.includes('vuln')) list = list.filter((f) => f.severity !== 'info');
      const kw = q.search.trim().toLowerCase();
      if (kw) list = list.filter((f) => graphqlAdapter.getSearchText(f).toLowerCase().includes(kw));
      return [...list].sort((a, b) => {
        if (q.sort.key === 'test') return a.test.localeCompare(b.test);
        return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
      });
    },
    getSearchText(f) {
      return `${f.test} ${f.severity} ${f.detail} ${f.evidence ?? ''}`;
    },
    getId(f) {
      return f.test + f.severity;
    },
  };

  let sortedFindings = $derived(graphqlAdapter.apply(findings, query));
  let vulnOnly = $derived(query.filters.scope?.includes('vuln') ?? false);
  function toggleVuln() {
    query.filters = vulnOnly ? {} : { scope: ['vuln'] };
  }

  let vulnCount = $derived(findings.filter((f) => f.severity !== 'info').length);

  // 映射 GraphqlFinding[] → ScanFinding[]
  function mapGraphqlToFindings(items: GraphqlFinding[]): ScanFinding[] {
    return items.map((f) => ({
      title: `GraphQL: ${f.test}`,
      severity: f.severity,
      detail: f.detail,
      evidence: f.evidence,
      url: targetUrl,
    }));
  }

  async function probeEndpoint(url: string, body: string, timeout = $scanSettingsStore.requestTimeoutMs): Promise<ProbeResult | null> {
    try {
      const res = await sendMessage({
        type: 'FETCH_PROBE',
        url,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        timeout,
      });
      return res as ProbeResult;
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
    scanned = 0;
    total = 0;
    endpoints = [];
    schemaInfo = null;
    findings = [];
    batchSupported = false;
    suggestionsEnabled = false;

    const origin = v.parsed.origin;
    const allPaths = [...COMMON_GRAPHQL_PATHS];
    if (customPath.trim()) {
      const cp = customPath.trim();
      if (!allPaths.includes(cp)) allPaths.push(cp);
    }

    // === Phase 1: 端点发现 ===
    phase = '探测 GraphQL 端点...';
    let foundEndpointUrl: string | null = null;

    for (const path of allPaths) {
      if (cancelled) {
        phase = '';
        scanning = false;
        toastStore.show('扫描已取消', 'info');
        return;
      }
      phase = `探测 ${path}...`;
      const url = origin + path;
      const resp = await probeEndpoint(url, INTROSPECTION_QUERIES[0]);
      if (!resp) continue;

      const parsed: any = { status: resp.status, body: resp.body, headers: resp.headers, error: resp.error };
      if (isGraphqlEndpoint(parsed)) {
        let introspection = false;
        let json: any = null;
        try { json = JSON.parse(resp.body || ''); } catch { /* ignore */ }
        if (json?.data?.__schema) {
          introspection = true;
          schemaInfo = extractSchemaInfo(json);
          findings.push({
            test: 'introspection',
            severity: 'high',
            detail: 'GraphQL schema 可被完整读取，泄露所有类型、查询和变更定义',
            evidence: `类型: ${schemaInfo!.totalTypes}, Query: ${schemaInfo!.queries.length}`,
          });
        }
        endpoints.push({ path, status: resp.status, introspection });
        foundEndpointUrl = url;
        break;
      }
    }

    if (!foundEndpointUrl) {
      phase = '';
      findings.push({
        test: 'discovery',
        severity: 'info',
        detail: '常见路径均未返回 GraphQL 响应，可尝试手动输入自定义端点',
      });
      scanning = false;
      toastStore.show('未发现 GraphQL 端点', 'info');
      return;
    }

    // === Phase 2: 安全测试 ===
    phase = '执行安全测试...';
    const tasks: (() => Promise<void>)[] = [];

    for (const probe of GRAPHQL_PROBES) {
      tasks.push(async () => {
        const resp = await probeEndpoint(foundEndpointUrl!, probe.body);
        if (!resp) { scanned++; return; }
        const parsed: any = { status: resp.status, body: resp.body, headers: resp.headers, error: resp.error };
        const results = analyzeGraphqlResponse(probe, parsed);
        for (const f of results) {
          findings.push(f);
          // 同步标记状态
          if (probe.name === 'batch-query' && Array.isArray(results)) batchSupported = true;
          if (probe.name === 'field-suggestion' && results.length > 0) suggestionsEnabled = true;
        }
        scanned++;
      });
    }

    // schema 附加信息
    if (schemaInfo) {
      tasks.push(async () => {
        if (schemaInfo!.mutations.length > 0) {
          findings.push({
            test: 'schema-mutations',
            severity: 'info',
            detail: `发现 ${schemaInfo!.mutations.length} 个 mutation: ${schemaInfo!.mutations.slice(0, 5).join(', ')}${schemaInfo!.mutations.length > 5 ? '...' : ''}`,
          });
        }
        if (schemaInfo!.subscriptions.length > 0) {
          findings.push({
            test: 'schema-subscriptions',
            severity: 'info',
            detail: `发现 ${schemaInfo!.subscriptions.length} 个 subscription`,
          });
        }
        scanned++;
      });
    }

    total = tasks.length;
    scanned = 0;

    // 并发限流
    await runConcurrent(tasks, async (task) => {
      await task();
    }, { concurrency: $scanSettingsStore.concurrency, cancelled: () => cancelled });

    if (cancelled) {
      phase = '';
      scanning = false;
      toastStore.show('扫描已取消', 'info');
      return;
    }

    // 补充 batch/suggestion 状态
    batchSupported = findings.some(f => f.test === 'batch-query');
    suggestionsEnabled = findings.some(f => f.test === 'field-suggestion');

    phase = '';
    scanning = false;

    if (vulnCount > 0) {
      toastStore.show(`发现 ${vulnCount} 个安全问题`, 'warning');
    } else {
      toastStore.show(`GraphQL 检测完成，${endpoints.length} 个端点，${findings.length} 个发现`, 'success');
    }

    try {
      await scanHistoryStore.addScan({
        url: targetUrl,
        module: 'graphql',
        findings: mapGraphqlToFindings(findings),
      });
    } catch { /* store failure must not break scan */ }
  }

  function cancel() { cancelled = true; }

  async function copyFinding(f: GraphqlFinding) {
    const text = [
      `[${f.severity.toUpperCase()}] ${f.test}`,
      f.detail,
      f.evidence ? `Evidence: ${f.evidence}` : '',
    ].filter(Boolean).join('\n');
    await copyText(text, '已复制到剪贴板');
  }

  // —— 导出/复制序列化器（作用于当前筛选 sortedFindings，展示/导出同源 §6.1）——
  function graphqlJson(items: GraphqlFinding[]): string {
    return JSON.stringify(
      { url: targetUrl, endpoints, schemaInfo, batchSupported, suggestionsEnabled, findings: items },
      null,
      2,
    );
  }
  function graphqlMd(items: GraphqlFinding[]): string {
    const lines = [`# GraphQL 安全扫描`, ``, `**目标:** ${targetUrl}`, ``];
    if (endpoints.length > 0) {
      lines.push(`## 端点 (${endpoints.length})`, ...endpoints.map((ep) => `- \`${ep.path}\` (HTTP ${ep.status}, introspection: ${ep.introspection ? '开启' : '关闭'})`), ``);
    }
    if (schemaInfo) {
      lines.push(`## Schema`, `- 类型: ${schemaInfo.totalTypes}`, `- Query: ${schemaInfo.queries.length}`, `- Mutation: ${schemaInfo.mutations.length}`, ``);
    }
    lines.push(`## 发现 (${items.length})`);
    for (const f of items) {
      lines.push(`- **[${f.severity.toUpperCase()}] ${f.test}** — ${f.detail}`);
    }
    return lines.join('\n');
  }
  function graphqlText(items: GraphqlFinding[]): string {
    const lines = ['GraphQL Security Scan Results', '==================', `Target: ${targetUrl}`, ''];
    if (endpoints.length > 0) {
      lines.push('Endpoints:');
      for (const ep of endpoints) {
        lines.push(`  ${ep.path} (HTTP ${ep.status}, introspection: ${ep.introspection})`);
      }
      lines.push('');
    }
    if (schemaInfo) {
      const si = schemaInfo;
      lines.push(`Schema: ${si.totalTypes} types, ${si.queries.length} queries, ${si.mutations.length} mutations`);
      lines.push('');
    }
    lines.push('Findings:');
    for (const f of items) {
      lines.push(`[${f.severity.toUpperCase()}] ${f.test}: ${f.detail}`);
    }
    return lines.join('\n');
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
    <div class="flex items-center gap-2 text-xs">
      <input class="input text-xs flex-1" placeholder="自定义路径，如 /api/gateway" bind:value={customPath} />
      <span class="text-gray-400 shrink-0">端点: {COMMON_GRAPHQL_PATHS.length}</span>
    </div>
    <ScanProgress {scanned} {total} {scanning} label={phase || 'GraphQL 安全测试'} />
  </div>

  <!-- 端点发现 -->
  {#if endpoints.length > 0}
    <div class="card p-3 space-y-2">
      <div class="text-xs font-medium text-gray-600 dark:text-gray-300">发现端点</div>
      {#each endpoints as ep (ep.path)}
        <div class="flex items-center gap-2">
          <span class="text-xs font-mono text-gray-700 dark:text-gray-200 break-all">{ep.path}</span>
          <span class="badge text-xs {ep.introspection ? 'bg-red-500 text-white' : 'bg-blue-500 text-white'}">
            {ep.introspection ? 'Introspection 开启' : 'Introspection 关闭'}
          </span>
          <span class="badge text-xs bg-gray-200 dark:bg-gray-700">HTTP {ep.status}</span>
        </div>
      {/each}
    </div>
  {/if}

  <!-- Schema 概览 -->
  {#if schemaInfo}
    <div class="card p-3 space-y-2">
      <button class="flex items-center gap-2 text-xs font-medium text-gray-600 dark:text-gray-300 w-full" onclick={() => (showSchema = !showSchema)}>
        <span class="text-gray-400">{showSchema ? '▼' : '▶'}</span>
        Schema 概览
      </button>
      {#if showSchema}
        <div class="flex gap-3 text-xs text-gray-500 dark:text-gray-400">
          <span>类型: {schemaInfo.totalTypes}</span>
          <span>Query: {schemaInfo.queries.length}</span>
          <span>Mutation: {schemaInfo.mutations.length}</span>
          <span>Subscription: {schemaInfo.subscriptions.length}</span>
        </div>
        {#if schemaInfo.queries.length > 0}
          <div class="space-y-1">
            <div class="text-xs text-gray-400">Queries</div>
            <div class="flex flex-wrap gap-1">
              {#each schemaInfo.queries as q}
                <span class="badge text-xs bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300">{q}</span>
              {/each}
            </div>
          </div>
        {/if}
        {#if schemaInfo.mutations.length > 0}
          <div class="space-y-1">
            <div class="text-xs text-gray-400">Mutations</div>
            <div class="flex flex-wrap gap-1">
              {#each schemaInfo.mutations as m}
                <span class="badge text-xs bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300">{m}</span>
              {/each}
            </div>
          </div>
        {/if}
        {#if schemaInfo.subscriptions.length > 0}
          <div class="space-y-1">
            <div class="text-xs text-gray-400">Subscriptions</div>
            <div class="flex flex-wrap gap-1">
              {#each schemaInfo.subscriptions as s}
                <span class="badge text-xs bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300">{s}</span>
              {/each}
            </div>
          </div>
        {/if}
      {/if}
    </div>
  {/if}

  <!-- 工具栏：ResultToolbar 包裹 风险筛选 / 排序 / 导出 -->
  {#if findings.length > 0}
    <ResultToolbar {query} total={findings.length} shown={sortedFindings.length} searchPlaceholder="搜索测试/详情...">
      <button
        class="badge cursor-pointer {vulnOnly ? 'bg-red-500 text-white' : 'bg-gray-200 dark:bg-gray-700'}"
        aria-pressed={vulnOnly}
        onclick={toggleVuln}
      >
        风险 {vulnCount}
      </button>
      <select
        class="input text-xs w-24"
        value={query.sort.key}
        onchange={(e) => { query.sort.key = (e.currentTarget as HTMLSelectElement).value; }}
        aria-label="排序"
      >
        <option value="severity">按风险</option>
        <option value="test">按类型</option>
      </select>
      <ExportMenu items={sortedFindings} module="graphql" serializers={{ json: graphqlJson, markdown: graphqlMd, text: graphqlText }} />
    </ResultToolbar>
  {/if}

  <!-- 安全发现 -->
  {#if sortedFindings.length > 0}
    <div class="space-y-1.5">
      {#each sortedFindings as f (f.test + f.severity)}
        <div class="card p-2.5 space-y-1">
          <div class="flex items-center gap-2">
            <SeverityBadge severity={f.severity} />
            <span class="text-xs text-gray-500 dark:text-gray-400">{f.test}</span>
            <button class="ml-auto text-xs text-gray-400 hover:text-primary" onclick={() => copyFinding(f)}>复制</button>
          </div>
          <div class="text-xs text-gray-700 dark:text-gray-300">{f.detail}</div>
          {#if f.evidence}
            <div class="text-xs font-mono text-blue-600 dark:text-blue-400 break-all truncate">{f.evidence}</div>
          {/if}
        </div>
      {/each}
    </div>
  {:else if !scanning && findings.length === 0 && scanned > 0}
    <EmptyState message="未发现安全问题" icon="✅" />
  {:else if !scanning}
    <EmptyState
      message="输入目标 URL，点击「检测」开始 GraphQL 安全扫描"
      hint="支持常见路径探测 + 多项安全测试"
      icon="🔍"
    />
  {/if}
</div>
