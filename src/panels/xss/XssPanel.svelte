<script lang="ts">
  // XSS 扫描面板 — 灵眸 v6.0
  // 流程：自动填充 URL → 提取 query 参数 → 参数 × payload 并发探测 → 引擎分析 → 排序渲染
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore } from '@/stores/ui';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import type { ProbeResult } from '@/lib/types/messaging';
  import {
    buildPayloadsForContext,
    detectContext,
    findReflection,
    isSanitized,
    assessSeverity,
    severityLabel,
    XSS_MARKERS,
    REFLECTION_PROBE,
    XSS_SORT_FNS,
    type XssFinding,
    type XssContext,
    type XssSeverity,
  } from '@/lib/scanners/xss-engine';

  let targetUrl = $state('');
  let scanning = $state(false);
  let scanned = $state(0);
  let total = $state(0);
  let findings = $state<XssFinding[]>([]);
  let sortBy = $state<'severity' | 'param' | 'context'>('severity');
  let filter = $state<'all' | 'vuln'>('all');
  let customPayload = $state('');
  let useCustom = $state(false);

  $effect(() => {
    getActiveTabUrl().then(u => {
      if (u) targetUrl = u;
    });
  });

  let filteredFindings = $derived.by(() => {
    let list = findings;
    if (filter === 'vuln') list = list.filter(f => f.reflected && !f.sanitized);
    const order: Record<XssSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return [...list].sort((a, b) => {
      if (sortBy === 'param') return a.param.localeCompare(b.param);
      if (sortBy === 'context') return a.context.localeCompare(b.context);
      return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
    });
  });

  let vulnCount = $derived(findings.filter(f => f.reflected && !f.sanitized).length);
  let reflectedCount = $derived(findings.filter(f => f.reflected).length);

  const SEV_COLOR: Record<string, string> = {
    critical: 'bg-red-600 text-white',
    high: 'bg-red-500 text-white',
    medium: 'bg-yellow-500 text-white',
    low: 'bg-blue-500 text-white',
    info: 'bg-gray-400 text-white',
  };

  const CTX_LABELS: Record<XssContext, string> = {
    html: 'HTML 文本',
    attr: '属性',
    script: 'Script',
    url: 'URL',
    style: 'Style',
  };

  function mapToFindings(findings: XssFinding[]): ScanFinding[] {
    return findings
      .filter(f => f.reflected && !f.sanitized)
      .map(f => ({
        title: `XSS [${f.param}] (${f.context})`,
        severity: f.severity,
        detail: f.payload,
        evidence: f.evidence,
        url: targetUrl,
      }));
  }

  /** 从 URL 中提取查询参数名列表 */
  function extractParams(url: string): string[] {
    try {
      const u = new URL(url);
      const params: string[] = [];
      for (const key of u.searchParams.keys()) {
        if (!params.includes(key)) params.push(key);
      }
      return params;
    } catch {
      return [];
    }
  }

  /** 构建测试 URL：将指定参数替换为 marker + payload */
  function buildTestUrl(baseUrl: string, param: string, marker: string, payload: string): string {
    try {
      const u = new URL(baseUrl);
      // 先用 marker 探测反射，然后对每个 payload 独立检测
      u.searchParams.set(param, payload);
      return u.href;
    } catch {
      return '';
    }
  }

  /** 对单个 param × payload 发起探测 */
  async function probeSingle(
    url: string,
    param: string,
    payload: string,
  ): Promise<XssFinding | null> {
    const testUrl = buildTestUrl(url, param, '', payload);
    if (!testUrl) return null;
    try {
      const res = await sendMessage({
        type: 'FETCH_PROBE',
        url: testUrl,
        method: 'GET',
        includeBody: true,
        timeout: 10000,
      });
      const r = res as ProbeResult;
      const body = r.body ?? '';

      // 使用 payload 中最独特的部分作为 marker 检测反射
      // 对于自定义 payload 直接检测；对于通用 payload 检测 XSS_MARKERS 或 payload 子串
      let marker = payload;
      // 尝试找到 payload 中最短的独特子串作为 marker
      for (const m of XSS_MARKERS) {
        if (payload.includes(m)) {
          marker = m;
          break;
        }
      }

      const refl = findReflection(body, marker);
      const sanitized = isSanitized(body, payload);
      const ctx = refl.found ? refl.context : detectContext(body.substring(0, 500));
      const sev = assessSeverity(ctx, refl.found, sanitized);

      return {
        param,
        payload,
        context: ctx,
        reflected: refl.found,
        sanitized,
        severity: sev,
        evidence: refl.found ? refl.surrounding : undefined,
      };
    } catch {
      return null;
    }
  }

  /** 快速反射探测：使用 REFLECTION_PROBE 判断哪些参数存在反射 */
  async function probeReflection(
    url: string,
    param: string,
  ): Promise<{ reflected: boolean; context: XssContext }> {
    try {
      const u = new URL(url);
      u.searchParams.set(param, REFLECTION_PROBE);
      const res = await sendMessage({
        type: 'FETCH_PROBE',
        url: u.href,
        method: 'GET',
        includeBody: true,
        timeout: 10000,
      });
      const r = res as ProbeResult;
      const body = r.body ?? '';
      const refl = findReflection(body, REFLECTION_PROBE);
      return { reflected: refl.found, context: refl.context };
    } catch {
      return { reflected: false, context: 'html' };
    }
  }

  async function scan() {
    const v = validateProbeUrl(targetUrl);
    if ('error' in v) {
      toastStore.show('请输入合法的 http(s) URL', 'error');
      return;
    }

    const params = extractParams(targetUrl);
    if (params.length === 0 && !useCustom) {
      toastStore.show('URL 中未发现查询参数', 'warning');
      return;
    }

    scanning = true;
    findings = [];
    scanned = 0;

    let payloads: string[];
    if (useCustom && customPayload.trim()) {
      payloads = [customPayload.trim()];
    } else {
      // 收集所有上下文的 payload（去重）
      const allPayloads = new Set<string>();
      for (const ctx of ['html', 'attr', 'script', 'url', 'style'] as XssContext[]) {
        for (const p of buildPayloadsForContext(ctx)) {
          allPayloads.add(p);
        }
      }
      payloads = [...allPayloads];
    }

    // Phase 1: 快速反射过滤（如果不用自定义 payload）
    let reflectedParams: string[] = [];
    if (!useCustom) {
      const CONCURRENCY = 8;
      let probeIdx = 0;
      const probeTasks = params.map(p => () => probeReflection(targetUrl, p));
      const probeResults: { reflected: boolean; context: XssContext }[] = [];
      let probeTotal = probeTasks.length;
      let probeScanned = 0;

      async function probeWorker() {
        while (probeIdx < probeTasks.length) {
          const cur = probeIdx++;
          const r = await probeTasks[cur]();
          probeResults[cur] = r;
          probeScanned++;
        }
      }
      await Promise.all(Array.from({ length: CONCURRENCY }, () => probeWorker()));

      reflectedParams = params.filter((_, i) => probeResults[i]?.reflected);
      if (reflectedParams.length === 0) {
        scanning = false;
        toastStore.show(`${params.length} 个参数均无反射`, 'success');
        return;
      }
    } else {
      reflectedParams = params;
    }

    // Phase 2: 对反射参数 × payload 进行详细测试
    const tasks: (() => Promise<XssFinding | null>)[] = [];
    for (const param of reflectedParams) {
      for (const payload of payloads) {
        tasks.push(() => probeSingle(targetUrl, param, payload));
      }
    }

    total = tasks.length;
    scanned = 0;
    const collected: XssFinding[] = [];
    const CONCURRENCY = 8;
    let idx = 0;

    async function worker() {
      while (idx < tasks.length) {
        const cur = idx++;
        const r = await tasks[cur]();
        if (r) collected.push(r);
        scanned++;
      }
    }
    await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));

    // 按严重性排序
    findings = collected.sort(XSS_SORT_FNS.severity);
    scanning = false;

    try {
      await scanHistoryStore.addScan({ url: targetUrl, module: 'xssscan', findings: mapToFindings(findings) });
    } catch { /* store failure must not break scan */ }

    if (vulnCount > 0) {
      toastStore.show(`发现 ${vulnCount} 个潜在 XSS 点（${reflectedCount} 个反射）`, 'warning');
    } else if (reflectedCount > 0) {
      toastStore.show(`${reflectedCount} 个参数存在反射，但已被净化`, 'success');
    } else {
      toastStore.show(`XSS 检测完成，未发现漏洞（${total} 个测试）`, 'success');
    }
  }

  function copyFinding(f: XssFinding) {
    const text = [
      `Param: ${f.param}`,
      `Payload: ${f.payload}`,
      `Context: ${CTX_LABELS[f.context] ?? f.context}`,
      `Severity: ${severityLabel(f.severity)}`,
      `Reflected: ${f.reflected}`,
      `Sanitized: ${f.sanitized}`,
      f.evidence ? `Evidence: ${f.evidence}` : '',
    ].filter(Boolean).join('\n');
    navigator.clipboard.writeText(text);
    toastStore.show('已复制到剪贴板', 'success');
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

    <div class="flex items-center gap-2 text-xs">
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={useCustom} />
        <span>自定义 Payload</span>
      </label>
    </div>

    {#if useCustom}
      <textarea
        class="input w-full text-sm font-mono"
        rows="2"
        placeholder="输入自定义 XSS payload（每行一个）"
        bind:value={customPayload}
      ></textarea>
    {:else}
      <div class="text-xs text-gray-400">
        自动提取查询参数，使用反射探针 + 上下文 payload 进行并发检测
      </div>
    {/if}

    {#if scanning}
      <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5 overflow-hidden">
        <div class="bg-primary h-full transition-all" style="width: {total ? (scanned / total) * 100 : 0}%"></div>
      </div>
      <div class="text-xs text-gray-400">{scanned} / {total}</div>
    {/if}
  </div>

  <!-- 统计 -->
  {#if findings.length > 0}
    <div class="flex gap-2 text-xs">
      <button
        class="badge {filter === 'all' ? 'bg-primary text-white' : 'bg-gray-200 dark:bg-gray-700'}"
        onclick={() => (filter = 'all')}>全部 {findings.length}</button>
      <button
        class="badge {filter === 'vuln' ? 'bg-red-500 text-white' : 'bg-gray-200 dark:bg-gray-700'}"
        onclick={() => (filter = 'vuln')}>漏洞 {vulnCount}</button>
      <span class="badge bg-blue-500 text-white">反射 {reflectedCount}</span>
      <select class="input text-xs ml-auto w-24" bind:value={sortBy}>
        <option value="severity">按严重性</option>
        <option value="param">按参数</option>
        <option value="context">按上下文</option>
      </select>
    </div>
  {/if}

  <!-- 结果 -->
  {#if filteredFindings.length > 0}
    <div class="space-y-1.5">
      {#each filteredFindings as f (f.param + f.payload + f.context)}
        <div class="card p-2.5 space-y-1">
          <div class="flex items-center gap-2">
            <span class="badge text-xs {SEV_COLOR[f.severity]}">{severityLabel(f.severity)}</span>
            <span class="badge text-xs bg-gray-200 dark:bg-gray-700">{f.param}</span>
            <span class="badge text-xs bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300">
              {CTX_LABELS[f.context] ?? f.context}
            </span>
            {#if f.reflected}
              <span class="badge text-xs bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300">反射</span>
            {/if}
            {#if f.sanitized}
              <span class="badge text-xs bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300">已净化</span>
            {/if}
            <button class="ml-auto text-xs text-gray-400 hover:text-primary" onclick={() => copyFinding(f)}>复制</button>
          </div>
          <div class="text-xs font-mono text-gray-600 dark:text-gray-300 break-all max-h-16 overflow-hidden">{f.payload}</div>
          {#if f.evidence}
            <div class="text-xs text-gray-400 break-all max-h-10 overflow-hidden font-mono">{f.evidence}</div>
          {/if}
        </div>
      {/each}
    </div>
  {:else if !scanning && findings.length === 0 && scanned > 0}
    <div class="text-center text-gray-400 text-sm py-8">未发现 XSS 漏洞</div>
  {:else if !scanning}
    <div class="text-center text-gray-400 text-sm py-8">
      输入目标 URL，点击「检测」开始 XSS 反射扫描
    </div>
  {/if}
</div>
