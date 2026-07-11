<script lang="ts">
  // 安全头检测面板 — 灵眸 v6.0
  // 流程：自动填充 URL → FETCH_HEADER_PROBE → analyzeHeaders → 评分环 + 缺失/问题/签名
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore } from '@/stores/ui';
  import UrlInput from '@/components/scanner/UrlInput.svelte';
  import EmptyState from '@/components/scanner/EmptyState.svelte';
  import SeverityBadge from '@/components/scanner/SeverityBadge.svelte';
  import FilterBar from '@/components/scanner/FilterBar.svelte';
  import type { ProbeResult } from '@/lib/types/messaging';
  import {
    analyzeHeaders,
    STATUS_COLOR,
    CATEGORY_LABELS,
    CATEGORY_ORDER,
    type HeaderAnalysisResult,
    type HeaderIssue,
    type HeaderCheckResult,
    type HeaderSeverity,
  } from '@/lib/scanners/headers-engine';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';

  let targetUrl = $state('');
  let scanning = $state(false);
  let result = $state<HeaderAnalysisResult | null>(null);
  let filter = $state<'all' | 'miss' | 'warn' | 'pass'>('all');
  let searchQuery = $state('');
  let sortBy = $state<'severity' | 'name' | 'category'>('severity');

  // 自动填充当前页 URL
  $effect(() => {
    getActiveTabUrl().then(u => {
      if (u) targetUrl = u;
    });
  });

  // 按分类分组 + 过滤 + 排序
  let filteredResults = $derived.by(() => {
    if (!result) return [];
    let list = result.results;

    // 过滤
    if (filter === 'miss') list = list.filter(r => r.status === 'miss');
    else if (filter === 'warn') list = list.filter(r => r.status === 'warn');
    else if (filter === 'pass') list = list.filter(r => r.status === 'pass');

    // 搜索
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      list = list.filter(r => {
        const text = `${r.name} ${r.detail} ${r.recommendation}`.toLowerCase();
        return text.indexOf(q) !== -1;
      });
    }

    // 排序
    list = [...list].sort((a, b) => {
      if (sortBy === 'severity') {
        const o: Record<string, number> = { miss: 0, warn: 1, pass: 2 };
        return (o[a.status] ?? 2) - (o[b.status] ?? 2);
      }
      if (sortBy === 'name') return a.name.localeCompare(b.name);
      return a.category.localeCompare(b.category);
    });

    return list;
  });

  // 按分类分组
  let groupedResults = $derived.by(() => {
    const groups: Record<string, HeaderCheckResult[]> = {};
    for (const r of filteredResults) {
      const cat = r.category || 'other';
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(r);
    }
    return groups;
  });

  // 评分环样式
  let scoreRingStyle = $derived.by(() => {
    const circumference = 2 * Math.PI * 54;
    const score = result?.score ?? 0;
    const offset = circumference - (score / 100) * circumference;
    return `stroke-dashoffset: ${offset}px`;
  });

  let scoreRingColor = $derived.by(() => {
    const score = result?.score ?? 0;
    if (score >= 75) return 'text-green-500';
    if (score >= 50) return 'text-yellow-500';
    return 'text-red-500';
  });

  let gradeColor = $derived.by(() => {
    const score = result?.score ?? 0;
    if (score >= 75) return 'bg-green-500 text-white';
    if (score >= 50) return 'bg-yellow-500 text-white';
    return 'bg-red-500 text-white';
  });

  // 映射 HeaderAnalysisResult → ScanFinding[]
  function mapHeadersToFindings(r: HeaderAnalysisResult): ScanFinding[] {
    return r.issues.map((issue) => ({
      title: issue.header,
      severity: issue.severity,
      detail: issue.message,
      evidence: issue.recommendation,
      url: targetUrl,
    }));
  }

  // 主扫描
  async function scan() {
    const v = validateProbeUrl(targetUrl);
    if ('error' in v) {
      toastStore.show('请输入合法的 http(s) URL', 'error');
      return;
    }

    scanning = true;
    result = null;

    try {
      const probe = await sendMessage({
        type: 'FETCH_HEADER_PROBE',
        url: v.parsed.href,
        timeout: 10000,
      });
      const r = probe as ProbeResult;

      if (r.error || !r.headers) {
        toastStore.show('获取响应头失败: ' + (r.error || '无响应'), 'warning');
        return;
      }

      // 将 headers 键转为小写（engine 期望全小写）
      const normalizedHeaders: Record<string, string> = {};
      for (const [k, val] of Object.entries(r.headers)) {
        normalizedHeaders[k.toLowerCase()] = val;
      }

      result = analyzeHeaders(normalizedHeaders);

      if (result.issues.length > 0) {
        toastStore.show(`发现 ${result.issues.length} 个安全头问题（评分 ${result.score}）`, 'warning');
      } else {
        toastStore.show(`安全头评分 ${result.score}，配置良好`, 'success');
      }

      try {
        await scanHistoryStore.addScan({
          url: targetUrl,
          module: 'headers',
          findings: mapHeadersToFindings(result),
        });
      } catch { /* store failure must not break scan */ }
    } catch (err: any) {
      toastStore.show('扫描出错: ' + (err.message || '未知错误'), 'warning');
    } finally {
      scanning = false;
    }
  }

  function copyText() {
    if (!result) return;
    const lines = [
      '安全头分析报告',
      '==================',
      `目标: ${targetUrl}`,
      `评分: ${result.score} (${result.grade})`,
      '',
      '结果:',
    ];
    for (const r of result.results) {
      const statusText = r.status === 'pass' ? '[通过]' : r.status === 'warn' ? '[警告]' : '[缺失]';
      lines.push(`${statusText} ${r.name}: ${r.detail || '-'}`);
      if (r.recommendation) lines.push(`  建议: ${r.recommendation}`);
    }
    for (const l of result.infoLeaks) {
      lines.push(`[泄露] ${l.name}: ${l.detail} (${l.message})`);
    }
    navigator.clipboard.writeText(lines.join('\n'));
    toastStore.show('已复制报告文本', 'success');
  }

  function copyMarkdown() {
    if (!result) {
      toastStore.show('没有检测结果', 'warning');
      return;
    }
    let md = '# Security Headers Report\n\n';
    md += `**Target:** ${targetUrl}\n`;
    md += `**Score:** ${result.score} (${result.grade})\n\n`;
    md += '| Header | Status | Value | Description |\n';
    md += '|--------|--------|-------|-------------|\n';
    for (const r of result.results) {
      md += `| ${r.name} | ${r.status} | ${r.detail || '-'} | ${r.recommendation || '-'} |\n`;
    }
    navigator.clipboard.writeText(md);
    toastStore.show('已复制 Markdown', 'success');
  }
</script>

<div class="space-y-3">
  <!-- 输入 -->
  <div class="card p-3 space-y-2">
    <UrlInput bind:value={targetUrl} {scanning} buttonText="检测" onscan={scan} />
    {#if scanning}
      <div class="text-xs text-gray-400">正在获取响应头...</div>
    {/if}
  </div>

  <!-- 评分区 -->
  {#if result}
    <div class="card p-3">
      <div class="flex items-center gap-4">
        <!-- 评分环 -->
        <div class="relative shrink-0">
          <svg width="120" height="120" viewBox="0 0 120 120">
            <circle cx="60" cy="60" r="54" fill="none" stroke-width="8"
              class="stroke-gray-200 dark:stroke-gray-700" />
            <circle cx="60" cy="60" r="54" fill="none" stroke-width="8"
              class={scoreRingColor}
              stroke-dasharray={2 * Math.PI * 54}
              stroke-linecap="round"
              transform="rotate(-90 60 60)"
              style={scoreRingStyle} />
          </svg>
          <div class="absolute inset-0 flex flex-col items-center justify-center">
            <span class="text-2xl font-bold {scoreRingColor}">{result.score}</span>
          </div>
        </div>

        <div class="flex-1 space-y-1.5">
          <!-- 评级 -->
          <div class="flex items-center gap-2">
            <span class="badge text-lg font-bold {gradeColor}">{result.grade}</span>
            <span class="text-sm text-gray-500">安全头评分</span>
          </div>

          <!-- 统计 -->
          <div class="flex flex-wrap gap-1 text-xs">
            <span class="badge bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300">通过 {result.passed}</span>
            <span class="badge bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300">警告 {result.warning}</span>
            <span class="badge bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300">缺失 {result.missing}</span>
          </div>

          <!-- 签名 -->
          {#if result.serverSignatures.length > 0}
            <div class="text-xs">
              <span class="text-gray-400">服务器:</span>
              {#each result.serverSignatures as sig}
                <span class="badge text-xs bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300 ml-1">{sig}</span>
              {/each}
            </div>
          {/if}
          {#if result.frameworkSignatures.length > 0}
            <div class="text-xs">
              <span class="text-gray-400">框架:</span>
              {#each result.frameworkSignatures as sig}
                <span class="badge text-xs bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300 ml-1">{sig}</span>
              {/each}
            </div>
          {/if}
        </div>
      </div>
    </div>
  {/if}

  <!-- 筛选工具栏 -->
  {#if result && result.results.length > 0}
    <FilterBar
      active={filter}
      options={[
        { key: 'all', label: '全部', count: result.results.length, color: 'bg-primary text-white' },
        { key: 'miss', label: '缺失', count: result.missing, color: 'bg-red-500 text-white' },
        { key: 'warn', label: '警告', count: result.warning, color: 'bg-yellow-500 text-white' },
        { key: 'pass', label: '通过', count: result.passed, color: 'bg-green-500 text-white' },
      ]}
      onchange={(k) => (filter = k as 'all' | 'miss' | 'warn' | 'pass')}
    >
      <input class="input text-xs w-24" placeholder="搜索..." bind:value={searchQuery} />
      <select class="input text-xs w-20" bind:value={sortBy}>
        <option value="severity">按严重度</option>
        <option value="name">按名称</option>
        <option value="category">按分类</option>
      </select>
    </FilterBar>
  {/if}

  <!-- 问题列表（按严重度排序，从 issues 汇总） -->
  {#if result && result.issues.length > 0 && filter === 'all'}
    <div class="card p-3 space-y-1.5">
      <div class="text-xs font-medium text-gray-500">问题汇总（按严重度）</div>
      <div class="space-y-1">
        {#each result.issues as issue (issue.header + issue.message)}
          <div class="flex items-start gap-2 text-xs">
            <SeverityBadge severity={issue.severity} />
            <div class="min-w-0">
              <span class="font-mono text-gray-700 dark:text-gray-200">{issue.header}</span>
              <span class="text-gray-500 dark:text-gray-400 ml-1">{issue.message}</span>
              {#if issue.recommendation}
                <div class="text-gray-400 dark:text-gray-500 mt-0.5">建议: {issue.recommendation}</div>
              {/if}
            </div>
          </div>
        {/each}
      </div>
    </div>
  {/if}

  <!-- 安全头检测结果（按分类分组） -->
  {#if filteredResults.length > 0}
    <div class="space-y-3">
      {#each CATEGORY_ORDER as cat}
        {@const items = groupedResults[cat]}
        {#if items && items.length > 0}
          <div class="space-y-1">
            <div class="text-xs font-medium text-gray-400 px-1">{CATEGORY_LABELS[cat] || cat}</div>
            {#each items as r (r.name)}
              <div class="card p-2.5 space-y-1">
                <div class="flex items-center gap-2">
                  <span class="badge text-xs {STATUS_COLOR[r.status]}">
                    {r.status === 'pass' ? '通过' : r.status === 'warn' ? '警告' : '缺失'}
                  </span>
                  <span class="text-xs font-medium">{r.name}</span>
                  <span class="text-xs text-gray-400 ml-auto">w={r.weight}</span>
                </div>
                <div class="text-xs font-mono text-gray-600 dark:text-gray-300 break-all truncate">{r.detail || '-'}</div>
                {#if r.recommendation}
                  <div class="text-xs text-gray-400 dark:text-gray-500">建议: {r.recommendation}</div>
                {/if}
              </div>
            {/each}
          </div>
        {/if}
      {/each}
    </div>
  {:else if !scanning && result && filteredResults.length === 0}
    <EmptyState message="无匹配结果" icon="🔍" />
  {:else if !scanning && !result}
    <EmptyState
      message="输入目标 URL，点击「检测」开始 HTTP 安全头扫描"
      hint="自动分析 20+ 安全头配置并评分"
      icon="🛡️"
    />
  {/if}

  <!-- 信息泄露 -->
  {#if result && result.infoLeaks.length > 0}
    <div class="space-y-1">
      <div class="text-xs font-medium text-gray-400 px-1">信息泄露</div>
      {#each result.infoLeaks as leak (leak.name)}
        <div class="card p-2.5 space-y-1 border-l-2 border-yellow-500">
          <div class="flex items-center gap-2">
            <span class="badge text-xs bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300">泄露</span>
            <span class="text-xs font-medium">{leak.name}</span>
          </div>
          <div class="text-xs font-mono text-gray-600 dark:text-gray-300 break-all">{leak.detail}</div>
          <div class="text-xs text-gray-400 dark:text-gray-500">{leak.message}</div>
        </div>
      {/each}
    </div>
  {/if}

  <!-- Cookie 安全 -->
  {#if result && result.cookieFindings.length > 0}
    <div class="space-y-1">
      <div class="text-xs font-medium text-gray-400 px-1">Cookie 安全</div>
      {#each result.cookieFindings as cf (cf.name)}
        <div class="card p-2.5 space-y-1">
          <div class="flex items-center gap-2">
            <span class="badge text-xs bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300">Cookie</span>
            <span class="text-xs font-medium">{cf.name}</span>
          </div>
          <div class="flex flex-wrap gap-1">
            {#each cf.issues as issue}
              <span class="badge text-xs bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300">{issue}</span>
            {/each}
            {#if cf.flags.secure}
              <span class="badge text-xs bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300">Secure</span>
            {/if}
            {#if cf.flags.httponly}
              <span class="badge text-xs bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300">HttpOnly</span>
            {/if}
            {#if cf.flags.samesite}
              <span class="badge text-xs bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300">SameSite={cf.flags.samesite}</span>
            {/if}
          </div>
        </div>
      {/each}
    </div>
  {/if}

  <!-- CSP 深度分析 -->
  {#if result && result.cspDeep && (result.cspDeep.bypasses.length > 0 || result.cspDeep.missingCritical.length > 0)}
    <div class="space-y-1">
      <div class="text-xs font-medium text-gray-400 px-1">CSP 深度分析</div>

      {#if result.cspDeep.bypasses.length > 0}
        {#each result.cspDeep.bypasses as bp (bp.type)}
          <div class="card p-2.5 space-y-1 border-l-2 border-red-500">
            <div class="flex items-center gap-2">
              <SeverityBadge severity={bp.severity} />
              <span class="text-xs font-mono">{bp.type}</span>
            </div>
            <div class="text-xs text-gray-400 dark:text-gray-500">{bp.description}</div>
          </div>
        {/each}
      {/if}

      {#if result.cspDeep.missingCritical.length > 0}
        {#each result.cspDeep.missingCritical as mc (mc.directive)}
          <div class="card p-2.5 space-y-1">
            <div class="flex items-center gap-2">
              <SeverityBadge severity={mc.severity} />
              <span class="text-xs font-mono">{mc.directive}</span>
            </div>
            <div class="text-xs text-gray-400 dark:text-gray-500">{mc.impact}</div>
          </div>
        {/each}
      {/if}

      {#if result.cspDeep.summary}
        <div class="text-xs text-gray-400 px-1">摘要: {result.cspDeep.summary}</div>
      {/if}
    </div>
  {/if}

  <!-- 操作按钮 -->
  {#if result}
    <div class="flex gap-1">
      <button class="btn btn-sm flex-1" onclick={copyText}>复制文本</button>
      <button class="btn btn-sm flex-1" onclick={copyMarkdown}>复制 Markdown</button>
    </div>
  {/if}
</div>
