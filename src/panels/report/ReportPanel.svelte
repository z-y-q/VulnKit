<script lang="ts">
  // 统一报告面板 — 灵眸 v6.0
  // 从 scan-history store 读取扫描记录，聚合展示 + 多格式导出
  import { scanHistoryStore, type ScanHistoryEntry, type ScanSeverity } from '@/stores/scan-history';
  import { toastStore } from '@/stores/ui';
  import {
    aggregateByModule,
    aggregateByDomain,
    extractDomains,
    countSeverities,
    sortFindings,
    severityLabel,
    severityBadgeClass,
    buildCsv,
    buildJson,
    buildMarkdown,
    type ModuleGroup,
  } from '@/lib/report/report-builder';

  // —— 状态 ——
  let entries = $state<ScanHistoryEntry[]>([]);
  let domainFilter = $state<string>('');
  let sevFilter = $state<string>('');
  let loading = $state(true);

  // 订阅 store
  scanHistoryStore.subscribe(v => {
    entries = v;
    loading = false;
  });

  // 挂载时刷新数据
  $effect(() => {
    scanHistoryStore.refresh();
  });

  // —— 派生数据 ——

  let filteredEntries = $derived.by(() => {
    let list = entries;
    if (domainFilter) {
      list = list.filter(e => e.domain === domainFilter);
    }
    return list;
  });

  let allFindings = $derived(
    filteredEntries.flatMap(e => e.findings),
  );

  let severityFiltered = $derived.by(() => {
    let list = allFindings;
    if (sevFilter) {
      list = list.filter(f => f.severity === sevFilter);
    }
    return list;
  });

  let moduleGroups = $derived(aggregateByModule(filteredEntries));
  let domainGroups = $derived(aggregateByDomain(filteredEntries));
  let domains = $derived(extractDomains(entries));
  let globalSummary = $derived(countSeverities(allFindings));

  // —— 导出 ——

  function downloadBlob(content: string, filename: string, mimeType: string) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `lingmou-report-${Date.now()}.${filename.split('.').pop()}`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function exportCsv() {
    if (filteredEntries.length === 0) {
      toastStore.show('没有可导出的数据', 'warning');
      return;
    }
    downloadBlob(buildCsv(filteredEntries), 'lingmou-report.csv', 'text/csv;charset=utf-8');
    toastStore.show('CSV 报告已导出', 'success');
  }

  function exportJsonReport() {
    if (filteredEntries.length === 0) {
      toastStore.show('没有可导出的数据', 'warning');
      return;
    }
    downloadBlob(buildJson(filteredEntries), 'lingmou-report.json', 'application/json;charset=utf-8');
    toastStore.show('JSON 报告已导出', 'success');
  }

  function exportMarkdownReport() {
    if (filteredEntries.length === 0) {
      toastStore.show('没有可导出的数据', 'warning');
      return;
    }
    downloadBlob(buildMarkdown(filteredEntries), 'lingmou-report.md', 'text/markdown;charset=utf-8');
    toastStore.show('Markdown 报告已导出', 'success');
  }

  // —— 清空 ——

  async function clearAll() {
    if (!confirm('确定清空所有扫描历史？此操作不可恢复。')) return;
    await scanHistoryStore.clear();
    domainFilter = '';
    sevFilter = '';
    toastStore.show('扫描历史已清空', 'success');
  }

  // —— 严重程度 badge 列表 ——

  const SEV_KEYS: ScanSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
</script>

<div class="space-y-3">
  <!-- 总览统计 -->
  {#if filteredEntries.length > 0}
    <div class="card p-3 space-y-2">
      <div class="flex items-center gap-2 flex-wrap">
        <span class="text-sm font-medium">总览</span>
        <span class="text-xs text-gray-400">
          {filteredEntries.length} 次扫描 / {allFindings.length} 项发现
        </span>
      </div>

      <!-- 严重程度统计 -->
      <div class="flex items-center gap-1.5 flex-wrap">
        {#each SEV_KEYS as sev}
          <span class="badge text-xs {severityBadgeClass(sev)}">
            {severityLabel(sev)} {globalSummary[sev]}
          </span>
        {/each}
      </div>

      <!-- 域名统计 -->
      <div class="text-xs text-gray-400">
        涉及域名: {domains.length > 0 ? domains.join(', ') : '无'}
      </div>
    </div>
  {:else if !loading && entries.length === 0}
    <div class="card p-6 text-center space-y-2">
      <div class="text-2xl">📋</div>
      <div class="text-sm text-gray-500">暂无扫描记录</div>
      <div class="text-xs text-gray-400">运行各扫描模块后，发现将自动汇总到此处</div>
    </div>
  {/if}

  <!-- 过滤器 + 操作 -->
  {#if entries.length > 0}
    <div class="card p-3 space-y-2">
      <div class="flex items-center gap-2 text-xs">
        <select class="input text-xs flex-1" value={domainFilter} onchange={(e) => domainFilter = (e.target as HTMLSelectElement).value}>
          <option value="">全部域名</option>
          {#each domains as d}
            <option value={d}>{d}</option>
          {/each}
        </select>
        <select class="input text-xs flex-1" value={sevFilter} onchange={(e) => sevFilter = (e.target as HTMLSelectElement).value}>
          <option value="">全部级别</option>
          {#each SEV_KEYS as sev}
            <option value={sev}>{severityLabel(sev)}</option>
          {/each}
        </select>
      </div>

      <div class="flex items-center gap-1 text-xs">
        <button class="btn btn-sm flex-1" onclick={exportCsv}>CSV</button>
        <button class="btn btn-sm flex-1" onclick={exportJsonReport}>JSON</button>
        <button class="btn btn-sm flex-1" onclick={exportMarkdownReport}>Markdown</button>
        <button class="btn btn-sm btn-ghost text-red-500 ml-auto" onclick={clearAll}>清空</button>
      </div>
    </div>
  {/if}

  <!-- 发现列表（按模块分组） -->
  {#if moduleGroups.length > 0}
    {#each moduleGroups as group (group.module)}
      <div class="card p-3 space-y-2">
        <div class="flex items-center gap-2">
          <span class="text-sm font-medium">{group.label}</span>
          <span class="badge text-xs">{group.findings.length}</span>
        </div>
        <div class="space-y-1">
          {#each group.findings as f (f.title + f.severity + (f.url || ''))}
            <div class="p-2 rounded bg-gray-50 dark:bg-gray-800/50 space-y-1">
              <div class="flex items-center gap-2">
                <span class="badge text-xs {severityBadgeClass(f.severity)}">{severityLabel(f.severity)}</span>
                <span class="text-xs font-medium">{f.title}</span>
              </div>
              {#if f.detail}
                <div class="text-xs text-gray-500">{f.detail}</div>
              {/if}
              {#if f.url}
                <div class="text-xs font-mono text-gray-400 break-all truncate">{f.url}</div>
              {/if}
            </div>
          {/each}
        </div>
      </div>
    {/each}
  {:else if !loading && entries.length > 0 && filteredEntries.length === 0}
    <div class="card p-4 text-center text-sm text-gray-400">
      当前筛选条件下无结果
    </div>
  {/if}
</div>
