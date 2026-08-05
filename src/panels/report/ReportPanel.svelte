<script lang="ts">
  // 统一报告面板
  // 从 scan-history store 读取扫描记录，聚合展示 + 多格式导出
  import { scanHistoryStore, type ScanHistoryEntry, type ScanFinding, type ScanSeverity } from '@/stores/scan-history';
  import { toastStore } from '@/stores/ui';
  import { confirmStore } from '@/stores/confirm';
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import DetailDrawer from '@/components/results/DetailDrawer.svelte';
  import type { DetailField } from '@/components/results/detail-drawer-utils';
  import {
    aggregateByModule,
    extractDomains,
    countSeverities,
    sortFindings,
    severityLabel,
    severityBadgeClass,
    buildCsv,
    buildJson,
    buildMarkdown,
    buildHtml,
    type ModuleGroup,
  } from '@/lib/report/report-builder';

  // —— 状态 ——
  let entries = $derived($scanHistoryStore);
  let domainFilter = $state<string>('');
  let sevFilter = $state<string>('');
  let loading = $state(true);

  // 挂载时刷新数据（订阅由 $scanHistoryStore 自动管理）
  $effect(() => {
    scanHistoryStore.refresh().finally(() => {
      loading = false;
    });
  });

  // —— 派生数据 ——

  // 单一 query：domain + severity 同时作用；展示 / 统计 / 导出全部消费同一结果（对齐 §3.5）
  let queryEntries = $derived.by(() => {
    let list = entries;
    if (domainFilter) list = list.filter(e => e.domain === domainFilter);
    if (!sevFilter) return list;
    // severity 在 finding 层：过滤每个 entry 的 findings，丢弃无匹配 finding 的 entry
    return list
      .map(e => ({ ...e, findings: e.findings.filter(f => f.severity === sevFilter) }))
      .filter(e => e.findings.length > 0);
  });

  let queryFindings = $derived(queryEntries.flatMap(e => e.findings));

  let moduleGroups = $derived(aggregateByModule(queryEntries));
  let domains = $derived(extractDomains(entries)); // 域名下拉用全量，避免筛选后选项消失
  let globalSummary = $derived(countSeverities(queryFindings));

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

  // CSV / JSON / Markdown 导出统一交给 ExportMenu（serializers 直接复用 report-builder 的 buildCsv/buildJson/buildMarkdown）。
  // HTML 因体量大、含统计图表，保留独立按钮（exportHtmlReport）。

  function exportHtmlReport() {
    if (queryFindings.length === 0) {
      toastStore.show('当前筛选下没有可导出的数据', 'warning');
      return;
    }
    downloadBlob(buildHtml(queryEntries), 'lingmou-report.html', 'text/html;charset=utf-8');
    toastStore.show(`HTML 已导出（当前筛选 ${queryFindings.length} 项，含严重度分布 + 模块覆盖）`, 'success');
  }

  /** 一键全量审计：聚合所有扫描记录生成 HTML 报告（忽略当前过滤） */
  function fullAuditReport() {
    const all = entries;
    if (all.length === 0) {
      toastStore.show('暂无扫描记录，请先运行各检测面板', 'warning');
      return;
    }
    const totalFindings = all.reduce((n, e) => n + e.findings.length, 0);
    downloadBlob(buildHtml(all), `lingmou-audit-${new Date().toISOString().slice(0, 10)}.html`, 'text/html;charset=utf-8');
    toastStore.show(`全量审计报告已生成（${all.length} 模块记录 / ${totalFindings} 发现）`, 'success');
  }

  // —— 清空 ——

  async function clearAll() {
    const ok = await confirmStore.ask({
      title: '清空扫描历史',
      message: '确定清空所有扫描历史？此操作不可恢复。',
      confirmLabel: '清空',
      variant: 'danger',
    });
    if (!ok) return;
    await scanHistoryStore.clear();
    domainFilter = '';
    sevFilter = '';
    toastStore.show('扫描历史已清空', 'success');
  }

  // —— 严重程度 badge 列表 ——

  const SEV_KEYS: ScanSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

  // ===== 详情抽屉（按模块分组点击进入；items 为当前组的 findings）=====
  let detailFindings = $state<ScanFinding[]>([]);
  let detailIndex = $state<number | null>(null);
  let detailModule = $state('');
  function openDetail(group: ModuleGroup, idx: number) {
    detailFindings = group.findings;
    detailModule = group.label;
    detailIndex = idx;
  }
  function reportFields(f: ScanFinding): DetailField[] {
    const fields: DetailField[] = [{ label: '严重度', value: severityLabel(f.severity) }];
    if (f.url) fields.push({ label: 'URL', value: f.url, mono: true });
    return fields;
  }
  function reportEvidence(f: ScanFinding): string {
    return [f.detail, f.evidence].filter(Boolean).join('\n');
  }
</script>

<div class="space-y-3">
  <!-- 总览统计 -->
  {#if queryEntries.length > 0}
    <div class="card p-3 space-y-2">
      <div class="flex items-center gap-2 flex-wrap">
        <span class="text-sm font-medium">总览</span>
        <span class="text-xs text-gray-500">
          {queryEntries.length} 次扫描 / {queryFindings.length} 项发现
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
      <div class="text-xs text-gray-500">
        涉及域名: {domains.length > 0 ? domains.join(', ') : '无'}
      </div>
    </div>
  {:else if !loading && entries.length === 0}
    <div class="card p-6 text-center space-y-2">
      <div class="text-2xl">📋</div>
      <div class="text-sm text-gray-500">暂无扫描记录</div>
      <div class="text-xs text-gray-500">运行各扫描模块后，发现将自动汇总到此处</div>
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
        <ExportMenu
          items={queryEntries}
          module="report"
          serializers={{ csv: buildCsv, json: buildJson, markdown: buildMarkdown }}
        />
        <button class="btn btn-sm flex-1 btn-primary" onclick={exportHtmlReport} disabled={queryFindings.length === 0}>HTML</button>
        <button class="btn btn-sm btn-ghost text-red-500 ml-auto" onclick={clearAll}>清空</button>
      </div>
      <button class="btn btn-sm btn-primary w-full" onclick={fullAuditReport} title="聚合全部扫描记录，忽略当前筛选条件">📊 一键全量审计报告（忽略当前筛选）</button>
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
          {#each group.findings as f, i (f.title + f.severity + (f.url || ''))}
            <div
              class="p-2 rounded bg-gray-50 dark:bg-gray-800/50 space-y-1 cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
              role="button"
              tabindex="0"
              aria-label="查看发现详情"
              onclick={() => openDetail(group, i)}
              onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDetail(group, i); } }}
            >
              <div class="flex items-center gap-2">
                <span class="badge text-xs {severityBadgeClass(f.severity)}">{severityLabel(f.severity)}</span>
                <span class="text-xs font-medium">{f.title}</span>
              </div>
              {#if f.detail}
                <div class="text-xs text-gray-500">{f.detail}</div>
              {/if}
              {#if f.url}
                <div class="text-xs font-mono text-gray-500 break-all truncate">{f.url}</div>
              {/if}
            </div>
          {/each}
        </div>
      </div>
    {/each}
  {:else if !loading && entries.length > 0 && queryEntries.length === 0}
    <div class="card p-4 text-center text-sm text-gray-500">
      当前筛选条件下无结果
    </div>
  {/if}

  <!-- 详情抽屉 -->
  <DetailDrawer
    items={detailFindings}
    index={detailIndex}
    onclose={() => (detailIndex = null)}
    onnavigate={(idx) => (detailIndex = idx)}
    sourcePanel="report"
    sourceLabel="统一报告"
    moduleLabel={detailModule}
    title={(f) => f.title}
    severity={(f) => f.severity}
    target={(f) => f.url || ''}
    fields={reportFields}
    evidence={reportEvidence}
  />
</div>
