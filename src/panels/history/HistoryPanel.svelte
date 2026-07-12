<script lang="ts">
  // 历史档案面板 — 灵眸 v6.0
  // 订阅 scanHistoryStore，展示/筛选/删除历史扫描记录
  import { scanHistoryStore, MODULE_LABELS, SEV_ORDER, type ScanHistoryEntry, type ScanSeverity } from '@/stores/scan-history';
  import { toastStore } from '@/stores/ui';

  let entries = $derived($scanHistoryStore);
  let filterDomain = $state('');
  let filterModule = $state('');
  let expandedId = $state<string | null>(null);

  // 挂载时刷新数据（订阅由 $scanHistoryStore 自动管理）
  $effect(() => {
    scanHistoryStore.refresh();
  });

  // 提取所有不重复域名
  let domains = $derived.by(() => {
    const set = new Set<string>();
    for (const e of entries) set.add(e.domain);
    return [...set].sort();
  });

  // 提取所有不重复模块 id
  let modules = $derived.by(() => {
    const set = new Set<string>();
    for (const e of entries) set.add(e.module);
    return [...set].sort();
  });

  // 筛选后的列表
  let filtered = $derived.by(() => {
    let list = entries;
    if (filterDomain) list = list.filter(e => e.domain === filterDomain);
    if (filterModule) list = list.filter(e => e.module === filterModule);
    return list;
  });

  function formatTime(ts: number): string {
    const d = new Date(ts);
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${d.getMonth() + 1}/${d.getDate()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function sevColor(sev: ScanSeverity): string {
    switch (sev) {
      case 'critical': return 'text-red-600 dark:text-red-400';
      case 'high': return 'text-orange-500 dark:text-orange-400';
      case 'medium': return 'text-yellow-500 dark:text-yellow-400';
      case 'low': return 'text-blue-500 dark:text-blue-400';
      default: return 'text-gray-400 dark:text-gray-500';
    }
  }

  function toggleExpand(id: string) {
    expandedId = expandedId === id ? null : id;
  }

  async function deleteEntry(id: string) {
    // 从 store 中过滤掉该条目（store 没有 deleteEntry，使用 clear + re-add 手段不合适，
    // 直接操作存储层 — 但按规则不修改 store，所以用 clearDomain 后 refresh）
    // scanHistoryStore 没有 delete 单条的能力，所以我们直接对 storage 操作
    const STORAGE_KEY = 'pentest_scan_history';
    try {
      const data = await browser.storage.local.get(STORAGE_KEY);
      const all = (data[STORAGE_KEY] as ScanHistoryEntry[]) || [];
      const next = all.filter(e => e.id !== id);
      await browser.storage.local.set({ [STORAGE_KEY]: next });
      await scanHistoryStore.refresh();
      toastStore.show('已删除该条记录', 'success');
    } catch {
      toastStore.show('删除失败', 'error');
    }
  }

  async function clearAll() {
    if (!confirm('确定要清空所有扫描历史吗？此操作不可恢复。')) return;
    await scanHistoryStore.clear();
    toastStore.show('历史已清空', 'success');
  }

  async function clearDomain(domain: string) {
    if (!confirm(`确定要清空 ${domain} 的所有历史记录吗？`)) return;
    await scanHistoryStore.clearDomain(domain);
    toastStore.show(`已清空 ${domain} 的历史`, 'success');
  }
</script>

<div class="space-y-3">
  <!-- 筛选 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-2">
      <select class="input text-xs flex-1" bind:value={filterDomain}>
        <option value="">所有域名</option>
        {#each domains as d}
          <option value={d}>{d}</option>
        {/each}
      </select>
      <select class="input text-xs flex-1" bind:value={filterModule}>
        <option value="">所有模块</option>
        {#each modules as m}
          <option value={m}>{MODULE_LABELS[m] || m}</option>
        {/each}
      </select>
    </div>
    {#if entries.length > 0}
      <div class="flex items-center justify-between text-xs text-gray-400">
        <span>共 {filtered.length} 条记录</span>
        <button class="btn btn-sm text-xs text-red-500 dark:text-red-400" onclick={clearAll}>
          清空全部
        </button>
      </div>
    {/if}
  </div>

  <!-- 列表 -->
  {#if filtered.length > 0}
    <div class="space-y-1">
      {#each filtered as entry (entry.id)}
        {@const isExpanded = expandedId === entry.id}
        <div class="card p-2 space-y-1">
          <!-- 标题行 -->
          <div class="flex items-center gap-2 cursor-pointer" role="button" tabindex="0" onclick={() => toggleExpand(entry.id)} onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleExpand(entry.id); } }}>
            <span class="badge text-xs">{entry.moduleName || MODULE_LABELS[entry.module] || entry.module}</span>
            <span class="text-xs text-gray-600 dark:text-gray-300 truncate flex-1">{entry.domain}</span>
            <span class="text-xs text-gray-400 shrink-0">{formatTime(entry.timestamp)}</span>

            <!-- 严重程度徽标 -->
            <span class="flex items-center gap-1 shrink-0 text-xs">
              {#if entry.summary.critical > 0}
                <span class="text-red-600 dark:text-red-400 font-bold">C{entry.summary.critical}</span>
              {/if}
              {#if entry.summary.high > 0}
                <span class="text-orange-500 dark:text-orange-400 font-bold">H{entry.summary.high}</span>
              {/if}
              {#if entry.summary.medium > 0}
                <span class="text-yellow-500 dark:text-yellow-400 font-bold">M{entry.summary.medium}</span>
              {/if}
              {#if entry.summary.low > 0}
                <span class="text-blue-500 dark:text-blue-400 font-bold">L{entry.summary.low}</span>
              {/if}
              {#if entry.summary.info > 0}
                <span class="text-gray-400 font-bold">I{entry.summary.info}</span>
              {/if}
              {#if entry.summary.total === 0}
                <span class="text-green-500 dark:text-green-400">无风险</span>
              {/if}
            </span>

            <span class="text-xs text-gray-400 shrink-0">{entry.summary.total}条</span>

            <!-- 操作按钮 -->
            <button
              class="btn btn-sm text-xs text-red-500 dark:text-red-400 shrink-0 px-1"
              onclick={(e) => { e.stopPropagation(); clearDomain(entry.domain); }}
              title="清空该域名历史"
            >
              域名清空
            </button>
            <button
              class="btn btn-sm text-xs text-red-500 dark:text-red-400 shrink-0 px-1"
              onclick={(e) => { e.stopPropagation(); deleteEntry(entry.id); }}
              title="删除该条"
            >
              ✕
            </button>

            <span class="text-gray-400 text-xs shrink-0">{isExpanded ? '▾' : '▸'}</span>
          </div>

          <!-- 展开详情 -->
          {#if isExpanded && entry.findings.length > 0}
            <div class="mt-1 pl-2 border-l-2 border-gray-200 dark:border-gray-700 space-y-0.5">
              {#each entry.findings as f, i (i)}
                <div class="flex items-start gap-1.5 text-xs py-0.5">
                  <span class="{sevColor(f.severity as ScanSeverity)} font-bold shrink-0">
                    [{(f.severity || 'info').toUpperCase().slice(0, 1)}]
                  </span>
                  <span class="flex-1 text-gray-700 dark:text-gray-200">{f.title || '未知'}</span>
                  {#if f.detail}
                    <span class="text-gray-400 truncate max-w-48">{f.detail}</span>
                  {/if}
                </div>
              {/each}
            </div>
          {:else if isExpanded}
            <div class="text-xs text-gray-400 pl-2">无发现</div>
          {/if}
        </div>
      {/each}
    </div>
  {:else if entries.length === 0}
    <div class="text-center text-gray-400 text-sm py-8">
      暂无历史记录
    </div>
  {:else}
    <div class="text-center text-gray-400 text-sm py-8">
      没有匹配的记录
    </div>
  {/if}
</div>
