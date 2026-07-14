<script lang="ts">
  // 任务中心气泡 — 灵眸 v6.0（对齐 docs/UX-UI优化建议.md §9.2）
  // 显示最近已结束任务（succeeded/partial/cancelled/failed），点击切到对应面板。
  // 务实范围：只聚合历史（架构限制，运行中任务随面板卸载中断，不做实时聚合）。
  import { taskCenterStore, type TaskRecord, type TaskRecordStatus } from '@/stores/task-center';
  import { activePanelStore } from '@/stores/ui';

    let records = $derived($taskCenterStore);

    const STATUS_META: Record<TaskRecordStatus, { icon: string; cls: string; text: string }> = {
    succeeded: { icon: '✓', cls: 'text-green-500 dark:text-green-400', text: '成功' },
    partial: { icon: '◐', cls: 'text-yellow-500 dark:text-yellow-400', text: '部分' },
    cancelled: { icon: '⊘', cls: 'text-gray-400 dark:text-gray-500', text: '已取消' },
    failed: { icon: '✗', cls: 'text-red-500 dark:text-red-400', text: '失败' },
  };

    function fmtTime(ts: number): string {
    if (!ts) return '';
    const d = new Date(ts);
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

    function goto(rec: TaskRecord) {
    activePanelStore.set(rec.panel);
  }
</script>

{#if records.length > 0}
  {@const latest = records[0]}
  <details class="relative">
    <summary
      class="flex items-center gap-1 cursor-pointer list-none outline-none rounded px-1 py-0.5 hover:bg-gray-200/50 dark:hover:bg-gray-700/40"
      title={`最近任务（共 ${records.length} 条）`}
      aria-label={`最近任务（共 ${records.length} 条，最新：${latest.label} ${STATUS_META[latest.status].text}）`}
    >
      <span class={STATUS_META[latest.status].cls} aria-hidden="true">{STATUS_META[latest.status].icon}</span>
      <span class="tabular-nums">{records.length}</span>
    </summary>
    <div
      class="absolute bottom-full right-0 mb-1 w-60 max-h-72 overflow-y-auto rounded-md border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shadow-lg z-40"
      role="menu"
      aria-label="最近任务列表"
    >
      <div class="flex items-center justify-between px-2 py-1 text-[11px] text-gray-400 border-b border-gray-100 dark:border-gray-700">
        <span>最近任务（{records.length}）</span>
        <button
          type="button"
          class="hover:text-red-500 dark:hover:text-red-400"
          onclick={() => taskCenterStore.clear()}
          aria-label="清空任务历史"
        >
          清空
        </button>
      </div>
      {#each records as rec (rec.id)}
        {@const meta = STATUS_META[rec.status]}
        <button
          type="button"
          class="flex items-center gap-1.5 w-full text-left px-2 py-1 text-[11px] hover:bg-blue-50 dark:hover:bg-blue-900/30"
          role="menuitem"
          onclick={() => goto(rec)}
          title={`回到「${rec.label}」`}
        >
          <span class={meta.cls} aria-hidden="true">{meta.icon}</span>
          <span class="flex-1 truncate text-gray-700 dark:text-gray-200">{rec.label}</span>
          {#if rec.summary}
            <span class="text-gray-400 truncate max-w-24">{rec.summary}</span>
          {/if}
          <span class="text-gray-400 tabular-nums shrink-0">{fmtTime(rec.finishedAt)}</span>
        </button>
      {/each}
    </div>
  </details>
{/if}
