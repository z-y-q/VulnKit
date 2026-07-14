<script lang="ts">
  // 跨面板来源横幅（对齐 docs/UX-UI优化建议.md §6.3）
  //
  // 当存在待消费的 analysisContext 时显示：
  // - 当前已在目标面板：显示来源，提供「返回来源」「清除」
  // - 当前不在目标面板：显示「→ 目标」，提供「前往目标」「清除」
  //
  // 正常 navigate=true 流程中，目标面板 mount effect 会 consume 清掉 context，横幅随即消失；
  // 横幅主要服务于 navigate=false、目标面板无 consume 逻辑、或用户停留在非目标面板时的引导。
  import { analysisContextStore, PANEL_LABELS } from '@/stores/analysis-context';
  import { activePanelStore } from '@/stores/ui';

    let ctx = $derived($analysisContextStore);
    let active = $derived($activePanelStore);
    let onTarget = $derived(!!ctx && ctx.targetPanel === active);
    let targetLabel = $derived(ctx ? PANEL_LABELS[ctx.targetPanel] ?? ctx.targetPanel : '');
    let sourceLabel = $derived(ctx?.sourceLabel || ctx?.sourcePanel || '');

    function go() {
      if (!ctx) return;
      if (onTarget) analysisContextStore.back();
      else activePanelStore.set(ctx.targetPanel);
    }
    function dismiss() {
      analysisContextStore.clear();
    }
</script>

{#if ctx}
  <div
    class="flex items-center gap-2 px-4 py-1.5 text-xs bg-blue-50 dark:bg-blue-900/30 border-b border-blue-200/60 dark:border-blue-700/40 shrink-0"
    role="status"
    aria-live="polite"
  >
    <span class="text-blue-500 dark:text-blue-300 shrink-0" aria-hidden="true">↪</span>
    <span class="flex-1 min-w-0 truncate text-blue-700 dark:text-blue-200">
      来自 <b class="font-semibold">{sourceLabel}</b>{ctx.summary ? ` · ${ctx.summary}` : ''}
      {#if !onTarget}
        <span class="text-blue-400 dark:text-blue-400/80"> → {targetLabel}</span>
      {/if}
    </span>
    <button
      class="btn btn-xs btn-primary shrink-0"
      onclick={go}
      title={onTarget ? '返回来源面板' : `前往「${targetLabel}」`}
    >
      {onTarget ? '返回' : '前往'}
    </button>
    <button
      class="btn btn-xs shrink-0"
      onclick={dismiss}
      title="清除这条待处理数据"
      aria-label="清除待处理数据"
    >
      清除
    </button>
  </div>
{/if}
