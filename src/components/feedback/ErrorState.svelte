<script lang="ts">
  // 错误状态卡片 — 灵眸 v6.0
  // 对齐 docs/UX-UI优化建议.md §5.4：内联展示 ActionableError + 恢复动作，
  // 取代「错误只靠 Toast」。role="alert" 让读屏即时感知。
  import type { ActionableError } from '@/lib/errors/actionable-error';

  type RecoveryAction = ActionableError['recovery'][number]['action'];

  let {
    error,
    onRetry,
    onOpenSettings,
    onRefresh,
    onCopyDiagnostics,
  }: {
    error: ActionableError;
    /** 各 recovery action 的处理回调；未提供则对应按钮禁用 */
    onRetry?: () => void;
    onOpenSettings?: () => void;
    onRefresh?: () => void;
    onCopyDiagnostics?: () => void;
  } = $props();

  function callbackFor(action: RecoveryAction): (() => void) | undefined {
    switch (action) {
      case 'retry': return onRetry;
      case 'open-settings': return onOpenSettings;
      case 'refresh-page': return onRefresh;
      case 'copy-diagnostics': return onCopyDiagnostics;
    }
  }
</script>

<div class="card border border-red-300 dark:border-red-800 p-3 space-y-2" role="alert">
  <div class="flex items-start gap-2">
    <span class="text-red-500 dark:text-red-400 shrink-0" aria-hidden="true">⚠</span>
    <div class="min-w-0 flex-1">
      <p class="font-semibold text-sm text-gray-800 dark:text-gray-100">{error.title}</p>
      <p class="text-xs text-gray-600 dark:text-gray-300 mt-0.5 break-words">{error.message}</p>
      {#if error.cause}
        <details class="mt-1">
          <summary class="text-xs text-gray-400 cursor-pointer select-none">诊断信息</summary>
          <pre class="text-xs text-gray-500 dark:text-gray-400 mt-1 whitespace-pre-wrap break-all">{error.cause}</pre>
        </details>
      {/if}
    </div>
  </div>
  {#if error.recovery.length > 0}
    <div class="flex flex-wrap gap-1 pt-1">
      {#each error.recovery as r (r.action)}
        <button
          class="btn btn-sm btn-soft"
          disabled={!callbackFor(r.action)}
          onclick={callbackFor(r.action)}
        >{r.label}</button>
      {/each}
    </div>
  {/if}
</div>
