<script lang="ts">
  // Toast 视口 — 对齐 docs/UX-UI优化建议.md §8.4：
  // - role="alert"(error)/"status"(其他) 隐含 aria-live，读屏可感知且不抢焦点；
  // - 明确关闭按钮（键盘可达），不再用整块 div onclick；
  // - 去掉 hover:scale（高密度浮层不用位移动效）。
  import { toastStore, type ToastItem } from '@/stores/ui';

  let toasts = $derived($toastStore);

  const gradients: Record<ToastItem['type'], string> = {
    success: 'linear-gradient(135deg, #10b981, #059669)',
    error: 'linear-gradient(135deg, #ef4444, #dc2626)',
    warning: 'linear-gradient(135deg, #f59e0b, #d97706)',
    info: 'linear-gradient(135deg, #3b82f6, #2563eb)',
  };

  const icons: Record<ToastItem['type'], string> = {
    success: '✓',
    error: '✕',
    warning: '⚠',
    info: 'ℹ',
  };

  function dismiss(toast: ToastItem) {
    toastStore.dismiss(toast.id);
  }
</script>

{#if toasts.length > 0}
  <div class="fixed top-4 right-4 z-50 flex flex-col gap-2.5 pointer-events-none" role="region" aria-label="通知">
    {#each toasts as toast (toast.id)}
      <div
        class="vk-slide-in pointer-events-auto flex items-center gap-2 pl-3.5 pr-1.5 py-2.5 rounded-xl shadow-lg text-sm text-white max-w-xs vk-glass"
        style="background: {gradients[toast.type]}"
        role={toast.type === 'error' ? 'alert' : 'status'}
      >
        <span class="text-white/80" aria-hidden="true">{icons[toast.type]}</span>
        <span class="font-medium flex-1">{toast.message}</span>
        <button
          type="button"
          class="shrink-0 w-5 h-5 rounded flex items-center justify-center text-white/70 hover:text-white hover:bg-white/20 transition-colors"
          onclick={() => dismiss(toast)}
          aria-label="关闭通知"
        >
          <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
    {/each}
  </div>
{/if}
