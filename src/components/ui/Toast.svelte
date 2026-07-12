<script lang="ts">
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
  <div class="fixed top-4 right-4 z-50 flex flex-col gap-2.5 pointer-events-none">
    {#each toasts as toast (toast.id)}
      <!-- svelte-ignore a11y-click-events-have-key-events a11y-no-static-element-interactions -->
      <div
        class="vk-slide-in pointer-events-auto flex items-center gap-2 px-3.5 py-2.5 rounded-xl shadow-lg text-sm text-white max-w-xs cursor-pointer transition-all duration-200 hover:scale-[1.02] vk-glass"
        style="background: {gradients[toast.type]}"
        onclick={() => dismiss(toast)}
        role="alert"
      >
        <span class="text-white/80">{icons[toast.type]}</span>
        <span class="font-medium">{toast.message}</span>
      </div>
    {/each}
  </div>
{/if}
