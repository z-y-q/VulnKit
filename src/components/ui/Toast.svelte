<script lang="ts">
  import { toastStore, type ToastItem } from '@/stores/ui';

  let toasts = $derived($toastStore);

  function dismiss(toast: ToastItem) {
    toastStore.dismiss(toast.id);
  }
</script>

{#if toasts.length > 0}
  <div class="fixed top-3 right-3 z-50 flex flex-col gap-2 pointer-events-none">
    {#each toasts as toast (toast.id)}
      <div
        class="vk-slide-in pointer-events-auto px-3 py-2 rounded-lg shadow-lg text-sm text-white max-w-xs cursor-pointer transition-opacity"
        class:bg-green-500={toast.type === 'success'}
        class:bg-red-500={toast.type === 'error'}
        class:bg-yellow-500={toast.type === 'warning'}
        class:bg-blue-500={toast.type === 'info'}
        onclick={() => dismiss(toast)}
      >
        {toast.message}
      </div>
    {/each}
  </div>
{/if}
