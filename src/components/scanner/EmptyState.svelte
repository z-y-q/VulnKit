<script lang="ts">
  // 空状态 — 扫描前/无结果的统一占位
  let {
    message,
    hint = '',
    icon = '',
  }: { message: string; hint?: string; icon?: string } = $props();
</script>

<div class="text-center text-gray-500 py-10">
  {#if icon}
    <div class="inline-flex items-center justify-center w-14 h-14 mb-2 rounded-full bg-gray-100 dark:bg-gray-800 text-3xl">{icon}</div>
  {/if}
  <div class="text-sm">{message}</div>
  {#if hint}
    <div class="text-xs mt-1 text-gray-500 dark:text-gray-500">{hint}</div>
  {/if}
</div>
