<script lang="ts">
  // 空状态 — 扫描前/无结果的统一占位
  let {
    message,
    hint = '',
    icon = '',
  }: { message: string; hint?: string; icon?: string } = $props();
</script>

<div class="text-center text-gray-400 py-10">
  {#if icon}
    <div class="text-4xl mb-2">{icon}</div>
  {/if}
  <div class="text-sm">{message}</div>
  {#if hint}
    <div class="text-xs mt-1 text-gray-400 dark:text-gray-500">{hint}</div>
  {/if}
</div>
