<script lang="ts">
  // 面板加载态 — 对齐 docs/UX-UI优化建议.md §3.3。
  // 保留在面板主内容区，显示工具名 + skeleton，role="status" 让读屏感知「加载中」。
  let { label, icon = '' }: { label: string; icon?: string } = $props();
</script>

<div class="flex flex-col items-center justify-center py-12 text-gray-500" role="status" aria-live="polite">
  {#if icon}
    <div class="text-3xl mb-3 animate-pulse" aria-hidden="true">{icon}</div>
  {/if}
  <div class="text-sm">正在加载「{label}」…</div>
  <div class="mt-3 w-44 space-y-1.5" aria-hidden="true">
    <div class="h-2 rounded bg-gray-200 dark:bg-gray-700 animate-pulse"></div>
    <div class="h-2 rounded bg-gray-200 dark:bg-gray-700 animate-pulse w-4/5"></div>
    <div class="h-2 rounded bg-gray-200 dark:bg-gray-700 animate-pulse w-3/5"></div>
  </div>
</div>
