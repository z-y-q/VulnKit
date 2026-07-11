<script lang="ts">
  // 扫描进度条 — 统一所有扫描面板的进度展示
  let {
    scanned = 0,
    total = 0,
    scanning = false,
    label,
  }: { scanned?: number; total?: number; scanning?: boolean; label?: string } = $props();

  let pct = $derived(total > 0 ? Math.round((scanned / total) * 100) : 0);
</script>

{#if scanning}
  <div class="space-y-1">
    <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5 overflow-hidden">
      <div class="bg-primary h-full transition-all duration-150" style="width:{pct}%"></div>
    </div>
    <div class="text-xs text-gray-400 flex justify-between">
      <span>{label ?? '进度'}</span>
      <span>{scanned} / {total}{#if total > 0} · {pct}%{/if}</span>
    </div>
  </div>
{/if}
