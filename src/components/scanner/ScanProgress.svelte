<script lang="ts">
  // 扫描进度条 — 统一所有扫描面板的进度展示。
  // 增强（对齐 docs/UX-UI优化建议.md §3.4 / §8.3）：
  // - total 未知/为 0 时显示 indeterminate（脉动条），不再显示误导性的 0/0 · 0%；
  // - role="progressbar" + aria-value*，读屏可感知；
  // - 可选阶段(phase)、耗时(elapsedMs)、失败数(failed)。
  let {
    scanned = 0,
    total = 0,
    scanning = false,
    label,
    phase,
    elapsedMs,
    failed = 0,
  }: {
    scanned?: number;
    total?: number;
    scanning?: boolean;
    label?: string;
    phase?: string;
    elapsedMs?: number;
    failed?: number;
  } = $props();

  let determinate = $derived(total > 0);
  let pct = $derived(determinate ? Math.min(100, Math.round((scanned / total) * 100)) : 0);

  function fmtMs(ms: number): string {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    const m = Math.floor(ms / 60000);
    const s = Math.floor((ms % 60000) / 1000);
    return `${m}m${s}s`;
  }
</script>

{#if scanning}
  <div
    class="space-y-1"
    role="progressbar"
    aria-valuemin={0}
    aria-valuemax={determinate ? total : undefined}
    aria-valuenow={determinate ? scanned : undefined}
    aria-label={phase ?? label ?? '扫描进度'}
  >
    <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1 overflow-hidden">
      {#if determinate}
        <div class="bg-primary h-full rounded-full transition-[width] duration-[var(--vk-dur)] ease-[var(--vk-ease)]" style="width:{pct}%"></div>
      {:else}
        <div class="relative h-full w-full">
          <div class="absolute inset-y-0 left-0 w-1/3 rounded-full bg-primary/70" style="animation: vk-progress-slide 1.1s cubic-bezier(0.4, 0, 0.2, 1) infinite;"></div>
        </div>
      {/if}
    </div>
    <div class="text-xs text-gray-500 flex justify-between gap-2">
      <span class="truncate">{phase ?? label ?? '进度'}</span>
      <span class="shrink-0 tabular-nums">
        {#if determinate}{scanned} / {total} · {pct}%{:else}{scanned} 项{/if}
        {#if failed > 0}<span class="text-red-400 dark:text-red-500 ml-1">· 失败 {failed}</span>{/if}
        {#if elapsedMs != null}<span class="ml-1">· {fmtMs(elapsedMs)}</span>{/if}
      </span>
    </div>
  </div>
{/if}
