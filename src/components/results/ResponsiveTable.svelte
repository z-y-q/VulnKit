<script lang="ts" module>
  // 响应式表格 — 灵眸 v6（对齐 docs/UX-UI优化建议.md §7.4 / §14.3）
  // 宽屏：完整表格（sticky thead + min-width + 按列 hideUnder 隐藏次要列）。
  // 窄屏（< cardBreakpoint，默认 480px）：卡片列表，primary 列做标题，其余键值对。
  // 宽度由 ResizeObserver 探测（复用 Sidebar iconMode 模式）。
  // 单元格内容由调用方经 cell 片段提供，保留每列自定义格式（badge/truncate/mono）。
  // 泛型 T 为行类型，调用方 cell 片段直接拿到强类型 row，无需 cast。
  import type { Snippet } from 'svelte';
  export type { Col } from './responsive-table-utils';
  import { visibleColumns, pickPrimary, cardColumns, shouldUseCardMode, type Col } from './responsive-table-utils';
</script>

<script lang="ts" generics="T">
  let {
    cols,
    rows,
    cell,
    cardLabel,
    cardBreakpoint = 480,
    scrollClass = 'max-h-72 overflow-y-auto',
    tableClass = 'w-full text-xs',
    cardClass = 'space-y-1.5',
    rowKey,
  }: {
    cols: Col[];
    rows: T[];
    /** 渲染单元格内容（表格 td 与卡片值共用），按 col.key 分支即可 */
    cell: Snippet<[Col, T]>;
    /** 卡片标题；不传则取 primary 列原始值 */
    cardLabel?: (row: T) => string;
    cardBreakpoint?: number;
    /** 表格滚动容器类名（含高度/纵向滚动） */
    scrollClass?: string;
    tableClass?: string;
    cardClass?: string;
    /** {#each} key；不传则用索引 */
    rowKey?: (row: T, i: number) => string | number;
  } = $props();

  let el: HTMLDivElement | undefined = $state();
  let width = $state(1024);

  $effect(() => {
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      for (const e of entries) width = Math.round(e.contentRect.width);
    });
    ro.observe(el);
    return () => ro.disconnect();
  });

  const isCard = $derived(shouldUseCardMode(width, cardBreakpoint));
  const visibleCols = $derived(visibleColumns(cols, width));
  const primary = $derived(pickPrimary(cols));
  const cardCols = $derived(cardColumns(cols, primary));
  const minPx = $derived(Math.max(visibleCols.length * 96, 300));

  function fallbackTitle(row: T): string {
    if (!primary) return '';
    return String((row as Record<string, unknown>)[primary.key] ?? '');
  }
</script>

<div bind:this={el} class="w-full">
  {#if isCard}
    <div class={cardClass}>
      {#each rows as row, i (rowKey ? rowKey(row, i) : i)}
        <div class="card p-2.5 text-xs space-y-1">
          <div class="font-semibold text-gray-700 dark:text-gray-200 break-all">
            {cardLabel ? cardLabel(row) : fallbackTitle(row)}
          </div>
          {#each cardCols as col (col.key)}
            <div class="flex justify-between gap-2">
              <span class="text-gray-400 shrink-0">{col.header}</span>
              <span class="text-right truncate min-w-0">{@render cell(col, row)}</span>
            </div>
          {/each}
        </div>
      {/each}
    </div>
  {:else}
    <div class="overflow-x-auto {scrollClass}">
      <table class={tableClass} style="min-width: {minPx}px; table-layout: auto;">
        <thead class="sticky top-0 bg-white dark:bg-gray-800 z-10">
          <tr class="border-b border-gray-200 dark:border-gray-700">
            {#each visibleCols as col (col.key)}
              <th class="text-left px-3 py-1.5 font-medium text-gray-500 whitespace-nowrap">{col.header}</th>
            {/each}
          </tr>
        </thead>
        <tbody>
          {#each rows as row, i (rowKey ? rowKey(row, i) : i)}
            <tr class="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/50">
              {#each visibleCols as col (col.key)}
                <td class="px-3 py-1.5 align-top">{@render cell(col, row)}</td>
              {/each}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>
