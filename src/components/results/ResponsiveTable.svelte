<script lang="ts" module>
  // 响应式表格 — 灵眸 v6（对齐 docs/UX-UI优化建议.md §7.4 / §14.3）
  // 宽屏：完整表格（sticky thead + min-width + 按列 hideUnder 隐藏次要列）。
  // 窄屏（< cardBreakpoint，默认 480px）：卡片列表，primary 列做标题，其余键值对。
  // 宽度由 ResizeObserver 探测（复用 Sidebar iconMode 模式）。
  // 单元格内容由调用方经 cell 片段提供，保留每列自定义格式（badge/truncate/mono）。
  // 泛型 T 为行类型，调用方 cell 片段直接拿到强类型 row，无需 cast。
  import type { Snippet } from 'svelte';
  export type { Col } from './responsive-table-utils';
  import { visibleColumns, pickPrimary, cardColumns, shouldUseCardMode, paginate, type Col } from './responsive-table-utils';
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
    pagination = false,
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
    /** 启用分页（§4.1）；传对象可定制 pageSizeOptions，不传则全渲染（向后兼容） */
    pagination?: boolean | { pageSizeOptions?: number[] };
  } = $props();

  let el: HTMLDivElement | undefined = $state();
  let width = $state(1024);

  // §4.2：宽度去重 + rAF 合并，拖动侧栏时每帧最多一次状态更新
  $effect(() => {
    if (!el) return;
    let raf = 0;
    let lastW = -1;
    const ro = new ResizeObserver((entries) => {
      const w = Math.round(entries[0]?.contentRect.width ?? 0);
      if (w === lastW) return;
      lastW = w;
      if (raf) cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => { width = w; raf = 0; });
    });
    ro.observe(el);
    return () => { if (raf) cancelAnimationFrame(raf); ro.disconnect(); };
  });

  const isCard = $derived(shouldUseCardMode(width, cardBreakpoint));
  const visibleCols = $derived(visibleColumns(cols, width));
  const primary = $derived(pickPrimary(cols));
  const cardCols = $derived(cardColumns(cols, primary));
  const minPx = $derived(Math.max(visibleCols.length * 96, 300));

  // §4.1：分页状态
  const pageSizeOpts = $derived(
    typeof pagination === 'object' && pagination.pageSizeOptions ? pagination.pageSizeOptions : [50, 100, 200],
  );
  let pageSize = $state(50);
  let page = $state(1);
  // rows 变化（搜索/排序/刷新）时回到第一页
  $effect(() => { void rows.length; page = 1; });
  const pagi = $derived(pagination ? paginate(rows.length, page, pageSize) : null);
  const visibleRows = $derived(pagi ? rows.slice(pagi.start, pagi.end) : rows);

  function fallbackTitle(row: T): string {
    if (!primary) return '';
    return String((row as Record<string, unknown>)[primary.key] ?? '');
  }

  // §11.3：分页状态摘要（辅助技术可读）
  const paginationLabel = $derived(
    pagi ? `第 ${pagi.start + 1} 至 ${pagi.end} 条，共 ${rows.length} 条` : `共 ${rows.length} 条`
  );
</script>

<div bind:this={el} class="w-full">
  {#if isCard}
    <div class={cardClass}>
      {#each visibleRows as row, i (rowKey ? rowKey(row, i) : i)}
        <div class="card p-2.5 text-xs space-y-1">
          <div class="font-semibold text-gray-700 dark:text-gray-200 break-all">
            {cardLabel ? cardLabel(row) : fallbackTitle(row)}
          </div>
          {#each cardCols as col (col.key)}
            <div class="flex justify-between gap-2">
              <span class="text-gray-500 shrink-0">{col.header}</span>
              <span class="text-right truncate min-w-0">{@render cell(col, row)}</span>
            </div>
          {/each}
        </div>
      {/each}
    </div>
  {:else}
    <div class="overflow-x-auto {scrollClass}" role="region" aria-label="表格内容（可横向滚动）" tabindex="0">
      <table class={tableClass} style="min-width: {minPx}px; table-layout: auto;" aria-label={paginationLabel}>
        <thead class="sticky top-0 bg-white/85 dark:bg-gray-800/85 backdrop-blur-md z-10 shadow-[var(--vk-shadow-sm)]">
          <tr class="border-b border-gray-200 dark:border-gray-700">
            {#each visibleCols as col (col.key)}
              <th class="text-left px-3 py-1.5 font-medium text-gray-500 whitespace-nowrap">{col.header}</th>
            {/each}
          </tr>
        </thead>
        <tbody>
          {#each visibleRows as row, i (rowKey ? rowKey(row, i) : i)}
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
  {#if pagi && pagi.totalPages > 1}
    <nav class="flex items-center justify-between gap-2 mt-2 text-xs text-gray-500 dark:text-gray-500" aria-label="表格分页">
      <span aria-live="polite">共 {rows.length} 条，第 {pagi.start + 1}-{pagi.end} 条</span>
      <div class="flex items-center gap-1">
        <select class="input !py-0.5 !text-xs" aria-label="每页条数" bind:value={pageSize} onchange={() => { page = 1; }}>
          {#each pageSizeOpts as ps}
            <option value={ps}>{ps} / 页</option>
          {/each}
        </select>
        <button type="button" class="btn btn-xs" disabled={pagi.safePage <= 1} onclick={() => (page = pagi!.safePage - 1)} aria-label="上一页">上一页</button>
        <span aria-current="page" aria-label="当前页">{pagi.safePage} / {pagi.totalPages}</span>
        <button type="button" class="btn btn-xs" disabled={pagi.safePage >= pagi.totalPages} onclick={() => (page = pagi!.safePage + 1)} aria-label="下一页">下一页</button>
      </div>
    </nav>
  {/if}
</div>
