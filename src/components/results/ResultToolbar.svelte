<script lang="ts" generics="TItem">
  // 结果工具栏
  // 对齐 docs/UX-UI优化建议.md §5.2：统一「发现 N · 显示 M + 搜索 + 自定义筛选 + 清除 + 复制」。
  // query 由面板持有并 $derived(adapter.apply(items, query)) 算 shown；toolbar 只负责
  // 渲染搜索框（bind query.search）、计数、清除、复制，以及 children slot 供面板放
  // 自定义筛选控件与导出按钮。
  import type { Snippet } from 'svelte';
  import { type ResultQuery, hasActiveQuery } from '@/lib/results/result-adapter';

  let {
    query,
    total = 0,
    shown = 0,
    searchPlaceholder = '搜索...',
    children,
    onCopy,
    copyLabel,
  }: {
    query: ResultQuery;
    /** 原始结果总数（「发现 N」） */
    total?: number;
    /** 当前筛选后展示数（「显示 M」），由面板 adapter.apply 计算 */
    shown?: number;
    searchPlaceholder?: string;
    /** 自定义筛选/排序控件 + 导出按钮的插槽 */
    children?: Snippet;
    onCopy?: () => void;
    copyLabel?: string;
  } = $props();

  let active = $derived(hasActiveQuery(query));

  function clear() {
    query.search = '';
    query.filters = {};
    query.sort = { key: '', direction: 'asc' };
  }
</script>

<div class="flex flex-wrap items-center gap-2 text-xs">
  <span class="text-gray-500 dark:text-gray-500 shrink-0">
    发现 <b class="text-gray-700 dark:text-gray-200">{total}</b>
    {#if shown !== total}· 显示 <b class="text-gray-700 dark:text-gray-200">{shown}</b>{/if}
  </span>
  <input
    type="search"
    class="input text-xs flex-1 min-w-[8rem]"
    placeholder={searchPlaceholder}
    bind:value={query.search}
    aria-label="搜索结果"
  />
  {@render children?.()}
  {#if active}
    <button class="btn btn-sm btn-ghost" onclick={clear}>清除筛选</button>
  {/if}
  {#if onCopy}
    <button class="btn btn-sm" onclick={onCopy} disabled={shown === 0}>
      {copyLabel ?? `复制当前 ${shown}`}
    </button>
  {/if}
</div>
