<script lang="ts" module>
  /**
   * 虚拟滚动容器 — 灵眸 v6
   * 只渲染可见区域 + 上下缓冲区的 DOM 节点，支持千行级列表流畅滚动。
   * 泛型 T 为列表项类型，调用方通过 item snippet 渲染单个条目。
   */
  import type { Snippet } from 'svelte';

  interface VirtualRange {
    /** 渲染起始索引（含） */
    start: number;
    /** 渲染结束索引（不含） */
    end: number;
    /** 顶部空白占位高度 */
    offsetY: number;
  }

  /**
   * 计算虚拟滚动可见范围
   * @param scrollTop 容器滚动位置
   * @param containerHeight 容器可见高度
   * @param itemHeight 单项高度
   * @param itemCount 总项数
   * @param overscan 上下缓冲项数（默认 3）
   */
  function calculateRange(
    scrollTop: number,
    containerHeight: number,
    itemHeight: number,
    itemCount: number,
    overscan = 3,
  ): VirtualRange {
    const visibleStart = Math.floor(scrollTop / itemHeight);
    const visibleEnd = Math.ceil((scrollTop + containerHeight) / itemHeight);
    const start = Math.max(0, visibleStart - overscan);
    const end = Math.min(itemCount, visibleEnd + overscan);
    const offsetY = start * itemHeight;
    return { start, end, offsetY };
  }
</script>

<script lang="ts" generics="T">
  let {
    items,
    itemHeight = 40,
    height = '400px',
    overscan = 3,
    item,
    itemKey,
    containerClass = '',
  }: {
    /** 列表项数组 */
    items: readonly T[];
    /** 单项固定高度（px） */
    itemHeight?: number;
    /** 容器高度（CSS 值） */
    height?: string;
    /** 上下缓冲项数（默认 3） */
    overscan?: number;
    /** 渲染单项内容 */
    item: Snippet<[T, number]>;
    /** {#each} key；不传则用索引 */
    itemKey?: (item: T, index: number) => string | number;
    /** 容器额外类名 */
    containerClass?: string;
  } = $props();

  let container: HTMLDivElement | undefined = $state();
  let scrollTop = $state(0);
  let containerHeight = $state(0);

  // 容器高度探测（ResizeObserver）
  $effect(() => {
    if (!container) return;
    let raf = 0;
    const ro = new ResizeObserver((entries) => {
      const h = Math.round(entries[0]?.contentRect.height ?? 0);
      if (raf) cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        containerHeight = h;
        raf = 0;
      });
    });
    ro.observe(container);
    return () => {
      if (raf) cancelAnimationFrame(raf);
      ro.disconnect();
    };
  });

  // 滚动事件节流（requestAnimationFrame）
  let scrollRaf = 0;
  function onScroll(e: Event) {
    if (scrollRaf) return;
    scrollRaf = requestAnimationFrame(() => {
      scrollTop = (e.target as HTMLDivElement).scrollTop;
      scrollRaf = 0;
    });
  }

  const range = $derived(calculateRange(scrollTop, containerHeight, itemHeight, items.length, overscan));
  const visibleItems = $derived(items.slice(range.start, range.end));
  const totalHeight = $derived(items.length * itemHeight);
</script>

<div
  bind:this={container}
  class="overflow-y-auto {containerClass}"
  style="height: {height}; contain: strict;"
  onscroll={onScroll}
  role="list"
>
  <div style="height: {totalHeight}px; position: relative;">
    <div style="transform: translateY({range.offsetY}px); will-change: transform;">
      {#each visibleItems as itm, i (itemKey ? itemKey(itm, range.start + i) : range.start + i)}
        <div style="height: {itemHeight}px;" role="listitem">
          {@render item(itm, range.start + i)}
        </div>
      {/each}
    </div>
  </div>
</div>
