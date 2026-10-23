<script lang="ts">
  // Sidebar — 工具导航（对齐 docs/UX-UI优化建议.md §4.1）
  // 搜索 / 最近 / 收藏 / 分类（折叠持久化）/ iconMode 图标栏。
  // 行点击区与收藏星标分离（不嵌套 button，§6.2/§8）；当前项 aria-current；
  // 折叠分类 aria-expanded+aria-controls；icon-only 按钮均带 aria-label。
  // §7.1：hover 时预加载面板 chunk，空闲时预加载高频面板。
  import { panels, type PanelConfig } from '@/panels';
  import { panelMatches } from '@/panels/registry';
  import { preloadPanels } from '@/panels/loaders';
  import SearchField from '@/components/form/SearchField.svelte';
  import PanelIcon from '@/components/ui/PanelIcon.svelte';
  import { sniffBadgeStore } from '@/stores/sniff-badge';
  import { panelLayoutStore, applyLayout } from '@/stores/panel-layout';
  import { sidebarStateStore } from '@/stores/sidebar-state';
  import { recentPanelsStore } from '@/stores/recent-panels';
  import { favoritePanelsStore } from '@/stores/favorite-panels';

  interface Props {
    activePanel: string;
    onselect: (id: string) => void;
    /** 窄宽图标栏模式（由 side-panel ResizeObserver 驱动 + 用户手动覆盖） */
    iconMode?: boolean;
    onToggleIconMode?: () => void;
  }

  let { activePanel, onselect, iconMode = false, onToggleIconMode }: Props = $props();

  let layout = $derived($panelLayoutStore);
  let visiblePanels = $derived(applyLayout(panels, layout));
  let visibleIds = $derived(new Set(visiblePanels.map((p) => p.id)));
  let collapsedCats = $derived($sidebarStateStore.collapsedCats);
  let recent = $derived($recentPanelsStore);
  let favorites = $derived($favoritePanelsStore);
  let sniffBadge = $derived($sniffBadgeStore);

  // —— 搜索 ——
  let query = $state('');
  let q = $derived(query.trim().toLowerCase());
  let searchInput: HTMLInputElement | undefined = $state();

  let searchResults = $derived(
    q ? visiblePanels.filter((p) => panelMatches(p, q)) : [],
  );

  function isFav(id: string): boolean {
    return favorites.includes(id);
  }

  // 最近 / 收藏区：仅显示「当前可见」面板，避免指向已隐藏面板
  let recentVisible = $derived(recent.filter((id) => visibleIds.has(id)).slice(0, 6));
  let favoriteVisible = $derived(favorites.filter((id) => visibleIds.has(id)));

  function panelById(id: string): PanelConfig | undefined {
    return visiblePanels.find((p) => p.id === id);
  }

  // 按分类分组
  let categories = $derived(
    visiblePanels.reduce(
      (acc, panel) => {
        if (!acc[panel.category]) {
          acc[panel.category] = { label: panel.categoryLabel, color: panel.catColor, panels: [] };
        }
        acc[panel.category].panels.push(panel);
        return acc;
      },
      {} as Record<string, { label: string; color: string; panels: PanelConfig[] }>,
    ),
  );

  // ⌘K / Ctrl+K 聚焦搜索
  $effect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInput?.focus();
        searchInput?.select();
      }
    };
      window.addEventListener('keydown', handler);
      return () => window.removeEventListener('keydown', handler);
  });

  function shortcutIdx(panel: PanelConfig): number {
    return visiblePanels.findIndex((p) => p.id === panel.id) + 1;
  }

  async function toggleFav(id: string, e: Event) {
    e.stopPropagation();
    await favoritePanelsStore.toggle(id);
  }

  function select(id: string) {
    onselect(id);
  }

  // §7.1：hover 预加载面板 chunk（防抖 150ms，避免快速划过时浪费）
  let preloadTimer: ReturnType<typeof setTimeout> | undefined;
  function onPanelHover(id: string) {
    if (preloadTimer) clearTimeout(preloadTimer);
    preloadTimer = setTimeout(() => { preloadPanels([id]); }, 150);
  }
  function onPanelLeave() {
    if (preloadTimer) { clearTimeout(preloadTimer); preloadTimer = undefined; }
  }

  // 空闲时预加载高频面板（最近使用 + 收藏）
  $effect(() => {
    const idleId = requestIdleCallback(() => {
      const highFreq = [...new Set([...recent.slice(0, 3), ...favorites.slice(0, 3)])];
      preloadPanels(highFreq);
    }, { timeout: 3000 });
    return () => cancelIdleCallback(idleId);
  });

  // §11.2：combobox 键盘导航（方向键移动高亮、Enter 选中；Escape 清空由 SearchField 处理）
  let activeIdx = $state(-1);
  $effect(() => { void searchResults.length; activeIdx = -1; });
  function searchKeydown(e: KeyboardEvent) {
    if (!searchResults.length) return;
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      activeIdx = (activeIdx + 1) % searchResults.length;
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      activeIdx = (activeIdx - 1 + searchResults.length) % searchResults.length;
    } else if (e.key === 'Enter' && activeIdx >= 0) {
      e.preventDefault();
      select(searchResults[activeIdx].id);
    }
  }
</script>

<aside
  class="shrink-0 bg-gray-50/80 dark:bg-slate-900/60 border-r border-gray-200/50 dark:border-gray-700/30 vk-glass flex flex-col {iconMode
    ? 'w-12'
    : 'w-44'} transition-[width] duration-200 ease-[var(--vk-ease)]"
  aria-label="工具导航"
>
  {#if iconMode}
    <!-- ====== 图标栏模式（窄宽） ====== -->
    <div class="overflow-y-auto flex-1 py-1.5 px-1 space-y-0.5">
      {#each visiblePanels as panel (panel.id)}
        <button
          type="button"
          class="w-full h-9 flex items-center justify-center rounded-lg text-base transition-all duration-200 {activePanel ===
          panel.id
            ? 'bg-white dark:bg-gray-800/80 shadow-sm'
            : 'hover:bg-white/60 dark:hover:bg-gray-800/40'}"
          aria-label={panel.label}
          aria-current={activePanel === panel.id ? 'page' : undefined}
          title={panel.label}
          onclick={() => select(panel.id)}
        >
          <PanelIcon id={panel.id} fallback={panel.icon} class="w-5 h-5" />
          {#if isFav(panel.id)}
            <span class="absolute text-[7px] text-amber-400 ml-3 -mt-3">●</span>
          {/if}
        </button>
      {/each}
    </div>
    {#if onToggleIconMode}
      <button
        type="button"
        class="shrink-0 h-9 flex items-center justify-center border-t border-gray-200/50 dark:border-gray-700/30 text-gray-500 hover:text-gray-600 dark:hover:text-gray-200 hover:bg-gray-100/60 dark:hover:bg-gray-800/40"
        aria-label="展开侧栏"
        title="展开侧栏"
        onclick={onToggleIconMode}
      >
        <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M13 5l7 7-7 7M5 5l7 7-7 7" /></svg>
      </button>
    {/if}
  {:else}
    <!-- ====== 完整模式 ====== -->
    <!-- 搜索框 -->
    <div class="shrink-0 p-2 border-b border-gray-200/40 dark:border-gray-700/20">
      <SearchField
        bind:value={query}
        bind:inputEl={searchInput}
        id="sb-search"
        label="搜索工具"
        placeholder="搜索工具 ⌘K"
        role="combobox"
        aria-expanded={searchResults.length > 0}
        aria-controls="sb-results"
        aria-autocomplete="list"
        aria-activedescendant={activeIdx >= 0 && searchResults[activeIdx] ? `sb-opt-${searchResults[activeIdx].id}` : undefined}
        onkeydown={searchKeydown}
      />
    </div>

    <div id="sb-results" class="overflow-y-auto flex-1">
      {#if q}
        <!-- 搜索结果（扁平） -->
        {#if searchResults.length}
          <div class="p-1.5 space-y-0.5" role="listbox" aria-label="搜索结果">
            <div class="px-2 py-1 text-[10px] text-gray-500 dark:text-gray-500">匹配 {searchResults.length} 个工具</div>
            {#each searchResults as panel, i (panel.id)}
              {@render panelRow(panel, false, i)}
            {/each}
          </div>
        {:else}
          <div class="px-4 py-8 text-center text-xs text-gray-500 dark:text-gray-500">
            <div class="text-2xl mb-2" aria-hidden="true">🔍</div>
            未找到匹配「{query}」的工具
          </div>
        {/if}
      {:else}
        <!-- 最近使用 -->
        {#if recentVisible.length}
          <div class="border-b border-gray-200/40 dark:border-gray-700/20">
            <div class="px-3 pt-2 pb-1 text-[11px] font-semibold text-gray-500 dark:text-gray-400">最近</div>
            <div class="pb-1 px-1.5 space-y-0.5">
              {#each recentVisible as id (id)}
                {@const panel = panelById(id)}
                {#if panel}{@render panelRow(panel, false)}{/if}
              {/each}
            </div>
          </div>
        {/if}

        <!-- 收藏 -->
        {#if favoriteVisible.length}
          <div class="border-b border-gray-200/40 dark:border-gray-700/20">
            <div class="px-3 pt-2 pb-1 text-[11px] font-semibold text-gray-500 dark:text-gray-400 flex items-center gap-1">
              <svg class="w-2.5 h-2.5 text-amber-400" fill="currentColor" viewBox="0 0 24 24"><path d="M12 17.27L18.18 21l-1.64-7.03L22 9.24l-7.19-.61L12 2 9.19 8.63 2 9.24l5.46 4.73L5.82 21z" /></svg>
              收藏
            </div>
            <div class="pb-1 px-1.5 space-y-0.5">
              {#each favoriteVisible as id (id)}
                {@const panel = panelById(id)}
                {#if panel}{@render panelRow(panel, false)}{/if}
              {/each}
            </div>
          </div>
        {/if}

        <!-- 分类列表 -->
        {#each Object.entries(categories) as [catId, cat] (catId)}
          <div class="border-b border-gray-200/40 dark:border-gray-700/20">
            <button
              type="button"
              class="w-full flex items-center justify-between px-3 py-2 text-[11px] font-semibold text-gray-500 dark:text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors duration-200"
              aria-expanded={!collapsedCats[catId]}
              aria-controls="sb-cat-{catId}"
              onclick={() => sidebarStateStore.toggleCat(catId)}
            >
              <span>{cat.label} <span class="font-normal opacity-50">({cat.panels.length})</span></span>
              <svg class="w-3 h-3 transition-transform duration-200 {collapsedCats[catId] ? '' : 'rotate-90'}" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 5l7 7-7 7" /></svg>
            </button>
            {#if !collapsedCats[catId]}
              <div id="sb-cat-{catId}" class="pb-1.5 px-1.5 space-y-1">
                {#each cat.panels as panel (panel.id)}
                  {@render panelRow(panel, true)}
                {/each}
              </div>
            {/if}
          </div>
        {/each}
      {/if}
    </div>

    {#if onToggleIconMode}
      <button
        type="button"
        class="shrink-0 flex items-center justify-center gap-1.5 py-1.5 border-t border-gray-200/50 dark:border-gray-700/30 text-[10px] text-gray-500 hover:text-gray-600 dark:hover:text-gray-200 hover:bg-gray-100/60 dark:hover:bg-gray-800/40 transition-colors"
        aria-label="折叠侧栏为图标栏"
        title="折叠侧栏"
        onclick={onToggleIconMode}
      >
        <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M11 19l-7-7 7-7M19 19l-7-7 7-7" /></svg>
        折叠
      </button>
    {/if}
  {/if}
</aside>

{#snippet panelRow(panel: PanelConfig, withShortcut: boolean, optionIdx: number = -1)}
  {@const idx = withShortcut ? shortcutIdx(panel) : 0}
  <div
    class="group relative flex items-center rounded-lg transition-colors duration-200 {activePanel === panel.id
      ? 'bg-gray-100/80 dark:bg-gray-800/60'
      : 'hover:bg-gray-100/60 dark:hover:bg-gray-800/40'}{optionIdx >= 0 && optionIdx === activeIdx ? ' ring-2 ring-blue-400/50 bg-blue-50 dark:bg-blue-900/20' : ''}"
    role={optionIdx >= 0 ? 'option' : undefined}
    id={optionIdx >= 0 ? `sb-opt-${panel.id}` : undefined}
    aria-selected={optionIdx >= 0 ? optionIdx === activeIdx : undefined}
  >
    {#if activePanel === panel.id}
      <span class="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-4 rounded-r-full" style="background: {panel.catColor}"></span>
    {/if}
    <!-- 主点击区（切换面板） -->
    <button
      type="button"
      class="flex-1 min-w-0 flex items-center gap-2 pl-3 pr-6 py-1.5 text-[13px] text-left {activePanel === panel.id
        ? 'text-gray-900 dark:text-gray-100 font-semibold'
        : 'text-gray-500 dark:text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'}"
      aria-current={activePanel === panel.id ? 'page' : undefined}
      title={idx >= 1 && idx <= 8 ? `{panel.label} (Alt+${idx})` : panel.label}
      onclick={() => select(panel.id)}
      onmouseenter={() => onPanelHover(panel.id)}
      onmouseleave={onPanelLeave}
    >
      <PanelIcon id={panel.id} fallback={panel.icon} class="w-[18px] h-[18px] shrink-0 transition-transform duration-200 {activePanel === panel.id ? 'scale-110' : 'group-hover:scale-110'}" />
      <span class="truncate flex-1">
        {panel.label}
      </span>
    </button>
    {#if panel.id === 'sniff' && sniffBadge.items.length > 0}
      <span class="shrink-0 flex gap-0.5 mr-1" title="最近嗅探: {sniffBadge.items.map((i) => i.name + (i.version ? ' v' + i.version : '')).join(', ')}">
        {#each sniffBadge.items.slice(0, 2) as item}
          <span class="text-[9px] font-mono px-1 rounded bg-blue-100 text-blue-600 dark:bg-blue-900/50 dark:text-blue-300 leading-tight">{item.name}{#if item.version}{item.version}{/if}</span>
        {/each}
      </span>
    {/if}
    <!-- 收藏：仅悬停浮现；已收藏项已在顶部「收藏」区聚合，行内不留常驻星标（展开态不再满屏星） -->
    <button
      type="button"
      class="absolute right-1 top-1/2 -translate-y-1/2 p-1 rounded opacity-0 group-hover:opacity-100 focus-visible:opacity-100 transition-colors {isFav(panel.id) ? 'text-amber-400 hover:text-amber-500' : 'text-gray-500 dark:text-gray-400 hover:text-amber-400'}"
      aria-pressed={isFav(panel.id)}
      aria-label={isFav(panel.id) ? `取消收藏 ${panel.label}` : `收藏 ${panel.label}`}
      title={isFav(panel.id) ? '取消收藏' : '收藏'}
      onclick={(e) => toggleFav(panel.id, e)}
    >
      <svg class="w-3 h-3" viewBox="0 0 24 24" fill={isFav(panel.id) ? 'currentColor' : 'none'} stroke="currentColor" stroke-width="2" stroke-linejoin="round" aria-hidden="true"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" /></svg>
    </button>
  </div>
{/snippet}
