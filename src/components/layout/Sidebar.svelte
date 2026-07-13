<script lang="ts">
  import { panels, type PanelConfig } from '@/panels';
  import { sniffBadgeStore } from '@/stores/sniff-badge';
  import { panelLayoutStore, applyLayout } from '@/stores/panel-layout';

  let layout = $derived($panelLayoutStore);
  // 应用用户排序 + 过滤隐藏面板（与 options 页、popup 共用同一逻辑）
  let visiblePanels = $derived(applyLayout(panels, layout));

  interface Props {
    activePanel: string;
    onselect: (id: string) => void;
  }

  let { activePanel, onselect }: Props = $props();

  // 嗅探徽标（storage.session 持久化）— 仅 sniff 面板按钮显示
  let sniffBadge = $derived($sniffBadgeStore);

  // 按分类分组
  let categories = $derived(
    visiblePanels.reduce((acc, panel) => {
      if (!acc[panel.category]) {
        acc[panel.category] = { label: panel.categoryLabel, color: panel.catColor, panels: [] };
      }
      acc[panel.category].panels.push(panel);
      return acc;
    }, {} as Record<string, { label: string; color: string; panels: PanelConfig[] }>)
  );

  // 折叠状态
  let collapsedCats = $state<Record<string, boolean>>({});

  function toggleCat(cat: string) {
    collapsedCats[cat] = !collapsedCats[cat];
  }

  function select(id: string) {
    onselect(id);
  }

  function isCatActive(cat: string): boolean {
    return panels.some(p => p.category === cat && p.id === activePanel);
  }
</script>

<aside class="w-44 shrink-0 bg-gray-50/80 dark:bg-slate-900/60 border-r border-gray-200/50 dark:border-gray-700/30 overflow-y-auto vk-glass">
  {#each Object.entries(categories) as [catId, cat]}
    <div class="border-b border-gray-200/40 dark:border-gray-700/20">
      <!-- 分类标题 -->
      <button
        class="w-full flex items-center justify-between px-3 py-2 text-[10px] font-bold text-gray-400 dark:text-gray-500 uppercase tracking-widest hover:text-gray-600 dark:hover:text-gray-300 transition-colors duration-200"
        onclick={() => toggleCat(catId)}
      >
        <span class="flex items-center gap-1.5">
          <span class="w-1.5 h-1.5 rounded-full shadow-sm" style="background: {cat.color}; box-shadow: 0 0 6px {cat.color}40"></span>
          {cat.label}
        </span>
        <svg class="w-3 h-3 transition-transform duration-200 {collapsedCats[catId] ? '' : 'rotate-90'}" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 5l7 7-7 7" />
        </svg>
      </button>

      <!-- 面板列表 -->
      {#if !collapsedCats[catId]}
        <div class="pb-1 px-1.5 space-y-0.5">
          {#each cat.panels as panel, i}
            {@const shortcutIdx = visiblePanels.findIndex(p => p.id === panel.id) + 1}
            <button
              class="group w-full text-left pl-3 pr-2 py-1.5 text-[13px] flex items-center gap-2 rounded-lg transition-all duration-200 relative {activePanel === panel.id
                ? 'bg-white dark:bg-gray-800/80 text-gray-900 dark:text-gray-100 font-semibold shadow-sm vk-glass'
                : 'text-gray-500 dark:text-gray-400 hover:bg-white/60 dark:hover:bg-gray-800/40 hover:text-gray-700 dark:hover:text-gray-300'}"
              onclick={() => select(panel.id)}
              title={shortcutIdx >= 1 && shortcutIdx <= 8 ? `${panel.label} (Alt+${shortcutIdx})` : panel.label}
            >
              <!-- 激活指示条 -->
              {#if activePanel === panel.id}
                <span class="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-4 rounded-r-full" style="background: {cat.color}; box-shadow: 0 0 8px {cat.color}60"></span>
              {/if}
              <span class="text-[15px] w-6 text-center transition-transform duration-200 {activePanel === panel.id ? 'scale-110' : 'group-hover:scale-110'}">{panel.icon}</span>
              <span class="truncate flex-1">
                {#if shortcutIdx >= 1 && shortcutIdx <= 8}
                  <span class="text-[9px] font-mono mr-1 px-0.5 rounded bg-gray-200/70 dark:bg-gray-700/70 text-gray-400 dark:text-gray-500 group-hover:bg-gray-300 dark:group-hover:bg-gray-600">{shortcutIdx}</span>
                {/if}
                {panel.label}
              </span>
              {#if panel.id === 'sniff' && sniffBadge.items.length > 0}
                <span class="flex gap-0.5 shrink-0" title="最近嗅探: {sniffBadge.items.map(i => i.name + (i.version ? ' v' + i.version : '')).join(', ')}">
                  {#each sniffBadge.items.slice(0, 2) as item}
                    <span class="text-[9px] font-mono px-1 rounded bg-blue-100 text-blue-600 dark:bg-blue-900/50 dark:text-blue-300 leading-tight">
                      {item.name}{#if item.version}{item.version}{/if}
                    </span>
                  {/each}
                </span>
              {/if}
            </button>
          {/each}
        </div>
      {/if}
    </div>
  {/each}
</aside>
