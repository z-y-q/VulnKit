<script lang="ts">
  import { panels, type PanelConfig } from '@/panels';

  interface Props {
    activePanel: string;
    onselect: (id: string) => void;
  }

  let { activePanel, onselect }: Props = $props();

  // 按分类分组
  let categories = $derived(
    panels.reduce((acc, panel) => {
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

<aside class="w-44 shrink-0 border-r border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 overflow-y-auto">
  {#each Object.entries(categories) as [catId, cat]}
    <div class="border-b border-gray-100 dark:border-gray-700/50">
      <button
        class="w-full flex items-center justify-between px-3 py-2 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
        onclick={() => toggleCat(catId)}
      >
        <span class="flex items-center gap-1.5">
          <span class="w-1.5 h-1.5 rounded-full" style="background: {cat.color}"></span>
          {cat.label}
        </span>
        <svg class="w-3 h-3 transition-transform {collapsedCats[catId] ? '' : 'rotate-90'}" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
        </svg>
      </button>
      {#if !collapsedCats[catId]}
        {#each cat.panels as panel}
          <button
            class="w-full text-left px-3 py-1.5 text-sm flex items-center gap-2 transition-colors {activePanel === panel.id
              ? 'bg-blue-50 dark:bg-blue-900/30 text-primary font-medium'
              : 'text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/50'}"
            onclick={() => select(panel.id)}
          >
            <span class="text-base">{panel.icon}</span>
            <span class="truncate">{panel.label}</span>
          </button>
        {/each}
      {/if}
    </div>
  {/each}
</aside>
