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

<aside class="w-44 shrink-0 border-r border-gray-200 dark:border-gray-700/70 bg-white dark:bg-gray-800 overflow-y-auto">
  {#each Object.entries(categories) as [catId, cat]}
    <div class="border-b border-gray-100 dark:border-gray-700/40">
      <button
        class="w-full flex items-center justify-between px-3 py-2 text-[11px] font-semibold text-gray-400 dark:text-gray-500 uppercase tracking-wider hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
        onclick={() => toggleCat(catId)}
      >
        <span class="flex items-center gap-1.5">
          <span class="w-1.5 h-1.5 rounded-full" style="background: {cat.color}"></span>
          {cat.label}
        </span>
        <svg class="w-3 h-3 transition-transform duration-200 {collapsedCats[catId] ? '' : 'rotate-90'}" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 5l7 7-7 7" />
        </svg>
      </button>
      {#if !collapsedCats[catId]}
        {#each cat.panels as panel}
          <button
            class="group w-full text-left pl-2.5 pr-3 py-1.5 text-sm flex items-center gap-2 transition-all duration-150 relative {activePanel === panel.id
              ? 'bg-blue-50/70 dark:bg-blue-900/25 text-primary font-semibold'
              : 'text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/40'}"
            onclick={() => select(panel.id)}
          >
            {#if activePanel === panel.id}
              <span class="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 rounded-r" style="background: {cat.color}"></span>
            {/if}
            <span class="text-base w-5 text-center transition-transform duration-150 {activePanel === panel.id ? 'scale-110' : 'group-hover:scale-110'}">{panel.icon}</span>
            <span class="truncate">{panel.label}</span>
          </button>
        {/each}
      {/if}
    </div>
  {/each}
</aside>
