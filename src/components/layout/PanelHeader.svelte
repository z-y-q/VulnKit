<script lang="ts">
  import type { Snippet } from 'svelte';
  import PanelIcon from '@/components/ui/PanelIcon.svelte';

  interface Props {
    title: string;
    icon: string;
    id?: string;
    category?: string;
    categoryLabel?: string;
    catColor?: string;
    actions?: Snippet;
  }

  let { title, icon, id, category, categoryLabel, catColor = '#4A90E2', actions }: Props = $props();
</script>

<div class="flex items-center justify-between px-4 py-2.5 bg-white/80 dark:bg-gray-800/60 border-b border-gray-200/50 dark:border-gray-700/30 shrink-0 vk-glass">
  <div class="flex items-center gap-2.5 min-w-0">
    <PanelIcon id={id ?? ''} fallback={icon} class="w-5 h-5 shrink-0" />
    <h2 class="text-sm font-bold text-gray-800 dark:text-gray-100 truncate vk-text-display">{title}</h2>
    {#if category}
      <span
        class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold shrink-0"
        style="background: {catColor}18; color: {catColor}"
      >
        {categoryLabel || category}
      </span>
    {/if}
  </div>
  {#if actions}
    {@render actions()}
  {/if}
</div>
