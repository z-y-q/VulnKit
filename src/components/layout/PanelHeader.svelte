<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    title: string;
    icon: string;
    category?: string;
    categoryLabel?: string;
    catColor?: string;
    actions?: Snippet;
  }

  let { title, icon, category, categoryLabel, catColor = '#4A90E2', actions }: Props = $props();
</script>

<div class="flex items-center justify-between px-3 py-2 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700/70 shrink-0">
  <div class="flex items-center gap-2 min-w-0">
    <span class="text-lg shrink-0">{icon}</span>
    <h2 class="text-sm font-semibold text-gray-800 dark:text-gray-100 truncate">{title}</h2>
    {#if category}
      <span class="badge text-[10px] shrink-0" style="background: {catColor}1a; color: {catColor}">{categoryLabel || category}</span>
    {/if}
  </div>
  {#if actions}
    {@render actions()}
  {/if}
</div>
