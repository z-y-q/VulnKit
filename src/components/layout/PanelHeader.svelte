<script lang="ts">
  interface Props {
    title: string;
    icon: string;
    category?: string;
    categoryLabel?: string;
    catColor?: string;
  }

  let { title, icon, category, categoryLabel, catColor = '#4A90E2' }: Props = $props();
</script>

<div class="flex items-center justify-between px-3 py-2 bg-gray-50 dark:bg-gray-800/50 border-b border-gray-100 dark:border-gray-700 shrink-0">
  <div class="flex items-center gap-2">
    <span class="text-lg">{icon}</span>
    <h2 class="text-sm font-semibold">{title}</h2>
    {#if category}
      <span class="badge-info" style="background: {catColor}20; color: {catColor}">{categoryLabel || category}</span>
    {/if}
  </div>
  <!-- Actions slot -->
  <slot name="actions" />
</div>
