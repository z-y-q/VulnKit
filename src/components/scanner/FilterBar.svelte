<script lang="ts">
  // 筛选/统计徽章组 — 可点击切换的统计徽章 + 右侧插槽（排序/导出）
  import type { Snippet } from 'svelte';

  export interface FilterOption {
    key: string;
    label: string;
    count: number;
    color: string; // 激活态背景类，如 'bg-red-500 text-white'
  }

  let {
    options,
    active,
    onchange,
    children,
  }: {
    options: FilterOption[];
    active: string;
    onchange?: (key: string) => void;
    children?: Snippet;
  } = $props();
</script>

{#if options.length > 0}
  <div class="flex gap-2 text-xs items-center flex-wrap">
    {#each options as opt (opt.key)}
      <button
        class="badge cursor-pointer transition-all duration-[var(--vk-dur-fast)] ease-[var(--vk-ease)] active:scale-[0.96] {active === opt.key ? opt.color : 'bg-gray-200 dark:bg-gray-700'}"
        onclick={() => onchange?.(opt.key)}
      >
        {opt.label} {opt.count}
      </button>
    {/each}
    {#if children}
      <div class="ml-auto flex items-center gap-2">
        {@render children()}
      </div>
    {/if}
  </div>
{/if}
