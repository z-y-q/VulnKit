<script lang="ts">
  // 面板图标 —— 统一 Lucide 单线图标（经 UnoCSS presetIcons），emoji 作回退。
  // 替代 registry 里彩色 emoji 的「卡通/不一致」观感，向 SF Symbols 的克制一致靠拢（§16 Craft）。
  // Lucide 经 CSS mask 内联，颜色 = currentColor（随父级 text 色变化），尺寸由 class 的 w/h 控制。
  import { panelIconClass } from '@/lib/panels/icons';

  let {
    id,
    fallback,
    class: cls = 'w-4 h-4',
    style,
  }: { id: string; fallback?: string; class?: string; style?: string } = $props();

  let iconClass = $derived(panelIconClass(id));
</script>

{#if iconClass}
  <span class="{iconClass} {cls}" {style} aria-hidden="true"></span>
{:else if fallback}
  <span class={cls} {style} aria-hidden="true">{fallback}</span>
{/if}
