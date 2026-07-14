<script lang="ts">
  // 搜索输入框 — 灵眸 v6（对齐 docs/UX-UI优化建议.md §9.1 form/ 组件族）
  // 带搜索图标 + Esc 清空 + label（sr-only 默认）。其余 a11y 属性（aria-expanded /
  // aria-controls / role 等）通过 ...rest 透传到 input，适配 combobox 语义。
  // bindable value；向后兼容：未传 label 时用 sr-only 占位，不破坏现有调用。
  import type { HTMLInputAttributes } from 'svelte/elements';

  let {
    value = $bindable(''),
    id,
    placeholder = '搜索…',
    label = '搜索',
    srOnlyLabel = true,
    class: cls = '',
    inputEl = $bindable(),
    onkeydown,
    ...rest
  }: HTMLInputAttributes & {
    value?: string;
    id?: string;
    placeholder?: string;
    label?: string;
    /** label 是否仅屏幕阅读器可见（默认 true，紧凑搜索框） */
    srOnlyLabel?: boolean;
    class?: string;
    /** 可绑定到内部 input，供调用方 focus（如 ⌘K 聚焦） */
    inputEl?: HTMLInputElement;
    onkeydown?: (e: KeyboardEvent) => void;
  } = $props();

  const autoId = `sf-${Math.random().toString(36).slice(2, 8)}`;
  const uid = $derived(id ?? autoId);

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape' && value) {
      e.preventDefault();
      value = '';
    }
    onkeydown?.(e);
  }
</script>

<div class={`relative ${cls}`}>
  <svg
    class="w-3.5 h-3.5 absolute left-2 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none"
    fill="none"
    viewBox="0 0 24 24"
    stroke="currentColor"
    aria-hidden="true"
  >
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
  </svg>
  <label for={uid} class={srOnlyLabel ? 'sr-only' : 'panel-label'}>{label}</label>
  <input
    id={uid}
    bind:this={inputEl}
    type="search"
    {placeholder}
    bind:value
    onkeydown={handleKeydown}
    autocomplete="off"
    spellcheck="false"
    class="w-full pl-7 pr-2 py-1.5 text-xs rounded-lg bg-white/80 dark:bg-gray-800/60 border border-gray-200/60 dark:border-gray-700/50 text-gray-700 dark:text-gray-200 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500/30 focus:border-blue-400 transition-all"
    {...rest}
  />
</div>
