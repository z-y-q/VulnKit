<script lang="ts">
  // 密钥/口令输入框 — 灵眸 v6（对齐 docs/UX-UI优化建议.md §9.1 form/ 组件族）
  // password 显隐切换 + label/控件 id 关联 + hint。用于 API Key/Token 等敏感配置。
  // bindable value。
  let {
    value = $bindable(''),
    id,
    label = '密钥',
    placeholder = '输入密钥',
    hint = '',
    class: cls = '',
  }: {
    value?: string;
    id?: string;
    label?: string;
    placeholder?: string;
    hint?: string;
    class?: string;
  } = $props();

  const autoId = `secret-${Math.random().toString(36).slice(2, 8)}`;
  const uid = $derived(id ?? autoId);
  let visible = $state(false);
</script>

<div class={`space-y-1 ${cls}`}>
  <label for={uid} class="panel-label">{label}</label>
  <div class="relative">
    <input
      id={uid}
      type={visible ? 'text' : 'password'}
      {placeholder}
      bind:value
      autocomplete="off"
      spellcheck="false"
      class="input w-full text-sm font-mono pr-9"
    />
    <button
      type="button"
      class="absolute right-1.5 top-1/2 -translate-y-1/2 text-xs text-gray-500 hover:text-gray-600 dark:hover:text-gray-300 px-1"
      onclick={() => (visible = !visible)}
      aria-label={visible ? '隐藏密钥' : '显示密钥'}
      aria-pressed={visible}
      title={visible ? '隐藏' : '显示'}
    >
      {visible ? '🙈' : '👁'}
    </button>
  </div>
  {#if hint}<p class="text-xs text-gray-500">{hint}</p>{/if}
</div>
