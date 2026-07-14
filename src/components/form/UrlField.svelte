<script lang="ts">
  // URL 输入框 — 灵眸 v6（对齐 docs/UX-UI优化建议.md §9.1 form/ 组件族）
  // 组合 Field：label/控件关联由 Field 保证。可选 onValidate 即时校验（错误经
  // aria-describedby 关联）。用于非扫描型 URL 字段（如 Options 远程 URL）；
  // 扫描型（带扫描按钮 + recent-targets）仍用 UrlInput。
  import Field from './Field.svelte';

  let {
    value = $bindable(''),
    label = '目标 URL',
    placeholder = 'https://...',
    id,
    hint = '',
    required = false,
    onValidate,
    class: cls = '',
  }: {
    value?: string;
    label?: string;
    placeholder?: string;
    id?: string;
    hint?: string;
    required?: boolean;
    onValidate?: (v: string) => string | null;
    class?: string;
  } = $props();

  let error = $derived(onValidate && value ? onValidate(value) : null);
</script>

<div class={cls}>
  <Field {label} {id} {hint} error={error ?? ''} {required}>
    {#snippet children({ id: fid, describedBy })}
      <input
        id={fid}
        type="url"
        {placeholder}
        bind:value
        aria-invalid={error ? 'true' : undefined}
        aria-describedby={describedBy}
        autocomplete="off"
        spellcheck="false"
        class="input w-full text-sm font-mono"
      />
    {/snippet}
  </Field>
</div>
