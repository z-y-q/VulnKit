<script lang="ts" module>
  // 表单字段基础组件 — 灵眸 v6（对齐 docs/UX-UI优化建议.md §9.1 form/ 组件族）
  // 结构性保证 label 与控件关联：把生成的稳定 id + aria-describedby 目标经 snippet
  // 传给调用方的控件，消除「label 未关联 control」类 a11y warning 的根因。
  import type { Snippet } from 'svelte';

  let seq = 0;

  export interface FieldSlotProps {
    /** 控件应使用的 id（与 label for 关联） */
    id: string;
    /** 控件应通过 aria-describedby 指向的目标（错误/提示），无则为 undefined */
    describedBy: string | undefined;
  }
</script>

<script lang="ts">
  let {
    label,
    id,
    hint = '',
    error = '',
    required = false,
    children,
  }: {
    label: string;
    /** 显式 id；不传则自动生成。 */
    id?: string;
    hint?: string;
    /** 校验错误（非空时渲染为 aria-describedby 关联的红字，优先级高于 hint） */
    error?: string;
    required?: boolean;
    /** 接收 { id, describedBy } 的控件片段。 */
    children: Snippet<[FieldSlotProps]>;
  } = $props();

  const autoId = `field-${(seq++).toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
  const uid = $derived(id ?? autoId);
  const errId = $derived(`${uid}-err`);
  const hintId = $derived(`${uid}-hint`);
  const describedBy = $derived(error ? errId : hint ? hintId : undefined);
</script>

<div class="space-y-1">
  <label for={uid} class="panel-label">
    {label}{#if required}<span class="text-red-500 ml-0.5" aria-hidden="true">*</span>{/if}
  </label>
  {@render children({ id: uid, describedBy })}
  {#if error}
    <p id={errId} class="text-xs text-red-500 dark:text-red-400">{error}</p>
  {:else if hint}
    <p id={hintId} class="text-xs text-gray-400">{hint}</p>
  {/if}
</div>
