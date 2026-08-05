<script lang="ts">
  // 面板加载失败态 — 对齐 docs/UX-UI优化建议.md §3.3。
  // 提供真实恢复路径：重试（重新触发 loader）、返回上一面板、复制诊断信息。
  // role="alert" 让读屏即时感知失败。
  import { toastStore } from '@/stores/ui';

  let {
    label,
    error,
    onRetry,
    onBack,
  }: {
    label: string;
    error: unknown;
    onRetry?: () => void;
    onBack?: () => void;
  } = $props();

  let err = $derived(error instanceof Error ? error : new Error(String(error ?? '未知错误')));

  async function copyDiagnostics() {
    const text = `[灵眸] 面板加载失败\n面板: ${label}\n错误: ${err.message}\nstack:\n${err.stack ?? '(无栈信息)'}`;
    try {
      await navigator.clipboard.writeText(text);
      toastStore.show('诊断信息已复制', 'success');
    } catch {
      toastStore.show('复制失败，请手动选择文本', 'error');
    }
  }
</script>

<div class="flex flex-col items-center justify-center py-10 text-center px-4" role="alert">
  <div class="inline-flex items-center justify-center w-14 h-14 mb-3 rounded-full bg-red-100 dark:bg-red-900/40 text-3xl" aria-hidden="true">⚠️</div>
  <div class="text-sm font-medium text-gray-700 dark:text-gray-200">「{label}」加载失败</div>
  <div class="text-xs text-gray-500 dark:text-gray-500 mt-1 max-w-xs break-all">{err.message}</div>
  <div class="flex flex-wrap gap-2 mt-4 justify-center">
    {#if onRetry}
      <button type="button" class="btn btn-sm btn-primary" onclick={onRetry}>重试加载</button>
    {/if}
    {#if onBack}
      <button type="button" class="btn btn-sm" onclick={onBack}>返回上一面板</button>
    {/if}
    <button type="button" class="btn btn-sm" onclick={copyDiagnostics}>复制诊断</button>
  </div>
</div>
