<script lang="ts" generics="TItem">
  // 导出菜单
  // 对齐 docs/UX-UI优化建议.md §6.1：统一「复制当前 / 导出 CSV|JSON|Markdown」，
  // 文件名规范 lingmou-{module}-{date}.{ext}，空结果禁用，复制/导出仅作用于传入的 items（当前筛选集）。
  import { copyText } from '@/lib/actions/clipboard';
  import { downloadText, buildFilename } from '@/lib/actions/download';
  import type { ExportFormat } from '@/lib/actions/serializers';

  let {
    items,
    serializers,
    module,
    disabled = false,
    copySerialize,
    copyLabel,
  }: {
    items: TItem[];
    /** 各格式序列化器；仅渲染提供的格式 */
    serializers: Partial<Record<ExportFormat, (items: TItem[]) => string>>;
    /** 模块名，用于文件名 */
    module: string;
    disabled?: boolean;
    /** 复制当前结果的文本；默认 serializers.text ?? JSON.stringify */
    copySerialize?: (items: TItem[]) => string;
    copyLabel?: string;
  } = $props();

  let open = $state(false);
  let count = $derived(Array.isArray(items) ? items.length : 0);
  let empty = $derived(disabled || count === 0);

  const EXTS: Record<ExportFormat, string> = { csv: 'csv', json: 'json', markdown: 'md', text: 'txt' };
  const MIMES: Record<ExportFormat, string> = {
    csv: 'text/csv;charset=utf-8',
    json: 'application/json;charset=utf-8',
    markdown: 'text/markdown;charset=utf-8',
    text: 'text/plain;charset=utf-8',
  };
  const ORDER: ExportFormat[] = ['csv', 'json', 'markdown', 'text'];
  let formats = $derived(ORDER.filter((f) => typeof serializers[f] === 'function'));

  function close() { open = false; }

  async function doCopy() {
    if (empty) return;
    const text = copySerialize
      ? copySerialize(items)
      : serializers.text
        ? serializers.text(items)
        : JSON.stringify(items, null, 2);
    await copyText(text, copyLabel ?? `已复制 ${count} 项`);
    close();
  }

  function doExport(f: ExportFormat) {
    if (empty) return;
    const content = serializers[f]!(items);
    downloadText(content, buildFilename(module, EXTS[f]), MIMES[f]);
    close();
  }
</script>

<details class="relative inline-block export-menu" bind:open>
  <summary
    class="btn btn-sm select-none {empty ? 'opacity-50 pointer-events-none' : ''}"
    aria-label="导出菜单"
  >
    导出{#if count > 0}<span class="opacity-70 ml-0.5">({count})</span>{/if}
    <span class="ml-0.5" aria-hidden="true">▾</span>
  </summary>
  {#if !empty}
    <div class="absolute right-0 mt-1 z-20 card p-1 min-w-[10rem] shadow-lg space-y-0.5">
      <button class="menu-btn" onclick={doCopy}>复制当前 {count} 项</button>
      {#each formats as f (f)}
        <button class="menu-btn" onclick={() => doExport(f)}>导出 {EXTS[f].toUpperCase()}</button>
      {/each}
    </div>
  {/if}
</details>

<style>
  .export-menu > summary {
    cursor: pointer;
    list-style: none;
  }
  .export-menu > summary::-webkit-details-marker {
    display: none;
  }
  .menu-btn {
    display: block;
    width: 100%;
    text-align: left;
    padding: 0.3rem 0.5rem;
    font-size: 0.75rem;
    border-radius: 0.25rem;
    color: inherit;
    background: transparent;
    border: none;
  }
  .menu-btn:hover {
    background: rgba(0, 0, 0, 0.06);
  }
  :global(.dark) .menu-btn:hover {
    background: rgba(255, 255, 255, 0.08);
  }
</style>
