<script lang="ts">
  // URL多开面板 — 灵眸 v6.0
  // 粘贴多个 URL，批量在新标签页中打开
  import { toastStore } from '@/stores/ui';

  let rawText = $state('');
  let delay = $state(0);
  let maxUrls = 20;
  let opening = $state(false);
  let openedCount = $state(0);

  let urls = $derived.by(() => {
    return rawText
      .split(/[\n\r,;]+/)
      .map(line => {
        let url = line.trim();
        if (!url) return null;
        if (!/^https?:\/\//i.test(url)) url = `http://${url}`;
        return url;
      })
      .filter((u): u is string => u !== null);
  });

  let uniqueUrls = $derived.by(() => {
    return [...new Set(urls)];
  });

  let duplicateCount = $derived(urls.length - uniqueUrls.length);

  function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async function openAll() {
    if (uniqueUrls.length === 0) {
      toastStore.show('请输入 URL', 'warning');
      return;
    }
    if (uniqueUrls.length > maxUrls) {
      toastStore.show(`一次最多打开 ${maxUrls} 个标签页`, 'warning');
      return;
    }

    if (!confirm(`即将打开 ${uniqueUrls.length} 个标签页，是否继续？`)) {
      return;
    }

    opening = true;
    openedCount = 0;

    for (const url of uniqueUrls) {
      browser.tabs.create({ url, active: false });
      openedCount++;
      if (delay > 0) await sleep(delay);
    }

    opening = false;
    toastStore.show(`已打开 ${uniqueUrls.length} 个标签页`, 'success');
  }

  function dedup() {
    if (duplicateCount === 0) {
      toastStore.show('没有重复 URL', 'info');
      return;
    }
    rawText = uniqueUrls.join('\n');
    toastStore.show(`去重完成，移除 ${duplicateCount} 个重复`, 'success');
  }

  function copyUrls() {
    if (uniqueUrls.length === 0) {
      toastStore.show('没有可复制的 URL', 'warning');
      return;
    }
    navigator.clipboard.writeText(uniqueUrls.join('\n')).then(() => {
      toastStore.show(`已复制 ${uniqueUrls.length} 个 URL`, 'success');
    });
  }

  function clearAll() {
    rawText = '';
    openedCount = 0;
  }
</script>

<div class="space-y-3">
  <!-- 输入区 -->
  <div class="card p-3 space-y-2">
    <textarea
      class="input w-full font-mono text-xs"
      rows="8"
      placeholder="粘贴多个 URL，每行一个，或用逗号/分号分隔&#10;https://example.com/1&#10;https://example.com/2&#10;https://example.com/3"
      bind:value={rawText}
    ></textarea>

    <!-- 统计 -->
    {#if urls.length > 0}
      <div class="flex items-center gap-2 text-xs text-gray-400">
        <span>
          已识别 <b class="text-gray-600 dark:text-gray-200">{uniqueUrls.length}</b> 个 URL
        </span>
        {#if duplicateCount > 0}
          <span>(含 {duplicateCount} 个重复)</span>
        {/if}
        <span class="ml-auto">
          上限 {maxUrls} 个
          {#if uniqueUrls.length > maxUrls}
            <span class="text-red-500 dark:text-red-400 font-bold">超限!</span>
          {/if}
        </span>
      </div>
    {/if}
  </div>

  <!-- 选项 -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center gap-2 text-xs">
      <span class="text-gray-400 shrink-0">打开间隔:</span>
      <input
        type="number"
        class="input text-xs w-24"
        min="0"
        max="5000"
        step="100"
        bind:value={delay}
      />
      <span class="text-gray-400">ms</span>
      <span class="text-gray-400 ml-auto">
        {delay === 0 ? '无间隔' : `${delay}ms/个`}
      </span>
    </div>
  </div>

  <!-- 操作按钮 -->
  <div class="flex gap-1">
    <button
      class="btn btn-sm btn-primary flex-1"
      disabled={opening || uniqueUrls.length === 0}
      onclick={openAll}
    >
      {opening ? `打开中... (${openedCount}/${uniqueUrls.length})` : '全部打开'}
    </button>
    <button
      class="btn btn-sm flex-1"
      disabled={uniqueUrls.length === 0 || duplicateCount === 0}
      onclick={dedup}
    >
      去重
    </button>
    <button
      class="btn btn-sm flex-1"
      disabled={uniqueUrls.length === 0}
      onclick={copyUrls}
    >
      复制
    </button>
    <button
      class="btn btn-sm"
      disabled={urls.length === 0}
      onclick={clearAll}
    >
      清空
    </button>
  </div>

  <!-- 空状态 -->
  {#if urls.length === 0}
    <div class="text-center text-gray-400 text-sm py-6">
      粘贴多个 URL，点击「全部打开」批量在新标签页中打开
    </div>
  {/if}
</div>
