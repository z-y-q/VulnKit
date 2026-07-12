<script lang="ts">
  // 标签页保存面板 — 灵眸 v6.0
  // 收集当前窗口所有标签页 URL（过滤 chrome:/about:），去重，复制/导出。
  // 对齐 v5 vk-tabsave.js。
  import { toastStore } from '@/stores/ui';

  let savedTabs = $state<{ url: string; title: string }[]>([]);
  let collecting = $state(false);

  const URL_BLOCKLIST = /^(chrome|edge|about|moz-extension|chrome-extension|devtools|view-source):/i;

  async function grabAllTabs() {
    collecting = true;
    try {
      const tabs = await browser.tabs.query({ currentWindow: true });
      const seen = new Set<string>();
      const collected: { url: string; title: string }[] = [];
      for (const t of tabs) {
        const url = t.url || '';
        if (!url || URL_BLOCKLIST.test(url)) continue;
        if (seen.has(url)) continue;
        seen.add(url);
        collected.push({ url, title: (t.title || '').trim() });
      }
      savedTabs = collected;
      toastStore.show(`收集 ${collected.length} 个标签页`, 'success');
    } catch (e: any) {
      toastStore.show('收集失败: ' + (e.message || ''), 'error');
    } finally {
      collecting = false;
    }
  }

  async function grabAllWindows() {
    collecting = true;
    try {
      const tabs = await browser.tabs.query({});
      const seen = new Set<string>();
      const collected: { url: string; title: string }[] = [];
      for (const t of tabs) {
        const url = t.url || '';
        if (!url || URL_BLOCKLIST.test(url)) continue;
        if (seen.has(url)) continue;
        seen.add(url);
        collected.push({ url, title: (t.title || '').trim() });
      }
      savedTabs = collected;
      toastStore.show(`收集全部窗口 ${collected.length} 个标签页`, 'success');
    } catch (e: any) {
      toastStore.show('收集失败: ' + (e.message || ''), 'error');
    } finally {
      collecting = false;
    }
  }

  function copyUrls() {
    if (savedTabs.length === 0) { toastStore.show('没有可复制的内容', 'warning'); return; }
    navigator.clipboard.writeText(savedTabs.map(t => t.url).join('\n')).then(() =>
      toastStore.show(`已复制 ${savedTabs.length} 个 URL`, 'success'));
  }

  function exportTxt() {
    if (savedTabs.length === 0) { toastStore.show('没有可导出的内容', 'warning'); return; }
    const text = savedTabs.map(t => `${t.title}\n${t.url}\n`).join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `tabs-${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    toastStore.show('已导出 TXT', 'success');
  }

  function reopenAll() {
    if (savedTabs.length === 0) return;
    for (const t of savedTabs) {
      try { browser.tabs.create({ url: t.url, active: false }); } catch { /* ignore */ }
    }
    toastStore.show(`已打开 ${savedTabs.length} 个标签页`, 'success');
  }

  function clearAll() { savedTabs = []; }
</script>

<div class="space-y-3">
  <div class="card p-3 space-y-2">
    <div class="text-sm font-medium">标签页收集</div>
    <div class="text-xs text-gray-400">收集浏览器标签页 URL，过滤 chrome:/about: 内部页，去重后可复制/导出/重开。</div>
    <div class="flex gap-1 flex-wrap">
      <button class="btn btn-sm btn-primary" onclick={grabAllTabs} disabled={collecting}>收集当前窗口</button>
      <button class="btn btn-sm" onclick={grabAllWindows} disabled={collecting}>收集全部窗口</button>
      {#if savedTabs.length > 0}
        <button class="btn btn-sm" onclick={copyUrls}>复制 URL</button>
        <button class="btn btn-sm" onclick={exportTxt}>导出 TXT</button>
        <button class="btn btn-sm" onclick={reopenAll}>全部重开</button>
        <button class="btn btn-sm btn-danger" onclick={clearAll}>清空</button>
      {/if}
    </div>
    {#if savedTabs.length > 0}
      <div class="text-xs text-gray-400">共 {savedTabs.length} 个标签页</div>
    {/if}
  </div>

  {#if savedTabs.length > 0}
    <div class="card p-2 space-y-1 max-h-96 overflow-y-auto">
      {#each savedTabs as t, i (t.url)}
        <div class="text-xs py-1 border-b border-gray-100 dark:border-gray-800 last:border-0">
          <div class="text-gray-600 dark:text-gray-300 truncate">{i + 1}. {t.title || '(无标题)'}</div>
          <a href={t.url} target="_blank" class="font-mono text-blue-500 hover:underline break-all">{t.url}</a>
        </div>
      {/each}
    </div>
  {:else}
    <div class="text-center text-xs text-gray-400 py-8">
      <div class="text-3xl mb-2">📑</div>
      点击「收集当前窗口」开始
    </div>
  {/if}
</div>
