<script lang="ts">
  // 源码加载面板 — 灵眸 v6.0
  // 获取页面 HTML 源码并展示，支持搜索/高亮/下载/外部资源提取
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import type { FetchResult } from '@/lib/types/messaging';
  import { extractScriptSrcs, extractLinkHrefs, formatSize } from '@/lib/source/source-utils';

  let url = $state('');
  let loading = $state(false);
  let source = $state('');
  let statusText = $state('');
  let searchText = $state('');
  let showLineNumbers = $state(true);
  let scriptSrcs = $state<string[]>([]);
  let linkHrefs = $state<string[]>([]);

  // 自动填充当前页 URL
  $effect(() => {
    getActiveTabUrl().then(u => {
      if (u) url = u;
    });
  });

  // 解析外部资源
  $effect(() => {
    if (source) {
      scriptSrcs = extractScriptSrcs(source);
      linkHrefs = extractLinkHrefs(source);
    } else {
      scriptSrcs = [];
      linkHrefs = [];
    }
  });

  let sourceSize = $derived(source ? new Blob([source]).size : 0);

  // 按行分割
  let lines = $derived(source ? source.split('\n') : []);

  // 搜索匹配行
  let matchLineSet = $derived.by(() => {
    if (!searchText.trim()) return null;
    const s = searchText.trim().toLowerCase();
    const set = new Set<number>();
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].toLowerCase().includes(s)) set.add(i);
    }
    return set;
  });

  let matchCount = $derived(matchLineSet ? matchLineSet.size : 0);

  async function fetchSource() {
    const u = url.trim();
    if (!u || !/^https?:\/\//i.test(u)) {
      toastStore.show('请输入有效的 URL（http/https）', 'warning');
      return;
    }

    loading = true;
    source = '';
    statusText = '加载中...';
    searchText = '';

    try {
      const res = await sendMessage({
        type: 'FETCH_URL',
        url: u,
        timeout: 15000,
      }) as FetchResult<string>;

      if ('error' in res) {
        source = '';
        statusText = `加载失败: ${res.error}`;
        toastStore.show(`加载失败: ${res.error}`, 'error');
      } else {
        source = res.data;
        statusText = `加载完成 — ${formatSize(sourceSize)}`;
        toastStore.show(`源码加载完成，共 ${lines.length} 行`, 'success');
      }
    } catch (err: any) {
      source = '';
      statusText = `请求失败: ${err.message || '未知错误'}`;
      toastStore.show(`请求失败: ${err.message || '未知错误'}`, 'error');
    } finally {
      loading = false;
    }
  }

  function downloadHtml() {
    if (!source) {
      toastStore.show('没有可下载的源码', 'warning');
      return;
    }
    const blob = new Blob([source], { type: 'text/html;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    const hostname = (() => {
      try { return new URL(url).hostname; } catch { return 'source'; }
    })();
    a.download = `${hostname}-${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(a.href);
    toastStore.show('已下载 HTML 文件', 'success');
  }

  function copySource() {
    if (!source) {
      toastStore.show('没有可复制的源码', 'warning');
      return;
    }
    navigator.clipboard.writeText(source).then(() => {
      toastStore.show('已复制源码', 'success');
    });
  }

  /** 高亮搜索关键词（简单实现，不使用 dangerouslySetInnerHTML） */
  function highlightMatch(line: string, lineIdx: number): boolean {
    if (!matchLineSet) return false;
    return matchLineSet.has(lineIdx);
  }

  function reset() {
    source = '';
    statusText = '';
    searchText = '';
    scriptSrcs = [];
    linkHrefs = [];
  }
</script>

<div class="space-y-3">
  <!-- URL 输入 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <input
        class="input text-xs font-mono flex-1"
        placeholder="https://target.example.com"
        bind:value={url}
      />
      <button class="btn btn-sm btn-ghost text-xs" onclick={() => getActiveTabUrl().then(u => { if (u) url = u; })}>
        自动填充
      </button>
    </div>
    <div class="flex gap-1">
      <button
        class="btn btn-sm btn-primary flex-1"
        disabled={loading || !url.trim()}
        onclick={fetchSource}
      >
        {loading ? '加载中...' : '获取源码'}
      </button>
      {#if source}
        <button class="btn btn-sm" onclick={reset}>重置</button>
      {/if}
    </div>
    {#if statusText}
      <div class="text-xs text-gray-500">{statusText}</div>
    {/if}
  </div>

  <!-- 搜索 + 工具栏 -->
  {#if source}
    <div class="card p-2 space-y-2">
      <div class="flex gap-1 items-center">
        <input
          class="input text-xs flex-1"
          placeholder="搜索源码..."
          bind:value={searchText}
        />
        <label class="flex items-center gap-1 text-xs text-gray-400 cursor-pointer shrink-0">
          <input type="checkbox" bind:checked={showLineNumbers} />
          <span>行号</span>
        </label>
        <button class="btn btn-sm text-xs" onclick={copySource}>复制</button>
        <button class="btn btn-sm text-xs" onclick={downloadHtml}>下载</button>
      </div>
      {#if searchText.trim()}
        <div class="text-xs text-gray-400">
          匹配 {matchCount} 行
        </div>
      {/if}
    </div>
  {/if}

  <!-- 源码展示 -->
  {#if source}
    <div class="card overflow-hidden">
      <div class="overflow-auto max-h-96 text-xs font-mono bg-gray-50 dark:bg-gray-900">
        <pre class="p-2 leading-5 whitespace-pre-wrap break-all">{#each lines as line, i (i)}
          {#if highlightMatch(line, i)}
            <mark class="bg-yellow-200 dark:bg-yellow-900 rounded px-0.5">{#if showLineNumbers}<span class="text-gray-400 select-none mr-2 inline-block w-8 text-right">{i + 1}</span>{/if}{line}</mark>
          {:else}
            {#if showLineNumbers}<span class="text-gray-400 select-none mr-2 inline-block w-8 text-right">{i + 1}</span>{/if}{line}
          {/if}
{/each}</pre>
      </div>
    </div>

    <!-- 外部资源列表 -->
    {#if scriptSrcs.length > 0 || linkHrefs.length > 0}
      <div class="card p-3 space-y-2">
        <div class="text-xs font-medium">外部资源</div>

        {#if scriptSrcs.length > 0}
          <div class="space-y-0.5">
            <div class="text-xs text-gray-400 font-medium">
              Scripts ({scriptSrcs.length})
            </div>
            {#each scriptSrcs as src}
              <div class="text-xs font-mono text-blue-600 dark:text-blue-400 truncate break-all pl-2" title={src}>
                {src}
              </div>
            {/each}
          </div>
        {/if}

        {#if linkHrefs.length > 0}
          <div class="space-y-0.5">
            <div class="text-xs text-gray-400 font-medium">
              Stylesheets ({linkHrefs.length})
            </div>
            {#each linkHrefs as href}
              <div class="text-xs font-mono text-green-600 dark:text-green-400 truncate break-all pl-2" title={href}>
                {href}
              </div>
            {/each}
          </div>
        {/if}
      </div>
    {/if}
  {:else if !loading}
    <div class="text-center text-gray-400 text-sm py-8">
      输入目标 URL，点击「获取源码」查看页面 HTML 源代码
    </div>
  {/if}

  <!-- 加载中 -->
  {#if loading}
    <div class="card p-3 text-center">
      <div class="text-xs text-gray-500">正在获取源码...</div>
    </div>
  {/if}
</div>
