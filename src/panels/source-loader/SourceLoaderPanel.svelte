<script lang="ts">
  // 源码加载面板
  // 获取页面 HTML 源码并展示，支持搜索/高亮/下载/外部资源提取
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import { downloadBlob } from '@/lib/actions/download';
  import { analysisContextStore } from '@/stores/analysis-context';
  import type { FetchResult } from '@/lib/types/messaging';
  import { extractScriptSrcs, extractLinkHrefs, formatSize } from '@/lib/source/source-utils';
  import { sourceLoaderStateStore } from '@/stores/source-loader-state';
  import { get } from 'svelte/store';
  import EmptyState from '@/components/scanner/EmptyState.svelte';

  // —— 大文件保护 ——
  // 抓取上限：交给 background 夹紧；超过返回 TOO_LARGE，避免一次性拉超大源码。
  const MAX_SOURCE_BYTES = 5 * 1024 * 1024;
  // 渲染行数上限：只渲染前 N 行，防止超大 HTML 一次性创建海量 DOM 节点卡死面板。
  // 完整内容仍可复制/下载，搜索在全文上进行。
  const MAX_RENDER_LINES = 5000;
  // 搜索防抖：连续输入时只在前一次输入停顿 200ms 后扫一次全文。
  const SEARCH_DEBOUNCE_MS = 200;

  // —— 状态（storage-backed）——
  let st = $state(get(sourceLoaderStateStore));
  $effect(() => sourceLoaderStateStore.subscribe(v => { st = v; }));

  let url = $derived(st.url);
  let source = $derived(st.source);
  let searchText = $derived(st.searchText);
  let showLineNumbers = $derived(st.showLineNumbers);
  let pendingUrls = $derived(st.pendingUrls);

  // —— 局部状态（不需要持久化）——
  let loading = $state(false);
  let statusText = $state('');
  let scriptSrcs = $state<string[]>([]);
  let linkHrefs = $state<string[]>([]);

  // 自动填充当前页 URL
  $effect(() => {
    getActiveTabUrl().then(u => {
      if (u) sourceLoaderStateStore.update(s => ({ ...s, url: u }));
    });
  });

  // §8.1：消费跨面板 handoff（只消费 text key，不整体清空 context）
  $effect(() => {
    analysisContextStore.consumePayload('source-loader', 'text').then((v) => {
      if (!v) return;
      const urls = v.split('\n').map(s => s.trim()).filter(Boolean);
      if (urls.length) {
        sourceLoaderStateStore.update(s => ({ ...s, pendingUrls: urls, url: urls[0] }));
        toastStore.show(`已载入 ${urls.length} 个待加载 URL，点击加载`, 'info');
      }
    }).catch(() => { /* ignore */ });
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

  // 全文按行分割（仅在 source 变化时重算一次）
  let allLines = $derived(source ? source.split('\n') : []);
  // 仅渲染前 N 行，避免超大 HTML 创建海量 DOM；完整内容可复制/下载
  let renderLines = $derived(allLines.slice(0, MAX_RENDER_LINES));
  let truncated = $derived(allLines.length > MAX_RENDER_LINES);
  let lineCount = $derived(allLines.length);

  // 搜索防抖：searchText 变化后延迟触发全文扫描
  let debouncedSearch = $state('');
  let searchTimer: ReturnType<typeof setTimeout> | undefined;
  $effect(() => {
    const v = searchText;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { debouncedSearch = v; }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(searchTimer);
  });

  // 搜索匹配行（在全文 allLines 上扫描，结果索引与原始行号对齐）
  let matchLineSet = $derived.by(() => {
    const s = debouncedSearch.trim().toLowerCase();
    if (!s) return null;
    const set = new Set<number>();
    for (let i = 0; i < allLines.length; i++) {
      if (allLines[i].toLowerCase().includes(s)) set.add(i);
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
    sourceLoaderStateStore.update(s => ({ ...s, source: '', searchText: '' }));
    statusText = '加载中...';

    try {
      const res = await sendMessage({
        type: 'FETCH_URL',
        url: u,
        timeout: 15000,
        maxBytes: MAX_SOURCE_BYTES,
      }) as FetchResult<string>;

      if (!res.success) {
        const msg = res.code === 'TOO_LARGE'
          ? `源码过大（超过 ${Math.round(MAX_SOURCE_BYTES / 1024 / 1024)}MB），已中止`
          : res.error;
        statusText = `加载失败: ${msg}`;
        toastStore.show(`加载失败: ${msg}`, 'error');
      } else {
        sourceLoaderStateStore.update(s => ({ ...s, source: res.data }));
        const sz = new Blob([res.data]).size;
        const lines = res.data.split('\n').length;
        const truncated = lines > MAX_RENDER_LINES;
        statusText = `加载完成 — ${formatSize(sz)}${truncated ? `（仅渲染前 ${MAX_RENDER_LINES} 行）` : ''}`;
        toastStore.show(`源码加载完成，共 ${lines} 行`, 'success');
      }
    } catch (err: any) {
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
    const hostname = (() => {
      try { return new URL(url).hostname; } catch { return 'source'; }
    })();
    downloadBlob(blob, `${hostname}-${Date.now()}.html`);
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
    sourceLoaderStateStore.update(s => ({
      ...s,
      source: '',
      searchText: '',
    }));
    statusText = '';
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
        value={url}
        oninput={(e) => sourceLoaderStateStore.update(s => ({ ...s, url: e.currentTarget.value }))}
      />
      <button class="btn btn-sm btn-ghost text-xs" onclick={() => getActiveTabUrl().then(u => { if (u) sourceLoaderStateStore.update(s => ({ ...s, url: u })); })}>
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

  <!-- 待加载 URL 队列（来自信息收集等面板） -->
  {#if pendingUrls.length > 0}
    <div class="card p-2 space-y-1">
      <div class="text-xs text-gray-500">待加载队列 ({pendingUrls.length})</div>
      <div class="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
        {#each pendingUrls as u2 (u2)}
          <button
            class="badge text-xs cursor-pointer font-mono truncate max-w-[16rem] {u2 === url ? 'bg-primary text-white' : 'bg-gray-200 dark:bg-gray-700'}"
            title={u2}
            onclick={() => { sourceLoaderStateStore.update(s => ({ ...s, url: u2 })); fetchSource(); }}
          >{u2.replace(/^https?:\/\//, '')}</button>
        {/each}
        <button class="badge text-xs bg-gray-100 dark:bg-gray-800 text-gray-500" onclick={() => sourceLoaderStateStore.update(s => ({ ...s, pendingUrls: [] }))}>清除</button>
      </div>
    </div>
  {/if}

  <!-- 搜索 + 工具栏 -->
  {#if source}
    <div class="card p-2 space-y-2">
      <div class="flex gap-1 items-center">
        <input
          class="input text-xs flex-1"
          placeholder="搜索源码..."
          value={searchText}
          oninput={(e) => sourceLoaderStateStore.update(s => ({ ...s, searchText: e.currentTarget.value }))}
        />
        <label class="flex items-center gap-1 text-xs text-gray-500 cursor-pointer shrink-0">
          <input type="checkbox" checked={showLineNumbers} onchange={(e) => sourceLoaderStateStore.update(s => ({ ...s, showLineNumbers: e.currentTarget.checked }))} />
          <span>行号</span>
        </label>
        <button class="btn btn-sm text-xs" onclick={copySource}>复制</button>
        <button class="btn btn-sm text-xs" onclick={downloadHtml}>下载</button>
      </div>
      {#if searchText.trim()}
        <div class="text-xs text-gray-500">
          匹配 {matchCount} 行
        </div>
      {/if}
    </div>
  {/if}

  <!-- 源码展示 -->
  {#if source}
    {#if truncated}
      <div class="text-xs text-amber-600 dark:text-amber-400">
        ⚠ 源码共 {lineCount} 行，为避免卡顿仅渲染前 {MAX_RENDER_LINES} 行（完整内容可复制/下载，搜索仍覆盖全文）
      </div>
    {/if}
    <div class="card overflow-hidden">
      <div class="overflow-auto max-h-96 text-xs font-mono bg-gray-50 dark:bg-gray-900">
        <pre class="p-2 leading-5 whitespace-pre-wrap break-all">{#each renderLines as line, i (i)}
          {#if highlightMatch(line, i)}
            <mark class="bg-yellow-200 dark:bg-yellow-900 rounded px-0.5">{#if showLineNumbers}<span class="text-gray-500 select-none mr-2 inline-block w-8 text-right">{i + 1}</span>{/if}{line}</mark>
          {:else}
            {#if showLineNumbers}<span class="text-gray-500 select-none mr-2 inline-block w-8 text-right">{i + 1}</span>{/if}{line}
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
            <div class="text-xs text-gray-500 font-medium">
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
            <div class="text-xs text-gray-500 font-medium">
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
    <EmptyState
      message="输入目标 URL，点击「获取源码」查看页面 HTML 源代码"
      icon="📄"
    />
  {/if}

  <!-- 加载中 -->
  {#if loading}
    <div class="card p-3 text-center">
      <div class="text-xs text-gray-500">正在获取源码...</div>
    </div>
  {/if}
</div>
