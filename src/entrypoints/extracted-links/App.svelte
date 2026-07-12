<script lang="ts">
  // 提取链接结果页 — 灵眸 v6.0
  // 右键「提取链接」后在此全屏页展示：搜索 / 标签筛选 / 复制 / 导出
  import { themeStore, toastStore } from '@/stores/ui';

  interface ExtLink {
    href: string;
    text: string;
    tag: string;
    domain: string;
  }

  let sourceUrl = $state('');
  let fetchedAt = $state(0);
  let links = $state<ExtLink[]>([]);
  let search = $state('');
  let tagFilter = $state<string>('all');
  let loaded = $state(false);

  $effect(() => {
    browser.storage.local.get('__extractedLinks').then((r) => {
      const data = r.__extractedLinks as { url: string; fetchedAt: number; links: ExtLink[] } | undefined;
      if (data) {
        sourceUrl = data.url || '';
        fetchedAt = data.fetchedAt || 0;
        links = Array.isArray(data.links) ? data.links : [];
      }
      loaded = true;
    });
  });

  let isDark = $derived($themeStore);

  let tags = $derived(() => {
    const map = new Map<string, number>();
    for (const l of links) map.set(l.tag, (map.get(l.tag) || 0) + 1);
    return [...map.entries()].sort((a, b) => b[1] - a[1]);
  });

  let filtered = $derived(() => {
    let list = links;
    if (tagFilter !== 'all') list = list.filter((l) => l.tag === tagFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(
        (l) => l.href.toLowerCase().includes(q) || l.text.toLowerCase().includes(q) || l.domain.toLowerCase().includes(q),
      );
    }
    return list;
  });

  const TAG_COLOR: Record<string, string> = {
    a: 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300',
    script: 'bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300',
    link: 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300',
    iframe: 'bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300',
  };

  function copyAll() {
    const text = filtered().map((l) => l.href).join('\n');
    navigator.clipboard.writeText(text).then(() => toastStore.show(`已复制 ${filtered().length} 条链接`, 'success'));
  }

  function exportTxt() {
    const text = filtered().map((l) => l.href).join('\n');
    download(text, 'lingmou-links.txt', 'text/plain');
  }

  function exportJson() {
    download(JSON.stringify({ url: sourceUrl, fetchedAt, links: filtered() }, null, 2), 'lingmou-links.json', 'application/json');
  }

  function download(content: string, name: string, type: string) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toastStore.show('已导出', 'success');
  }

  function toggleTheme() {
    themeStore.toggle();
  }
</script>

<div class="max-w-5xl mx-auto p-6 space-y-4">
  <header class="flex items-center justify-between">
    <div>
      <h1 class="text-2xl font-bold text-primary">🔗 提取链接</h1>
      <p class="text-xs text-gray-400 mt-1">
        {#if sourceUrl}
          来源: <span class="font-mono">{sourceUrl}</span>
          {#if fetchedAt}· {new Date(fetchedAt).toLocaleString('zh-CN')}{/if}
          · 共 {links.length} 条
        {:else}
          暂无数据 — 请在目标页面右键「灵眸 → 提取链接」
        {/if}
      </p>
    </div>
    <button class="p-2 rounded hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-500" onclick={toggleTheme} title="切换主题">
      {#if isDark}🌙{:else}☀️{/if}
    </button>
  </header>

  {#if loaded && links.length > 0}
    <!-- 工具栏 -->
    <div class="card p-3 space-y-2">
      <div class="flex gap-2 flex-wrap items-center">
        <input class="input flex-1 text-sm" placeholder="搜索 href / 文本 / 域名..." bind:value={search} />
        <button class="btn btn-sm btn-primary" onclick={copyAll}>复制全部</button>
        <button class="btn btn-sm" onclick={exportTxt}>导出 TXT</button>
        <button class="btn btn-sm" onclick={exportJson}>导出 JSON</button>
      </div>
      <div class="flex gap-1 flex-wrap items-center">
        <span class="text-xs text-gray-400">类型:</span>
        <button
          class="badge text-xs {tagFilter === 'all' ? 'bg-primary text-white' : 'bg-gray-200 dark:bg-gray-700'}"
          onclick={() => (tagFilter = 'all')}>全部 {links.length}</button>
        {#each tags() as [tag, count]}
          <button
            class="badge text-xs {tagFilter === tag ? TAG_COLOR[tag] || 'bg-primary text-white' : 'bg-gray-200 dark:bg-gray-700'}"
            onclick={() => (tagFilter = tag)}>{tag} {count}</button>
        {/each}
      </div>
    </div>

    <!-- 列表 -->
    <div class="card divide-y divide-gray-100 dark:divide-gray-800">
      {#each filtered() as l (l.href)}
        <div class="p-2.5 flex items-center gap-2 text-xs hover:bg-gray-50 dark:hover:bg-gray-800">
          <span class="badge text-xs shrink-0 {TAG_COLOR[l.tag] || 'bg-gray-200 dark:bg-gray-700'}">{l.tag}</span>
          <div class="flex-1 min-w-0">
            <div class="font-mono text-gray-700 dark:text-gray-300 truncate" title={l.href}>{l.href}</div>
            {#if l.text}
              <div class="text-gray-400 truncate">{l.text}</div>
            {/if}
          </div>
          {#if l.domain}
            <span class="text-gray-400 shrink-0 hidden sm:inline">{l.domain}</span>
          {/if}
          <a
            class="text-gray-400 hover:text-primary shrink-0"
            href={l.href}
            target="_blank"
            rel="noopener"
            title="打开">↗</a
          >
          <button
            class="text-gray-400 hover:text-primary shrink-0"
            onclick={() => navigator.clipboard.writeText(l.href).then(() => toastStore.show('已复制', 'success'))}
            title="复制">📋</button
          >
        </div>
      {/each}
    </div>
    <div class="text-center text-xs text-gray-400 py-2">显示 {filtered().length} / {links.length} 条</div>
  {:else if loaded}
    <div class="card p-8 text-center text-gray-400 text-sm">
      未提取到链接。请在目标网页上右键 →「灵眸 → 提取链接」。
    </div>
  {/if}
</div>
