<script lang="ts">
  // 链接提取面板
  // 提取当前页面所有链接/图片/脚本/资源/框架/表单，分类、去重、筛选、复制、导出
  import { getActiveTab, execInTab } from '@/lib/core/tabs';
  import { toastStore, autoRunStore } from '@/stores/ui';
  import { analysisContextStore } from '@/stores/analysis-context';
  import ResultToolbar from '@/components/results/ResultToolbar.svelte';
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import { copyText } from '@/lib/actions/clipboard';
  import { type ResultAdapter, type ResultQuery } from '@/lib/results/result-adapter';
  import {
    classifyLink,
    dedupeLinks,
    buildCsv,
    type ExtractedLink,
  } from '@/lib/scanners/links-engine';

  // --- State ---
  let loading = $state(false);
  let rawLinks = $state<ExtractedLink[]>([]);
  let query = $state<ResultQuery>({ search: '', filters: {}, sort: { key: 'default', direction: 'asc' } });

  // --- Constants ---
  const TAG_LABELS: Record<string, string> = {
    a: '链接', img: '图片', script: '脚本', link: '资源', iframe: '框架', form: '表单',
  };
  const TAG_COLORS: Record<string, string> = {
    a: 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300',
    img: 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300',
    script: 'bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300',
    link: 'bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300',
    iframe: 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300',
    form: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300',
  };
  const TYPE_OPTIONS: { value: string; label: string }[] = [
    { value: 'all', label: '全部' },
    { value: 'internal', label: '内部' },
    { value: 'external', label: '外部' },
    { value: 'relative', label: '相对' },
    { value: 'mailto', label: 'mailto' },
    { value: 'tel', label: 'tel' },
    { value: 'anchor', label: '锚点' },
  ];

  // --- Derived ---
  let totalCount = $derived(rawLinks.length);

  // 一键操作（右键菜单 / Popup）：命中本面板则自动提取
  $effect(() => {
    const sig = $autoRunStore;
    if (sig && sig.panel === 'links') {
      autoRunStore.clear();
      extract();
    }
  });

  let typeCounts = $derived.by(() => {
    const counts: Record<string, number> = {};
    for (const l of rawLinks) {
      counts[l.type] = (counts[l.type] || 0) + 1;
      if (l.tag) {
        const k = `tag:${l.tag}`;
        counts[k] = (counts[k] || 0) + 1;
      }
    }
    return counts;
  });

  let tagCounts = $derived.by(() => {
    const counts: Record<string, number> = {};
    for (const l of rawLinks) {
      if (l.tag) counts[l.tag] = (counts[l.tag] || 0) + 1;
    }
    return counts;
  });

  let uniqueDomains = $derived.by(() => {
    const s = new Set<string>();
    for (const l of rawLinks) {
      if (l.domain) s.add(l.domain);
    }
    return s.size;
  });

  const linksAdapter: ResultAdapter<ExtractedLink> = {
    apply(items, q) {
      let list = items;
      const typeSel = q.filters.type?.[0];
      if (typeSel && typeSel !== 'all') list = list.filter((l) => l.type === typeSel);
      const kw = q.search.trim().toLowerCase();
      if (kw) {
        list = list.filter(
          (l) =>
            l.href.toLowerCase().includes(kw) ||
            (l.text || '').toLowerCase().includes(kw) ||
            (l.domain || '').toLowerCase().includes(kw),
        );
      }
      if (q.sort.key === 'type') return [...list].sort((a, b) => (a.tag || '').localeCompare(b.tag || ''));
      if (q.sort.key === 'domain') return [...list].sort((a, b) => (a.domain || '').localeCompare(b.domain || ''));
      return list;
    },
    getSearchText(l) {
      return `${l.href} ${l.text || ''} ${l.domain || ''}`;
    },
    getId(l) {
      return l.href;
    },
  };

  let filtered = $derived(linksAdapter.apply(rawLinks, query));
  let filterTypeSel = $derived(query.filters.type?.[0] ?? 'all');
  function setTypeFilter(v: string) {
    query.filters = v === 'all' ? {} : { type: [v] };
  }

  // --- DOM extraction function (runs in MAIN world, cannot reference closures) ---
  function extractLinksFromPage() {
     
    const pageUrl = location.href;
    const pageDomain = location.hostname;
    const pageOrigin = location.origin;
    const links: { href: string; text: string; tag: string; domain: string }[] = [];

    function resolveDomain(href: string): string {
      try {
        return new URL(href, pageUrl).hostname;
      } catch {
        return '';
      }
    }

    // <a href>
    const anchors = document.querySelectorAll('a[href]');
    for (let i = 0; i < anchors.length; i++) {
      const el = anchors[i] as HTMLAnchorElement;
      const href = el.href;
      if (!href || href === '#' || href.startsWith('javascript:')) continue;
      links.push({
        href,
        text: (el.textContent || '').trim().substring(0, 60) || el.getAttribute('title') || '',
        tag: 'a',
        domain: resolveDomain(href),
      });
    }

    // <img src>
    const imgs = document.querySelectorAll('img[src]');
    for (let i = 0; i < imgs.length; i++) {
      const el = imgs[i] as HTMLImageElement;
      links.push({
        href: el.src,
        text: el.alt || '',
        tag: 'img',
        domain: resolveDomain(el.src),
      });
    }

    // <script src>
    const scripts = document.querySelectorAll('script[src]');
    for (let i = 0; i < scripts.length; i++) {
      const el = scripts[i] as HTMLScriptElement;
      links.push({
        href: el.src,
        text: '',
        tag: 'script',
        domain: resolveDomain(el.src),
      });
    }

    // <link href>
    const linkEls = document.querySelectorAll('link[href]');
    for (let i = 0; i < linkEls.length; i++) {
      const el = linkEls[i] as HTMLLinkElement;
      links.push({
        href: el.href,
        text: el.rel || '',
        tag: 'link',
        domain: resolveDomain(el.href),
      });
    }

    // <iframe src>, <frame src>
    const frames = document.querySelectorAll('iframe[src],frame[src]');
    for (let i = 0; i < frames.length; i++) {
      const el = frames[i] as HTMLIFrameElement;
      links.push({
        href: el.src,
        text: '',
        tag: 'iframe',
        domain: resolveDomain(el.src),
      });
    }

    // <form action>
    const forms = document.querySelectorAll('form');
    for (let i = 0; i < forms.length; i++) {
      const el = forms[i] as HTMLFormElement;
      let action = el.getAttribute('action') || pageUrl;
      const method = (el.getAttribute('method') || 'GET').toUpperCase();
      try {
        action = new URL(action, pageUrl).href;
      } catch { /* keep as-is */ }
      const inputs: string[] = [];
      const inputEls = el.querySelectorAll('input[name],select[name],textarea[name]');
      for (let j = 0; j < inputEls.length; j++) {
        const name = inputEls[j].getAttribute('name');
        if (name) inputs.push(name);
      }
      links.push({
        href: `${action} [${method}]${inputs.length ? ` {${inputs.join(', ')}}` : ''}`,
        text: inputs.length ? inputs.join(', ') : '',
        tag: 'form',
        domain: resolveDomain(action),
      });
    }

    // dedupe inside page context
    const seen = new Set<string>();
    const deduped: typeof links = [];
    for (const l of links) {
      if (!seen.has(l.href)) {
        seen.add(l.href);
        deduped.push(l);
      }
    }

    return { deduped, pageOrigin };
  }

  // --- Actions ---
  async function extract() {
    loading = true;
    rawLinks = [];

    const tab = await getActiveTab();
    if (!tab?.id) {
      toastStore.show('无法获取当前标签页', 'error');
      loading = false;
      return;
    }

    const result = await execInTab<{ deduped: { href: string; text: string; tag: string; domain: string }[]; pageOrigin: string }>(
      tab.id,
      extractLinksFromPage,
      { world: 'MAIN' },
    );

    if (!result) {
      toastStore.show('提取失败（可能无法访问该页面）', 'error');
      loading = false;
      return;
    }

    // Classify each link
    const classified: ExtractedLink[] = result.deduped.map(l => ({
      ...l,
      type: classifyLink(l.href, result.pageOrigin),
    }));

    rawLinks = classified;
    loading = false;
    toastStore.show(`提取完成，共 ${classified.length} 个链接`, 'success');
  }

  async function copyOne(href: string) {
    await copyText(href, '已复制');
  }

  // —— 序列化器（作用于当前筛选 filtered，展示/导出同源 §6.1）——
  function linksCsv(items: ExtractedLink[]): string {
    return buildCsv(items);
  }
  function linksText(items: ExtractedLink[]): string {
    return items.map((l) => l.href).join('\n');
  }

  async function sendToMultiUrl() {
    if (filtered.length === 0) {
      toastStore.show('没有可发送的链接', 'warning');
      return;
    }
    const urls = filtered
      .map(l => l.href)
      .filter(u => u.startsWith('http://') || u.startsWith('https://'));
    if (urls.length === 0) {
      toastStore.show('没有有效的 HTTP(S) 链接', 'warning');
      return;
    }
    await analysisContextStore.handoff({
      sourcePanel: 'links', sourceLabel: '链接提取',
      targetPanel: 'multiurl', payload: { text: urls.join('\n') }, summary: `${urls.length} 个 URL`,
    });
  }
</script>

<div class="space-y-3">
  <!-- 操作栏 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <button class="btn btn-sm btn-primary flex-1" disabled={loading} onclick={extract}>
        {loading ? '提取中...' : '提取链接'}
      </button>
    </div>

    {#if totalCount > 0}
      <!-- 统计 -->
      <div class="flex flex-wrap gap-2 text-xs">
        <span class="font-medium">总计: {totalCount}</span>
        {#each Object.entries(tagCounts) as [tag, count]}
          <span class="badge text-xs {TAG_COLORS[tag] || ''}">{TAG_LABELS[tag] || tag}: {count}</span>
        {/each}
        {#if (typeCounts['external'] || 0) > 0}
          <span class="badge text-xs bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300">外部: {typeCounts['external'] || 0}</span>
        {/if}
        {#if uniqueDomains > 1}
          <span class="text-gray-400">域名: {uniqueDomains}</span>
        {/if}
      </div>

      <!-- 工具栏：ResultToolbar 包裹 类型筛选 / 排序 / 发送·导出 -->
      <ResultToolbar {query} total={totalCount} shown={filtered.length} searchPlaceholder="搜索 URL / 域名 / 文本...">
        <select
          class="input text-xs w-20"
          value={filterTypeSel}
          onchange={(e) => setTypeFilter((e.currentTarget as HTMLSelectElement).value)}
          aria-label="类型筛选"
        >
          {#each TYPE_OPTIONS as opt}
            <option value={opt.value}>{opt.label}</option>
          {/each}
        </select>
        <select
          class="input text-xs w-20"
          value={query.sort.key}
          onchange={(e) => { query.sort.key = (e.currentTarget as HTMLSelectElement).value; }}
          aria-label="排序"
        >
          <option value="default">默认</option>
          <option value="type">按标签</option>
          <option value="domain">按域名</option>
        </select>
        <button class="btn btn-sm" onclick={sendToMultiUrl} disabled={filtered.length === 0}>发送到 MultiUrl</button>
        <ExportMenu items={filtered} module="links" serializers={{ csv: linksCsv, text: linksText }} />
      </ResultToolbar>
    {/if}
  </div>

  <!-- 结果列表 -->
  {#if filtered.length > 0}
    <div class="space-y-1">
      {#each filtered as link (link.href)}
        <div class="card p-2 flex items-start gap-2">
          <span class="badge text-xs shrink-0 {TAG_COLORS[link.tag || ''] || ''}">{link.tag || '?'}</span>
          <span class="badge text-xs shrink-0
            {link.type === 'external' ? 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300' : ''}
            {link.type === 'internal' ? 'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400' : ''}
            {link.type === 'mailto' ? 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300' : ''}
            {link.type === 'relative' ? 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400' : ''}
          ">{link.type}</span>
          <div class="flex-1 min-w-0">
            <div class="text-xs font-mono text-gray-700 dark:text-gray-200 break-all">{link.href}</div>
            {#if link.domain}
              <div class="text-xs text-gray-400 truncate mt-0.5">
                {link.domain}{link.text ? ` - ${link.text}` : ''}
              </div>
            {:else if link.text}
              <div class="text-xs text-gray-400 truncate mt-0.5">{link.text}</div>
            {/if}
          </div>
          <button class="btn btn-sm text-xs shrink-0" onclick={() => copyOne(link.href)}>复制</button>
        </div>
      {/each}
    </div>
  {:else if !loading && totalCount === 0}
    <div class="text-center text-gray-400 text-sm py-8">
      点击「提取链接」获取当前页面所有链接、图片、脚本等资源
    </div>
  {:else if !loading && totalCount > 0}
    <div class="text-center text-gray-400 text-sm py-8">没有匹配的链接</div>
  {/if}
</div>
