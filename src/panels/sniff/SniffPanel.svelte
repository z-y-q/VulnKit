<script lang="ts">
  // 网站嗅探面板 — 灵眸 v6.0
  // 流程：自动填充 URL → FETCH_URL 获取 HTML + FETCH_PROBE 获取 headers → 解析 meta/scriptSrc → scan() 匹配 → 分类标签展示
  import { sendMessage, sendToContent } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore, autoRunStore } from '@/stores/ui';
  import type { FetchResult, ProbeResult } from '@/lib/types/messaging';
  import {
    scan,
    CATEGORY_LABELS,
    CATEGORY_ORDER,
    SOURCE_LABELS,
    CONFIDENCE_LABELS,
    CONFIDENCE_COLORS,
    type SniffInput,
    type SniffMatch,
    type SniffEvidence,
  } from '@/lib/scanners/sniff-engine';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import { scanSettingsStore } from '@/stores/settings';
  import { activePanelStore } from '@/stores/ui';
  import { sniffBadgeStore } from '@/stores/sniff-badge';

  /** 框架名 → 对应分析面板 id（用于一键跳转）*/
  const FRAMEWORK_PANEL: Record<string, string> = {
    'Vue.js': 'vue', 'React': 'react', 'Angular': 'angular', 'Svelte': 'svelte',
    'Next.js': 'vue', 'Nuxt.js': 'vue', '若依框架': 'ruoyi',
  };
  function jumpToFramework(name: string) {
    const id = FRAMEWORK_PANEL[name];
    if (id) activePanelStore.set(id);
  }
  import UrlInput from '@/components/scanner/UrlInput.svelte';
  import EmptyState from '@/components/scanner/EmptyState.svelte';

  let targetUrl = $state('');
  let scanning = $state(false);
  let results = $state<SniffMatch[]>([]);
  let filter = $state('all');
  let expandedName = $state<string | null>(null);
  let cancelled = $state(false);

  // 自动填充当前页 URL
  $effect(() => {
    getActiveTabUrl().then(u => {
      if (u) targetUrl = u;
    });
  });

  // 一键操作（右键菜单 / Popup）：命中本面板则自动嗅探
  $effect(() => {
    const sig = $autoRunStore;
    if (sig && sig.panel === 'sniff') {
      autoRunStore.clear();
      if (sig.url) targetUrl = sig.url;
      startScan();
    }
  });

  // 按分类分组（使用 CATEGORY_ORDER 排序）
  let groupedResults = $derived.by(() => {
    const groups: { category: string; label: string; items: SniffMatch[] }[] = [];

    for (const cat of CATEGORY_ORDER) {
      // filter 为分类筛选：'all' 显示全部，否则只显示该分类
      if (filter !== 'all' && filter !== cat) continue;
      const items = results.filter(r => r.category === cat);
      if (items.length > 0) {
        groups.push({ category: cat, label: CATEGORY_LABELS[cat] || cat, items });
      }
    }

    // 追加不在 CATEGORY_ORDER 中的分类
    const seen = new Set(CATEGORY_ORDER);
    for (const r of results) {
      if (!seen.has(r.category)) {
        const cat = r.category;
        const items = results.filter(x => x.category === cat);
        if (items.length > 0) {
          groups.push({ category: cat, label: CATEGORY_LABELS[cat] || cat, items });
          seen.add(cat);
        }
      }
    }

    return groups;
  });

  let techCount = $derived(results.length);
  let catCount = $derived(new Set(results.map(r => r.category)).size);

  // 映射 SniffMatch[] → ScanFinding[]
  function mapSniffToFindings(matches: SniffMatch[]): ScanFinding[] {
    return matches.map((m) => ({
      title: `${m.name}${m.version ? ` v${m.version}` : ''} (${m.category})`,
      severity: (m.confidenceLevel === 'strong' ? 'medium' : 'info') as ScanFinding['severity'],
      detail: `置信度 ${m.confidence}/100 (${CONFIDENCE_LABELS[m.confidenceLevel]})\n${m.evidences.map((e) => `[${e.source}] ${e.evidence}`).join('\n')}`,
      url: targetUrl,
    }));
  }

  /** 从 HTML 中提取 script src 和 meta 标签 */
  function parseHtml(html: string): { scriptSrcs: string[]; meta: { name: string; content: string }[] } {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');

    // 提取 script src
    const scriptSrcs: string[] = [];
    for (const s of doc.querySelectorAll('script[src]')) {
      const src = s.getAttribute('src');
      if (src) scriptSrcs.push(src);
    }

    // 提取 meta 标签
    const meta: { name: string; content: string }[] = [];
    for (const m of doc.querySelectorAll('meta')) {
      const name = m.getAttribute('name') || m.getAttribute('http-equiv') || '';
      const content = m.getAttribute('content') || '';
      if (name) meta.push({ name, content });
    }

    return { scriptSrcs, meta };
  }

  async function startScan() {
    const v = validateProbeUrl(targetUrl);
    if ('error' in v) {
      toastStore.show('请输入合法的 http(s) URL', 'error');
      return;
    }

    scanning = true;
    cancelled = false;
    results = [];
    expandedName = null;

    try {
      // 并发获取 HTML 和 headers
      const [fetchRes, probeRes] = await Promise.all([
        sendMessage({ type: 'FETCH_URL', url: v.parsed.href, timeout: $scanSettingsStore.requestTimeoutMs }) as Promise<FetchResult<string>>,
        sendMessage({ type: 'FETCH_PROBE', url: v.parsed.href, method: 'GET', timeout: $scanSettingsStore.requestTimeoutMs }) as Promise<ProbeResult>,
      ]);

      if (cancelled) {
        scanning = false;
        toastStore.show('扫描已取消', 'info');
        return;
      }

      // 检查 HTML 获取
      let html = '';
      if ('success' in fetchRes && fetchRes.success) {
        html = fetchRes.data;
      } else {
        toastStore.show('获取页面内容失败', 'warning');
        scanning = false;
        return;
      }

      // 提取 headers
      const headers: Record<string, string> = {};
      if (probeRes && !probeRes.error && probeRes.headers) {
        for (const [k, val] of Object.entries(probeRes.headers)) {
          headers[k.toLowerCase()] = val;
        }
      }

      // 解析 HTML 中的 script src 和 meta
      const { scriptSrcs, meta } = parseHtml(html);

      // 通过 MAIN world 注入采集页面运行时信号：全局变量/类名/id/cookies/版本
      // 这让 sniff 引擎中 40% 的 globals/classNames/cookies 匹配器得以生效
      let globals: string[] = [];
      let classNames: string[] = [];
      let ids: string[] = [];
      let versions: Record<string, string> = {};
      const cookieMap: Record<string, string> = {};
      try {
        const fp = await sendToContent({ type: 'VK_PAGE_INSPECT', action: 'fingerprint' }) as any;
        if (fp && typeof fp === 'object') {
          if (Array.isArray(fp.globals)) globals = fp.globals;
          if (Array.isArray(fp.classNames)) classNames = fp.classNames;
          if (Array.isArray(fp.cookies)) {
            for (const c of fp.cookies) {
              const eq = c.indexOf('=');
              if (eq > 0) cookieMap[c.slice(0, eq).trim()] = c.slice(eq + 1).trim();
            }
          }
          if (fp.versions && typeof fp.versions === 'object' && !Array.isArray(fp.versions)) {
            versions = fp.versions;
          }
          // ids 可能是逗号分隔字符串或数组
          if (Array.isArray(fp.ids)) ids = fp.ids;
          else if (typeof fp.ids === 'string' && fp.ids) ids = fp.ids.split(',').map((s: string) => s.trim()).filter(Boolean);
        }
      } catch { /* 非当前标签页或注入失败，降级为纯静态分析 */ }

      // 构建 SniffInput 并扫描
      const input: SniffInput = {
        html,
        headers,
        scriptSrcs,
        cookies: cookieMap,
        meta,
        globals,
        classNames,
        ids,
        versions,
      };

      results = scan(input);

      if (results.length > 0) {
        toastStore.show(`识别 ${results.length} 项技术，涵盖 ${catCount} 个分类`, 'success');
      } else {
        toastStore.show('未检测到任何技术特征', 'info');
      }

      // 写入侧栏徽标：取置信度最高的若干项（带版本优先），供侧栏按钮显示
      try {
        const badgeItems = [...results]
          .sort((a, b) => b.confidence - a.confidence)
          .slice(0, 5)
          .map(r => ({ name: r.name, version: r.version || undefined }));
        sniffBadgeStore.set(badgeItems);
      } catch { /* 徽标失败不影响扫描 */ }

      try {
        await scanHistoryStore.addScan({
          url: targetUrl,
          module: 'sniff',
          findings: mapSniffToFindings(results),
        });
      } catch { /* store failure must not break scan */ }
    } catch (err: any) {
      toastStore.show('扫描出错: ' + (err.message || '未知错误'), 'warning');
    } finally {
      scanning = false;
    }
  }

  function cancel() { cancelled = true; }

  function toggleExpand(name: string) {
    expandedName = expandedName === name ? null : name;
  }

  function copyResults() {
    if (results.length === 0) {
      toastStore.show('没有可复制的结果', 'warning');
      return;
    }
    const lines = results.map(r => `${r.name}${r.version ? ' v' + r.version : ''} [${r.category}] 置信${r.confidence}(${CONFIDENCE_LABELS[r.confidenceLevel]}) (${r.matchedCount} 匹配)`);
    navigator.clipboard.writeText(lines.join('\n'));
    toastStore.show(`已复制 ${lines.length} 项技术指纹`, 'success');
  }

  function copyMarkdown() {
    if (results.length === 0) {
      toastStore.show('没有可复制的结果', 'warning');
      return;
    }
    const lines = [`# 网站技术指纹嗅探`, ``, `**目标:** ${targetUrl}`, ``, `## 识别技术 (${results.length})`];
    for (const g of groupedResults) {
      lines.push(``, `### ${g.label} (${g.items.length})`);
      for (const r of g.items) {
        lines.push(`- **${r.name}**${r.version ? ` v${r.version}` : ''} — 置信 ${r.confidence}/100 (${CONFIDENCE_LABELS[r.confidenceLevel]})`);
      }
    }
    navigator.clipboard.writeText(lines.join('\n'));
    toastStore.show('Markdown 已复制', 'success');
  }

  function exportResults() {
    if (results.length === 0) {
      toastStore.show('没有可导出的结果', 'warning');
      return;
    }
    const exportData = results.map(r => ({
      name: r.name,
      category: r.category,
      version: r.version || null,
      confidence: r.confidence,
      confidenceLevel: r.confidenceLevel,
      matchCount: r.matchedCount,
      evidences: r.evidences.map(e => ({
        source: e.source,
        evidence: typeof e.evidence === 'string' ? e.evidence.substring(0, 200) : null,
      })),
    }));
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sniff-results-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toastStore.show('已导出 JSON', 'success');
  }
</script>

<div class="space-y-3">
  <!-- 输入 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <UrlInput bind:value={targetUrl} {scanning} buttonText="检测" onscan={startScan} />
      {#if scanning}
        <button class="btn btn-sm btn-danger shrink-0" onclick={cancel}>取消</button>
      {/if}
    </div>
    {#if scanning}
      <div class="text-xs text-gray-400">正在获取页面并分析技术指纹...</div>
    {/if}
  </div>

  <!-- 统计摘要 -->
  {#if results.length > 0}
    <div class="card p-3">
      <div class="flex items-center gap-3 text-sm">
        <span>识别 <strong class="text-primary">{techCount}</strong> 项技术</span>
        <span class="text-gray-300 dark:text-gray-600">|</span>
        <span>涵盖 <strong class="text-primary">{catCount}</strong> 个分类</span>
        <div class="ml-auto flex gap-1">
          <button class="btn btn-sm" onclick={copyResults}>复制</button>
          <button class="btn btn-sm" onclick={copyMarkdown}>MD</button>
          <button class="btn btn-sm" onclick={exportResults}>导出</button>
        </div>
      </div>
    </div>
  {/if}

  <!-- 分类标签区 -->
  {#if results.length > 0}
    <div class="flex flex-wrap items-center gap-1.5 text-xs">
      <button
        class="badge {filter === 'all' ? 'bg-primary text-white' : 'bg-gray-200 dark:bg-gray-700'}"
        onclick={() => (filter = 'all')}>全部 {techCount}</button>
      {#each groupedResults as group}
        <button
          class="badge {filter === group.category ? 'bg-primary text-white' : 'bg-gray-200 dark:bg-gray-700'}"
          onclick={() => (filter = group.category)}>
          {group.label} {group.items.length}
        </button>
      {/each}
    </div>
  {/if}

  <!-- 分类结果 -->
  {#if groupedResults.length > 0}
    <div class="space-y-3">
      {#each groupedResults as group (group.category)}
        <div class="space-y-1.5">
          <div class="text-xs font-medium text-gray-400 px-1">
            {group.label}
            <span class="badge text-xs bg-gray-200 dark:bg-gray-700 ml-1">{group.items.length}</span>
          </div>
          <div class="flex flex-wrap gap-1.5">
            {#each group.items as item (item.name)}
              <button
                class="badge text-xs cursor-pointer {expandedName === item.name ? 'bg-primary text-white ring-2 ring-primary/30' : 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300'}"
                onclick={() => toggleExpand(item.name)}
                title="置信度 {item.confidence}/100 ({CONFIDENCE_LABELS[item.confidenceLevel]})"
              >
                {item.name}
                {#if item.version}
                  <span class="opacity-70 font-mono">v{item.version}</span>
                {/if}
                <span class="ml-0.5 px-1 rounded {CONFIDENCE_COLORS[item.confidenceLevel]}">{CONFIDENCE_LABELS[item.confidenceLevel]}</span>
                {#if FRAMEWORK_PANEL[item.name]}
                  <span
                    class="ml-0.5 opacity-70 hover:opacity-100"
                    role="button"
                    tabindex="0"
                    title="跳转到 {FRAMEWORK_PANEL[item.name]} 分析面板"
                    onclick={(e) => { e.stopPropagation(); jumpToFramework(item.name); }}
                    onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.stopPropagation(); e.preventDefault(); jumpToFramework(item.name); } }}
                  >→</span>
                {/if}
              </button>
            {/each}
          </div>
          <!-- 展开证据 -->
          {#each group.items as item (item.name)}
            {#if expandedName === item.name && item.evidences.length > 0}
              <div class="card p-2.5 space-y-1 ml-2">
                <div class="text-xs font-medium text-gray-500">{item.name} 匹配证据</div>
                {#each item.evidences as ev (ev.source + ev.evidence)}
                  <div class="flex items-start gap-2 text-xs">
                    <span class="badge shrink-0 text-xs bg-gray-200 dark:bg-gray-700">{SOURCE_LABELS[ev.source] || ev.source}</span>
                    <span class="font-mono text-gray-600 dark:text-gray-300 break-all">
                      {typeof ev.evidence === 'string' && ev.evidence.length > 120 ? ev.evidence.substring(0, 120) + '...' : ev.evidence}
                    </span>
                  </div>
                {/each}
              </div>
            {/if}
          {/each}
        </div>
      {/each}
    </div>
  {:else if !scanning && results.length === 0 && techCount === 0}
    <EmptyState
      message="输入目标 URL，点击「检测」开始技术指纹嗅探"
      hint="自动识别 Web 框架、JS 库、CDN、CMS 等技术栈"
      icon="🔍"
    />
  {/if}
</div>
