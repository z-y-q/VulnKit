<script lang="ts">
  // 网站嗅探面板
  // 流程：自动填充 URL → FETCH_URL 获取 HTML + FETCH_PROBE 获取 headers → 解析 meta/scriptSrc → scan() 匹配 → 分类标签展示
  import { sendMessage, sendToContent } from '@/lib/core/messaging';
  import { getActiveTabUrl, getActiveTab, execInTab } from '@/lib/core/tabs';
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
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import ErrorState from '@/components/feedback/ErrorState.svelte';
  import { createTaskController, IDLE, type TaskState } from '@/lib/tasks/task-controller';

  /** 框架名 → 对应分析面板 id（用于一键跳转）*/
  const FRAMEWORK_PANEL: Record<string, string> = {
    'Vue.js': 'vue', 'React': 'react', 'Angular': 'angular', 'Svelte': 'svelte',
    'Next.js': 'react', 'Nuxt.js': 'vue', '若依框架': 'ruoyi',
  };
  function jumpToFramework(name: string) {
    const id = FRAMEWORK_PANEL[name];
    if (id) activePanelStore.set(id);
  }
  import UrlInput from '@/components/scanner/UrlInput.svelte';
  import EmptyState from '@/components/scanner/EmptyState.svelte';

  let targetUrl = $state('');
  let results = $state<SniffMatch[]>([]);
  let filter = $state('all');
  let expandedName = $state<string | null>(null);
  // JS 内容扫描：SPA 的技术特征大多在同源 bundle/CSS 里（Wappalyzer 同款思路），默认开启
  let useJsScan = $state(true);
  // 内容抓取诊断（每次扫描后更新，显示在统计摘要下方）
  let contentScanDiag = $state('');

  // 自动填充当前页 URL
  $effect(() => {
    getActiveTabUrl().then(u => {
      if (u) targetUrl = u;
    });
  });

  // —— TaskController 接管扫描状态机 ——
  const controller = createTaskController<{ url: string }, void>({
    validate: (input) => {
      const v = validateProbeUrl(input.url);
      if ('error' in v) throw new Error('请输入合法的 http(s) URL');
    },
    run: async (input, ctx) => {
      const v = validateProbeUrl(input.url);
      if ('error' in v) throw new Error('无效的目标 URL');
      ctx.reportProgress({ phase: '获取页面内容' });
      results = [];
      expandedName = null;

      const [fetchRes, probeRes] = await Promise.all([
        sendMessage({ type: 'FETCH_URL', url: v.parsed.href, timeout: $scanSettingsStore.requestTimeoutMs }) as Promise<FetchResult<string>>,
        sendMessage({ type: 'FETCH_PROBE', url: v.parsed.href, method: 'GET', timeout: $scanSettingsStore.requestTimeoutMs }) as Promise<ProbeResult>,
      ]) as [FetchResult<string>, ProbeResult];

      let html = '';
      if ('success' in fetchRes && fetchRes.success) {
        html = fetchRes.data;
      } else {
        throw new Error('获取页面内容失败');
      }

      const headers: Record<string, string> = {};
      if (probeRes && !probeRes.error && probeRes.headers) {
        for (const [k, val] of Object.entries(probeRes.headers)) {
          headers[k.toLowerCase()] = val;
        }
      }

      ctx.reportProgress({ phase: '解析页面信号' });
      const { scriptSrcs, styleHrefs, meta } = parseHtml(html);

      let globals: string[] = [];
      let classNames: string[] = [];
      let ids: string[] = [];
      let versions: Record<string, string> = {};
      let domHtml = '';
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
          if (Array.isArray(fp.ids)) ids = fp.ids;
          else if (typeof fp.ids === 'string' && fp.ids) ids = fp.ids.split(',').map((s: string) => s.trim()).filter(Boolean);
          if (typeof fp.domHtml === 'string') domHtml = fp.domHtml;
        }
      } catch { /* 非当前标签页或注入失败，降级为纯静态分析 */ }

      // SPA 的响应 HTML 是空壳：运行时 DOM 与同源 JS/CSS 内容才是技术痕迹的主场
      // （Wappalyzer 同款思路）。限同源前 5 个 bundle + 3 个样式表、单个 300KB——
      // 混淆 bundle 的字符串是密文，但 UI 框架的 CSS 特征选择器（.ant-* 等）
      // 混淆器碰不到，是最可靠的载体。
      //
      // 抓取位置必须优先页面自身（execInTab）：带瑞数/账号通这类动态防护的站点，
      // background 的 fetch 没有 cookie 和验证上下文，拿到的是 412 挑战页而非真内容；
      // 页面内同源 fetch 与页面自己加载资源的行为完全一致，不会被拦。
      if (useJsScan && (scriptSrcs.length > 0 || styleHrefs.length > 0)) {
        ctx.reportProgress({ phase: '扫描同源 JS/CSS 内容' });
        const abs = (s: string) => { try { return new URL(s, v.parsed.href).href; } catch { return ''; } };
        const origin = new URL(v.parsed.href).origin;
        const sameOrigin = (s: string) => { try { return new URL(s, v.parsed.href).origin === origin; } catch { return false; } };
        const jsUrls = [...new Set(scriptSrcs)].filter(sameOrigin).map(abs).filter(Boolean).slice(0, 5);
        const cssUrls = [...new Set(styleHrefs)].filter(sameOrigin).map(abs).filter(Boolean).slice(0, 3);
        const targets = [...jsUrls, ...cssUrls];

        // 首选：页面内抓取（同源 + 页面 cookie + 已通过的防护验证上下文）。
        // 两阶段设计（kick off 同步启动 fetch → 轮询读取），不依赖
        // executeScript 对注入函数返回 Promise 的等待行为（各 Chrome 版本不一致）。
        // 每个资源保留「头 500KB + 尾 400KB」两段——UI 框架的 CSS 规则可能
        // 排在整个文件的任何位置（aaas 实测 .ant-btn 在 1.9MB CSS 的末尾 5KB 处）。
        const fetched: Record<string, string> = {};
        let pageOk = false;
        const tab = await getActiveTab();
        if (tab?.id && targets.length > 0) {
          try {
            const kicked = await execInTab<boolean>(tab.id, function (urls: string[]) {
              const w = window as any;
              const st = (w.__vkSniffGrab = { out: {} as Record<string, string>, done: false });
              Promise.all(
                urls.map(function (u: string) {
                  return fetch(u, { credentials: 'include' })
                    .then(function (r: any) { return r.ok ? r.text() : ''; })
                    .catch(function () { return ''; });
                }),
              ).then(function (texts: string[]) {
                urls.forEach(function (u: string, i: number) {
                  const t = String(texts[i] || '');
                  if (!t) return;
                  const head = t.slice(0, 500000);
                  const tail = t.length > 600000 ? '\n[...尾部...] ' + t.slice(-400000) : '';
                  st.out[u] = head + tail;
                });
                st.done = true;
              });
              return true;
            }, { world: 'ISOLATED', args: [targets] });
            if (kicked) {
              pageOk = true;
              // 轮询读取结果（最多 6 秒）
              for (let pi = 0; pi < 20; pi++) {
                if (ctx.signal.aborted) break;
                await new Promise((r) => setTimeout(r, 300));
                const st = await execInTab<{ done: boolean; out: Record<string, string> } | null>(tab.id, function () {
                  const s = (window as any).__vkSniffGrab;
                  return s ? { done: !!s.done, out: s.out } : null;
                }, { world: 'ISOLATED' });
                if (st?.done) {
                  Object.assign(fetched, st.out || {});
                  break;
                }
              }
            }
          } catch { /* 页面内抓取失败（无 tab / 跨域 tab），走 background 降级 */ }
        }

        // 降级：页面内没抓到的走 background；CSS 补尾部通道
        // （fetchUrl tailOnly: Range 206 直达尾部；服务器不支持 Range 时降级全文）
        const pending = targets.filter((u) => !fetched[u]);
        const pendingCss = pending.filter((u) => /\.css(\?|$)/i.test(u));
        if (pendingCss.length > 0) {
          const texts = await Promise.allSettled(
            pendingCss.map((u) => sendMessage({ type: 'FETCH_URL', url: u, tailOnly: 400000, maxBytes: 400000, timeout: $scanSettingsStore.requestTimeoutMs })),
          );
          for (const r of texts) {
            if (r.status === 'fulfilled') {
              const res = r.value as any;
              if (res && res.success && typeof res.data === 'string') html += '\n' + res.data;
            }
          }
        }
        let totalBytes = 0;
        for (const u of targets) {
          if (fetched[u]) { html += '\n' + fetched[u]; totalBytes += fetched[u].length; }
        }
        contentScanDiag = `页面内通道 ${pageOk ? '启动' : '未启动'} · 抓取 ${Object.keys(fetched).length}/${targets.length} · 注入 ${totalBytes} 字节`;
      }
      if (domHtml) html += '\n' + domHtml;

      ctx.reportProgress({ phase: '匹配规则' });
      const sniffInput: SniffInput = { html, headers, scriptSrcs, cookies: cookieMap, meta, globals, classNames, ids, versions };
      results = scan(sniffInput);

      try {
        const badgeItems = [...results]
          .sort((a, b) => b.confidence - a.confidence)
          .slice(0, 5)
          .map(r => ({ name: r.name, version: r.version || undefined }));
        sniffBadgeStore.set(badgeItems);
      } catch { /* 徽标失败不影响扫描 */ }

      try {
        await scanHistoryStore.addScan({ url: input.url, module: 'sniff', findings: mapSniffToFindings(results) });
      } catch { /* store failure must not break scan */ }
    },
  }, { centerPanel: 'sniff', centerLabel: '网站嗅探' });

  let cs = $state<TaskState>({ ...IDLE });
  $effect(() => controller.state.subscribe((v: TaskState) => { cs = v; }));
  let archiving = $derived(cs.status === 'running' || cs.status === 'paused' || cs.status === 'validating');

  async function handleScan() {
    const r = await controller.start({ url: targetUrl });
    if (r.status === 'succeeded') {
      if (results.length > 0) {
        toastStore.show(`识别 ${results.length} 项技术，涵盖 ${catCount} 个分类`, 'success');
      } else {
        toastStore.show('未检测到任何技术特征', 'info');
      }
    } else if (r.status === 'cancelled') {
      toastStore.show('扫描已取消', 'info');
    }
  }

  // 一键操作（右键菜单 / Popup）：命中本面板则自动嗅探
  $effect(() => {
    const sig = $autoRunStore;
    if (sig && sig.panel === 'sniff') {
      autoRunStore.clear();
      if (sig.url) targetUrl = sig.url;
      handleScan();
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
  function parseHtml(html: string): { scriptSrcs: string[]; styleHrefs: string[]; meta: { name: string; content: string }[] } {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');

    // 提取 script src
    const scriptSrcs: string[] = [];
    for (const s of doc.querySelectorAll('script[src]')) {
      const src = s.getAttribute('src');
      if (src) scriptSrcs.push(src);
    }

    // 提取样式表（UI 框架的编译产物 CSS 含 .ant-* / .el-* 等特征选择器，
    // 混淆器不碰 CSS —— 这是混淆 SPA 上 UI 框架最可靠的指纹载体）
    const styleHrefs: string[] = [];
    for (const l of doc.querySelectorAll('link[rel="stylesheet"]')) {
      const href = l.getAttribute('href');
      if (href) styleHrefs.push(href);
    }

    // 提取 meta 标签
    const meta: { name: string; content: string }[] = [];
    for (const m of doc.querySelectorAll('meta')) {
      const name = m.getAttribute('name') || m.getAttribute('http-equiv') || '';
      const content = m.getAttribute('content') || '';
      if (name) meta.push({ name, content });
    }

    return { scriptSrcs, styleHrefs, meta };
  }

  function toggleExpand(name: string) {
    expandedName = expandedName === name ? null : name;
  }

  // —— 导出/复制序列化器（统一走 ExportMenu；修原 navigator.clipboard 未 await）——
  function sniffJson(items: SniffMatch[]): string {
    return JSON.stringify(
      items.map((r) => ({
        name: r.name,
        category: r.category,
        version: r.version || null,
        confidence: r.confidence,
        confidenceLevel: r.confidenceLevel,
        matchCount: r.matchedCount,
        evidences: r.evidences.map((e) => ({
          source: e.source,
          evidence: typeof e.evidence === 'string' ? e.evidence.substring(0, 200) : null,
        })),
      })),
      null,
      2,
    );
  }
  function sniffMd(items: SniffMatch[]): string {
    const lines = [`# 网站技术指纹嗅探`, ``, `**目标:** ${targetUrl}`, ``, `## 识别技术 (${items.length})`];
    for (const r of items) {
      lines.push(
        `- **${r.name}**${r.version ? ` v${r.version}` : ''} [${r.category}] — 置信 ${r.confidence}/100 (${CONFIDENCE_LABELS[r.confidenceLevel]})`,
      );
    }
    return lines.join('\n');
  }
  function sniffText(items: SniffMatch[]): string {
    return items
      .map((r) => `${r.name}${r.version ? ' v' + r.version : ''} [${r.category}] 置信${r.confidence}(${CONFIDENCE_LABELS[r.confidenceLevel]}) (${r.matchedCount} 匹配)`)
      .join('\n');
  }
</script>

<div class="space-y-3">
  <!-- 输入 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <UrlInput bind:value={targetUrl} scanning={archiving} buttonText="检测" onscan={handleScan} />
      {#if archiving}
        <button class="btn btn-sm btn-danger shrink-0" onclick={() => controller.cancel()} disabled={!cs.canCancel}>取消</button>
      {/if}
    </div>
    <label class="text-xs text-gray-500 flex items-center gap-1 cursor-pointer" title="抓取同源前 5 个 bundle + 3 个样式表扫描技术特征，SPA 检出率的关键">
      <input type="checkbox" class="checkbox checkbox-xs" bind:checked={useJsScan} />
      内容扫描
    </label>
    {#if archiving}
      <div class="text-xs text-gray-500">{cs.phase || '扫描中...'}</div>
    {/if}
  </div>

  <!-- 统计摘要 -->
  {#if results.length > 0}
    <div class="card p-3">
      <div class="flex items-center gap-3 text-sm">
        <span>识别 <strong class="text-primary">{techCount}</strong> 项技术</span>
        <span class="text-gray-300 dark:text-gray-600">|</span>
        <span>涵盖 <strong class="text-primary">{catCount}</strong> 个分类</span>
        <div class="ml-auto">
          <ExportMenu items={results} module="sniff" serializers={{ json: sniffJson, markdown: sniffMd, text: sniffText }} />
        </div>
      </div>
      {#if contentScanDiag}
        <div class="text-[10px] text-gray-400 mt-1.5 font-mono">内容抓取: {contentScanDiag}</div>
      {/if}
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
          <div class="text-xs font-medium text-gray-500 px-1">
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
  {:else if cs.status === 'failed'}
    <ErrorState error={cs.error!} onRetry={handleScan} />
  {:else if !archiving && results.length === 0 && techCount === 0}
    <EmptyState
      message="输入目标 URL，点击「检测」开始技术指纹嗅探"
      hint="自动识别 Web 框架、JS 库、CDN、CMS 等技术栈"
      icon="🔍"
    />
  {/if}
</div>
