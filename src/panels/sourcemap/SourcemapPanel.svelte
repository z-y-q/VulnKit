<script lang="ts">
  // Source Map 检测面板 — 灵眸 v6.0（增强版，对齐 v5 能力）
  // 检测构建工具 + JS Bundle → 抓取 → 解析 Source Map → 源码还原/查看/下载 + 内容安全扫描
  import { sendToContent, sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import UrlInput from '@/components/scanner/UrlInput.svelte';
  import ScanProgress from '@/components/scanner/ScanProgress.svelte';
  import EmptyState from '@/components/scanner/EmptyState.svelte';
  import SeverityBadge from '@/components/scanner/SeverityBadge.svelte';
  import FilterBar from '@/components/scanner/FilterBar.svelte';
  import type { FetchResult } from '@/lib/types/messaging';
  import { scanSettingsStore } from '@/stores/settings';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import { runConcurrent } from '@/lib/core/concurrency';
  import { copyText } from '@/lib/actions/clipboard';
  import { downloadText, buildFilename } from '@/lib/actions/download';
  import {
    extractScriptUrls,
    extractInlineSourceMapHints,
    extractSourceMapUrl,
    extractInlineSourceMap,
    parseSourceMap,
    classifySources,
    hasSourceContent,
    assessRisk,
    severityLabel,
    guessMapUrls,
    extractEndpoints,
    scanSecrets,
    concatSources,
    resolveWebpackChunkUrls,
    extractChunkFilenames,
    discoverChunksByHashmap,
    type DetectResult,
    type SourceMapResult,
    type EndpointFinding,
    type SecretFinding,
    type WebpackSnapshot,
  } from '@/lib/analyzers/sourcemap-analyzer';
  import { PHASE1_MAIN_WORLD_FN } from '@/lib/analyzers/sourcemap-phase1';

  type Phase = 'idle' | 'detecting' | 'detected' | 'scanning' | 'done';

  let targetUrl = $state('');
  let phase = $state<Phase>('idle');
  let detectResult = $state<DetectResult | null>(null);
  let wpSnapshot = $state<WebpackSnapshot | null>(null);
  let bundleUrls = $state<string[]>([]);
  let results = $state<SourceMapResult[]>([]);
  let scanned = $state(0);
  let total = $state(0);
  let filter = $state<'all' | 'vuln'>('all');
  let cancelled = $state(false);

  // 聚合的源码内容扫描结果
  let allEndpoints = $state<EndpointFinding[]>([]);
  let allSecrets = $state<SecretFinding[]>([]);

  // 源码查看器状态
  let viewerOpen = $state(false);
  let viewerBundle = $state<SourceMapResult | null>(null);
  let viewerFile = $state<{ path: string; content: string } | null>(null);
  let fileSearch = $state('');

  const CONCURRENCY = $derived($scanSettingsStore.concurrency);
  const MAX_SCRIPTS = 500;
  const FETCH_TIMEOUT = $derived($scanSettingsStore.requestTimeoutMs);

  $effect(() => {
    getActiveTabUrl().then(u => {
      if (u) targetUrl = u;
    });
  });

  let filteredResults = $derived.by(() => {
    if (filter === 'vuln') {
      return results.filter(r => {
        const sev = assessRisk(r);
        return sev === 'critical' || sev === 'high' || sev === 'medium';
      });
    }
    return results;
  });

  let vulnCount = $derived(
    results.filter(r => {
      const sev = assessRisk(r);
      return sev === 'critical' || sev === 'high' || sev === 'medium';
    }).length,
  );

  let leakCount = $derived(results.filter(r => r.hasContentLeak).length);
  let mapCount = $derived(results.filter(r => r.mapUrl !== null).length);
  let totalSources = $derived(results.reduce((s, r) => s + r.sourceCount, 0));

  /** Phase 1: 检测构建工具 + 收集 JS Bundle */
  async function detect() {
    if (!targetUrl || !/^https?:\/\//.test(targetUrl)) {
      toastStore.show('请输入合法的 http(s) URL', 'error');
      return;
    }

    phase = 'detecting';
    detectResult = null;
    wpSnapshot = null;
    bundleUrls = [];
    results = [];
    allEndpoints = [];
    allSecrets = [];

    // 1. 构建工具检测
    const dt = await sendToContent({ type: 'VK_SOURCEMAP_DETECT' });
    if (dt && typeof dt === 'object' && 'tool' in (dt as any)) {
      detectResult = dt as DetectResult;
    }

    // 2. 抓取页面 HTML 提取 script[src] + performance API 资源
    const bundles = new Set<string>();

    // 1.5 Phase 1：MAIN world 拦截 webpack 运行时（对齐 v5：chrome.scripting.executeScript 直接注入）
    //     - 捕获 wpRequire，枚举模块，调用 u(id) 取 chunk 文件名
    //     - Strategy 0C：混淆 bundle 的 .u() 解码器
    //     - 安装网络钩子持久捕获动态 JS
    //     - 结果直接 return（不走 postMessage/bridge 链路，避免超时和二次注入问题）
    wpSnapshot = null;
    try {
      const tab = await (await import('@/lib/core/tabs')).getActiveTab();
      if (tab?.id) {
        const { execInTab } = await import('@/lib/core/tabs');
        const wp = await execInTab<WebpackSnapshot>(tab.id, PHASE1_MAIN_WORLD_FN, { world: 'MAIN' });
        if (wp && wp.hasWebpack) wpSnapshot = wp;
      }
    } catch { /* 非 webpack 站点，忽略 */ }
    try {
      const pageRes = await sendMessage({
        type: 'FETCH_URL',
        url: targetUrl,
        timeout: FETCH_TIMEOUT,
      }) as FetchResult<string>;

      if (pageRes.success && pageRes.data) {
        const html = pageRes.data;
        for (const u of extractScriptUrls(html, targetUrl)) bundles.add(u);
        for (const u of extractInlineSourceMapHints(html, targetUrl)) bundles.add(u);
      }
    } catch {
      // 页面抓取失败，仅依赖检测
    }

    // 3. 从实时 DOM 收集 script/preload/performance（对齐 v5：读 s.src 天然 base 感知、含动态注入脚本）
    //    这比解析静态 HTML 更全 —— SPA 运行时动态注入的 chunk、modulepreload、按需加载的 script 都能拿到。
    try {
      const tab = await (await import('@/lib/core/tabs')).getActiveTab();
      if (tab?.id) {
        const { execInTab } = await import('@/lib/core/tabs');
        const dom = await execInTab(tab.id, function () {
          const urls: string[] = [];
          // 实时 DOM 的 <script src>：s.src 是浏览器解析后的绝对 URL（已应用 <base>）
          try {
            document.querySelectorAll('script[src]').forEach(function (s: any) {
              if (s.src) urls.push(s.src);
            });
          } catch { /* ignore */ }
          // preload / modulepreload
          try {
            document
              .querySelectorAll('link[rel="preload"][as="script"], link[rel="modulepreload"]')
              .forEach(function (l: any) {
                if (l.href) urls.push(l.href);
              });
          } catch { /* ignore */ }
          // performance API：含动态 fetch/import 的 JS（含跨域 CDN）
          try {
            for (const e of performance.getEntriesByType('resource')) {
              const n = (e as any).name || '';
              if (/\.m?js(\?|$)/i.test(n)) urls.push(n);
            }
          } catch { /* ignore */ }
          return urls;
        }, { world: 'MAIN' });
        if (Array.isArray(dom)) {
          for (const u of dom) {
            try { bundles.add(new URL(u, targetUrl).href); } catch { /* ignore */ }
          }
        }
      }
    } catch { /* ignore */ }

    // 3.5 合并 Phase1 webpack 清单 chunk（用已知 bundle 反推 base）+ 网络钩子捕获的动态 JS
    if (wpSnapshot) {
      for (const u of resolveWebpackChunkUrls(wpSnapshot, targetUrl, [...bundles])) bundles.add(u);
      for (const u of wpSnapshot.monitoredScripts || []) {
        try { bundles.add(new URL(u, targetUrl).href); } catch { /* ignore */ }
      }
    }

    // 4. Phase 2.5：从 main/vendor/runtime bundle 源码深度 grep 发现隐藏 chunk（v5 discoverChunksDeepParse）
    //    webpack bundle 里含 "name.hash.js" 字面量（命名 chunk + 数字 chunk 通吃），
    //    不依赖 webpack 运行时是否暴露，是最可靠的 chunk 发现手段。
    try {
      const candidates = [...bundles].filter((u) => /(runtime|main|app|vendor|bundle\/|static\/js)/i.test(u)).slice(0, 3);
      for (const burl of candidates) {
        try {
          const res = await sendMessage({
            type: 'FETCH_URL',
            url: burl,
            timeout: FETCH_TIMEOUT,
          }) as FetchResult<string>;
          if (res.success && res.data) {
            const base = burl.substring(0, burl.lastIndexOf('/') + 1);
            // (a) 完整文件名字面量 grep
            for (const f of extractChunkFilenames(res.data)) {
              try { bundles.add(new URL(f, base).href); } catch { /* ignore */ }
            }
            // (b) 哈希表解析 + 重建（webpack5 动态拼接文件名的标准情况，命名+数字 chunk 通吃）
            for (const u of discoverChunksByHashmap(res.data, base)) {
              bundles.add(u);
            }
          }
        } catch { /* ignore */ }
      }
    } catch { /* ignore */ }

    bundleUrls = [...bundles].slice(0, MAX_SCRIPTS);
    phase = 'detected';

    // 统计 Phase1 枚举的 webpack 模块数（对齐 v5：显示模块数而非仅 bundle 数）
    const wpModuleCount = wpSnapshot?.modules?.length || 0;
    const totalLabel = wpModuleCount > 0
      ? `${bundleUrls.length} 个 Bundle / ${wpModuleCount} 个模块`
      : `${bundleUrls.length} 个 JS Bundle`;

    if (detectResult?.tool) {
      toastStore.show(
        `检测到 ${detectResult.tool.toUpperCase()}，发现 ${totalLabel}`,
        'success',
      );
    } else {
      toastStore.show(
        `发现 ${totalLabel}`,
        bundleUrls.length > 0 ? 'info' : 'warning',
      );
    }

    // JS Hook 状态提示（对齐 v5：浏览其他页面可自动捕获新 Chunk）
    if (wpSnapshot?.hasWebpack) {
      try {
        const tab2 = await (await import('@/lib/core/tabs')).getActiveTab();
        if (tab2?.id) {
          const { execInTab } = await import('@/lib/core/tabs');
          const hookActive = await execInTab<boolean>(tab2.id, function () {
            return !!(window as any).__vulnkitHookActive;
          }, { world: 'MAIN' });
          if (hookActive) {
            toastStore.show('JS Hook 已激活 — 浏览其他页面可自动捕获新 Chunk，再次检测即可合并', 'info');
          }
        }
      } catch { /* ignore */ }
    }
  }

  /** Phase 2: 并发抓取 Bundle → 提取 Source Map → 分析 */
  async function scan() {
    if (bundleUrls.length === 0) {
      toastStore.show('未检测到 JS Bundle，请先点击「检测」', 'error');
      return;
    }

    phase = 'scanning';
    cancelled = false;
    results = [];
    allEndpoints = [];
    allSecrets = [];
    scanned = 0;

    const urlsToScan = bundleUrls.slice(0, MAX_SCRIPTS);
    total = urlsToScan.length;
    const collected: SourceMapResult[] = [];

    const tasks = urlsToScan.map((url) => (): Promise<SourceMapResult> => scanBundle(url));

    await runConcurrent(tasks, async (task) => {
      collected.push(await task());
      scanned++;
    }, { concurrency: CONCURRENCY, cancelled: () => cancelled });

    results = collected;

    // 聚合扫描所有泄露的源码内容
    await scanAllSourceContent();

    // 保存 findings 到扫描历史
    await saveFindings();

    phase = 'done';
    if (cancelled) {
      toastStore.show('扫描已取消', 'info');
      return;
    }
    if (vulnCount > 0) {
      toastStore.show(
        `发现 ${mapCount} 个 Source Map，${vulnCount} 个风险项，${allSecrets.length} 个密钥，${allEndpoints.length} 个端点`,
        'warning',
      );
    } else if (mapCount > 0) {
      toastStore.show(`发现 ${mapCount} 个 Source Map`, 'info');
    } else {
      toastStore.show('未发现 Source Map 文件', 'success');
    }
  }

  /** 扫描单个 Bundle：抓 JS → 找 sourceMappingURL（含路径猜测）→ 抓 .map → 解析 */
  async function scanBundle(bundleUrl: string): Promise<SourceMapResult> {
    // 1. 抓取 JS 尾部找 sourceMappingURL
    const jsRes = await sendMessage({
      type: 'FETCH_URL',
      url: bundleUrl,
      tailOnly: 4096,
      timeout: FETCH_TIMEOUT,
    }) as FetchResult<string>;

    let mapUrl: string | null = null;
    if (jsRes.success && jsRes.data) {
      mapUrl = extractSourceMapUrl(jsRes.data, bundleUrl);
    }

    // 1.5 内联 base64 source map：尾部出现 sourceMappingURL=data: 时，抓全文解析
    if (!mapUrl && jsRes.success && jsRes.data && /sourceMappingURL\s*=\s*data:/i.test(jsRes.data)) {
      const fullRes = await sendMessage({
        type: 'FETCH_URL',
        url: bundleUrl,
        timeout: FETCH_TIMEOUT,
      }) as FetchResult<string>;
      if (fullRes.success && fullRes.data) {
        const inlineInfo = extractInlineSourceMap(fullRes.data);
        if (inlineInfo) {
          const { all, sensitive } = classifySources(inlineInfo.sources);
          return {
            bundleUrl,
            mapUrl: 'inline:data:application/json',
            info: inlineInfo,
            sourceCount: all.length,
            sensitiveFiles: sensitive,
            hasContentLeak: hasSourceContent(inlineInfo),
          };
        }
      }
    }

    // 2. 若尾部未声明，按构建工具猜测 .map 路径并探测（直接抓全文，命中即可复用）
    // 注意：不能用后缀 Range 探测 —— "version" 字段在 map JSON 开头，后缀取不到。
    let mapJsonData: string | null = null;
    if (!mapUrl) {
      const guesses = guessMapUrls(bundleUrl, detectResult?.tool ?? null);
      for (const g of guesses) {
        try {
          const probe = await sendMessage({
            type: 'FETCH_URL',
            url: g,
            timeout: FETCH_TIMEOUT,
          }) as FetchResult<string>;
          // 全文抓取：命中即可复用为 map 数据（404 时 success=false，自动跳过）
          if (probe.success && probe.data && probe.data.includes('"version"')) {
            mapUrl = g;
            mapJsonData = probe.data.includes('"mappings"') ? probe.data : null;
            break;
          }
        } catch { /* ignore */ }
      }
    }

    if (!mapUrl) {
      return emptyResult(bundleUrl, null);
    }

    // 3. 抓取完整 Source Map（探测数据不完整时才重新抓取）
    let mapRes: FetchResult<string>;
    if (mapJsonData) {
      mapRes = { success: true, data: mapJsonData };
    } else {
      mapRes = await sendMessage({
        type: 'FETCH_URL',
        url: mapUrl,
        timeout: FETCH_TIMEOUT,
      }) as FetchResult<string>;
    }

    if (!mapRes.success || !mapRes.data) {
      return emptyResult(bundleUrl, mapUrl, 'Source Map 抓取失败');
    }

    const info = parseSourceMap(mapRes.data);
    if (!info) {
      return emptyResult(bundleUrl, mapUrl, 'Source Map 解析失败');
    }

    const { all, sensitive } = classifySources(info.sources);
    return {
      bundleUrl,
      mapUrl,
      info,
      sourceCount: all.length,
      sensitiveFiles: sensitive,
      hasContentLeak: hasSourceContent(info),
    };
  }

  function emptyResult(bundleUrl: string, mapUrl: string | null, error?: string): SourceMapResult {
    return {
      bundleUrl,
      mapUrl,
      info: null,
      sourceCount: 0,
      sensitiveFiles: [],
      hasContentLeak: false,
      error,
    };
  }

  /** 聚合扫描所有泄露源码：提取端点 + 密钥 */
  async function scanAllSourceContent() {
    const endpoints = new Map<string, EndpointFinding>();
    const secrets = new Map<string, SecretFinding>();
    for (const r of results) {
      if (!r.info?.sourcesContent) continue;
      const body = concatSources(r.info.sources, r.info.sourcesContent);
      for (const e of extractEndpoints(body)) {
        const k = `${e.type}::${e.value}`;
        if (!endpoints.has(k)) endpoints.set(k, e);
      }
      for (const s of scanSecrets(body)) {
        const k = `${s.rule}::${s.value}`;
        if (!secrets.has(k)) secrets.set(k, s);
      }
    }
    allEndpoints = [...endpoints.values()];
    allSecrets = [...secrets.values()];
  }

  function cancel() { cancelled = true; }

  // ===== Findings 导出 =====
  /** 基于当前扫描结果生成安全发现（对齐 v5 vk-sourcemap getFindings） */
  function getFindings(): ScanFinding[] {
    const findings: ScanFinding[] = [];
    if (results.length === 0) return findings;

    const sourcemapCount = results.filter(r => r.mapUrl !== null).length;
    const leakModules = results.filter(r => {
      const sev = assessRisk(r);
      return sev === 'critical' || sev === 'high';
    });
    const criticalCount = results.filter(r => assessRisk(r) === 'critical').length;
    const highCount = results.filter(r => assessRisk(r) === 'high').length;

    if (sourcemapCount > 0) {
      findings.push({ severity: 'high', title: 'Source Map 泄露', detail: sourcemapCount + ' 个模块暴露源码映射文件，可还原原始源码', url: targetUrl });
    }
    if (criticalCount > 0) {
      const detail = leakModules.slice(0, 3).map(m => m.bundleUrl).join(', ');
      findings.push({ severity: 'critical', title: '源码敏感信息泄露 (' + criticalCount + ' 项)', detail, url: targetUrl });
    } else if (highCount > 0) {
      const detail = leakModules.slice(0, 3).map(m => m.bundleUrl).join(', ');
      findings.push({ severity: 'high', title: '源码安全风险 (' + highCount + ' 项)', detail, url: targetUrl });
    }
    if (results.length > 0 && sourcemapCount === 0) {
      findings.push({ severity: 'medium', title: 'Webpack 模块枚举', detail: '识别 ' + results.length + ' 个前端模块', url: targetUrl });
    }
    if (allSecrets.length > 0) {
      findings.push({ severity: 'high', title: '密钥泄露 (' + allSecrets.length + ' 项)', detail: allSecrets.slice(0, 5).map(s => s.rule + ': ' + s.value.slice(0, 40)).join('; '), url: targetUrl });
    }
    return findings;
  }

  /** 将 findings 保存到扫描历史 */
  async function saveFindings() {
    const findings = getFindings();
    if (findings.length > 0 && targetUrl) {
      await scanHistoryStore.addScan({ url: targetUrl, module: 'sourcemap', findings });
    }
  }

  // ===== 源码查看器 =====
  function openViewer(r: SourceMapResult) {
    if (!r.info?.sourcesContent) {
      toastStore.show('该 Source Map 未包含源码内容', 'warning');
      return;
    }
    viewerBundle = r;
    viewerFile = null;
    fileSearch = '';
    viewerOpen = true;
  }

  let viewerFiles = $derived.by(() => {
    if (!viewerBundle?.info) return [];
    const info = viewerBundle.info;
    const list = info.sources.map((s, i) => ({
      path: s.replace(/^webpack:\/\//, ''),
      content: info.sourcesContent?.[i] ?? '',
    })).filter(f => f.content);
    if (!fileSearch.trim()) return list;
    const q = fileSearch.toLowerCase();
    return list.filter(f => f.path.toLowerCase().includes(q));
  });

  function viewFile(f: { path: string; content: string }) {
    viewerFile = f;
  }

  function downloadFile(f: { path: string; content: string }) {
    const name = f.path.split('/').pop() || 'source.js';
    const blob = new Blob([f.content], { type: 'text/plain' });
    const a = document.createElement('a');
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  /** 下载某 bundle 的全部还原源码（合并 txt） */
  function downloadAllSource(r: SourceMapResult) {
    if (!r.info?.sourcesContent) {
      toastStore.show('该 Source Map 未包含源码内容', 'warning');
      return;
    }
    let out = '';
    for (let i = 0; i < r.info.sources.length; i++) {
      const path = r.info.sources[i].replace(/^webpack:\/\//, '');
      const content = r.info.sourcesContent[i];
      if (content) {
        out += `\n\n// ===== ${path} =====\n${content}\n`;
      }
    }
    const blob = new Blob([out], { type: 'text/plain' });
    const a = document.createElement('a');
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = `sourcemap-${new URL(r.bundleUrl).pathname.split('/').pop() || 'sources'}.txt`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toastStore.show('源码已下载', 'success');
  }

  /** 复制全部模块路径 */
  function copyAllPaths(r: SourceMapResult) {
    if (!r.info) return;
    const paths = r.info.sources.map(s => s.replace(/^webpack:\/\//, '')).join('\n');
    navigator.clipboard.writeText(paths).then(
      () => toastStore.show(`已复制 ${r.info!.sources.length} 个路径`, 'success'),
      () => toastStore.show('复制失败', 'error'),
    );
  }

  function copyResult(r: SourceMapResult) {
    const lines = [
      `Bundle: ${r.bundleUrl}`,
      `Source Map: ${r.mapUrl || '(无)'}`,
      `源文件数: ${r.sourceCount}`,
      `敏感文件: ${r.sensitiveFiles.length > 0 ? r.sensitiveFiles.join(', ') : '(无)'}`,
      `源码泄露: ${r.hasContentLeak ? '是' : '否'}`,
    ];
    if (r.error) lines.push(`错误: ${r.error}`);
    navigator.clipboard.writeText(lines.join('\n')).then(
      () => toastStore.show('已复制', 'success'),
      () => toastStore.show('复制失败', 'error'),
    );
  }

  function exportResults() {
    const rows = [['bundle_url', 'map_url', 'source_count', 'sensitive_count', 'content_leak', 'severity']];
    for (const r of filteredResults) {
      rows.push([
        r.bundleUrl,
        r.mapUrl || '',
        String(r.sourceCount),
        String(r.sensitiveFiles.length),
        r.hasContentLeak ? 'yes' : 'no',
        severityLabel(assessRisk(r)),
      ]);
    }
    const csv = rows.map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n');
    downloadText(csv, buildFilename('sourcemap-results', 'csv'), 'text/csv');
    toastStore.show(`已导出 ${filteredResults.length} 条`, 'success');
  }

  function exportEndpoints() {
    if (allEndpoints.length === 0) {
      toastStore.show('没有可导出的端点', 'warning');
      return;
    }
    const json = JSON.stringify(allEndpoints, null, 2);
    downloadText(json, buildFilename('sourcemap-endpoints', 'json'), 'application/json;charset=utf-8');
    toastStore.show(`已导出 ${allEndpoints.length} 个端点`, 'success');
  }

  /** 将发现的 JS 以 <script src=真实URL> 注入页面 MAIN world，使其出现在 Chrome DevTools
   *  Sources 面板（对齐 v5 loadSourcesToDevTools：DevTools 显示真实 https://... URL）。
   *  去查询串后去重，同步注入并计数，提示与 v5 一致。
   */
  async function loadChunksToDevTools() {
    // 收集绝对 URL、去查询串、去重（与 v5 一致）
    const seen = new Set<string>();
    const jsUrls: string[] = [];
    for (const r of results) {
      if (!r.bundleUrl || r.bundleUrl.startsWith('inline:')) continue;
      if (r.bundleUrl.indexOf('://') === -1) continue;
      const url = r.bundleUrl.split('?')[0];
      if (!seen.has(url)) { seen.add(url); jsUrls.push(url); }
    }
    if (jsUrls.length === 0) {
      toastStore.show('未找到可加载的 JS 文件', 'warning');
      return;
    }
    if (!confirm(`即将加载 ${jsUrls.length} 个 JS 源文件到 DevTools Sources 面板，是否继续？`)) return;

    const tab = await (await import('@/lib/core/tabs')).getActiveTab();
    if (!tab?.id) {
      toastStore.show('无法获取当前标签页', 'warning');
      return;
    }

    // 1) 用 background FETCH_URL 校验每个 URL 确实返回 JS（不走页面 fetch，避免被站点反爬 hook
    //    包装、避免 404 兜底页 text/html 被误注入）。只保留真能加载的 URL。
    toastStore.show(`正在校验 ${jsUrls.length} 个 URL...`, 'info');
    const validSet = new Set<string>();
    await Promise.all(jsUrls.map(async (u) => {
      try {
        const r = await sendMessage({ type: 'FETCH_URL', url: u, tailOnly: 256, timeout: FETCH_TIMEOUT }) as FetchResult<string>;
        if (r.success && r.data && !/^\s*<(?:!doctype|html)/i.test(r.data)) validSet.add(u);
      } catch { /* 跳过 */ }
    }));
    const validUrls = jsUrls.filter((u) => validSet.has(u));
    if (validUrls.length === 0) {
      toastStore.show('扫到的 bundle 在该站均不可直接访问（可能需要登录态/Cookie）', 'warning');
      return;
    }

    // 2) 在 MAIN world 注入 <script src>（去 DOM 已有的），DevTools Sources 显示真实 URL
    const { execInTab } = await import('@/lib/core/tabs');
    const execAny = execInTab as any;
    const count = (await execAny(tab.id, function (urls: string[]) {
      const existing = new Set();
      document.querySelectorAll('script[src]').forEach(function (s: any) {
        if (s.src) existing.add(s.src.split('?')[0]);
      });
      let injected = 0;
      urls.forEach(function (url: string) {
        if (existing.has(url)) return;
        const script = document.createElement('script');
        script.src = url;
        script.async = true;
        document.head.appendChild(script);
        injected++;
      });
      return injected;
    }, { world: 'MAIN', args: [validUrls] })) || 0;

    if (count === 0) {
      toastStore.show('所有 JS 文件已在页面中加载', 'info');
    } else {
      toastStore.show(`${count} 个 JS 文件已注入页面，刷新 DevTools Sources 查看`, 'success');
    }
  }

  /** 生成目录树：从所有 source map 的 sources 路径构建，复制到剪贴板（对齐 v5 generateSourcemapTree） */
  function generateTree() {
    const paths: string[] = [];
    for (const r of results) {
      if (!r.info?.sources) continue;
      for (const s of r.info.sources) {
        const clean = s.replace(/^webpack:\/\//, '');
        if (clean && clean.indexOf('node_modules') === -1) paths.push(clean);
      }
    }
    if (paths.length === 0) {
      toastStore.show('没有源文件路径', 'warning');
      return;
    }
    // 构建树
    const tree: Record<string, any> = {};
    for (const p of paths) {
      const parts = p.replace(/^\.\/?/, '').split('/');
      let node = tree;
      for (const part of parts) {
        if (!node[part]) node[part] = {};
        node = node[part];
      }
    }
    function render(obj: Record<string, any>, prefix: string): string[] {
      const lines: string[] = [];
      const keys = Object.keys(obj).sort();
      keys.forEach((key, idx) => {
        const last = idx === keys.length - 1;
        lines.push(prefix + (last ? '└── ' : '├── ') + key);
        if (Object.keys(obj[key]).length > 0) {
          lines.push(...render(obj[key], prefix + (last ? '    ' : '│   ')));
        }
      });
      return lines;
    }
    const text = render(tree, '').join('\n');
    void copyText(text, `目录树已复制（${paths.length} 个文件）`);
  }

  /** 导出全部模块 JSON（对齐 v5 exportModulesJSON） */
  function exportModulesJson() {
    const modules = results.filter(r => r.info).flatMap(r =>
      (r.info?.sources || []).map((s, i) => ({
        bundle: r.bundleUrl,
        source: s.replace(/^webpack:\/\//, ''),
        hasContent: !!(r.info?.sourcesContent?.[i]),
        sensitive: r.sensitiveFiles.includes(s),
      })),
    );
    const blob = new Blob([JSON.stringify(modules, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `sourcemap-modules-${Date.now()}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    toastStore.show(`已导出 ${modules.length} 个模块`, 'success');
  }

  function shortUrl(url: string): string {
    try {
      const u = new URL(url);
      const parts = u.pathname.split('/').filter(Boolean);
      if (parts.length > 2) return '.../' + parts.slice(-2).join('/');
      return u.pathname || u.host;
    } catch {
      return url.length > 40 ? '...' + url.slice(-37) : url;
    }
  }
</script>

<div class="space-y-3">
  <!-- 输入 -->
  <div class="card p-3 space-y-2">
    <UrlInput bind:value={targetUrl} scanning={phase === 'detecting' || phase === 'scanning'} buttonText="检测" scanningText="检测中..." onscan={detect} />

    {#if detectResult}
      <div class="text-xs text-gray-400 flex flex-wrap items-center gap-1">
        {#if detectResult.tool}
          <span class="badge bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300">
            {detectResult.tool.toUpperCase()}
          </span>
          {#if detectResult.version}
            <span class="badge bg-gray-200 dark:bg-gray-700">v{detectResult.version}</span>
          {/if}
        {:else}
          <span class="text-gray-400">未识别构建工具</span>
        {/if}
        <span>{bundleUrls.length} 个 Bundle</span>
        {#if wpSnapshot?.hasWebpack}
          {@const wpModules = wpSnapshot.modules?.length || 0}
          {@const wpChunks = wpSnapshot.chunkInfo?.chunkFilenames ? Object.keys(wpSnapshot.chunkInfo.chunkFilenames).length : 0}
          <span class="badge bg-amber-100 text-amber-700 dark:bg-amber-900 dark:text-amber-300" title="webpack 运行时拦截 + 混淆解码">
            🔍 WP {wpModules} 模块{#if wpChunks}/{wpChunks} chunk{/if}
          </span>
        {/if}
      </div>
    {/if}

    {#if phase === 'detected' || phase === 'scanning' || phase === 'done'}
      <div class="flex gap-1">
        <button class="btn btn-sm btn-primary flex-1" disabled={phase === 'scanning'} onclick={scan}>
          {phase === 'scanning' ? '扫描中...' : `扫描 ${bundleUrls.length} 个 Bundle`}
        </button>
        {#if phase === 'scanning'}
          <button class="btn btn-sm btn-danger shrink-0" onclick={cancel}>取消</button>
        {/if}
      </div>
    {/if}

    <ScanProgress {scanned} {total} scanning={phase === 'detecting' || phase === 'scanning'} label="Bundle 扫描" />
  </div>

  <!-- 统计栏 -->
  {#if results.length > 0}
    <FilterBar
      active={filter}
      options={[
        { key: 'all', label: '全部', count: results.length, color: 'bg-primary text-white' },
        { key: 'vuln', label: '风险', count: vulnCount, color: 'bg-red-500 text-white' },
      ]}
      onchange={(k) => (filter = k as 'all' | 'vuln')}
    >
      <span class="badge bg-green-500 text-white">Map {mapCount}</span>
      <span class="badge bg-orange-500 text-white">泄露 {leakCount}</span>
      <span class="badge bg-blue-500 text-white">源文件 {totalSources}</span>
      <button class="btn btn-sm" onclick={exportResults}>导出 CSV</button>
      <button class="btn btn-sm" onclick={exportEndpoints}>导出 JSON</button>
      <button class="btn btn-sm" onclick={exportModulesJson} title="导出全部模块路径为 JSON">模块 JSON</button>
      <button class="btn btn-sm" onclick={generateTree} title="生成源码目录树">目录树</button>
      <button class="btn btn-sm" onclick={loadChunksToDevTools} title="将 Bundle 注入页面使其出现在 DevTools Sources">DevTools 加载</button>
    </FilterBar>
  {/if}

  <!-- 内容安全扫描结果：端点 + 密钥 -->
  {#if phase === 'done' && (allEndpoints.length > 0 || allSecrets.length > 0)}
    <div class="space-y-2">
      {#if allSecrets.length > 0}
        <div class="card p-2.5 space-y-1.5 border-red-200 dark:border-red-900/40">
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold text-red-600 dark:text-red-400">🔑 密钥泄露（{allSecrets.length}）</span>
          </div>
          <div class="space-y-1 max-h-40 overflow-y-auto">
            {#each allSecrets.slice(0, 50) as s}
              <div class="flex items-center gap-2 text-xs">
                <span class="badge {s.severity === 'high' ? 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300' : 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300'} shrink-0">{s.rule}</span>
                <code class="font-mono text-gray-600 dark:text-gray-300 truncate" title={s.value}>{s.value}</code>
              </div>
            {/each}
          </div>
        </div>
      {/if}

      {#if allEndpoints.length > 0}
        <div class="card p-2.5 space-y-1.5">
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold text-blue-600 dark:text-blue-400">🔌 API 端点（{allEndpoints.length}）</span>
            <button class="text-xs text-primary hover:underline" onclick={exportEndpoints}>导出 JSON</button>
          </div>
          <div class="flex flex-wrap gap-1 max-h-32 overflow-y-auto">
            {#each allEndpoints.slice(0, 80) as e}
              <span class="badge text-xs {e.type === 'websocket' ? 'bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300' : e.type === 'graphql' ? 'bg-pink-100 text-pink-700 dark:bg-pink-900 dark:text-pink-300' : 'bg-blue-50 text-blue-600 dark:bg-blue-950 dark:text-blue-400'} font-mono" title={e.value}>{e.value}</span>
            {/each}
            {#if allEndpoints.length > 80}
              <span class="badge text-xs bg-gray-200 dark:bg-gray-700">+{allEndpoints.length - 80}</span>
            {/if}
          </div>
        </div>
      {/if}
    </div>
  {/if}

  <!-- 结果列表 -->
  {#if filteredResults.length > 0}
    <div class="space-y-2">
      {#each filteredResults as r (r.bundleUrl)}
        {@const sev = assessRisk(r)}
        <div class="card p-2.5 space-y-1.5">
          <div class="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={sev} />
            {#if r.mapUrl}
              <span class="badge text-xs bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300">MAP</span>
            {/if}
            {#if r.hasContentLeak}
              <span class="badge text-xs bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300">源码泄露</span>
            {/if}
            <span class="badge text-xs bg-gray-200 dark:bg-gray-700">{r.sourceCount} 文件</span>
            <div class="ml-auto flex items-center gap-1">
              {#if r.hasContentLeak && r.info}
                <button class="text-xs text-primary hover:underline" onclick={() => openViewer(r)}>查看源码</button>
                <button class="text-xs text-gray-500 hover:text-primary" onclick={() => downloadAllSource(r)} title="下载全部源码">⬇</button>
                <button class="text-xs text-gray-500 hover:text-primary" onclick={() => copyAllPaths(r)} title="复制所有路径">📋</button>
              {/if}
              <button class="text-xs text-gray-400 hover:text-primary" onclick={() => copyResult(r)}>复制</button>
            </div>
          </div>
          <div class="text-xs font-mono text-gray-600 dark:text-gray-300 truncate" title={r.bundleUrl}>
            {shortUrl(r.bundleUrl)}
          </div>
          {#if r.mapUrl}
            <div class="text-xs font-mono text-gray-400 truncate" title={r.mapUrl}>
              .map: {shortUrl(r.mapUrl)}
            </div>
          {/if}
          {#if r.error}
            <div class="text-xs text-red-500">{r.error}</div>
          {/if}
          {#if r.sensitiveFiles.length > 0}
            <div class="flex flex-wrap gap-1 mt-0.5">
              {#each r.sensitiveFiles.slice(0, 8) as f}
                <span class="badge text-xs bg-red-50 text-red-600 dark:bg-red-950 dark:text-red-400" title={f}>
                  {f.split('/').pop() || f}
                </span>
              {/each}
              {#if r.sensitiveFiles.length > 8}
                <span class="badge text-xs bg-gray-200 dark:bg-gray-700">+{r.sensitiveFiles.length - 8}</span>
              {/if}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {:else if phase === 'done' && results.length === 0}
    <EmptyState message="未发现 Source Map 文件" icon="✅" />
  {:else if phase === 'idle'}
    <EmptyState message="输入目标 URL，检测 JS Bundle 和 Source Map，还原并扫描源码" icon="🗺️" />
  {/if}
</div>

<!-- 源码查看器弹窗 -->
{#if viewerOpen && viewerBundle?.info}
  <div class="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" role="dialog" aria-modal="true">
    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-4xl h-[80vh] flex flex-col overflow-hidden">
      <!-- 弹窗头 -->
      <div class="flex items-center justify-between px-4 py-2.5 border-b border-gray-200 dark:border-gray-700 shrink-0">
        <div class="flex items-center gap-2 min-w-0">
          <span class="text-sm font-bold truncate">{viewerFile ? viewerFile.path : `${viewerBundle.sourceCount} 个源文件`}</span>
          {#if viewerFile}
            <button class="text-xs text-primary hover:underline shrink-0" onclick={() => (viewerFile = null)}>← 返回列表</button>
          {/if}
        </div>
        <div class="flex items-center gap-2 shrink-0">
          {#if viewerFile}
            <button class="btn btn-sm btn-soft" onclick={() => downloadFile(viewerFile!)}>下载</button>
            <button class="btn btn-sm btn-ghost" onclick={() => navigator.clipboard.writeText(viewerFile!.content).then(() => toastStore.show('已复制', 'success'))}>复制</button>
          {/if}
          <button class="btn btn-sm btn-ghost" onclick={() => (viewerOpen = false)}>关闭</button>
        </div>
      </div>

      <!-- 弹窗内容 -->
      {#if viewerFile}
        <pre class="flex-1 overflow-auto p-3 text-xs font-mono text-gray-800 dark:text-gray-200 bg-gray-50 dark:bg-gray-900/50 whitespace-pre">{viewerFile.content}</pre>
      {:else}
        <div class="flex-1 flex flex-col overflow-hidden">
          <div class="px-3 py-2 border-b border-gray-100 dark:border-gray-700/50">
            <input class="input text-xs" placeholder="搜索文件路径..." bind:value={fileSearch} />
          </div>
          <div class="flex-1 overflow-y-auto p-2 space-y-0.5">
            {#each viewerFiles as f (f.path)}
              <div class="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-blue-50 dark:hover:bg-blue-900/20 cursor-pointer group" onclick={() => viewFile(f)} onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); viewFile(f); } }} role="button" tabindex="0">
                <span class="text-gray-400 text-xs">📄</span>
                <span class="text-xs font-mono text-gray-700 dark:text-gray-300 truncate flex-1">{f.path}</span>
                <span class="text-[10px] text-gray-400 shrink-0">{(f.content.length / 1024).toFixed(1)}KB</span>
                <button class="opacity-0 group-hover:opacity-100 text-xs text-gray-400 hover:text-primary shrink-0" onclick={(e) => { e.stopPropagation(); downloadFile(f); }}>⬇</button>
              </div>
            {/each}
            {#if viewerFiles.length === 0}
              <div class="text-center text-xs text-gray-400 py-8">无匹配文件</div>
            {/if}
          </div>
        </div>
      {/if}
    </div>
    <button type="button" class="absolute inset-0 -z-10 cursor-default" aria-label="关闭源码查看器" onclick={() => (viewerOpen = false)}></button>
  </div>
{/if}
