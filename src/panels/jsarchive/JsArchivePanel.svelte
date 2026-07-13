<script lang="ts">
  // JS 归档面板 — 灵眸 v7.2
  // 收集当前页面所有 JS（DOM script + preload + performance + inline）→ 按原始 URL 路径
  // 组织进 zip → 下载，供本地安全审计。
  //
  // 资源预算（P0-2）：单响应 PER_FETCH_MAX_BYTES + 整档累计 MAX_ARCHIVE_BYTES，
  //   超累计预算的剩余条目标记 skip，不发请求，避免扩展 OOM。
  // 取消语义（P0-3）：显式状态机 + 各阶段边界检查，取消后绝不再触发下载/「成功」。
  // 压缩降级（P1-9）：zipSync 用 level 3，打包前 await tick() 让出主线程一次。
  import { tick } from 'svelte';
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTab, getActiveTabUrl, execInTab } from '@/lib/core/tabs';
  import { runConcurrent } from '@/lib/core/concurrency';
  import { toastStore } from '@/stores/ui';
  import { zipSync, strToU8 } from 'fflate';
  import EmptyState from '@/components/scanner/EmptyState.svelte';
  import {
    urlToZipPath,
    dedupePaths,
    isArchiveableScript,
    buildManifest,
    type ArchiveEntry,
  } from '@/lib/scanners/js-archive';
  import type { FetchResult } from '@/lib/types/messaging';

  /** 脚本来源置信度（与 ArchiveEntry.source 对齐） */
  type ArchiveSource = 'dom' | 'preload' | 'performance';

  // —— 上限常量 ——
  const MAX_SCRIPTS = 400;          // 单页 JS 数量上限
  const MAX_INLINE = 50;            // 内联脚本条数上限
  const MAX_INLINE_BYTES = 512_000; // 单条内联脚本字节上限
  const FETCH_TIMEOUT = 20_000;
  // 单次 FETCH_URL 响应上限（background 再夹紧到 20MB 硬顶）
  const PER_FETCH_MAX_BYTES = 5 * 1024 * 1024;
  // 整个归档的累计字节预算：超过即跳过剩余抓取并标注，避免内存爆涨
  const MAX_ARCHIVE_BYTES = 100 * 1024 * 1024;

  // 终端/进行中状态机：取消后不再误报「成功」
  type Status = 'idle' | 'collecting' | 'fetching' | 'packaging' | 'completed' | 'cancelled' | 'failed';

  let pageUrl = $state('');
  let status = $state<Status>('idle');
  let phase = $state('');         // 当前阶段提示文案
  let scanned = $state(0);
  let total = $state(0);
  let currentFile = $state('');
  let entries = $state<ArchiveEntry[]>([]);
  let lastBytes = $state(0);      // 上次产物大小
  let collectedBytes = $state(0); // 已收集累计字节（预算追踪）

  // 取消信号：true 后各阶段在边界处短路（非响应式，避免与 $state 触发额外渲染）
  let cancelRequested = false;

  // 选项
  let includeInline = $state(true);

  // 进行中 / 终端态派生
  let archiving = $derived(status === 'collecting' || status === 'fetching' || status === 'packaging');
  let terminal = $derived(status === 'completed' || status === 'cancelled' || status === 'failed');

  $effect(() => {
    getActiveTabUrl().then(u => { if (u) pageUrl = u; });
  });

  let okCount = $derived(entries.filter(e => e.status === 'ok').length);
  let failCount = $derived(entries.filter(e => e.status === 'fail').length);
  let skipCount = $derived(entries.filter(e => e.status === 'skip').length);
  let progress = $derived(total > 0 ? Math.round((scanned / total) * 100) : 0);

  /** 在页面 MAIN world 收集所有脚本 URL（按来源分组）+ 内联脚本内容 */
  async function gatherFromPage(): Promise<{
    dom: string[]; preload: string[]; performance: string[]; inline: string[];
  }> {
    const tab = await getActiveTab();
    if (!tab?.id) return { dom: [], preload: [], performance: [], inline: [] };
    const dom = await execInTab(tab.id, function () {
      const domUrls: string[] = [];
      const preloadUrls: string[] = [];
      const perfUrls: string[] = [];
      const inline: string[] = [];
      // 1) DOM script[src]：高置信，HTML 语义上就是脚本
      try {
        document.querySelectorAll('script[src]').forEach(function (s: any) {
          if (s.src) domUrls.push(s.src);
        });
      } catch { /* ignore */ }
      // 2) preload / modulepreload link：高置信
      try {
        document
          .querySelectorAll('link[rel="preload"][as="script"], link[rel="modulepreload"]')
          .forEach(function (l: any) { if (l.href) preloadUrls.push(l.href); });
      } catch { /* ignore */ }
      // 3) performance 资源：仅收 script/link 发起的，或带 .js 后缀的（排除图片/字体/CSS）
      try {
        for (const e of performance.getEntriesByType('resource')) {
          const n = (e as any).name || '';
          const init = (e as any).initiatorType || '';
          if (init === 'script' || init === 'link' || /\.m?js(\?|#|$)/i.test(n)) {
            perfUrls.push(n);
          }
        }
      } catch { /* ignore */ }
      // 4) 内联脚本
      try {
        document.querySelectorAll('script:not([src])').forEach(function (s: any) {
          const t = (s.textContent || '').trim();
          if (t) inline.push(t);
        });
      } catch { /* ignore */ }
      return { dom: domUrls, preload: preloadUrls, performance: perfUrls, inline };
    }, { world: 'MAIN' });
    return dom || { dom: [], preload: [], performance: [], inline: [] };
  }

  /** 主流程：收集 → 抓取 → 打包 → 下载 */
  async function archiveAll() {
    if (archiving) return;
    if (!pageUrl) { toastStore.show('未识别到当前页面 URL', 'warning'); return; }

    // 重置状态机
    cancelRequested = false;
    status = 'collecting';
    entries = []; scanned = 0; total = 0; currentFile = ''; lastBytes = 0; collectedBytes = 0;
    phase = '正在收集页面 JS...';

    const resultList: ArchiveEntry[] = [];
    const collected: { path: string; bytes: Uint8Array }[] = [];

    try {
      const { dom: domUrls, preload: preloadUrls, performance: perfUrls, inline } = await gatherFromPage();
      if (cancelRequested) return finishCancelled(resultList);

      // 按来源置信度合并去重（first-seen-wins 记录来源），统一解析为绝对 URL
      const urlSource = new Map<string, ArchiveSource>();
      const addAll = (list: string[], src: ArchiveSource) => {
        for (const raw of list) {
          try {
            const abs = new URL(raw, pageUrl).href;
            if (!urlSource.has(abs)) urlSource.set(abs, src);
          } catch { /* ignore */ }
        }
      };
      addAll(domUrls, 'dom');
      addAll(preloadUrls, 'preload');
      addAll(perfUrls, 'performance');

      // 过滤（来源置信度放宽版，覆盖 extensionless / query-only chunk）+ 截断
      const urls = [...urlSource.entries()]
        .filter(([u]) => isArchiveableScript(u))
        .slice(0, MAX_SCRIPTS);

      // 计算 zip 路径（URL 类）
      const pathInputs: { key: string; path: string }[] = [];
      for (const [u] of urls) {
        const p = urlToZipPath(u);
        if (p) pathInputs.push({ key: u, path: p });
      }
      const inlineSlices = includeInline
        ? inline.slice(0, MAX_INLINE).map((t, i) => ({ text: t, idx: i }))
        : [];

      // zip 路径分配
      const pathMap = dedupePaths(pathInputs);
      // inline 用独立命名空间 _inline/inline-001.js
      const inlinePaths = dedupePaths(
        inlineSlices.map(s => ({ key: `__inline_${s.idx}`, path: `_inline/inline-${String(s.idx + 1).padStart(3, '0')}.js` })),
      );

      total = pathMap.size + inlineSlices.length;

      // 1) 抓取远程 JS（并发限流）
      status = 'fetching';
      phase = `抓取远程 JS (0/${pathMap.size})`;
      await runConcurrent([...pathMap.entries()], async ([url, path]) => {
        if (cancelRequested) return;
        currentFile = path;
        const src = urlSource.get(url);
        // 预算已超限 → 标记跳过，不再发请求
        if (collectedBytes >= MAX_ARCHIVE_BYTES) {
          resultList.push({ url, path, size: 0, status: 'skip', note: '总预算超限', kind: 'http', source: src });
          return;
        }
        try {
          const res = await sendMessage({
            type: 'FETCH_URL',
            url,
            timeout: FETCH_TIMEOUT,
            maxBytes: PER_FETCH_MAX_BYTES,
          }) as FetchResult<string>;
          // 用 if/else 收窄联合类型：success 为 true 时 res 为 FetchOk
          if (res.success) {
            if (res.data != null) {
              const bytes = strToU8(res.data);
              collectedBytes += bytes.length;
              collected.push({ path, bytes });
              resultList.push({ url, path, size: bytes.length, status: 'ok', kind: 'http', source: src });
            } else {
              resultList.push({ url, path, size: 0, status: 'fail', note: '空响应', kind: 'http', source: src });
            }
          } else {
            // TOO_LARGE 给更明确提示，其余直接回传 error
            const note = res.code === 'TOO_LARGE'
              ? `响应过大（>${Math.round(PER_FETCH_MAX_BYTES / 1024 / 1024)}MB）`
              : res.error || '抓取失败';
            resultList.push({ url, path, size: 0, status: 'fail', note, kind: 'http', source: src });
          }
        } catch (e: any) {
          resultList.push({ url, path, size: 0, status: 'fail', note: String(e?.message || e), kind: 'http', source: src });
        } finally {
          scanned++;
          phase = `抓取远程 JS (${scanned}/${pathMap.size})`;
        }
      }, { concurrency: 6, cancelled: () => cancelRequested });

      if (cancelRequested) return finishCancelled(resultList);

      // 2) 内联脚本
      for (const s of inlineSlices) {
        if (cancelRequested) break;
        const path = inlinePaths.get(`__inline_${s.idx}`)!;
        if (collectedBytes >= MAX_ARCHIVE_BYTES) {
          resultList.push({ url: '', path, size: 0, status: 'skip', note: '总预算超限', kind: 'inline', source: 'inline' });
          scanned++;
          continue;
        }
        const text = s.text.slice(0, MAX_INLINE_BYTES);
        const bytes = strToU8(text);
        collectedBytes += bytes.length;
        collected.push({ path, bytes });
        resultList.push({
          url: '', path, size: bytes.length, status: 'ok', kind: 'inline', source: 'inline',
          note: s.text.length > MAX_INLINE_BYTES ? '已截断' : undefined,
        });
        scanned++;
      }

      if (cancelRequested) return finishCancelled(resultList);

      if (collected.length === 0) {
        phase = '';
        status = 'failed';
        toastStore.show('未抓取到任何 JS 内容', 'warning');
        entries = resultList;
        return;
      }

      // 3) 打包 zip —— 先让出主线程一帧，降低大体积打包对 UI 的阻塞
      status = 'packaging';
      phase = '正在打包 zip...';
      await tick();
      const tree: Record<string, Uint8Array> = {};
      // 按路径排序写入（更友好的归档结构）
      for (const { path, bytes } of collected.sort((a, b) => a.path.localeCompare(b.path))) {
        tree[path] = bytes;
      }
      const fetchedAt = Date.now();
      tree['MANIFEST.txt'] = strToU8(buildManifest(resultList, pageUrl, fetchedAt));
      // 简明 README
      tree['README.txt'] = strToU8(buildReadme(pageUrl, fetchedAt));

      // level 3：压缩比与耗时折中，避免在主线程长压一个超大 zip
      const zipped = zipSync(tree, { level: 3 });
      lastBytes = zipped.length;

      // 4) 下载
      const blob = new Blob([zipped], { type: 'application/zip' });
      downloadBlob(blob, zipFilename(pageUrl));
      entries = resultList.sort((a, b) => a.path.localeCompare(b.path));
      status = 'completed';
      phase = `完成：${collected.length} 个文件，zip ${(zipped.length / 1024).toFixed(1)} KB`;
      toastStore.show(`已打包 ${collected.length} 个 JS`, 'success');
    } catch (e: any) {
      status = 'failed';
      phase = `失败: ${e?.message || e}`;
      toastStore.show('打包失败: ' + (e?.message || e), 'error');
    } finally {
      currentFile = '';
    }
  }

  /** 取消收尾：落已收集清单，置 cancelled 终态，绝不触发下载或「成功」提示。 */
  function finishCancelled(resultList: ArchiveEntry[]) {
    entries = resultList.sort((a, b) => a.path.localeCompare(b.path));
    phase = `已取消（${scanned}/${total}）`;
    status = 'cancelled';
    currentFile = '';
    toastStore.show('已取消', 'warning');
  }

  function buildReadme(pageUrl: string, fetchedAt: number): string {
    return [
      '灵眸 JS 归档 / Lingmou JS Archive',
      '===============================',
      `页面: ${pageUrl}`,
      `时间: ${new Date(fetchedAt).toISOString()}`,
      '',
      '说明：zip 内每个 JS 的路径 = 其原始 URL 的 host + pathname，',
      '便于在本地按目录结构审计每个脚本来源。',
      '内联脚本统一放在 _inline/ 目录。',
      '完整映射（路径 ↔ URL ↔ 状态 ↔ 大小）见 MANIFEST.txt。',
    ].join('\n');
  }

  function zipFilename(pageUrl: string): string {
    try {
      const u = new URL(pageUrl);
      const safe = (u.host.replace(/[^\w.-]/g, '_'));
      return `lingmou-js-${safe}-${Date.now()}.zip`;
    } catch {
      return `lingmou-js-${Date.now()}.zip`;
    }
  }

  function downloadBlob(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    // 延迟回收：给浏览器留出启动下载的时间，避免过早 revoke 导致下载失败
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function stop() { cancelRequested = true; }

  function statusColor(s: ArchiveEntry['status']): string {
    return s === 'ok' ? 'text-green-600 dark:text-green-400'
      : s === 'fail' ? 'text-red-500' : 'text-gray-400';
  }
</script>

<div class="space-y-3">
  <!-- 说明 + 操作 -->
  <div class="card p-3 space-y-2.5">
    <div class="text-xs text-gray-500 leading-relaxed">
      收集当前页面的 <b>所有 JS</b>（DOM &lt;script&gt; / preload / performance 动态加载 / 内联），
      按各自 <b>原始 URL 路径</b> 组织进一个 zip 下载，便于本地审计。
    </div>

    {#if pageUrl}
      <div class="text-xs text-gray-400 font-mono truncate" title={pageUrl}>📍 {pageUrl}</div>
    {/if}

    <!-- 选项 -->
    <div class="flex items-center gap-4 text-xs flex-wrap">
      <label class="flex items-center gap-1.5 cursor-pointer select-none">
        <input type="checkbox" class="accent-blue-500" bind:checked={includeInline} />
        含内联脚本
      </label>
      <span class="text-gray-400">上限 {MAX_SCRIPTS} 个 JS / {MAX_INLINE} 条内联</span>
    </div>

    <div class="flex gap-2">
      <button class="btn btn-sm btn-primary flex-1" disabled={archiving || !pageUrl} onclick={archiveAll}>
        {archiving ? '打包中...' : '📦 打包下载全部 JS'}
      </button>
      {#if archiving}
        <button class="btn btn-sm btn-ghost" onclick={stop}>停止</button>
      {/if}
    </div>

    <!-- 终端状态徽标（取消/失败时清晰反馈，不与「成功」混淆） -->
    {#if status === 'cancelled'}
      <div class="text-xs text-amber-600 dark:text-amber-400">⚠ 已取消，未生成下载</div>
    {:else if status === 'failed'}
      <div class="text-xs text-red-500">✕ 打包失败（详见下方）</div>
    {/if}
  </div>

  <!-- 进度 -->
  {#if archiving || phase}
    <div class="card p-3 space-y-2">
      <div class="flex items-center justify-between text-xs">
        <span class="text-gray-600 dark:text-gray-300">{phase}</span>
        {#if total > 0}<span class="text-gray-400 font-mono">{scanned}/{total}</span>{/if}
      </div>
      {#if total > 0}
        <div class="h-1.5 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
          <div class="h-full bg-primary transition-all" style="width:{progress}%"></div>
        </div>
      {/if}
      {#if currentFile}
        <div class="text-[11px] text-gray-400 font-mono truncate" title={currentFile}>{currentFile}</div>
      {/if}
    </div>
  {/if}

  <!-- 结果统计 -->
  {#if entries.length > 0}
    <div class="flex items-center gap-3 text-xs flex-wrap">
      <span class="badge bg-green-100 text-green-700 dark:bg-green-900/50 dark:text-green-300">成功 {okCount}</span>
      <span class="badge bg-red-100 text-red-700 dark:bg-red-900/50 dark:text-red-300">失败 {failCount}</span>
      {#if skipCount > 0}
        <span class="badge bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300">跳过 {skipCount}</span>
      {/if}
      {#if lastBytes}<span class="text-gray-400">zip {(lastBytes / 1024).toFixed(1)} KB</span>{/if}
      {#if collectedBytes > 0}<span class="text-gray-400">已收集 {(collectedBytes / 1024).toFixed(1)} KB</span>{/if}
    </div>

    <!-- 文件清单 -->
    <div class="card overflow-hidden">
      <div class="overflow-x-auto max-h-72 overflow-y-auto">
        <table class="w-full text-xs">
          <thead class="sticky top-0 bg-white dark:bg-gray-800">
            <tr class="border-b border-gray-200 dark:border-gray-700">
              <th class="text-left px-3 py-1.5 font-medium text-gray-500">zip 路径</th>
              <th class="text-right px-3 py-1.5 font-medium text-gray-500">大小</th>
              <th class="text-left px-3 py-1.5 font-medium text-gray-500">状态</th>
            </tr>
          </thead>
          <tbody>
            {#each entries as e (e.path)}
              <tr class="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                <td class="px-3 py-1.5 font-mono truncate max-w-56" title={e.url || '(内联)'}>{e.path}</td>
                <td class="px-3 py-1.5 font-mono text-right text-gray-500">{e.size ? (e.size / 1024).toFixed(1) + ' KB' : '-'}</td>
                <td class="px-3 py-1.5 {statusColor(e.status)}">{e.status === 'ok' ? '✓' : e.note || e.status}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  {:else if status === 'idle'}
    <EmptyState message="点击「打包下载全部 JS」归档当前页面脚本" />
  {/if}
</div>
