<script lang="ts">
  // JS 归档面板 — 灵眸 v7.3
  // 收集当前页面所有 JS（DOM script + preload + performance + inline）→ 按原始 URL 路径
  // 组织进 zip → 下载，供本地安全审计。
  //
  // 资源预算（P0-2）：单响应 PER_FETCH_MAX_BYTES + 整档累计 MAX_ARCHIVE_BYTES，
  //   超累计预算的剩余条目标记 skip，不发请求，避免扩展 OOM。
  // 取消语义（P0-3 / §3.4）：统一 TaskController 状态机，取消通过 AbortSignal 传播；
  //   各阶段边界检查 ctx.signal.aborted，取消后绝不触发 zipSync/下载/「成功」。
  // 压缩降级（P1-9）：zipSync 用 level 3，打包前 await tick() 让出主线程一次。
  import { tick } from 'svelte';
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTab, getActiveTabUrl, execInTab } from '@/lib/core/tabs';
  import { runConcurrent } from '@/lib/core/concurrency';
  import { toastStore } from '@/stores/ui';
  import { zipSync, strToU8 } from 'fflate';
  import EmptyState from '@/components/scanner/EmptyState.svelte';
  import ErrorState from '@/components/feedback/ErrorState.svelte';
  import { downloadBlob } from '@/lib/actions/download';
  import { createTaskController, IDLE, type TaskState } from '@/lib/tasks/task-controller';
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

  type ArchiveInput = { pageUrl: string; includeInline: boolean };
  type ArchiveOutput = { entries: ArchiveEntry[]; zipBlob?: Blob; totalBytes?: number };

  let pageUrl = $state('');
  let currentFile = $state('');
  let entries = $state<ArchiveEntry[]>([]);
  let lastBytes = $state(0);      // 上次产物大小
  let collectedBytes = $state(0); // 已收集累计字节（预算追踪）
  let includeInline = $state(true);

  // —— TaskController 接管状态机（替代手写 status/cancelRequested）——
  // adapter.run 是面板闭包：用 ctx.signal 取代 cancelRequested、ctx.reportProgress 取代
  // phase/scanned/total 赋值；currentFile/entries/collectedBytes 等特有态直接写面板 $state。
  const controller = createTaskController<ArchiveInput, ArchiveOutput>({
    validate: (input) => {
      if (!input.pageUrl) throw new Error('未识别到当前页面 URL');
    },
    run: async (input, ctx) => {
      const resultList: ArchiveEntry[] = [];
      const collected: { path: string; bytes: Uint8Array }[] = [];
      collectedBytes = 0;
      entries = []; currentFile = ''; lastBytes = 0;

      // 1) 收集
      ctx.reportProgress({ phase: '正在收集页面 JS...', completed: 0, total: 0 });
      const { dom: domUrls, preload: preloadUrls, performance: perfUrls, inline } = await gatherFromPage();
      if (ctx.signal.aborted) return finishCancelled(resultList);

      // 按来源置信度合并去重（first-seen-wins 记录来源），统一解析为绝对 URL
      const urlSource = new Map<string, ArchiveSource>();
      const addAll = (list: string[], src: ArchiveSource) => {
        for (const raw of list) {
          try {
            const abs = new URL(raw, input.pageUrl).href;
            if (!urlSource.has(abs)) urlSource.set(abs, src);
          } catch { /* ignore */ }
        }
      };
      addAll(domUrls, 'dom');
      addAll(preloadUrls, 'preload');
      addAll(perfUrls, 'performance');

      const urls = [...urlSource.entries()]
        .filter(([u]) => isArchiveableScript(u))
        .slice(0, MAX_SCRIPTS);

      const pathInputs: { key: string; path: string }[] = [];
      for (const [u] of urls) {
        const p = urlToZipPath(u);
        if (p) pathInputs.push({ key: u, path: p });
      }
      const inlineSlices = input.includeInline
        ? inline.slice(0, MAX_INLINE).map((t, i) => ({ text: t, idx: i }))
        : [];

      const pathMap = dedupePaths(pathInputs);
      const inlinePaths = dedupePaths(
        inlineSlices.map(s => ({ key: `__inline_${s.idx}`, path: `_inline/inline-${String(s.idx + 1).padStart(3, '0')}.js` })),
      );

      ctx.reportProgress({ total: pathMap.size + inlineSlices.length });

      // 2) 抓取远程 JS（并发限流）
      ctx.reportProgress({ phase: `抓取远程 JS (0/${pathMap.size})` });
      let scanned = 0;
      await runConcurrent([...pathMap.entries()], async ([url, path]) => {
        if (ctx.signal.aborted) return;
        currentFile = path;
        const src = urlSource.get(url);
        if (collectedBytes >= MAX_ARCHIVE_BYTES) {
          resultList.push({ url, path, size: 0, status: 'skip', note: '总预算超限', kind: 'http', source: src });
          scanned++;
          ctx.reportProgress({ completed: scanned });
          return;
        }
        try {
          const res = await sendMessage({
            type: 'FETCH_URL', url, timeout: FETCH_TIMEOUT, maxBytes: PER_FETCH_MAX_BYTES,
          }) as FetchResult<string>;
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
            const note = res.code === 'TOO_LARGE'
              ? `响应过大（>${Math.round(PER_FETCH_MAX_BYTES / 1024 / 1024)}MB）`
              : res.error || '抓取失败';
            resultList.push({ url, path, size: 0, status: 'fail', note, kind: 'http', source: src });
          }
        } catch (e: any) {
          resultList.push({ url, path, size: 0, status: 'fail', note: String(e?.message || e), kind: 'http', source: src });
        } finally {
          scanned++;
          ctx.reportProgress({ completed: scanned, phase: `抓取远程 JS (${scanned}/${pathMap.size})` });
        }
      }, { concurrency: 6, cancelled: () => ctx.signal.aborted });

      if (ctx.signal.aborted) return finishCancelled(resultList);

      // 3) 内联脚本
      for (const s of inlineSlices) {
        if (ctx.signal.aborted) break;
        const path = inlinePaths.get(`__inline_${s.idx}`)!;
        if (collectedBytes >= MAX_ARCHIVE_BYTES) {
          resultList.push({ url: '', path, size: 0, status: 'skip', note: '总预算超限', kind: 'inline', source: 'inline' });
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
      }
      if (ctx.signal.aborted) return finishCancelled(resultList);

      if (collected.length === 0) {
        throw new Error('未抓取到任何 JS 内容');
      }

      // 4) 打包 zip —— 先让出主线程一帧，降低大体积打包对 UI 的阻塞
      ctx.reportProgress({ phase: '正在打包 zip...' });
      await tick();
      const tree: Record<string, Uint8Array> = {};
      for (const { path, bytes } of collected.sort((a, b) => a.path.localeCompare(b.path))) {
        tree[path] = bytes;
      }
      const fetchedAt = Date.now();
      tree['MANIFEST.txt'] = strToU8(buildManifest(resultList, input.pageUrl, fetchedAt));
      tree['README.txt'] = strToU8(buildReadme(input.pageUrl, fetchedAt));

      const zipped = zipSync(tree, { level: 3 });
      const blob = new Blob([zipped], { type: 'application/zip' });
      entries = resultList.sort((a, b) => a.path.localeCompare(b.path));
      ctx.reportProgress({ phase: `完成：${collected.length} 个文件，zip ${(zipped.length / 1024).toFixed(1)} KB` });
      return { entries: resultList, zipBlob: blob, totalBytes: zipped.length };
    },
  },
  { centerPanel: 'jsarchive', centerLabel: 'JS 归档' });

  // 订阅 controller.state 到本地 $state（模板 reactive 使用）
  let cs = $state<TaskState>({ ...IDLE });
  $effect(() => controller.state.subscribe((v: TaskState) => { cs = v; }));

  let archiving = $derived(cs.status === 'running' || cs.status === 'paused' || cs.status === 'validating');
  let okCount = $derived(entries.filter(e => e.status === 'ok').length);
  let failCount = $derived(entries.filter(e => e.status === 'fail').length);
  let skipCount = $derived(entries.filter(e => e.status === 'skip').length);
  let progress = $derived(cs.total && cs.total > 0 ? Math.round((cs.completed / cs.total) * 100) : 0);

  $effect(() => {
    getActiveTabUrl().then(u => { if (u) pageUrl = u; });
  });

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
      try {
        document.querySelectorAll('script[src]').forEach(function (s: any) {
          if (s.src) domUrls.push(s.src);
        });
      } catch { /* ignore */ }
      try {
        document
          .querySelectorAll('link[rel="preload"][as="script"], link[rel="modulepreload"]')
          .forEach(function (l: any) { if (l.href) preloadUrls.push(l.href); });
      } catch { /* ignore */ }
      try {
        for (const e of performance.getEntriesByType('resource')) {
          const n = (e as any).name || '';
          const init = (e as any).initiatorType || '';
          if (init === 'script' || init === 'link' || /\.m?js(\?|#|$)/i.test(n)) {
            perfUrls.push(n);
          }
        }
      } catch { /* ignore */ }
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

  /** 取消收尾：落已收集清单并返回（controller 将置 cancelled 终态，绝不 zipSync/下载/成功 toast） */
  function finishCancelled(resultList: ArchiveEntry[]): ArchiveOutput {
    entries = resultList.sort((a, b) => a.path.localeCompare(b.path));
    currentFile = '';
    return { entries: resultList };
  }

  async function handleStart() {
    try {
      const r = await controller.start({ pageUrl, includeInline });
      if (r.status === 'succeeded' && r.result?.zipBlob) {
        downloadBlob(r.result.zipBlob, zipFilename(pageUrl));
        lastBytes = r.result.totalBytes ?? 0;
        const ok = r.result.entries.filter(e => e.status === 'ok').length;
        toastStore.show(`已打包 ${ok} 个 JS`, 'success');
      } else if (r.status === 'cancelled') {
        if (r.result?.entries) entries = r.result.entries;
        toastStore.show('已取消', 'warning');
      }
    } catch {
      // failed：controller.state.error 已设；UI 由 cs.status==='failed' 渲染 ErrorState
    }
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
      <button class="btn btn-sm btn-primary flex-1" disabled={archiving || !pageUrl} onclick={handleStart}>
        {archiving ? '打包中...' : '📦 打包下载全部 JS'}
      </button>
      {#if archiving}
        <button class="btn btn-sm btn-ghost" onclick={() => controller.cancel()}>停止</button>
      {/if}
    </div>

    <!-- 终端状态徽标 / 错误恢复（取消/失败时清晰反馈，不与「成功」混淆） -->
    {#if cs.status === 'cancelled'}
      <div class="text-xs text-amber-600 dark:text-amber-400">⚠ 已取消，未生成下载</div>
    {:else if cs.status === 'failed' && cs.error}
      <ErrorState error={cs.error} onRetry={handleStart} />
    {/if}
  </div>

  <!-- 进度 -->
  {#if archiving || cs.phase}
    <div class="card p-3 space-y-2">
      <div class="flex items-center justify-between text-xs">
        <span class="text-gray-600 dark:text-gray-300">{cs.phase}</span>
        {#if cs.total && cs.total > 0}<span class="text-gray-400 font-mono">{cs.completed}/{cs.total}</span>{/if}
      </div>
      {#if cs.total && cs.total > 0}
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
  {:else if cs.status === 'idle'}
    <EmptyState message="点击「打包下载全部 JS」归档当前页面脚本" />
  {/if}
</div>
