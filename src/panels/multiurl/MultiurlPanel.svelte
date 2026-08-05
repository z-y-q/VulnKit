<script lang="ts">
  // URL多开面板 — 灵眸 v7.3
  // 粘贴多个 URL，批量在新标签页中打开。
  // v7.3：统一 TaskController（逐项成功/失败统计 + 可取消）+ ConfirmDialog（替代原生 confirm）
  //      + ExportMenu/copyText（规范文件名 + 修复未 await）。
  import { confirmStore } from '@/stores/confirm';
  import { toastStore } from '@/stores/ui';
  import { analysisContextStore } from '@/stores/analysis-context';
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import { copyText } from '@/lib/actions/clipboard';
  import { createTaskController, IDLE, type TaskState } from '@/lib/tasks/task-controller';
  import { abortableDelay } from '@/lib/tasks/abortable-delay';

  let rawText = $state('');
  let delay = $state(0);
  const maxUrls = 50;

  let urls = $derived.by(() => {
    return rawText
      .split(/[\n\r,;]+/)
      .map(line => {
        let url = line.trim();
        if (!url) return null;
        if (!/^https?:\/\//i.test(url)) url = `http://${url}`;
        return url;
      })
      .filter((u): u is string => u !== null);
  });

  let uniqueUrls = $derived.by(() => [...new Set(urls)]);
  let duplicateCount = $derived(urls.length - uniqueUrls.length);

  // —— TaskController 接管批量打开（逐项成败 + 可取消）——
  const controller = createTaskController<{ urls: string[]; delay: number }, { ok: number; fail: number; failedUrls: string[] }>({
    validate: (input) => {
      if (input.urls.length === 0) throw new Error('请输入 URL');
      if (input.urls.length > maxUrls) throw new Error(`一次最多打开 ${maxUrls} 个标签页`);
    },
    run: async (input, ctx) => {
      ctx.reportProgress({ total: input.urls.length, completed: 0, succeeded: 0, failed: 0, phase: '批量打开' });
      let ok = 0;
      let fail = 0;
      const failedUrls: string[] = [];
      for (const url of input.urls) {
        if (ctx.signal.aborted) break;
        try {
          await browser.tabs.create({ url, active: false });
          ok++;
        } catch {
          fail++;
          failedUrls.push(url);
        }
        ctx.reportProgress({
          completed: ok + fail,
          succeeded: ok,
          failed: fail,
          phase: `打开中 (${ok + fail}/${input.urls.length})`,
        });
        if (input.delay > 0 && !ctx.signal.aborted) {
          try { await abortableDelay(input.delay, ctx.signal); }
          catch { break; }  // 取消：退出循环，由 TaskController 走 cancelled（非 failed）
        }
      }
      return { ok, fail, failedUrls };
    },
  },
  { centerPanel: 'multiurl', centerLabel: 'URL 多开' });

  let cs = $state<TaskState>({ ...IDLE });
  $effect(() => controller.state.subscribe((v: TaskState) => { cs = v; }));
  let opening = $derived(cs.status === 'running' || cs.status === 'paused' || cs.status === 'validating');
  let lastFailedUrls = $state<string[]>([]);

  // 消费跨面板 handoff（统一 analysisContextStore，替代旧 lingmou:multiurl-pending）
  $effect(() => {
    analysisContextStore.consume('multiurl').then((c) => {
      if (c?.payload.text) rawText = c.payload.text;
    }).catch(() => { /* ignore */ });
  });

  async function openAll() {
    if (!(await confirmStore.ask({
      title: '批量打开',
      message: `即将打开 ${uniqueUrls.length} 个标签页，是否继续？`,
      confirmLabel: '打开',
      variant: 'default',
    }))) {
      return;
    }
    try {
      const r = await controller.start({ urls: uniqueUrls, delay });
      if (r.status === 'succeeded' && r.result) {
        const { ok, fail, failedUrls } = r.result;
        lastFailedUrls = failedUrls;
        toastStore.show(
          fail > 0 ? `已打开 ${ok} 个，失败 ${fail} 个（可重试失败）` : `已打开 ${ok} 个标签页`,
          fail > 0 ? 'warning' : 'success',
        );
      } else if (r.status === 'cancelled') {
        toastStore.show('已取消打开', 'info');
      }
    } catch {
      // failed：toast 已由 controller? 否；这里补一条
      toastStore.show('打开失败', 'error');
    }
  }

  /** 重试上次失败的 URL（retry 'failed'，复用 controller.retry 传参） */
  async function retryFailed() {
    if (lastFailedUrls.length === 0) return;
    try {
      const r = await controller.retry({ urls: lastFailedUrls, delay });
      if (r.status === 'succeeded' && r.result) {
        const { ok, fail, failedUrls } = r.result;
        lastFailedUrls = failedUrls;
        toastStore.show(
          fail > 0 ? `重试完成：再打开 ${ok} 个，仍失败 ${fail} 个` : `重试成功：已打开 ${ok} 个`,
          fail > 0 ? 'warning' : 'success',
        );
      }
    } catch {
      toastStore.show('重试失败', 'error');
    }
  }

  function dedup() {
    if (duplicateCount === 0) {
      toastStore.show('没有重复 URL', 'info');
      return;
    }
    rawText = uniqueUrls.join('\n');
    toastStore.show(`去重完成，移除 ${duplicateCount} 个重复`, 'success');
  }

  async function copyUrls() {
    if (uniqueUrls.length === 0) { toastStore.show('没有可复制的 URL', 'warning'); return; }
    await copyText(uniqueUrls.join('\n'), `已复制 ${uniqueUrls.length} 个 URL`);
  }

  function clearAll() {
    rawText = '';
    lastFailedUrls = [];
    controller.reset();
  }

  /** 抓取当前标签页及右侧所有标签页的 URL，填入文本框 */
  async function grabCurrentTab() {
    try {
      const [active] = await browser.tabs.query({ active: true, currentWindow: true });
      if (!active?.url) { toastStore.show('当前标签页无可抓取的 URL', 'warning'); return; }
      const all = await browser.tabs.query({ currentWindow: true });
      const list = all.map(t => t.url).filter((u): u is string => !!u && /^https?:\/\//i.test(u));
      const merged = rawText.trim() ? `${rawText.trim()}\n${list.join('\n')}` : list.join('\n');
      rawText = merged;
      toastStore.show(`已抓取 ${list.length} 个标签页 URL`, 'success');
    } catch (e: any) {
      toastStore.show('抓取失败: ' + (e?.message || ''), 'warning');
    }
  }

  function urlsText(list: string[]): string {
    return list.join('\n');
  }
</script>

<div class="space-y-3">
  <!-- 输入区 -->
  <div class="card p-3 space-y-2">
    <textarea
      class="input w-full font-mono text-xs"
      rows="8"
      placeholder="粘贴多个 URL，每行一个，或用逗号/分号分隔&#10;https://example.com/1&#10;https://example.com/2&#10;https://example.com/3"
      bind:value={rawText}
      disabled={opening}
    ></textarea>

    <!-- 统计 -->
    {#if urls.length > 0}
      <div class="flex items-center gap-2 text-xs text-gray-500">
        <span>
          已识别 <b class="text-gray-600 dark:text-gray-200">{uniqueUrls.length}</b> 个 URL
        </span>
        {#if duplicateCount > 0}
          <span>(含 {duplicateCount} 个重复)</span>
        {/if}
        <span class="ml-auto">
          上限 {maxUrls} 个
          {#if uniqueUrls.length > maxUrls}
            <span class="text-red-500 dark:text-red-400 font-bold">超限!</span>
          {/if}
        </span>
      </div>
    {/if}

    {#if opening}
      <div class="text-xs text-gray-500 dark:text-gray-500">
        {cs.phase} · 成功 {cs.succeeded} · 失败 {cs.failed}
      </div>
    {/if}
  </div>

  <!-- 选项 -->
  <div class="card p-3 space-y-2">
    <div class="flex items-center gap-2 text-xs">
      <span class="text-gray-500 shrink-0">打开间隔:</span>
      <input
        type="number"
        class="input text-xs w-24"
        min="0"
        max="5000"
        step="100"
        bind:value={delay}
        disabled={opening}
      />
      <span class="text-gray-500">ms</span>
      <span class="text-gray-500 ml-auto">
        {delay === 0 ? '无间隔' : `${delay}ms/个`}
      </span>
    </div>
  </div>

  <!-- 操作按钮 -->
  <div class="flex gap-1 flex-wrap">
    {#if opening}
      <button class="btn btn-sm btn-danger flex-1" onclick={() => controller.cancel()} disabled={!cs.canCancel}>
        取消（已打开 {cs.completed}/{cs.total ?? uniqueUrls.length}）
      </button>
    {:else}
      <button
        class="btn btn-sm btn-primary flex-1"
        disabled={uniqueUrls.length === 0}
        onclick={openAll}
      >
        全部打开
      </button>
      {#if lastFailedUrls.length > 0}
        <button class="btn btn-sm flex-1" onclick={retryFailed} title="只重试上次失败的 URL">
          重试失败 {lastFailedUrls.length}
        </button>
      {/if}
    {/if}
    <button class="btn btn-sm flex-1" disabled={opening || uniqueUrls.length === 0 || duplicateCount === 0} onclick={dedup}>
      去重
    </button>
    <button class="btn btn-sm" disabled={opening || uniqueUrls.length === 0} onclick={copyUrls} title="复制 URL 列表">
      复制
    </button>
    <ExportMenu
      items={uniqueUrls}
      module="multiurl"
      serializers={{ text: urlsText }}
      copySerialize={urlsText}
      disabled={opening}
    />
    <button class="btn btn-sm" disabled={opening} onclick={grabCurrentTab} title="抓取当前窗口所有标签页 URL">
      抓取
    </button>
    <button class="btn btn-sm" disabled={opening || urls.length === 0} onclick={clearAll}>
      清空
    </button>
  </div>

  <!-- 空状态 -->
  {#if urls.length === 0 && !opening}
    <div class="text-center text-gray-500 text-sm py-6">
      粘贴多个 URL，点击「全部打开」批量在新标签页中打开
    </div>
  {/if}
</div>
