<script lang="ts">
  // 信息收集面板
  // 一键收集：技术栈指纹 / 外链资源 / 敏感信息泄露
  import { sendToContent } from '@/lib/core/messaging';
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl, getActiveTab, execInTab } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import { analysisContextStore } from '@/stores/analysis-context';
  import type { DomFingerprint } from '@/lib/types/messaging';
  import { matchAllRules, type HaeMatch } from '@/lib/scanners/hae-engine';
  import { loadMergedGroups, type HaeGroup } from '@/lib/scanners/hae-store';
  import patternsData from '@/lib/data/gather-patterns.json';
  import { loadPrefs, isDomainExcluded } from '@/lib/core/general-prefs';
  import ErrorState from '@/components/feedback/ErrorState.svelte';
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import { copyText } from '@/lib/actions/clipboard';
  import { toCsv, toMarkdownTable } from '@/lib/actions/serializers';
  import { createTaskController, IDLE, type TaskState } from '@/lib/tasks/task-controller';
  import { runConcurrent } from '@/lib/core/concurrency';

  // ===== 类型 =====
  interface Finding {
    name: string;
    value: string;
    color: string;
    group: string;
  }

  interface TechPattern {
    target: string;
    field?: string;
    pattern: string;
    extract?: string;
    label: string;
    color: string;
  }

  interface CloudPattern {
    pattern: string;
    label: string;
    color: string;
  }

  interface SensitivePattern {
    regex: { source: string; flags: string };
    label: string;
    color: string;
    captureIdx?: number;
  }

  interface ApiPattern {
    regex: { source: string; flags: string };
    label: string;
  }

  // ===== 状态 =====
  type Category = 'tech' | 'resources' | 'leaks' | 'hae';
  let activeCategory = $state<Category>('tech');

  let techFindings = $state<Finding[]>([]);
  let resourceFindings = $state<Finding[]>([]);
  let leakFindings = $state<Finding[]>([]);
  let haeFindings = $state<HaeMatch[]>([]);
  // 当前生效的 HaE 规则组（默认 + 自定义合并）
  let haeGroups = $state<HaeGroup[]>([]);
  let excludeDomains = $state<string[]>([]);
  $effect(() => {
    loadPrefs().then(p => { excludeDomains = p.gatherExcludeDomains; });
  });

  // 载入 HaE 规则（默认 + 用户自定义），并监听 options 页变更热更新
  $effect(() => {
    const reload = () => loadMergedGroups().then(g => { haeGroups = g; }).catch(() => { /* */ });
    reload();
    const listener = (changes: any, area: string) => {
      if (area === 'local' && changes['haeCustomRules']) reload();
    };
    browser.storage.onChanged.addListener(listener);
    return () => browser.storage.onChanged.removeListener(listener);
  });
  let searchFilter = $state('');

  // ===== 派生状态 =====
  let totalCount = $derived(techFindings.length + resourceFindings.length + leakFindings.length);
  let techCount = $derived(techFindings.length);
  let resourceCount = $derived(resourceFindings.length);
  let leakCount = $derived(leakFindings.length);

  let filteredTech = $derived(applyFilter(techFindings));
  let filteredResources = $derived(applyFilter(resourceFindings));
  let filteredLeaks = $derived(applyFilter(leakFindings));

  // 跨分类搜索：搜索时合并所有分类结果
  let allFiltered = $derived.by(() => {
    if (!searchFilter) return [];
    return [
      ...techFindings.map(f => ({ ...f, _cat: 'tech' as const })),
      ...resourceFindings.map(f => ({ ...f, _cat: 'resources' as const })),
      ...leakFindings.map(f => ({ ...f, _cat: 'leaks' as const })),
    ].filter(f => f.name.toLowerCase().includes(searchFilter.toLowerCase()) || f.value.toLowerCase().includes(searchFilter.toLowerCase()));
  });

  function applyFilter(list: Finding[]): Finding[] {
    let out = list;
    // 采集域名排除：过滤掉值为排除域名的条目（外链域名/脚本域名/frame 等）
    if (excludeDomains.length) {
      out = out.filter(f => {
        const v = f.value.trim().toLowerCase();
        // 仅对看起来像主机名的值应用（含点、无空格）
        if (!v || !v.includes('.') || v.includes(' ')) return true;
        return !isDomainExcluded(v, excludeDomains);
      });
    }
    if (!searchFilter) return out;
    const q = searchFilter.toLowerCase();
    return out.filter(
      f => f.name.toLowerCase().includes(q) || f.value.toLowerCase().includes(q),
    );
  }

  // ===== 纯函数：指纹分析 =====

  /** 分析 DOM 指纹数据，返回技术栈发现 */
  function analyzeFingerprint(
    fp: DomFingerprint,
    inspectResult: { globals?: string[]; versions?: Record<string, string> | string[]; cookies?: string[] } | null,
    leakResult: { storage?: Record<string, string>; globals?: string[] } | null,
    patterns: typeof patternsData,
  ): { tech: Finding[]; resources: Finding[]; leaks: Finding[] } {
    const tech: Finding[] = [];
    const resources: Finding[] = [];
    const leaks: Finding[] = [];
    const seen = new Set<string>();

    function add(group: Finding['group'], name: string, value: string, color: string) {
      if (!value) return;
      const key = `${group}::${name}::${value}`;
      if (seen.has(key)) return;
      seen.add(key);
      const item: Finding = { name, value, color, group };
      if (group === 'tech') tech.push(item);
      else if (group === 'resources') resources.push(item);
      else leaks.push(item);
    }

    // 1. 技术栈模式匹配
    const techPatterns = patterns.TECH_PATTERNS as TechPattern[];
    for (const p of techPatterns) {
      if (p.target === 'meta') {
        for (const tag of fp.metaTags) {
          const fieldValue = (tag as any)[p.field || 'name'];
          if (fieldValue && new RegExp(p.pattern, 'i').test(fieldValue)) {
            const extracted = p.extract ? (tag as any)[p.extract] || fieldValue : tag.content || fieldValue;
            add('tech', p.label, extracted, p.color);
          }
        }
      } else if (p.target === 'scriptSrc') {
        for (const src of fp.scriptSrcs) {
          if (new RegExp(p.pattern, 'i').test(src)) {
            add('tech', p.label, src, p.color);
          }
        }
      } else if (p.target === 'body') {
        if (new RegExp(p.pattern, 'i').test(fp.bodyHtml)) {
          add('tech', p.label, 'detected', p.color);
        }
      }
    }

    // 2. 云服务匹配
    const cloudPatterns = patterns.CLOUD_PATTERNS as CloudPattern[];
    const allText = fp.bodyHtml + '\n' + fp.scriptSrcs.join('\n') + '\n' + fp.styleHrefs.join('\n');
    for (const cp of cloudPatterns) {
      if (new RegExp(cp.pattern, 'i').test(allText)) {
        add('tech', cp.label, 'detected', cp.color);
      }
    }

    // 3. 全局变量/版本信息（来自 fingerprint inspect）
    if (inspectResult) {
      if (inspectResult.globals) {
        for (const g of inspectResult.globals) {
          add('tech', '全局变量', g, 'cyan');
        }
      }
      if (inspectResult.versions) {
        const vObj = inspectResult.versions;
        // inject 返回 Record<string,string>（名→版本），兼容历史数组形式
        if (Array.isArray(vObj)) {
          for (const v of vObj) add('tech', '版本信息', v, 'blue');
        } else {
          for (const [name, ver] of Object.entries(vObj)) {
            add('tech', '版本信息', `${name} ${ver}`, 'blue');
          }
        }
      }
    }

    // 4. 所有外链 JS / CSS → 资源
    for (const src of fp.scriptSrcs) {
      if (src && /^https?:\/\//i.test(src)) {
        add('resources', 'JS', src, 'gray');
      }
    }
    for (const href of fp.styleHrefs) {
      if (href && /^https?:\/\//i.test(href)) {
        add('resources', 'CSS', href, 'gray');
      }
    }

    // 5. Meta 标签 → 资源（title, description, generator 等已由 tech 捕获，这里补 cookies）
    if (inspectResult?.cookies) {
      for (const c of inspectResult.cookies) {
        add('resources', 'Cookie', c, 'orange');
      }
    }

    // 6. 泄露检测
    if (leakResult) {
      // Storage 泄露
      if (leakResult.storage) {
        for (const [key, val] of Object.entries(leakResult.storage)) {
          add('leaks', 'Storage', `${key}: ${truncate(val)}`, 'yellow');
        }
      }
      // 敏感全局变量
      if (leakResult.globals) {
        for (const g of leakResult.globals) {
          add('leaks', '敏感全局变量', truncate(g), 'yellow');
        }
      }
    }

    return { tech, resources, leaks };
  }

  /** 从外部 JS 中提取 API 端点和敏感信息（通过 background fetch） */
  async function extractFromJsFiles(
    scriptSrcs: string[],
    pageUrl: string,
    patterns: typeof patternsData,
    signal: AbortSignal,
  ): Promise<{ resources: Finding[]; leaks: Finding[] }> {
    const apiPatterns = patterns.API_PATTERNS as ApiPattern[];
    const sensitivePatterns = patterns.SENSITIVE_PATTERNS as SensitivePattern[];
    const resources: Finding[] = [];
    const leaks: Finding[] = [];
    const seen = new Set<string>();

    // 只取同源 JS，最多 30 个
    let pageOrigin = '';
    try { pageOrigin = new URL(pageUrl).origin; } catch { /* ignore */ }
    const toFetch = [...new Set(scriptSrcs)]
      .filter(s => { try { return new URL(s).origin === pageOrigin; } catch { return false; } })
      .slice(0, 30);

    // §5.1：runConcurrent 限流（并发6）+ 可取消，取代 Promise.all 一次性并发；
    // 单个失败记录为结果不终止全部；取消后不再调度新请求
    await runConcurrent(
      toFetch,
      async (src) => {
        let result: any;
        try {
          result = await sendMessage({ type: 'FETCH_URL', url: src, timeout: 10000 });
        } catch { return; }
        if (!result || !result.success) return;
        const content = result.data as string;
        if (!content) return;
        const text = content.length > 300000 ? content.substring(0, 300000) : content;

        // API 端点
        for (const p of apiPatterns) {
          const regex = new RegExp(p.regex.source, p.regex.flags);
          let match;
          while ((match = regex.exec(text)) !== null) {
            const path = match[1];
            if (!path || path.length < 3 || path.length > 200) continue;
            if (/\.js(\?|$)/i.test(path) || /\.(css|png|jpg|svg|woff)(\?|$)/i.test(path)) continue;
            const key = `api::${path}`.toLowerCase();
            if (seen.has(key)) continue;
            seen.add(key);
            resources.push({ name: 'API', value: path, color: 'api', group: 'resources' });
          }
        }

        // 敏感信息
        for (const p of sensitivePatterns) {
          const regex = new RegExp(p.regex.source, p.regex.flags);
          let match;
          while ((match = regex.exec(text)) !== null) {
            let value = p.captureIdx ? match[p.captureIdx] : match[0];
            if (!value) continue;
            const key = `${p.label}::${value}`;
            if (seen.has(key)) continue;
            seen.add(key);
            leaks.push({ name: p.label, value: truncate(value), color: p.color, group: 'leaks' });
          }
        }
      },
      { concurrency: 6, cancelled: () => signal.aborted },
    );

    return { resources, leaks };
  }

  /** 敏感值截断 */
  function truncate(value: string, max = 100): string {
    if (value.length <= max) return value;
    return value.substring(0, max) + '...';
  }

  // ===== 收集逻辑（TaskController 接管）=====
  const controller = createTaskController<void, void>({
    run: async (_input, ctx) => {
      techFindings = [];
      resourceFindings = [];
      leakFindings = [];
      haeFindings = [];

      const url = await getActiveTabUrl();
      if (!url) throw new Error('无法获取当前页面（需 http/https）');

      ctx.reportProgress({ phase: '提取 DOM 指纹' });
      const fp = await sendToContent({ type: 'VK_FINGERPRINT_DOM' });
      if (!fp) throw new Error('无法连接 content script，请刷新页面后重试');

      ctx.reportProgress({ phase: '分析指纹信息' });
      const inspectResult = await sendToContent({ type: 'VK_PAGE_INSPECT', action: 'fingerprint' }) as any;

      ctx.reportProgress({ phase: '敏感信息泄露扫描' });
      const leakResult = await sendToContent({ type: 'VK_PAGE_INSPECT', action: 'leak-scan' }) as any;

      const result = analyzeFingerprint(fp, inspectResult, leakResult, patternsData);
      techFindings = result.tech;
      resourceFindings = result.resources;
      leakFindings = result.leaks;

      haeFindings = matchAllRules(fp.bodyHtml + '\n' + fp.scriptSrcs.join('\n'), haeGroups);

      if (fp.scriptSrcs.length > 0) {
        ctx.reportProgress({ phase: `分析 ${fp.scriptSrcs.length} 个 JS 文件` });
        const jsResult = await extractFromJsFiles(fp.scriptSrcs, url, patternsData, ctx.signal);
        if (jsResult.resources.length > 0) resourceFindings = [...resourceFindings, ...jsResult.resources];
        if (jsResult.leaks.length > 0) leakFindings = [...leakFindings, ...jsResult.leaks];
      }

      ctx.reportProgress({ phase: '扫描表单和内联框架' });
      const tab = await getActiveTab();
      if (tab?.id) {
        const domExtra = await execInTab(tab.id, function () {
          const items: { name: string; value: string; color: string }[] = [];
          const pageUrl = location.href;
          document.querySelectorAll('form[action]').forEach(function (form) {
            const action = form.getAttribute('action') || '';
            const method = ((form as HTMLFormElement).method || 'GET').toUpperCase();
            if (action) {
              try { items.push({ name: 'form', value: new URL(action, pageUrl).href + ' [' + method + ']', color: 'blue' }); }
              catch (e) { /* ignore */ }
            }
          });
          document.querySelectorAll('iframe[src],frame[src]').forEach(function (el) {
            try { items.push({ name: 'frame', value: new URL((el as HTMLIFrameElement).src, pageUrl).hostname, color: 'purple' }); }
            catch (e) { /* ignore */ }
          });
          const domains = new Set<string>();
          document.querySelectorAll('[href]').forEach(function (el) {
            try { const u = new URL((el as HTMLAnchorElement).href, pageUrl); if (u.hostname !== location.hostname) domains.add(u.hostname); }
            catch (e) { /* ignore */ }
          });
          document.querySelectorAll('[src]').forEach(function (el) {
            try { const u = new URL((el as HTMLElement).getAttribute('src') || '', pageUrl); if (u.hostname !== location.hostname) domains.add(u.hostname); }
            catch (e) { /* ignore */ }
          });
          domains.forEach(function (d) { items.push({ name: '外链域名', value: d, color: 'cyan' }); });
          return items;
        });
        if (domExtra) {
          for (const item of domExtra) {
            resourceFindings = [...resourceFindings, { ...item, group: 'resources' }];
          }
        }
      }
    },
  }, { centerPanel: 'gather', centerLabel: '信息收集' });

  let cs = $state<TaskState>({ ...IDLE });
  $effect(() => controller.state.subscribe((v: TaskState) => { cs = v; }));
  let collecting = $derived(cs.status === 'running' || cs.status === 'paused' || cs.status === 'validating');

  async function startGather() {
    const r = await controller.start();
    if (r.status === 'succeeded') {
      const total = techFindings.length + resourceFindings.length + leakFindings.length;
      toastStore.show(`收集完成，发现 ${total} 条信息`, 'success');
    } else if (r.status === 'cancelled') {
      toastStore.show('收集已取消', 'info');
    }
  }

  // ===== 导出 / 复制 =====
  function copyValue(value: string) {
    copyText(value, '已复制');
  }

  // 扁平化所有发现供 ExportMenu 消费
  type FlatFinding = { category: string; name: string; value: string };
  let flatFindings = $derived.by<FlatFinding[]>(() => [
    ...techFindings.map(f => ({ category: '技术栈', name: f.name, value: f.value })),
    ...resourceFindings.map(f => ({ category: '资源', name: f.name, value: f.value })),
    ...leakFindings.map(f => ({ category: '泄露', name: f.name, value: f.value })),
  ]);

  function gatherJson(items: FlatFinding[]): string {
    const output: Record<string, { name: string; value: string }[]> = {};
    for (const it of items) {
      if (!output[it.category]) output[it.category] = [];
      output[it.category].push({ name: it.name, value: it.value });
    }
    return JSON.stringify(output, null, 2);
  }
  function gatherCsv(items: FlatFinding[]): string {
    return toCsv([['Category', 'Type', 'Value'], ...items.map(i => [i.category, i.name, i.value])]);
  }
  function gatherText(items: FlatFinding[]): string {
    const lines: string[] = [`# 信息收集结果`, ''];
    const byCat: Record<string, FlatFinding[]> = {};
    for (const it of items) (byCat[it.category] ??= []).push(it);
    for (const [cat, list] of Object.entries(byCat)) {
      lines.push(`## ${cat} (${list.length})`);
      for (const f of list) lines.push(`- [${f.name}] ${f.value}`);
      lines.push('');
    }
    return lines.join('\n');
  }

  /** 复制全部发现（按分类分组纯文本） */
  function copyAll() {
    if (totalCount === 0) { toastStore.show('没有数据可复制', 'warning'); return; }
    copyText(gatherText(flatFindings), `已复制 ${totalCount} 条`);
  }

  /** 将外链 JS/CSS 资源发送到「源码加载」面板 */
  async function sendToSourceLoader() {
    const urls = resourceFindings
      .filter(f => (f.name === 'JS' || f.name === 'CSS') && /^https?:\/\//i.test(f.value))
      .map(f => f.value);
    const uniq = [...new Set(urls)];
    if (uniq.length === 0) { toastStore.show('没有可发送的 JS/CSS 资源', 'warning'); return; }
    await analysisContextStore.handoff({
      sourcePanel: 'gather', sourceLabel: '信息收集',
      targetPanel: 'source-loader', payload: { text: uniq.join('\n') }, summary: `${uniq.length} 个资源`,
    });
  }
</script>

<div class="space-y-3">
  <!-- 顶部操作栏 -->
  <div class="flex items-center gap-2">
    {#if collecting}
      <button class="btn btn-sm btn-danger" onclick={() => controller.cancel()} disabled={!cs.canCancel}>取消</button>
    {:else}
      <button class="btn btn-sm btn-primary" onclick={startGather}>收集当前页面</button>
    {/if}
    <button class="btn btn-sm" disabled={totalCount === 0} onclick={copyAll}>复制全部</button>
    <ExportMenu items={flatFindings} module="gather" serializers={{ json: gatherJson, csv: gatherCsv, text: gatherText }} disabled={collecting} />
    <button class="btn btn-sm" disabled={resourceCount === 0} onclick={sendToSourceLoader} title="发送 JS/CSS 到源码加载">→源码加载</button>
    <button class="btn btn-sm" onclick={() => browser.runtime.openOptionsPage()} title="管理 HaE 规则（YAML）">HaE 规则</button>
  </div>

  {#if collecting}
    <div class="text-xs text-gray-500">{cs.phase || '收集中...'} · {(cs.elapsedMs / 1000).toFixed(1)}s</div>
  {/if}

  {#if cs.status === 'failed'}
    <ErrorState error={cs.error!} onRetry={startGather} />
  {/if}

  {#if totalCount === 0 && !collecting}
    <div class="card p-4 text-center text-xs text-gray-400">
      点击「收集当前页面」开始信息收集
    </div>
  {:else if totalCount > 0}
    <!-- 搜索 -->
    <input
      class="input text-xs"
      placeholder="搜索结果..."
      bind:value={searchFilter}
    />

    <!-- 跨分类搜索结果 -->
    {#if searchFilter && allFiltered.length > 0}
      <div class="card p-3">
        <div class="text-xs font-medium mb-2 text-blue-600 dark:text-blue-400">全局搜索（{allFiltered.length} 条匹配）</div>
        <div class="space-y-1 max-h-64 overflow-y-auto">
          {#each allFiltered.slice(0, 100) as f (`${f._cat}:${f.name}:${f.value}`)}
            <div class="flex items-center justify-between gap-2 group">
              <div class="flex items-center gap-2 min-w-0 flex-1">
                <span class="badge badge-sm text-white" style="background-color: var(--color-{f.color}, #666)">{f.name}</span>
                <span class="badge text-xs bg-gray-200 dark:bg-gray-700">{f._cat}</span>
                <span class="text-xs font-mono truncate" title={f.value}>{f.value}</span>
              </div>
              <button class="btn btn-xs opacity-0 group-hover:opacity-100" onclick={() => copyValue(f.value)}>复制</button>
            </div>
          {/each}
        </div>
      </div>
    {/if}

    <!-- 分类标签 -->
    <div class="seg">
      {#each [
        { id: 'tech' as Category, label: '技术栈', count: filteredTech.length },
        { id: 'resources' as Category, label: '资源', count: filteredResources.length },
        { id: 'leaks' as Category, label: '泄露', count: filteredLeaks.length },
        { id: 'hae' as Category, label: 'HaE', count: haeFindings.length },
      ] as cat}
        <button
          class={activeCategory === cat.id ? 'seg-btn-active' : 'seg-btn-inactive'}
          onclick={() => (activeCategory = cat.id)}
        >
          {cat.label}
          {cat.count > 0 ? ` (${cat.count})` : ''}
        </button>
      {/each}
    </div>

    <!-- 技术栈 -->
    {#if activeCategory === 'tech'}
      <div class="card p-3">
        <div class="text-xs font-medium mb-2 text-gray-500">技术栈指纹（{filteredTech.length}）</div>
        {#if filteredTech.length === 0}
          <div class="text-xs text-gray-400">未检测到</div>
        {:else}
          <div class="space-y-1 max-h-64 overflow-y-auto">
            {#each filteredTech as f (`${f.name}:${f.value}`)}
              <div class="flex items-center justify-between gap-2 group">
                <div class="flex items-center gap-2 min-w-0 flex-1">
                  <span class="badge badge-sm text-white" style="background-color: var(--color-{f.color}, #666)">{f.name}</span>
                  <span class="text-xs font-mono truncate" title={f.value}>{f.value}</span>
                </div>
                <button class="btn btn-xs opacity-0 group-hover:opacity-100" onclick={() => copyValue(f.value)}>复制</button>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    {/if}

    <!-- 资源 -->
    {#if activeCategory === 'resources'}
      <div class="card p-3">
        <div class="text-xs font-medium mb-2 text-gray-500">外链资源（{filteredResources.length}）</div>
        {#if filteredResources.length === 0}
          <div class="text-xs text-gray-400">未发现</div>
        {:else}
          <div class="space-y-1 max-h-64 overflow-y-auto">
            {#each filteredResources as f (`${f.name}:${f.value}`)}
              <div class="flex items-center justify-between gap-2 group">
                <div class="flex items-center gap-2 min-w-0 flex-1">
                  <span class="badge badge-sm text-white" style="background-color: var(--color-{f.color}, #666)">{f.name}</span>
                  <span class="text-xs font-mono truncate" title={f.value}>{f.value}</span>
                </div>
                <button class="btn btn-xs opacity-0 group-hover:opacity-100" onclick={() => copyValue(f.value)}>复制</button>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    {/if}

    <!-- 泄露 -->
    {#if activeCategory === 'leaks'}
      <div class="card p-3">
        <div class="text-xs font-medium mb-2 text-gray-500">敏感信息泄露（{filteredLeaks.length}）</div>
        {#if filteredLeaks.length === 0}
          <div class="text-xs text-green-600 dark:text-green-400">未发现敏感信息泄露</div>
        {:else}
          <div class="space-y-1 max-h-64 overflow-y-auto">
            {#each filteredLeaks as f (`${f.name}:${f.value}`)}
              <div class="flex items-center justify-between gap-2 group">
                <div class="flex items-center gap-2 min-w-0 flex-1">
                  <span class="badge badge-sm text-white {f.color === 'red' ? 'bg-red-600' : f.color === 'yellow' ? 'bg-yellow-600' : 'bg-gray-600'}">{f.name}</span>
                  <span class="text-xs font-mono truncate text-red-600 dark:text-red-400" title={f.value}>{f.value}</span>
                </div>
                <button class="btn btn-xs opacity-0 group-hover:opacity-100" onclick={() => copyValue(f.value)}>复制</button>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    {/if}

    <!-- HaE 规则命中 -->
    {#if activeCategory === 'hae'}
      <div class="card p-3">
        <div class="text-xs font-medium mb-2 text-gray-500">HaE 规则命中（{haeFindings.length}）</div>
        {#if haeFindings.length === 0}
          <div class="text-xs text-gray-400">未命中 HaE 规则</div>
        {:else}
          <div class="space-y-1 max-h-64 overflow-y-auto">
            {#each haeFindings as m}
              <div class="flex items-center gap-2 group">
                <span class="badge badge-sm shrink-0 bg-purple-500 text-white">{m.group}</span>
                <span class="text-xs font-medium shrink-0">{m.rule}{#if m.sensitive} 🔒{/if}</span>
                <span class="text-xs font-mono truncate text-gray-600 dark:text-gray-300 flex-1" title={m.value}>{m.value}</span>
                <button class="btn btn-xs opacity-0 group-hover:opacity-100 shrink-0" onclick={() => copyValue(m.value)}>复制</button>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    {/if}
  {/if}
</div>
