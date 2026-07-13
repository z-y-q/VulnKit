<script lang="ts">
  // 信息收集面板 — 灵眸 v6.0
  // 一键收集：技术栈指纹 / 外链资源 / 敏感信息泄露
  import { sendToContent } from '@/lib/core/messaging';
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl, getActiveTab, execInTab } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import type { DomFingerprint } from '@/lib/types/messaging';
  import { matchAllRules, type HaeMatch } from '@/lib/scanners/hae-engine';
  import { loadMergedGroups, type HaeGroup } from '@/lib/scanners/hae-store';
  import patternsData from '@/lib/data/gather-patterns.json';
  import { loadPrefs, isDomainExcluded } from '@/lib/core/general-prefs';

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
  let collecting = $state(false);
  let statusText = $state('');
  let elapsedSec = $state(0);
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

  let _timerHandle: ReturnType<typeof setInterval> | null = null;
  let _startTime = 0;

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
  ): Promise<{ resources: Finding[]; leaks: Finding[] }> {
    const apiPatterns = patterns.API_PATTERNS as ApiPattern[];
    const sensitivePatterns = patterns.SENSITIVE_PATTERNS as SensitivePattern[];
    const resources: Finding[] = [];
    const leaks: Finding[] = [];
    const seen = new Set<string>();

    // 只取同源 JS，最多 30 个
    let pageOrigin = '';
    try { pageOrigin = new URL(pageUrl).origin; } catch { /* ignore */ }
    const toFetch = scriptSrcs
      .filter(s => { try { return new URL(s).origin === pageOrigin; } catch { return false; } })
      .slice(0, 30);

    const fetchResults = await Promise.all(
      toFetch.map(src => sendMessage({ type: 'FETCH_URL', url: src, timeout: 10000 })),
    );

    for (const result of fetchResults) {
      if (!result || !(result as any).success) continue;
      const content = (result as any).data as string;
      if (!content) continue;
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
    }

    return { resources, leaks };
  }

  /** 敏感值截断 */
  function truncate(value: string, max = 100): string {
    if (value.length <= max) return value;
    return value.substring(0, max) + '...';
  }

  // ===== 收集逻辑 =====
  async function startGather() {
    collecting = true;
    statusText = '正在收集页面信息...';
    elapsedSec = 0;
    _startTime = Date.now();
    _timerHandle = setInterval(() => {
      elapsedSec = Math.floor((Date.now() - _startTime) / 1000);
    }, 1000);

    techFindings = [];
    resourceFindings = [];
    leakFindings = [];
    haeFindings = [];

    try {
      const url = await getActiveTabUrl();
      if (!url) {
        toastStore.show('无法获取当前页面（需 http/https）', 'error');
        return;
      }

      // 1. DOM 指纹
      statusText = '提取 DOM 指纹...';
      const fp = await sendToContent({ type: 'VK_FINGERPRINT_DOM' });
      if (!fp) {
        toastStore.show('无法连接 content script，请刷新页面后重试', 'error');
        return;
      }

      // 2. Fingerprint inspect（全局变量、版本、cookies）
      statusText = '分析指纹信息...';
      const inspectResult = await sendToContent({ type: 'VK_PAGE_INSPECT', action: 'fingerprint' }) as any;

      // 3. 泄露扫描（storage、敏感全局变量）
      statusText = '敏感信息泄露扫描...';
      const leakResult = await sendToContent({ type: 'VK_PAGE_INSPECT', action: 'leak-scan' }) as any;

      // 4. 模式分析
      const result = analyzeFingerprint(fp, inspectResult, leakResult, patternsData);
      techFindings = result.tech;
      resourceFindings = result.resources;
      leakFindings = result.leaks;

      // 4.5 HaE 规则匹配（默认 + 用户自定义，在页面 HTML + scriptSrcs 上提取指纹/凭证）
      haeFindings = matchAllRules(fp.bodyHtml + '\n' + fp.scriptSrcs.join('\n'), haeGroups);

      // 5. 外部 JS 文件分析
      if (fp.scriptSrcs.length > 0) {
        statusText = `分析 ${fp.scriptSrcs.length} 个 JS 文件...`;
        const jsResult = await extractFromJsFiles(fp.scriptSrcs, url, patternsData);
        if (jsResult.resources.length > 0) {
          resourceFindings = [...resourceFindings, ...jsResult.resources];
        }
        if (jsResult.leaks.length > 0) {
          leakFindings = [...leakFindings, ...jsResult.leaks];
        }
      }

      // 6. 扫描 forms / iframes（通过 execInTab 注入）
      statusText = '扫描表单和内联框架...';
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
          // 外部域名
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

      const total = techFindings.length + resourceFindings.length + leakFindings.length;
      statusText = `收集完成，共 ${total} 条（${elapsedSec}s）`;
      toastStore.show(`收集完成，发现 ${total} 条信息`, 'success');
    } catch (e: any) {
      statusText = `收集失败: ${e.message}`;
      toastStore.show(`收集失败: ${e.message}`, 'error');
    } finally {
      collecting = false;
      if (_timerHandle) { clearInterval(_timerHandle); _timerHandle = null; }
    }
  }

  // ===== 导出 / 复制 =====
  function copyValue(value: string) {
    navigator.clipboard.writeText(value).then(() => {
      toastStore.show('已复制', 'success');
    });
  }

  function exportJson() {
    const output: Record<string, { name: string; value: string }[]> = {};
    if (techFindings.length > 0) output['技术栈'] = techFindings.map(f => ({ name: f.name, value: f.value }));
    if (resourceFindings.length > 0) output['资源'] = resourceFindings.map(f => ({ name: f.name, value: f.value }));
    if (leakFindings.length > 0) output['泄露'] = leakFindings.map(f => ({ name: f.name, value: f.value }));
    if (Object.keys(output).length === 0) {
      toastStore.show('没有数据可导出', 'warning');
      return;
    }
    const json = JSON.stringify(output, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `lingmou-gather-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toastStore.show('JSON 已导出', 'success');
  }

  function exportCsv() {
    const rows: string[][] = [];
    for (const f of techFindings) rows.push(['技术栈', f.name, f.value]);
    for (const f of resourceFindings) rows.push(['资源', f.name, f.value]);
    for (const f of leakFindings) rows.push(['泄露', f.name, f.value]);
    if (rows.length === 0) { toastStore.show('没有数据可导出', 'warning'); return; }
    const csv = '﻿' + 'Category,Type,Value\n' + rows.map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `lingmou-gather-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toastStore.show('CSV 已导出', 'success');
  }

  /** 复制全部发现（按分类分组纯文本） */
  function copyAll() {
    if (totalCount === 0) { toastStore.show('没有数据可复制', 'warning'); return; }
    const lines: string[] = [`# 信息收集结果`, ''];
    const dump = (title: string, list: Finding[]) => {
      if (!list.length) return;
      lines.push(`## ${title} (${list.length})`);
      for (const f of list) lines.push(`- [${f.name}] ${f.value}`);
      lines.push('');
    };
    dump('技术栈', techFindings);
    dump('资源', resourceFindings);
    dump('泄露', leakFindings);
    navigator.clipboard.writeText(lines.join('\n')).then(() =>
      toastStore.show(`已复制 ${totalCount} 条`, 'success'));
  }

  /** 将外链 JS/CSS 资源发送到「源码加载」面板 */
  async function sendToSourceLoader() {
    const urls = resourceFindings
      .filter(f => (f.name === 'JS' || f.name === 'CSS') && /^https?:\/\//i.test(f.value))
      .map(f => f.value);
    const uniq = [...new Set(urls)];
    if (uniq.length === 0) { toastStore.show('没有可发送的 JS/CSS 资源', 'warning'); return; }
    await browser.storage.local.set({ 'lingmou:source-pending': uniq.join('\n') });
    toastStore.show(`已发送 ${uniq.length} 条到「源码加载」`, 'success');
  }
</script>

<div class="space-y-3">
  <!-- 顶部操作栏 -->
  <div class="flex items-center gap-2">
    <button
      class="btn btn-sm btn-primary"
      disabled={collecting}
      onclick={startGather}
    >
      {collecting ? `收集中... ${elapsedSec}s` : '收集当前页面'}
    </button>
    <button class="btn btn-sm" disabled={totalCount === 0} onclick={copyAll}>复制全部</button>
    <button class="btn btn-sm" disabled={totalCount === 0} onclick={exportJson}>导出 JSON</button>
    <button class="btn btn-sm" disabled={totalCount === 0} onclick={exportCsv}>导出 CSV</button>
    <button class="btn btn-sm" disabled={resourceCount === 0} onclick={sendToSourceLoader} title="发送 JS/CSS 到源码加载">→源码加载</button>
    <button class="btn btn-sm" onclick={() => browser.runtime.openOptionsPage()} title="管理 HaE 规则（YAML）">HaE 规则</button>
  </div>

  {#if statusText}
    <div class="text-xs text-gray-500">{statusText}</div>
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
          {#each allFiltered.slice(0, 100) as f}
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
    <div class="flex gap-1">
      {#each [
        { id: 'tech' as Category, label: '技术栈', count: filteredTech.length },
        { id: 'resources' as Category, label: '资源', count: filteredResources.length },
        { id: 'leaks' as Category, label: '泄露', count: filteredLeaks.length },
        { id: 'hae' as Category, label: 'HaE', count: haeFindings.length },
      ] as cat}
        <button
          class="btn btn-sm {activeCategory === cat.id ? 'bg-primary text-white' : 'btn-ghost'}"
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
            {#each filteredTech as f}
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
            {#each filteredResources as f}
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
            {#each filteredLeaks as f}
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
