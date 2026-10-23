<script lang="ts">
  // HAE 规则引擎面板
  // HaE 风格正则匹配：对响应体/页面 HTML 应用规则组，提取敏感信息/指纹/凭证。
  import { getActiveTab, execInTab } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import { matchAllRules, HAE_COLOR_CLASS, DEFAULT_HAE_GROUPS, type HaeMatch } from '@/lib/scanners/hae-engine';
  import { copyText } from '@/lib/actions/clipboard';
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import { haeStateStore } from '@/stores/hae-state';
  import { get } from 'svelte/store';
  import EmptyState from '@/components/scanner/EmptyState.svelte';

  // —— 状态（storage-backed）——
  let st = $state(get(haeStateStore));
  $effect(() => haeStateStore.subscribe(v => { st = v; }));

  let inputText = $derived(st.inputText);
  let matches = $derived(st.matches);
  let groupFilter = $derived(st.groupFilter);
  let onlySensitive = $derived(st.onlySensitive);

  let groups = $derived(DEFAULT_HAE_GROUPS.map(g => g.group));
  let totalRules = $derived(DEFAULT_HAE_GROUPS.reduce((n, g) => n + g.rules.filter(r => r.loaded).length, 0));

  let filtered = $derived(
    matches.filter(m =>
      (groupFilter === 'all' || m.group === groupFilter) &&
      (!onlySensitive || m.sensitive),
    ),
  );
  let sensitiveCount = $derived(matches.filter(m => m.sensitive).length);

  function runMatch() {
    if (!inputText.trim()) { toastStore.show('请输入待匹配文本', 'warning'); return; }
    const result = matchAllRules(inputText);
    haeStateStore.update(s => ({ ...s, matches: result }));
    const sensitiveCount = result.filter(m => m.sensitive).length;
    toastStore.show(`匹配 ${result.length} 处（${sensitiveCount} 敏感）`, result.length ? 'success' : 'info');
  }

  async function collectPage() {
    const tab = await getActiveTab();
    if (!tab?.id) { toastStore.show('无法获取标签页', 'error'); return; }
    const html = await execInTab<string>(tab.id, function () {
      return document.documentElement.outerHTML;
    });
    if (html) {
      haeStateStore.update(s => ({ ...s, inputText: html }));
      toastStore.show(`已采集页面 HTML（${(html.length / 1024).toFixed(1)}KB）`, 'success');
    } else {
      toastStore.show('采集失败', 'error');
    }
  }

  function colorClass(c: string): string {
    return HAE_COLOR_CLASS[c] || 'bg-gray-500';
  }

  async function copyValue(v: string) {
    await copyText(v, '已复制');
  }

  // —— 序列化器（作用于当前筛选 filtered）——
  function haeText(items: HaeMatch[]): string {
    return items.map((m) => `[${m.rule}] ${m.value}`).join('\n');
  }
  function haeJson(items: HaeMatch[]): string {
    return JSON.stringify(items, null, 2);
  }
</script>

<div class="space-y-3">
  <div class="card p-3 space-y-2">
    <div class="flex items-center justify-between">
      <div class="text-sm font-medium">HAE 规则引擎</div>
      <div class="flex gap-1">
        <button class="btn btn-xs" onclick={collectPage}>采集当前页</button>
        <button class="btn btn-xs btn-primary" onclick={runMatch}>匹配规则</button>
      </div>
    </div>
    <div class="text-xs text-gray-500">{groups.length} 个规则组 · {totalRules} 条规则（指纹/凭证/敏感信息高亮提取）</div>
    <textarea class="input font-mono text-xs" rows="5" placeholder="粘贴响应体/页面 HTML，或点「采集当前页」自动填入..." aria-label="响应体" value={inputText} oninput={(e) => haeStateStore.update(s => ({ ...s, inputText: e.currentTarget.value }))}></textarea>
  </div>

  {#if matches.length > 0}
    <div class="flex items-center gap-2 text-xs flex-wrap">
      <span>共 {matches.length} 处</span>
      {#if sensitiveCount > 0}<span class="badge bg-red-50 text-red-700 ring-1 ring-inset ring-red-200 dark:bg-red-900/30 dark:text-red-300 dark:ring-red-800/60">敏感 {sensitiveCount}</span>{/if}
      <select class="input text-xs w-32 ml-auto" aria-label="分组筛选" value={groupFilter} onchange={(e) => haeStateStore.update(s => ({ ...s, groupFilter: e.currentTarget.value }))}>
        <option value="all">全部分组</option>
        {#each groups as g}<option value={g}>{g}</option>{/each}
      </select>
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" checked={onlySensitive} onchange={(e) => haeStateStore.update(s => ({ ...s, onlySensitive: e.currentTarget.checked }))} class="accent-blue-500" />
        <span>仅敏感</span>
      </label>
      <ExportMenu items={filtered} module="hae" serializers={{ json: haeJson, text: haeText }} />
    </div>

    <div class="space-y-1 max-h-[28rem] overflow-y-auto">
      {#each filtered as m (m.rule + m.value)}
        <div class="card p-2 flex items-start gap-2">
          <span class="badge text-xs text-white shrink-0 {colorClass(m.color)}">{m.group}</span>
          <div class="flex-1 min-w-0">
            <div class="text-xs font-medium flex items-center gap-1">
              {m.rule}
              {#if m.sensitive}<span class="text-red-500">🔒</span>{/if}
            </div>
            <div class="text-xs font-mono text-gray-600 dark:text-gray-300 break-all bg-gray-50 dark:bg-gray-900 px-1.5 py-0.5 rounded mt-0.5">{m.value}</div>
          </div>
          <button class="text-xs text-gray-500 hover:text-primary shrink-0" onclick={() => copyValue(m.value)}>复制</button>
        </div>
      {/each}
    </div>
  {:else if inputText}
    <div class="text-xs text-gray-500 text-center py-4">点击「匹配规则」提取敏感信息</div>
  {:else}
    <EmptyState
      message="粘贴文本或采集页面，用 HaE 规则提取指纹/凭证"
      icon="🎨"
    />
  {/if}
</div>
