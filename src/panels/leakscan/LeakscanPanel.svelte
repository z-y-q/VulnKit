<script lang="ts">
  // 敏感信息泄露深度扫描面板 — 灵眸 v6.0
  // 采集当前页 DOM + localStorage + sessionStorage + 全局变量，用 90 条泄露规则引擎扫描。
  import { sendToContent, sendMessage } from '@/lib/core/messaging';
  import { getActiveTab, getActiveTabUrl, execInTab } from '@/lib/core/tabs';
  import { toastStore } from '@/stores/ui';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import { scanLeaks, severityRank, type LeakFinding, type LeakSeverity } from '@/lib/scanners/leak-scanner';
  import UrlInput from '@/components/scanner/UrlInput.svelte';
  import EmptyState from '@/components/scanner/EmptyState.svelte';
  import SeverityBadge from '@/components/scanner/SeverityBadge.svelte';
  import FilterBar from '@/components/scanner/FilterBar.svelte';

  let targetUrl = $state('');
  let scanning = $state(false);
  let findings = $state<LeakFinding[]>([]);
  let filter = $state<'all' | LeakSeverity>('all');
  let sources = $state<{ dom: number; storage: number; js: number }>({ dom: 0, storage: 0, js: 0 });

  $effect(() => {
    getActiveTabUrl().then(u => { if (u) targetUrl = u; });
  });

  let sevCounts = $derived.by(() => {
    const c: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1;
    return c;
  });

  let filtered = $derived(
    filter === 'all' ? findings : findings.filter(f => f.severity === filter),
  );

  const SEV_TO_BADGE: Record<LeakSeverity, string> = {
    critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info',
  };

  /** 采集页面 DOM + storage + 全局变量，返回拼接文本与各来源大小 */
  async function collectPageSignals(): Promise<{ text: string; dom: number; storage: number; js: number }> {
    const tab = await getActiveTab();
    let text = '';
    let dom = 0, storage = 0, js = 0;

    // 1) DOM + localStorage/sessionStorage + 全局变量名（ISOLATED world）
    if (tab?.id) {
      const collected = await execInTab<{ html: string; ls: string; ss: string; globals: string[] }>(
        tab.id,
        () => {
          const html = document.documentElement.outerHTML;
          let ls = '', ss = '';
          try { for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i)!; ls += k + '=' + localStorage.getItem(k) + '\n'; } } catch { /* */ }
          try { for (let i = 0; i < sessionStorage.length; i++) { const k = sessionStorage.key(i)!; ss += k + '=' + sessionStorage.getItem(k) + '\n'; } } catch { /* */ }
          const globals: string[] = [];
          for (const k of Object.getOwnPropertyNames(window)) {
            try { const v = (window as any)[k]; if (typeof v === 'string' && v.length > 8) globals.push(k + '=' + v); } catch { /* */ }
          }
          return { html, ls, ss, globals };
        },
      );
      if (collected) {
        dom = collected.html.length;
        storage = collected.ls.length + collected.ss.length;
        text += collected.html + '\n' + collected.ls + '\n' + collected.ss + '\n' + collected.globals.join('\n');
      }
    }

    // 2) 外部 JS 文件内容（最多 15 个，仅 src 同源/相对）
    if (tab?.id) {
      const scriptUrls = await execInTab<string[]>(tab.id, () => {
        return Array.from(document.querySelectorAll('script[src]')).map(s => (s as HTMLScriptElement).src).slice(0, 15);
      });
      if (scriptUrls && scriptUrls.length) {
        const results = await Promise.allSettled(
          scriptUrls.slice(0, 15).map(u => sendMessage({ type: 'FETCH_URL', url: u, tailOnly: true })),
        );
        for (const r of results) {
          if (r.status === 'fulfilled') {
            const res = r.value as any;
            if (res && res.success && res.data) { text += '\n' + res.data; js += (res.data as string).length; }
          }
        }
      }
    }

    return { text: text.slice(0, 4_000_000), dom, storage, js };
  }

  async function startScan() {
    if (!targetUrl) { toastStore.show('请先在目标页面打开本面板', 'error'); return; }
    scanning = true;
    findings = [];
    try {
      const { text, dom, storage, js } = await collectPageSignals();
      sources = { dom, storage, js };
      if (!text || text.length < 10) {
        toastStore.show('未能采集到页面内容（可能无权限）', 'warning');
        scanning = false;
        return;
      }
      // 90 条规则扫描
      const raw = scanLeaks(text, 30);
      // 截断条数（v5 上限 200）
      findings = raw.slice(0, 200);

      try {
        await scanHistoryStore.addScan({ url: targetUrl, module: 'leakscan', findings: mapToFindings(findings) });
      } catch { /* */ }

      if (findings.length > 0) {
        const crit = sevCounts.critical + sevCounts.high;
        toastStore.show(`发现 ${findings.length} 处泄露（${crit} 处高危）`, crit > 0 ? 'error' : 'warning');
      } else {
        toastStore.show('深度扫描完成，未发现敏感信息泄露', 'success');
      }
    } catch (e: any) {
      toastStore.show('扫描出错: ' + (e.message || ''), 'warning');
    } finally {
      scanning = false;
    }
  }

  function mapToFindings(items: LeakFinding[]): ScanFinding[] {
    return items.map(f => ({
      title: `${f.rule} [${f.category}]`,
      severity: (f.severity === 'info' ? 'info' : f.severity === 'critical' ? 'critical' : f.severity) as ScanFinding['severity'],
      detail: [f.description, f.exploit ? '利用: ' + f.exploit : '', f.recommendation ? '修复: ' + f.recommendation : ''].filter(Boolean).join('\n'),
      evidence: f.value,
      url: targetUrl,
    }));
  }

  function copyAll() {
    if (!findings.length) return;
    const text = findings.map(f => `[${f.severity}] ${f.rule} (${f.confidence})\n  值: ${f.value}\n  ${f.description || ''}`).join('\n\n');
    navigator.clipboard.writeText(text);
    toastStore.show('已复制泄露报告', 'success');
  }

  function copyMarkdown() {
    if (!findings.length) return;
    const lines = [`# 敏感信息泄露扫描`, ``, `**目标:** ${targetUrl}`, ``, `## 发现 (${findings.length})`];
    for (const f of findings) {
      lines.push(`- **[${f.severity.toUpperCase()}] ${f.rule}** (${f.category}, ${f.confidence})`);
      lines.push(`  - 值: \`${f.value}\``);
      if (f.description) lines.push(`  - ${f.description}`);
      if (f.exploit) lines.push(`  - ⚡ ${f.exploit}`);
    }
    navigator.clipboard.writeText(lines.join('\n'));
    toastStore.show('Markdown 已复制', 'success');
  }

  function exportResults() {
    if (!findings.length) return;
    const blob = new Blob([JSON.stringify(findings, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `leakscan-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toastStore.show('已导出 JSON', 'success');
  }
</script>

<div class="space-y-3">
  <!-- 输入 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <UrlInput bind:value={targetUrl} {scanning} buttonText="深度扫描" onscan={startScan} />
    </div>
    <div class="text-xs text-gray-400">
      采集 DOM / localStorage / sessionStorage / 全局变量 / 外部 JS，运行 90 条泄露规则引擎（含熵值/Luhn/占位符校验降误报）。
    </div>
    {#if scanning}
      <div class="text-xs text-blue-500">正在采集页面信号并匹配规则...</div>
    {/if}
  </div>

  <!-- 统计 -->
  {#if findings.length > 0}
    <FilterBar
      active={filter}
      options={[
        { key: 'all', label: '全部', count: findings.length, color: 'bg-primary text-white' },
        { key: 'critical', label: '严重', count: sevCounts.critical, color: 'bg-red-600 text-white' },
        { key: 'high', label: '高危', count: sevCounts.high, color: 'bg-red-500 text-white' },
        { key: 'medium', label: '中危', count: sevCounts.medium, color: 'bg-amber-500 text-white' },
        { key: 'low', label: '低危', count: sevCounts.low, color: 'bg-gray-400 text-white' },
      ]}
      onchange={(k) => (filter = k as 'all' | LeakSeverity)}
    >
      <button class="btn btn-sm" onclick={copyAll}>复制</button>
      <button class="btn btn-sm" onclick={copyMarkdown}>MD</button>
      <button class="btn btn-sm" onclick={exportResults}>导出</button>
    </FilterBar>
    <div class="text-xs text-gray-400 px-1">
      来源大小：DOM {(sources.dom / 1024).toFixed(1)}KB · 存储 {(sources.storage / 1024).toFixed(1)}KB · JS {(sources.js / 1024).toFixed(1)}KB
    </div>
  {/if}

  <!-- 结果 -->
  {#if filtered.length > 0}
    <div class="space-y-2">
      {#each filtered as f (f.ruleId + f.value)}
        <div class="card p-2.5 space-y-1">
          <div class="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={SEV_TO_BADGE[f.severity]} />
            <span class="text-sm font-medium">{f.rule}</span>
            <span class="badge text-xs bg-gray-200 dark:bg-gray-700">{f.category}</span>
            <span class="badge text-xs bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300">{f.confidence}</span>
          </div>
          <div class="text-xs font-mono text-red-600 dark:text-red-400 break-all bg-red-50 dark:bg-red-950/30 px-2 py-1 rounded">
            {f.value}
          </div>
          {#if f.description}
            <div class="text-xs text-gray-600 dark:text-gray-300">{f.description}</div>
          {/if}
          {#if f.exploit}
            <div class="text-xs text-amber-600 dark:text-amber-400">⚡ {f.exploit}</div>
          {/if}
          {#if f.recommendation}
            <div class="text-xs text-green-600 dark:text-green-400">✔ {f.recommendation}</div>
          {/if}
        </div>
      {/each}
    </div>
  {:else if !scanning && findings.length === 0}
    <EmptyState
      message="点击「深度扫描」检测页面中的敏感信息泄露"
      hint="90 条规则覆盖云密钥/加密缺陷/PII/基础设施凭证/Webhook 等"
      icon="🔓"
    />
  {/if}
</div>
