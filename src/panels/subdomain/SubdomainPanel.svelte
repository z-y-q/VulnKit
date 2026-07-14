<script lang="ts">
  // 子域名枚举面板
  // 流程：自动填充 URL → 提取根域 → 词表生成 → DNS 并发解析 → 结果渲染
  import { sendMessage, sendToContent } from '@/lib/core/messaging';
  import { getActiveTabUrl, getActiveTab, execInTab } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore, autoRunStore } from '@/stores/ui';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import { scanSettingsStore } from '@/stores/settings';
  import { runConcurrent } from '@/lib/core/concurrency';
  import type { FetchResult, DnsResolveResult, ProbeResult } from '@/lib/types/messaging';
  import {
    SUBDOMAIN_WORDLIST,
    extractRootDomain,
    buildSubdomainCandidates,
    analyzeDnsResult,
    dedupAliveResults,
    buildStats,
    detectWildcard,
    parseCrtshResponse,
    parseWaybackResponse,
    parseCertspotterResponse,
    parseDnsRecords,
    parsePageLinks,
    type SubdomainResult,
  } from '@/lib/scanners/subdomain-engine';
  import UrlInput from '@/components/scanner/UrlInput.svelte';
  import ScanProgress from '@/components/scanner/ScanProgress.svelte';
  import EmptyState from '@/components/scanner/EmptyState.svelte';
  import ResultToolbar from '@/components/results/ResultToolbar.svelte';
  import ExportMenu from '@/components/results/ExportMenu.svelte';
  import ErrorState from '@/components/feedback/ErrorState.svelte';
  import { createTaskController, IDLE, type TaskState } from '@/lib/tasks/task-controller';
  import { copyText } from '@/lib/actions/clipboard';
  import { toCsv } from '@/lib/actions/serializers';
  import { type ResultAdapter, type ResultQuery } from '@/lib/results/result-adapter';

  let targetUrl = $state('');
  let results = $state<SubdomainResult[]>([]);
  let query = $state<ResultQuery>({ search: '', filters: {}, sort: { key: 'name', direction: 'asc' } });

  // 枚举方法开关
  let useBrute = $state(true);     // DNS 暴力
  let useCT = $state(true);        // 证书透明（crt.sh）
  let useCertspotter = $state(false); // CertSpotter 第三方证书
  let useDnsRec = $state(false);   // DNS NS/MX 记录枚举
  let useWayback = $state(true);   // Wayback Machine
  let usePage = $state(true);      // 当前页面链接
  let wildcardDetected = $state(false);

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
      if (!useBrute && !useCT && !useCertspotter && !useDnsRec && !useWayback && !usePage) {
        throw new Error('请至少选择一种枚举方法');
      }
    },
    run: async (input, ctx) => {
      const v = validateProbeUrl(input.url);
      if ('error' in v) throw new Error('无效的目标 URL');
      const rootDomain = extractRootDomain(v.parsed.hostname);
      const candidates = buildSubdomainCandidates(rootDomain);

      results = [];
      wildcardDetected = false;
      const collected: SubdomainResult[] = [];
      let scanned = 0;

      // —— 阶段 0：Wildcard 泛解析检测 ——
      if (useBrute) {
        ctx.reportProgress({ phase: '检测泛解析...' });
        wildcardDetected = await detectWildcard(rootDomain, resolvesToIp);
        if (wildcardDetected) {
          toastStore.show('检测到 DNS 泛解析，暴力结果将标记为待验证', 'warning');
        }
      }

      // —— 阶段 1：被动枚举（零噪声，优先）——
      const passiveTasks: Promise<void>[] = [];

      if (useCT) {
        passiveTasks.push((async () => {
          ctx.reportProgress({ phase: '查询证书透明日志 (crt.sh)...' });
          try {
            const res = await sendMessage({ type: 'FETCH_URL', url: `https://crt.sh/?q=%25.${rootDomain}&output=json` }) as FetchResult<string>;
            if (res.success && res.data) {
              await verifyAndMerge(parseCrtshResponse(res.data, rootDomain), 'ct', collected, ctx, () => scanned);
            }
          } catch { /* crt.sh 可能超时，忽略 */ }
        })());
      }

      if (useWayback) {
        passiveTasks.push((async () => {
          ctx.reportProgress({ phase: '查询 Wayback Machine...' });
          try {
            const res = await sendMessage({ type: 'FETCH_URL', url: `https://web.archive.org/cdx/search/cdx?url=*.${rootDomain}/*&output=text&fl=original&collapse=urlkey` }) as FetchResult<string>;
            if (res.success && res.data) {
              await verifyAndMerge(parseWaybackResponse(res.data, rootDomain), 'wayback', collected, ctx, () => scanned);
            }
          } catch { /* ignore */ }
        })());
      }

      if (useCertspotter) {
        passiveTasks.push((async () => {
          ctx.reportProgress({ phase: '查询 CertSpotter...' });
          try {
            const res = await sendMessage({ type: 'FETCH_URL', url: `https://api.certspotter.com/v1/issuances?domain=${rootDomain}&include_subdomains=true&expand=dns_names` }) as FetchResult<string>;
            if (res.success && res.data) {
              await verifyAndMerge(parseCertspotterResponse(res.data, rootDomain), 'ct', collected, ctx, () => scanned);
            }
          } catch { /* ignore */ }
        })());
      }

      if (useDnsRec) {
        passiveTasks.push((async () => {
          ctx.reportProgress({ phase: '查询 DNS NS/MX 记录...' });
          try {
            const dohUrls = [
              `https://dns.google/resolve?name=${rootDomain}&type=NS`,
              `https://dns.google/resolve?name=${rootDomain}&type=MX`,
            ];
            for (const u of dohUrls) {
              const res = await sendMessage({ type: 'FETCH_URL', url: u }) as FetchResult<string>;
              if (res.success && res.data) {
                try {
                  const json = JSON.parse(res.data);
                  const text = (json.Answer || json.Authority || []).map((a: any) => a.data || '').join('\n');
                  await verifyAndMerge(parseDnsRecords(text, rootDomain), 'ct', collected, ctx, () => scanned);
                } catch { /* ignore */ }
              }
            }
          } catch { /* ignore */ }
        })());
      }

      if (usePage) {
        passiveTasks.push((async () => {
          ctx.reportProgress({ phase: '提取页面链接...' });
          const links = await harvestPageLinks(rootDomain);
          if (links.length > 0) await verifyAndMerge(links, 'page', collected, ctx, () => scanned);
        })());
      }

      await Promise.all(passiveTasks);

      // —— 阶段 2：DNS 暴力枚举 ——
      if (useBrute && !ctx.signal.aborted) {
        ctx.reportProgress({ phase: 'DNS 暴力枚举...' });
        const bruteTodo = candidates.filter(c => !collected.some(r => r.subdomain === c.full));
        ctx.reportProgress({ total: bruteTodo.length + scanned, completed: scanned });
        await runConcurrent(bruteTodo, async (c) => {
          const r = await resolveOne(c.full);
          r.source = 'brute';
          collected.push(r);
          scanned++;
          ctx.reportProgress({ completed: scanned });
        }, { concurrency: $scanSettingsStore.concurrency, cancelled: () => ctx.signal.aborted });

        if (wildcardDetected) {
          for (const r of collected) {
            if (r.source === 'brute') r.status = 'alive';
          }
        }
      }

      // —— 阶段 3：HTTP 探测验证 ——
      if (!ctx.signal.aborted) {
        ctx.reportProgress({ phase: 'HTTP 探测验证中...' });
        const aliveHosts = collected
          .filter(r => r.status === 'alive')
          .map(r => r.subdomain)
          .filter((v, i, a) => a.indexOf(v) === i);
        if (aliveHosts.length > 0) {
          const verified = await httpProbeVerify(aliveHosts, rootDomain, ctx);
          for (const r of collected) {
            if (r.status === 'alive' && !verified.has(r.subdomain)) {
              r.status = 'dead';
            }
          }
        }
      }

      // 合并去重
      const merged = new Map<string, SubdomainResult>();
      for (const r of collected) {
        const ex = merged.get(r.subdomain);
        if (!ex || r.ips.length > ex.ips.length) merged.set(r.subdomain, r);
      }
      results = [...merged.values()];

      if (ctx.signal.aborted) return;

      try {
        const alive = results.filter(r => r.status === 'alive');
        await scanHistoryStore.addScan({
          url: input.url,
          module: 'subdomain',
          findings: mapSubdomainsToFindings(alive),
        });
      } catch { /* store failure must not break scan */ }
    },
  }, { centerPanel: 'subdomain', centerLabel: '子域名枚举' });

  let cs = $state<TaskState>({ ...IDLE });
  $effect(() => controller.state.subscribe((v: TaskState) => { cs = v; }));
  let archiving = $derived(cs.status === 'running' || cs.status === 'paused' || cs.status === 'validating');

  async function handleScan() {
    const r = await controller.start({ url: targetUrl });
    if (r.status === 'succeeded') {
      const aliveCount = results.filter(r => r.status === 'alive').length;
      const srcCount = {
        ct: results.filter(r => r.source === 'ct' && r.status === 'alive').length,
        wayback: results.filter(r => r.source === 'wayback' && r.status === 'alive').length,
        page: results.filter(r => r.source === 'page' && r.status === 'alive').length,
        brute: results.filter(r => r.source === 'brute' && r.status === 'alive').length,
      };
      if (aliveCount > 0) {
        toastStore.show(
          `发现 ${aliveCount} 个存活子域名（证书${srcCount.ct}/历史${srcCount.wayback}/页面${srcCount.page}/暴力${srcCount.brute}）`,
          'warning',
        );
      } else {
        toastStore.show('枚举完成，未发现存活子域名', 'success');
      }
    } else if (r.status === 'cancelled') {
      toastStore.show('扫描已取消', 'info');
    }
  }

  // 一键操作（右键菜单 / Popup）：命中本面板则自动扫描
  $effect(() => {
    const sig = $autoRunStore;
    if (sig && sig.panel === 'subdomain') {
      autoRunStore.clear();
      if (sig.url) targetUrl = sig.url;
      handleScan();
    }
  });

  // ===== 派生：结果（统一 ResultAdapter，供 ResultToolbar/ExportMenu 消费）=====
  const subdomainAdapter: ResultAdapter<SubdomainResult> = {
    apply(items, q) {
      let list = dedupAliveResults(items);
      const kw = q.search.trim().toLowerCase();
      if (kw) list = list.filter((r) => r.subdomain.toLowerCase().includes(kw));
      return [...list].sort((a, b) => {
        if (q.sort.key === 'ips') return b.ips.length - a.ips.length;
        return a.subdomain.localeCompare(b.subdomain);
      });
    },
    getSearchText(r) {
      return r.subdomain;
    },
    getId(r) {
      return r.subdomain;
    },
  };

  let filteredResults = $derived(subdomainAdapter.apply(results, query));

  let stats = $derived(buildStats(results, 0));

  async function resolveOne(hostname: string): Promise<SubdomainResult> {
    try {
      const res = await sendMessage({ type: 'FETCH_DNS_RESOLVE', hostname }) as DnsResolveResult;
      return analyzeDnsResult(hostname, res);
    } catch {
      return { subdomain: hostname, ips: [], records: [], status: 'dead' };
    }
  }

  /** DNS 是否解析到 IP（用于 Wildcard 检测） */
  async function resolvesToIp(hostname: string): Promise<boolean> {
    try {
      const r = await resolveOne(hostname);
      return r.status === 'alive' && r.ips.length > 0;
    } catch {
      return false;
    }
  }

  /** HTTP HEAD 探测子域名（验证存活 / 过滤泛解析假阳性） */
  async function httpProbeOne(hostname: string): Promise<ProbeResult | null> {
    try {
      return await sendMessage({
        type: 'FETCH_PROBE',
        url: `https://${hostname}`,
        method: 'HEAD',
        timeout: 5000,
      }) as ProbeResult;
    } catch {
      return null;
    }
  }

  /** 批量 HTTP 探测验证存活，返回通过验证的子域名集合 */
  async function httpProbeVerify(
    aliveHosts: string[],
    rootDomain: string,
    ctx: { signal: AbortSignal },
  ): Promise<Set<string>> {
    const verified = new Set<string>();
    await runConcurrent(aliveHosts, async (host) => {
      if (ctx.signal.aborted) return;
      const res = await httpProbeOne(host);
      // 连接失败 / 无响应 → 泛解析假阳性
      if (!res || res.error || res.status === 0) return;
      // 服务端错误 → 假阳性
      if (res.status >= 500) return;
      // 跨域重定向 → 泛解析假阳性（被重定向到统一落地页）
      if (res.url) {
        try {
          const finalHost = new URL(res.url).hostname.toLowerCase();
          if (finalHost !== host.toLowerCase() && !finalHost.endsWith(rootDomain)) return;
        } catch { /* ignore */ }
      }
      verified.add(host);
    }, { concurrency: $scanSettingsStore.concurrency, cancelled: () => ctx.signal.aborted });
    return verified;
  }

  /** 被动源获取的子域名 → DNS 验证存活并合并；onScanned 回调上报进度 */
  async function verifyAndMerge(
    hostnames: string[],
    source: SubdomainResult['source'],
    acc: SubdomainResult[],
    ctx: { signal: AbortSignal },
    onScanned: () => void,
  ) {
    const seen = new Set(acc.map(r => r.subdomain));
    const todo = hostnames.filter(h => !seen.has(h));
    for (const h of todo) {
      if (ctx.signal.aborted) break;
      const r = await resolveOne(h);
      r.source = source;
      acc.push(r);
      onScanned();
    }
  }

  /** 从当前页面提取链接中的子域名 */
  async function harvestPageLinks(rootDomain: string): Promise<string[]> {
    try {
      const tab = await getActiveTab();
      if (!tab?.id) return [];
      const hrefs = await execInTab<string[]>(tab.id, function () {
        const out: string[] = [];
        document.querySelectorAll('a[href]').forEach(function (el) {
          out.push((el as HTMLAnchorElement).href);
        });
        return out;
      }, { world: 'MAIN' });
      return Array.isArray(hrefs) ? parsePageLinks(hrefs, rootDomain) : [];
    } catch {
      return [];
    }
  }

  function mapSubdomainsToFindings(alive: SubdomainResult[]): ScanFinding[] {
    return alive.map(r => ({
      title: `子域名: ${r.subdomain}`,
      severity: 'info' as const,
      detail: `IPs: ${r.ips.join(', ')}`,
      evidence: r.cname || undefined,
      url: `https://${r.subdomain}`,
    }));
  }

  // —— 导出/复制序列化器（作用于当前筛选 filteredResults，展示/导出同源 §6.1）——
  function subdomainCsv(items: SubdomainResult[]): string {
    return toCsv([
      ['subdomain', 'ips', 'cname', 'record_count'],
      ...items.map((r) => [r.subdomain, r.ips.join(';'), r.cname || '', String(r.records.length)]),
    ]);
  }
  function subdomainText(items: SubdomainResult[]): string {
    return items.map((r) => r.subdomain).join('\n');
  }

  async function copyRow(r: SubdomainResult) {
    const text = [
      `Subdomain: ${r.subdomain}`,
      `IPs: ${r.ips.join(', ') || '(无)'}`,
      `CNAME: ${r.cname || '(无)'}`,
      `Records: ${r.records.map((rec) => `${rec.type}: ${rec.data}`).join(', ') || '(无)'}`,
    ].join('\n');
    await copyText(text, `已复制: ${r.subdomain}`);
  }

  function formatElapsed(ms: number): string {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  }
</script>

<div class="space-y-3">
  <!-- 输入 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <UrlInput bind:value={targetUrl} scanning={archiving} buttonText="枚举" scanningText="枚举中..." onscan={handleScan} />
      {#if archiving}
        <button class="btn btn-sm btn-danger shrink-0" onclick={() => controller.cancel()} disabled={!cs.canCancel}>取消</button>
      {/if}
    </div>
    <div class="flex items-center gap-2 text-xs text-gray-400">
      <span>词表: {SUBDOMAIN_WORDLIST.length} 条</span>
      <span>·</span>
      <span>并发: {$scanSettingsStore.concurrency}</span>
    </div>

    <!-- 枚举方法开关 -->
    <div class="flex flex-wrap items-center gap-1.5 text-xs">
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={useCT} disabled={archiving} class="accent-blue-500" />
        <span class="text-gray-600 dark:text-gray-300">证书透明 (crt.sh)</span>
      </label>
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={useCertspotter} disabled={archiving} class="accent-blue-500" />
        <span class="text-gray-600 dark:text-gray-300">CertSpotter</span>
      </label>
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={useDnsRec} disabled={archiving} class="accent-blue-500" />
        <span class="text-gray-600 dark:text-gray-300">DNS NS/MX</span>
      </label>
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={useWayback} disabled={archiving} class="accent-blue-500" />
        <span class="text-gray-600 dark:text-gray-300">Wayback 历史</span>
      </label>
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={usePage} disabled={archiving} class="accent-blue-500" />
        <span class="text-gray-600 dark:text-gray-300">页面链接</span>
      </label>
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={useBrute} disabled={archiving} class="accent-blue-500" />
        <span class="text-gray-600 dark:text-gray-300">DNS 暴力</span>
      </label>
    </div>

    {#if wildcardDetected}
      <div class="text-xs text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/30 rounded px-2 py-1">
        ⚠️ 检测到 DNS 泛解析，暴力枚举结果可能含假阳性，建议结合 HTTP 存活验证
      </div>
    {/if}

    <ScanProgress scanned={cs.completed} total={cs.total ?? 0} scanning={archiving} phase={cs.phase} label="子域名枚举" />
  </div>

  <!-- 工具栏：ResultToolbar 包裹 搜索 / 排序 / 导出 -->
  {#if results.length > 0}
    <ResultToolbar {query} total={results.length} shown={filteredResults.length} searchPlaceholder="搜索子域名...">
      <span class="badge bg-green-500 text-white">存活 {stats.alive}</span>
      <span class="badge bg-gray-200 dark:bg-gray-700">总计 {stats.total}</span>
      <select
        class="input text-xs w-20"
        value={query.sort.key}
        onchange={(e) => { query.sort.key = (e.currentTarget as HTMLSelectElement).value; }}
        aria-label="排序"
      >
        <option value="name">按名称</option>
        <option value="ips">按 IP 数</option>
      </select>
      <ExportMenu items={filteredResults} module="subdomain" serializers={{ csv: subdomainCsv, text: subdomainText }} />
    </ResultToolbar>
  {/if}

  <!-- 结果 -->
  {#if filteredResults.length > 0}
    <div class="space-y-1">
      {#each filteredResults as r (r.subdomain)}
        <div class="card p-2 flex items-center gap-2">
          <span class="badge text-xs bg-green-600 text-white w-8 justify-center shrink-0">
            {r.ips.length}
          </span>
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-1.5">
              <span class="text-xs font-mono text-gray-700 dark:text-gray-200 truncate">{r.subdomain}</span>
              {#if r.source}
                <span class="badge text-[9px] shrink-0 {r.source === 'ct' ? 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300' : r.source === 'wayback' ? 'bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300' : r.source === 'page' ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900 dark:text-cyan-300' : 'bg-gray-200 dark:bg-gray-700'}">
                  {r.source === 'ct' ? '证书' : r.source === 'wayback' ? '历史' : r.source === 'page' ? '页面' : '暴力'}
                </span>
              {/if}
            </div>
            {#if r.ips.length > 0}
              <div class="text-xs text-gray-400 truncate">{r.ips.join(', ')}</div>
            {/if}
            {#if r.cname}
              <div class="text-xs text-blue-500 dark:text-blue-400 truncate">
                CNAME: {r.cname}
              </div>
            {/if}
          </div>
          <span class="badge text-xs bg-gray-200 dark:bg-gray-700 shrink-0">
            {r.records.length}
          </span>
          <button
            class="ml-auto text-xs text-gray-400 hover:text-primary shrink-0"
            onclick={() => copyRow(r)}
          >
            复制
          </button>
        </div>
      {/each}
    </div>
  {:else if cs.status === 'failed'}
    <ErrorState error={cs.error!} onRetry={handleScan} />
  {:else if !archiving && results.length === 0 && cs.completed > 0}
    <EmptyState message="未发现存活子域名" icon="✅" />
  {:else if !archiving}
    <EmptyState
      message="输入目标 URL，点击「枚举」开始 DNS 子域名扫描"
      hint="自动提取根域，基于词表并发 DNS 解析"
      icon="🌐"
    />
  {/if}
</div>
