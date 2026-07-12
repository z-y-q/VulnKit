<script lang="ts">
  // 子域名枚举面板 — 灵眸 v6.0
  // 流程：自动填充 URL → 提取根域 → 词表生成 → DNS 并发解析 → 结果渲染
  import { sendMessage, sendToContent } from '@/lib/core/messaging';
  import { getActiveTabUrl, getActiveTab, execInTab } from '@/lib/core/tabs';
  import { validateProbeUrl } from '@/lib/core/url-guard';
  import { toastStore } from '@/stores/ui';
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

  let targetUrl = $state('');
  let scanning = $state(false);
  let scanned = $state(0);
  let total = $state(0);
  let results = $state<SubdomainResult[]>([]);
  let searchQuery = $state('');
  let sortBy = $state<'name' | 'ips'>('name');
  let cancelled = $state(false);

  // 枚举方法开关
  let useBrute = $state(true);     // DNS 暴力
  let useCT = $state(true);        // 证书透明（crt.sh）
  let useCertspotter = $state(false); // CertSpotter 第三方证书
  let useDnsRec = $state(false);   // DNS NS/MX 记录枚举
  let useWayback = $state(true);   // Wayback Machine
  let usePage = $state(true);      // 当前页面链接
  let wildcardDetected = $state(false);
  let phase = $state('');          // 当前阶段提示

  $effect(() => {
    getActiveTabUrl().then(u => {
      if (u) targetUrl = u;
    });
  });

  let filteredResults = $derived.by(() => {
    let list = dedupAliveResults(results);
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(r => r.subdomain.toLowerCase().includes(q));
    }
    if (sortBy === 'name') {
      list.sort((a, b) => a.subdomain.localeCompare(b.subdomain));
    } else {
      list.sort((a, b) => b.ips.length - a.ips.length);
    }
    return list;
  });

  let stats = $derived(buildStats(results, 0));
  let elapsed = $state(0);

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
  ): Promise<Set<string>> {
    const verified = new Set<string>();
    await runConcurrent(aliveHosts, async (host) => {
      if (cancelled) return;
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
    }, { concurrency: $scanSettingsStore.concurrency, cancelled: () => cancelled });
    return verified;
  }

  /** 被动源获取的子域名 → DNS 验证存活并合并 */
  async function verifyAndMerge(hostnames: string[], source: SubdomainResult['source'], acc: SubdomainResult[]) {
    const seen = new Set(acc.map(r => r.subdomain));
    const todo = hostnames.filter(h => !seen.has(h));
    for (const h of todo) {
      if (cancelled) break;
      const r = await resolveOne(h);
      r.source = source;
      acc.push(r);
      scanned++;
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

  async function scan() {
    const v = validateProbeUrl(targetUrl);
    if ('error' in v) {
      toastStore.show('请输入合法的 http(s) URL', 'error');
      return;
    }

    if (!useBrute && !useCT && !useCertspotter && !useDnsRec && !useWayback && !usePage) {
      toastStore.show('请至少选择一种枚举方法', 'warning');
      return;
    }

    const rootDomain = extractRootDomain(v.parsed.hostname);
    const candidates = buildSubdomainCandidates(rootDomain);

    scanning = true;
    results = [];
    scanned = 0;
    cancelled = false;
    wildcardDetected = false;
    elapsed = 0;
    const startMs = Date.now();
    const collected: SubdomainResult[] = [];

    // —— 阶段 0：Wildcard 泛解析检测（决定暴力枚举是否有意义）——
    if (useBrute) {
      phase = '检测泛解析...';
      wildcardDetected = await detectWildcard(rootDomain, resolvesToIp);
      if (wildcardDetected) {
        toastStore.show('检测到 DNS 泛解析，暴力结果将标记为待验证', 'warning');
      }
    }

    // —— 阶段 1：被动枚举（零噪声，优先）——
    const passiveTasks: Promise<void>[] = [];

    if (useCT) {
      passiveTasks.push((async () => {
        phase = '查询证书透明日志 (crt.sh)...';
        try {
          const res = await sendMessage({ type: 'FETCH_URL', url: `https://crt.sh/?q=%25.${rootDomain}&output=json` }) as FetchResult<string>;
          if (res.success && res.data) {
            await verifyAndMerge(parseCrtshResponse(res.data, rootDomain), 'ct', collected);
          }
        } catch { /* crt.sh 可能超时，忽略 */ }
      })());
    }

    if (useWayback) {
      passiveTasks.push((async () => {
        phase = '查询 Wayback Machine...';
        try {
          const res = await sendMessage({ type: 'FETCH_URL', url: `https://web.archive.org/cdx/search/cdx?url=*.${rootDomain}/*&output=text&fl=original&collapse=urlkey` }) as FetchResult<string>;
          if (res.success && res.data) {
            await verifyAndMerge(parseWaybackResponse(res.data, rootDomain), 'wayback', collected);
          }
        } catch { /* ignore */ }
      })());
    }

    if (useCertspotter) {
      passiveTasks.push((async () => {
        phase = '查询 CertSpotter...';
        try {
          const res = await sendMessage({ type: 'FETCH_URL', url: `https://api.certspotter.com/v1/issuances?domain=${rootDomain}&include_subdomains=true&expand=dns_names` }) as FetchResult<string>;
          if (res.success && res.data) {
            await verifyAndMerge(parseCertspotterResponse(res.data, rootDomain), 'ct', collected);
          }
        } catch { /* ignore */ }
      })());
    }

    if (useDnsRec) {
      passiveTasks.push((async () => {
        phase = '查询 DNS NS/MX 记录...';
        try {
          // 用 Google DoH 查 NS + MX 记录（默认返回 JSON），从响应中提取主机名
          const dohUrls = [
            `https://dns.google/resolve?name=${rootDomain}&type=NS`,
            `https://dns.google/resolve?name=${rootDomain}&type=MX`,
          ];
          for (const u of dohUrls) {
            const res = await sendMessage({ type: 'FETCH_URL', url: u }) as FetchResult<string>;
            if (res.success && res.data) {
              // DoH JSON: { Answer: [{ data: "ns1.example.com." }] }
              try {
                const json = JSON.parse(res.data);
                const text = (json.Answer || json.Authority || []).map((a: any) => a.data || '').join('\n');
                await verifyAndMerge(parseDnsRecords(text, rootDomain), 'ct', collected);
              } catch { /* ignore */ }
            }
          }
        } catch { /* ignore */ }
      })());
    }

    if (usePage) {
      passiveTasks.push((async () => {
        phase = '提取页面链接...';
        const links = await harvestPageLinks(rootDomain);
        if (links.length > 0) await verifyAndMerge(links, 'page', collected);
      })());
    }

    await Promise.all(passiveTasks);

    // —— 阶段 2：DNS 暴力枚举 ——
    if (useBrute && !cancelled) {
      phase = 'DNS 暴力枚举...';
      const bruteTodo = candidates.filter(c => !collected.some(r => r.subdomain === c.full));
      total = bruteTodo.length + scanned;
      await runConcurrent(bruteTodo, async (c) => {
        const r = await resolveOne(c.full);
        r.source = 'brute';
        collected.push(r);
        scanned++;
        elapsed = Date.now() - startMs;
      }, { concurrency: $scanSettingsStore.concurrency, cancelled: () => cancelled });

      // 泛解析域名：所有 brute 结果都"存活"，需标记可疑
      if (wildcardDetected) {
        for (const r of collected) {
          if (r.source === 'brute') r.status = 'alive'; // 保留，但 UI 会提示
        }
      }
    }

    // —— 阶段 3：HTTP 探测验证（过滤泛解析假阳性）——
    if (!cancelled) {
      phase = 'HTTP 探测验证中...';
      const aliveHosts = collected
        .filter(r => r.status === 'alive')
        .map(r => r.subdomain)
        .filter((v, i, a) => a.indexOf(v) === i);
      if (aliveHosts.length > 0) {
        const verified = await httpProbeVerify(aliveHosts, rootDomain);
        for (const r of collected) {
          if (r.status === 'alive' && !verified.has(r.subdomain)) {
            r.status = 'dead';
          }
        }
      }
    }

    phase = '';
    // 合并去重：同子域名保留信息最全的（IP 多的优先）
    const merged = new Map<string, SubdomainResult>();
    for (const r of collected) {
      const ex = merged.get(r.subdomain);
      if (!ex || r.ips.length > ex.ips.length) merged.set(r.subdomain, r);
    }
    results = [...merged.values()];
    elapsed = Date.now() - startMs;
    scanning = false;

    if (cancelled) {
      toastStore.show('扫描已取消', 'info');
      return;
    }

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

    // 发布到扫描历史
    try {
      const alive = results.filter(r => r.status === 'alive');
      await scanHistoryStore.addScan({
        url: targetUrl,
        module: 'subdomain',
        findings: mapSubdomainsToFindings(alive),
      });
    } catch { /* store failure must not break scan */ }
  }

  function cancel() { cancelled = true; }

  function copyAll() {
    if (filteredResults.length === 0) {
      toastStore.show('没有可复制的结果', 'warning');
      return;
    }
    const text = filteredResults.map(r => r.subdomain).join('\n');
    navigator.clipboard.writeText(text);
    toastStore.show(`已复制 ${filteredResults.length} 个子域名`, 'success');
  }

  function exportCsv() {
    if (filteredResults.length === 0) return;
    const rows = [['subdomain', 'ips', 'cname', 'record_count']];
    for (const r of filteredResults) {
      rows.push([r.subdomain, r.ips.join(';'), r.cname || '', String(r.records.length)]);
    }
    const csv = rows.map(row => row.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'subdomains.csv';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function copyRow(r: SubdomainResult) {
    const text = [
      `Subdomain: ${r.subdomain}`,
      `IPs: ${r.ips.join(', ') || '(无)'}`,
      `CNAME: ${r.cname || '(无)'}`,
      `Records: ${r.records.map(rec => `${rec.type}: ${rec.data}`).join(', ') || '(无)'}`,
    ].join('\n');
    navigator.clipboard.writeText(text);
    toastStore.show(`已复制: ${r.subdomain}`, 'success');
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
      <UrlInput bind:value={targetUrl} {scanning} buttonText="枚举" scanningText="枚举中..." onscan={scan} />
      {#if scanning}
        <button class="btn btn-sm btn-danger shrink-0" onclick={cancel}>取消</button>
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
        <input type="checkbox" bind:checked={useCT} disabled={scanning} class="accent-blue-500" />
        <span class="text-gray-600 dark:text-gray-300">证书透明 (crt.sh)</span>
      </label>
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={useCertspotter} disabled={scanning} class="accent-blue-500" />
        <span class="text-gray-600 dark:text-gray-300">CertSpotter</span>
      </label>
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={useDnsRec} disabled={scanning} class="accent-blue-500" />
        <span class="text-gray-600 dark:text-gray-300">DNS NS/MX</span>
      </label>
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={useWayback} disabled={scanning} class="accent-blue-500" />
        <span class="text-gray-600 dark:text-gray-300">Wayback 历史</span>
      </label>
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={usePage} disabled={scanning} class="accent-blue-500" />
        <span class="text-gray-600 dark:text-gray-300">页面链接</span>
      </label>
      <label class="flex items-center gap-1 cursor-pointer">
        <input type="checkbox" bind:checked={useBrute} disabled={scanning} class="accent-blue-500" />
        <span class="text-gray-600 dark:text-gray-300">DNS 暴力</span>
      </label>
    </div>

    {#if wildcardDetected}
      <div class="text-xs text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/30 rounded px-2 py-1">
        ⚠️ 检测到 DNS 泛解析，暴力枚举结果可能含假阳性，建议结合 HTTP 存活验证
      </div>
    {/if}

    {#if scanning && phase}
      <div class="text-xs text-gray-400">{phase}</div>
    {/if}

    <ScanProgress {scanned} {total} {scanning} label="子域名枚举" />
  </div>

  <!-- 工具栏 -->
  {#if results.length > 0}
    <div class="flex items-center gap-2 text-xs">
      <span class="badge bg-green-500 text-white">存活 {stats.alive}</span>
      <span class="badge bg-gray-200 dark:bg-gray-700">总计 {stats.total}</span>
      <span class="text-gray-400">·</span>
      <span>{filteredResults.length} 条</span>
      <input
        class="input text-xs flex-1 ml-2"
        placeholder="搜索子域名..."
        bind:value={searchQuery}
      />
      <select class="input text-xs w-20" bind:value={sortBy}>
        <option value="name">按名称</option>
        <option value="ips">按 IP 数</option>
      </select>
      <button class="btn btn-sm" onclick={copyAll}>复制</button>
      <button class="btn btn-sm" onclick={exportCsv}>导出</button>
    </div>
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
  {:else if !scanning && results.length === 0 && scanned > 0}
    <EmptyState message="未发现存活子域名" icon="✅" />
  {:else if !scanning}
    <EmptyState
      message="输入目标 URL，点击「枚举」开始 DNS 子域名扫描"
      hint="自动提取根域，基于词表并发 DNS 解析"
      icon="🌐"
    />
  {/if}
</div>
