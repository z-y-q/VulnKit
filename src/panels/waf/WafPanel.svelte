<script lang="ts">
  // WAF 指纹检测面板
  // 通过多路径探测 + 签名匹配识别目标 WAF 类型
  import { sendMessage } from '@/lib/core/messaging';
  import { getActiveTabUrl } from '@/lib/core/tabs';
  import { toastStore, autoRunStore } from '@/stores/ui';
  import type { ProbeResult } from '@/lib/types/messaging';
  import wafSignaturesJson from '@/lib/data/waf-signatures.json';
  import { scanHistoryStore, type ScanFinding } from '@/stores/scan-history';
  import { confirmStore } from '@/stores/confirm';
  import ExportMenu from '@/components/results/ExportMenu.svelte';

  // —— 类型 ——
  interface WafPattern {
    __regexp__: boolean;
    source: string;
    flags: string;
  }

  interface WafSignature {
    name: string;
    severity: 'high' | 'medium' | 'low';
    headerMatch: WafPattern[];
    bodyMatch: WafPattern[];
    cookieMatch: WafPattern[];
  }

  interface Evidence {
    type: 'header' | 'body' | 'cookie';
    value: string;
  }

  interface WafDetection {
    name: string;
    severity: string;
    confidence: 'high' | 'medium' | 'low';
    evidence: Evidence[];
    probe?: string;
  }

  const SIGNATURES: WafSignature[] = wafSignaturesJson as WafSignature[];

  // 探测路径（与旧版保持一致）
  const PROBE_PATHS = [
    { path: '', desc: '正常请求' },
    { path: '/../../../etc/passwd', desc: '路径穿越探测' },
    { path: "/?id=1' OR '1'='1", desc: 'SQL 注入探测' },
    { path: '/?id=<script>alert(1)<\/script>', desc: 'XSS 探测' },
  ];

  // —— 状态 ——
  let targetUrl = $state('');
  let scanning = $state(false);
  let aborted = $state(false);
  let statusText = $state('');
  let detections = $state<WafDetection[]>([]);
  let probeHeaders = $state<Record<string, string> | null>(null);
  let probeDomain = $state('');
  let probeCount = $state(0);
  let elapsed = $state('0.0');

  // 严重程度排序
  const SEV_ORDER: Record<string, number> = { high: 3, medium: 2, low: 1 };

  // 一键操作（右键菜单 / Popup）：命中本面板则自动填充并扫描
  $effect(() => {
    const sig = $autoRunStore;
    if (sig && sig.panel === 'waf') {
      autoRunStore.clear();
      if (sig.url) targetUrl = sig.url;
      startScan();
    }
  });

  // —— 签名匹配核心逻辑（纯函数，逐条保留原匹配规则）——

  /** 将 JSON 中的 WafPattern 还原为 RegExp 实例 */
  function compilePattern(p: WafPattern): RegExp {
    return new RegExp(p.source, p.flags);
  }

  /** 对文本执行多条模式匹配，返回命中的原文片段 */
  function matchPatterns(text: string, patterns: WafPattern[]): string[] {
    if (!text || patterns.length === 0) return [];
    const hits: string[] = [];
    for (let i = 0; i < patterns.length; i++) {
      const re = compilePattern(patterns[i]);
      const m = text.match(re);
      if (m) hits.push(m[0]);
    }
    return hits;
  }

  /**
   * 纯函数：输入响应头 / body / 签名库 → 匹配结果列表
   * 逐条保留原版 headerMatch / bodyMatch / cookieMatch 规则
   */
  function analyzeResponse(
    headers: Record<string, string> | undefined,
    body: string | undefined,
    signatures: WafSignature[],
  ): WafDetection[] {
    // 序列化 header 字符串（key: value 形式，方便正则整行匹配）
    let headerStr = '';
    if (headers) {
      for (const k of Object.keys(headers)) {
        const val = headers[k];
        headerStr += `${k}: ${Array.isArray(val) ? (val as unknown as string[]).join('\n') : val}\n`;
      }
    }

    // 提取 Set-Cookie 字段值
    let cookieStr = '';
    if (headers) {
      const sc = headers['set-cookie'] || headers['Set-Cookie'] || '';
      cookieStr = Array.isArray(sc) ? (sc as unknown as string[]).join('\n') : sc;
    }

    const bodyStr = typeof body === 'string' ? body : '';
    const detected: WafDetection[] = [];

    for (const sig of signatures) {
      const evidence: Evidence[] = [];

      // 匹配 header
      for (const hit of matchPatterns(headerStr, sig.headerMatch)) {
        evidence.push({ type: 'header', value: hit });
      }
      // 匹配 body
      for (const hit of matchPatterns(bodyStr, sig.bodyMatch)) {
        evidence.push({ type: 'body', value: hit });
      }
      // 匹配 cookie
      for (const hit of matchPatterns(cookieStr, sig.cookieMatch)) {
        evidence.push({ type: 'cookie', value: hit });
      }

      if (evidence.length > 0) {
        detected.push({
          name: sig.name,
          severity: sig.severity,
          confidence: evidence.length >= 3 ? 'high' : evidence.length >= 2 ? 'medium' : 'low',
          evidence,
        });
      }
    }

    return detected;
  }

  // —— 扫描流程 ——

  /** 自动填充当前页 URL */
  async function autoFill() {
    const url = await getActiveTabUrl();
    if (url) targetUrl = url;
  }

  /** 发起一次探测请求 */
  async function fetchProbe(url: string): Promise<ProbeResult | null> {
    try {
      const r = await sendMessage({
        type: 'FETCH_WAF_PROBE',
        url,
        method: 'GET',
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
        timeout: 8000,
      });
      if ((r as any).error) return null;
      return r as ProbeResult;
    } catch {
      return null;
    }
  }

  // 映射 WafDetection[] → ScanFinding[]
  function mapWafToFindings(detections: WafDetection[]): ScanFinding[] {
    return detections.map((d) => ({
      title: `WAF: ${d.name}`,
      severity: 'info' as const,
      detail: `置信度: ${d.confidence} | ${d.evidence.map((e) => `[${e.type}] ${e.value}`).join('; ')}`,
      url: targetUrl,
    }));
  }

  /** 主扫描逻辑 */
  async function startScan() {
    if (scanning) {
      // 正在扫描时点击 → 停止
      aborted = true;
      return;
    }

    const url = targetUrl.trim();
    if (!url || !/^https?:\/\//i.test(url)) {
      toastStore.show('请输入有效的 URL（http/https）', 'warning');
      return;
    }

    const confirmed = await confirmStore.ask({
      title: 'WAF 指纹检测',
      message: 'WAF 扫描将向目标发送攻击载荷（SQL注入/XSS/路径穿越等），是否继续？',
      confirmLabel: '开始扫描',
      variant: 'danger',
    });
    if (!confirmed) {
      return;
    }

    scanning = true;
    aborted = false;
    detections = [];
    probeHeaders = null;
    probeCount = 0;
    elapsed = '0.0';
    statusText = '扫描中...';

    const origin = new URL(url).origin;
    const domain = new URL(url).hostname;
    probeDomain = domain;

    const startTime = Date.now();
    const detectedMap = new Map<string, WafDetection>();

    try {
      for (let i = 0; i < PROBE_PATHS.length; i++) {
        if (aborted) break;

        const probe = PROBE_PATHS[i];
        elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        statusText = `探测中... (${i + 1}/${PROBE_PATHS.length}) ${elapsed}s`;

        const probeUrl = origin + probe.path;
        const result = await fetchProbe(probeUrl);

        if (result && result.headers) {
          probeHeaders = result.headers;
          const found = analyzeResponse(result.headers, result.body, SIGNATURES);

          for (const f of found) {
            const existing = detectedMap.get(f.name);
            if (existing) {
              // 合并 evidence（去重）
              const existingValues = new Set(existing.evidence.map((e) => e.value));
              const newEvidence = f.evidence.filter((e) => !existingValues.has(e.value));
              if (newEvidence.length > 0) {
                existing.evidence = [...existing.evidence, ...newEvidence];
              }
              // 取更高严重程度
              if ((SEV_ORDER[f.severity] || 0) > (SEV_ORDER[existing.severity] || 0)) {
                existing.severity = f.severity;
              }
            } else {
              detectedMap.set(f.name, { ...f, probe: probe.desc });
            }
          }
        }
      }

      // 汇总 + 排序 + 重新评估置信度
      let allDetected = Array.from(detectedMap.values());
      allDetected.sort((a, b) => (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0));
      for (const d of allDetected) {
        const evCount = d.evidence.length;
        d.confidence = evCount >= 3 ? 'high' : evCount >= 2 ? 'medium' : 'low';
      }

      if (aborted) {
        statusText = '扫描已取消';
      } else {
        detections = allDetected;
        probeCount = PROBE_PATHS.length;
        statusText =
          allDetected.length > 0 ? `检测到 ${allDetected.length} 个 WAF` : '未检测到 WAF';
        toastStore.show(
          allDetected.length > 0 ? `检测到 ${allDetected.length} 个 WAF` : '未检测到 WAF',
          allDetected.length > 0 ? 'warning' : 'success',
        );

        try {
          await scanHistoryStore.addScan({
            url: targetUrl,
            module: 'waf',
            findings: mapWafToFindings(allDetected),
          });
        } catch { /* store failure must not break scan */ }
      }
    } catch (err: any) {
      statusText = `扫描失败: ${err.message || '未知错误'}`;
      toastStore.show(`扫描失败: ${err.message || '未知错误'}`, 'error');
    } finally {
      scanning = false;
      aborted = false;
    }
  }

  // —— 复制 / 导出 ——

  // —— 导出/复制序列化器（统一走 ExportMenu；修原 navigator.clipboard 未 await）——
  function wafJson(items: WafDetection[]): string {
    const report = {
      timestamp: new Date().toISOString(),
      target: probeDomain,
      probeCount,
      detections: items.map((d) => ({
        name: d.name,
        severity: d.severity,
        confidence: d.confidence,
        evidence: d.evidence,
      })),
    };
    return JSON.stringify(report, null, 2);
  }
  function wafMd(items: WafDetection[]): string {
    const header = '| Name | Severity | Confidence | Evidence |';
    const sep = '|------|----------|------------|----------|';
    const body = items
      .map((d) => `| ${d.name} | ${d.severity} | ${d.confidence} | ${d.evidence.map((e) => e.value).join('; ')} |`)
      .join('\n');
    return `# WAF Detection Results\n\n${header}\n${sep}\n${body}\n`;
  }
  function wafText(items: WafDetection[]): string {
    return items
      .map((d) => {
        const lines = [`${d.name} [${d.severity}] 置信度: ${d.confidence}`];
        for (const e of d.evidence) lines.push(`  [${e.type}] ${e.value}`);
        return lines.join('\n');
      })
      .join('\n\n');
  }

  // —— 辅助 ——
  function severityLabel(s: string): string {
    if (s === 'high') return '高';
    if (s === 'medium') return '中';
    if (s === 'low') return '低';
    return '信息';
  }

  function confidenceLabel(c: string): string {
    if (c === 'high') return '高';
    if (c === 'medium') return '中';
    return '低';
  }

  function severityColor(s: string): string {
    if (s === 'high') return 'text-red-500 dark:text-red-400';
    if (s === 'medium') return 'text-yellow-500 dark:text-yellow-400';
    return 'text-gray-400 dark:text-gray-500';
  }
</script>

<div class="space-y-3">
  <!-- URL 输入 -->
  <div class="card p-3 space-y-2">
    <div class="flex gap-1">
      <input
        class="input text-xs font-mono flex-1"
        placeholder="https://target.example.com"
        bind:value={targetUrl}
      />
      <button class="btn btn-sm btn-ghost text-xs" onclick={autoFill}>自动填充</button>
    </div>

    <div class="flex gap-1">
      <button
        class="btn btn-sm btn-primary flex-1"
        disabled={scanning || !targetUrl.trim()}
        onclick={startScan}
      >
        {scanning ? '停止扫描' : 'WAF 指纹检测'}
      </button>
    </div>

    {#if statusText}
      <div class="text-xs text-gray-500">{statusText}</div>
    {/if}
  </div>

  <!-- 探测信息 -->
  {#if probeDomain && detections.length >= 0 && !scanning}
    <div class="card p-2 text-xs text-gray-500 space-y-0.5">
      <div><b>目标:</b> <span class="font-mono">{probeDomain}</span></div>
      <div><b>探测次数:</b> {probeCount}</div>
      <div>
        <b>检测结果:</b>
        {detections.length > 0 ? `${detections.length} 个 WAF` : '未检测到 WAF'}
      </div>
    </div>
  {/if}

  <!-- 扫描进度 -->
  {#if scanning}
    <div class="card p-3 text-center">
      <div class="text-xs text-gray-500">正在发送探测请求... ({elapsed}s)</div>
    </div>
  {/if}

  <!-- 检测结果 -->
  {#if !scanning && detections.length > 0}
    <div class="space-y-1">
      {#each detections as d}
        <div class="card p-3 space-y-1.5">
          <div class="flex items-center gap-2 flex-wrap">
            <span class="text-xs font-bold {severityColor(d.severity)}">
              [{severityLabel(d.severity)}]
            </span>
            <span class="text-sm font-medium">{d.name}</span>
            <span class="text-xs text-gray-400">置信度: {confidenceLabel(d.confidence)}</span>
          </div>
          <div class="space-y-0.5">
            {#each d.evidence as e}
              <div class="text-xs font-mono">
                <span class="text-gray-400">[{e.type}]</span>
                <code class="text-xs ml-1 break-all">{e.value}</code>
              </div>
            {/each}
          </div>
          {#if d.probe}
            <div class="text-xs text-gray-400">探测来源: {d.probe}</div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}

  <!-- 未检测到 WAF -->
  {#if !scanning && detections.length === 0 && probeCount > 0}
    <div class="card p-3 text-center space-y-1">
      <div class="text-2xl">&#128274;</div>
      <div class="text-sm">未检测到 WAF</div>
      <div class="text-xs text-gray-400">
        目标站点可能没有部署 WAF，或使用了自定义规则
      </div>
      <div class="text-xs text-gray-400">
        提示: 探测请求已通过后台发送(不带 Cookie)，如仍无法检测，可尝试手动访问恶意路径
      </div>
    </div>
  {/if}

  <!-- 响应头信息 -->
  {#if !scanning && probeHeaders && Object.keys(probeHeaders).length > 0 && detections.length > 0}
    <div class="card p-3 space-y-1.5">
      <div class="text-xs font-medium">响应头信息</div>
      <div class="overflow-x-auto">
        <table class="w-full text-xs">
          <thead>
            <tr class="text-left text-gray-400 border-b border-gray-200 dark:border-gray-700">
              <th class="py-1 pr-2 font-normal">Header</th>
              <th class="py-1 font-normal">Value</th>
            </tr>
          </thead>
          <tbody>
            {#each Object.entries(probeHeaders) as [k, v]}
              <tr class="border-b border-gray-100 dark:border-gray-800">
                <td class="py-1 pr-2 font-mono whitespace-nowrap text-gray-500">{k}</td>
                <td class="py-1 font-mono break-all">{v}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  {/if}

  <!-- 导出菜单（复制文本/MD + 导出 JSON） -->
  {#if !scanning && detections.length > 0}
    <ExportMenu items={detections} module="waf" serializers={{ json: wafJson, markdown: wafMd, text: wafText }} />
  {/if}
</div>
