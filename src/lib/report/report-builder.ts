/**
 * 统一报告引擎 — 灵眸 v6.0
 * 纯函数：聚合 / 排序 / 导出（CSV / JSON / Markdown）
 * 不含 UI 逻辑，不依赖 Svelte store
 */
import type { ScanHistoryEntry, ScanFinding, ScanSeverity } from '@/stores/scan-history';
import { SEV_ORDER, MODULE_LABELS } from '@/stores/scan-history';
import { getAppVersion } from '@/lib/core/app-version';

// ===== 严重程度显示映射 =====

const SEV_LABELS: Record<ScanSeverity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

const SEV_COLORS: Record<ScanSeverity, string> = {
  critical: 'text-red-600 dark:text-red-400',
  high: 'text-orange-500 dark:text-orange-400',
  medium: 'text-yellow-500 dark:text-yellow-400',
  low: 'text-green-600 dark:text-green-400',
  info: 'text-blue-500 dark:text-blue-400',
};

const SEV_BG_CLASSES: Record<ScanSeverity, string> = {
  critical: 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300',
  high: 'bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300',
  medium: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300',
  low: 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300',
  info: 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300',
};

// ===== 公共辅助 =====

/** 严重程度 → 中文标签 */
export function severityLabel(sev: ScanSeverity): string {
  return SEV_LABELS[sev] || sev;
}

/** 严重程度 → UnoCSS 颜色 class（用于文字） */
export function severityColor(sev: ScanSeverity): string {
  return SEV_COLORS[sev] || 'text-gray-500';
}

/** 严重程度 → UnoCSS badge class */
export function severityBadgeClass(sev: ScanSeverity): string {
  return SEV_BG_CLASSES[sev] || SEV_BG_CLASSES.info;
}

// ===== 聚合函数 =====

export interface ModuleGroup {
  module: string;
  label: string;
  findings: ScanFinding[];
  summary: { critical: number; high: number; medium: number; low: number; info: number };
}

export interface DomainGroup {
  domain: string;
  entries: ScanHistoryEntry[];
  summary: { critical: number; high: number; medium: number; low: number; info: number };
  total: number;
}

/** 按模块分组聚合 */
export function aggregateByModule(entries: ScanHistoryEntry[]): ModuleGroup[] {
  const map = new Map<string, ScanFinding[]>();

  for (const entry of entries) {
    const findings = map.get(entry.module) || [];
    findings.push(...entry.findings);
    map.set(entry.module, findings);
  }

  const groups: ModuleGroup[] = [];
  for (const [module, findings] of map) {
    const summary = countSeverities(findings);
    groups.push({
      module,
      label: MODULE_LABELS[module] || module,
      findings: sortFindings(findings),
      summary,
    });
  }

  // 按总发现数降序
  groups.sort((a, b) => b.findings.length - a.findings.length);
  return groups;
}

/** 按域名分组聚合 */
export function aggregateByDomain(entries: ScanHistoryEntry[]): DomainGroup[] {
  const map = new Map<string, ScanHistoryEntry[]>();

  for (const entry of entries) {
    const arr = map.get(entry.domain) || [];
    arr.push(entry);
    map.set(entry.domain, arr);
  }

  const groups: DomainGroup[] = [];
  for (const [domain, domainEntries] of map) {
    const allFindings = domainEntries.flatMap(e => e.findings);
    const summary = countSeverities(allFindings);
    groups.push({
      domain,
      entries: domainEntries,
      summary,
      total: allFindings.length,
    });
  }

  groups.sort((a, b) => b.total - a.total);
  return groups;
}

/** 按 SEV_ORDER 降序排列 */
export function sortFindings(findings: ScanFinding[]): ScanFinding[] {
  return [...findings].sort(
    (a, b) => (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0),
  );
}

/** 计算各严重程度计数 */
export function countSeverities(
  findings: ScanFinding[],
): { critical: number; high: number; medium: number; low: number; info: number } {
  const s = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const sev = (f.severity || 'info').toLowerCase() as ScanSeverity;
    if (sev in s) s[sev]++;
    else s.info++;
  }
  return s;
}

/** 从 entries 列表中提取所有 distinct 域名 */
export function extractDomains(entries: ScanHistoryEntry[]): string[] {
  return [...new Set(entries.map(e => e.domain))].sort();
}

// ===== 导出格式 =====

/** 导出为 CSV */
export function buildCsv(entries: ScanHistoryEntry[]): string {
  const rows: string[][] = [['模块', '标题', '严重程度', '详情', 'URL', '域名', '时间']];
  for (const entry of entries) {
    const time = new Date(entry.timestamp).toISOString().replace('T', ' ').substring(0, 19);
    for (const f of entry.findings) {
      rows.push([
        MODULE_LABELS[entry.module] || entry.module,
        f.title,
        severityLabel(f.severity),
        f.detail || '',
        f.url || '',
        entry.domain,
        time,
      ]);
    }
  }
  return rows.map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n');
}

/** 导出为 JSON。appVersion 缺省取 manifest 版本（扩展上下文可用）。 */
export function buildJson(entries: ScanHistoryEntry[], appVersion: string = getAppVersion()): string {
  const allFindings = entries.flatMap(entry =>
    entry.findings.map(f => ({
      module: entry.module,
      moduleName: entry.moduleName,
      domain: entry.domain,
      url: entry.url,
      timestamp: new Date(entry.timestamp).toISOString(),
      ...f,
    })),
  );
  const report = {
    tool: '灵眸 VulnKit',
    version: appVersion,
    timestamp: new Date().toISOString(),
    totalEntries: entries.length,
    totalFindings: allFindings.length,
    summary: countSeverities(allFindings),
    findings: allFindings,
  };
  return JSON.stringify(report, null, 2);
}

/** 导出为 Markdown */
export function buildMarkdown(entries: ScanHistoryEntry[]): string {
  // 将 entry 上下文附加到 finding 用于渲染
  interface FindingWithContext extends ScanFinding {
    moduleName: string;
    domain: string;
  }
  const allFindings: FindingWithContext[] = entries.flatMap(entry =>
    entry.findings.map(f => ({
      ...f,
      moduleName: entry.moduleName,
      domain: entry.domain,
    })),
  );

  const sorted = [...allFindings].sort(
    (a, b) => (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0),
  );
  const summary = countSeverities(sorted);
  const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const domains = extractDomains(entries);

  const lines: string[] = [];
  lines.push('# 灵眸渗透测试报告');
  lines.push('');
  lines.push(`**时间**: ${now}  `);
  lines.push(`**目标域名**: ${domains.length > 0 ? domains.join(', ') : '无'}  `);
  lines.push(`**扫描记录**: ${entries.length} 条  `);
  lines.push(`**发现总数**: ${sorted.length}  `);
  lines.push('');

  lines.push('## 概要');
  lines.push('');
  lines.push('| 级别 | 数量 |');
  lines.push('|------|------|');
  lines.push(`| ${severityLabel('critical')} | ${summary.critical} |`);
  lines.push(`| ${severityLabel('high')} | ${summary.high} |`);
  lines.push(`| ${severityLabel('medium')} | ${summary.medium} |`);
  lines.push(`| ${severityLabel('low')} | ${summary.low} |`);
  lines.push(`| ${severityLabel('info')} | ${summary.info} |`);
  lines.push('');

  if (sorted.length > 0) {
    lines.push('## 发现列表');
    lines.push('');
    for (let i = 0; i < sorted.length; i++) {
      const f = sorted[i];
      lines.push(`### ${i + 1}. [${severityLabel(f.severity)}] ${f.title}`);
      lines.push(`- **模块**: ${f.moduleName}`);
      lines.push(`- **域名**: ${f.domain}`);
      lines.push(`- **详情**: ${f.detail || '无'}`);
      if (f.url) lines.push(`- **URL**: ${f.url}`);
      lines.push('');
    }
  }

  return lines.join('\n');
}

/** HTML 转义 */
function escapeHtml(s: string): string {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * 生成独立 HTML 报告（暗色主题 + 打印 CSS）。
 * 含严重度分布条、模块覆盖网格、发现列表。对齐 v5 vk-report.js buildHtmlReport。
 */
export function buildHtml(entries: ScanHistoryEntry[]): string {
  interface FindingWithContext extends ScanFinding { moduleName: string; domain: string }
  const allFindings: FindingWithContext[] = entries.flatMap(entry =>
    entry.findings.map(f => ({ ...f, moduleName: entry.moduleName, domain: entry.domain })),
  );
  const sorted = [...allFindings].sort(
    (a, b) => (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0),
  );
  const summary = countSeverities(sorted);
  const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const domains = extractDomains(entries);
  const modules = aggregateByModule(entries);
  const total = sorted.length || 1;

  // 模块覆盖网格
  const moduleGrid = modules.map(mg => {
    const crit = mg.findings.filter(f => f.severity === 'critical' || f.severity === 'high').length;
    const cls = crit > 0 ? 'mod-high' : (mg.findings.length > 0 ? 'mod-ok' : 'mod-empty');
    return `<div class="mod ${cls}"><div class="mod-name">${escapeHtml(mg.module)}</div><div class="mod-count">${mg.findings.length}</div></div>`;
  }).join('');

  // 严重度分布条
  const distBar = (['critical', 'high', 'medium', 'low', 'info'] as ScanSeverity[]).map(sev => {
    const n = summary[sev];
    const pct = (n / total * 100).toFixed(1);
    return `<div class="dist-seg dist-${sev}" style="width:${pct}%" title="${severityLabel(sev)}: ${n}">${n > 0 ? n : ''}</div>`;
  }).join('');

  // 发现表
  const rows = sorted.map((f, i) => `
    <tr>
      <td>${i + 1}</td>
      <td><span class="sev sev-${f.severity}">${severityLabel(f.severity)}</span></td>
      <td>${escapeHtml(f.moduleName)}</td>
      <td>${escapeHtml(f.title)}</td>
      <td>${escapeHtml(f.domain)}</td>
      <td>${escapeHtml((f.detail || '').slice(0, 200))}</td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>灵眸渗透测试报告 ${now}</title>
<style>
  :root { --bg:#0f172a; --card:#1e293b; --text:#e2e8f0; --muted:#94a3b8; --accent:#3b82f6; }
  * { box-sizing: border-box; }
  body { background:var(--bg); color:var(--text); font-family:-apple-system,'Segoe UI',sans-serif; margin:0; padding:24px; }
  h1 { font-size:22px; margin:0 0 4px; }
  .meta { color:var(--muted); font-size:13px; margin-bottom:20px; }
  .summary { display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin-bottom:20px; }
  .stat { background:var(--card); border-radius:10px; padding:14px; text-align:center; }
  .stat .n { font-size:26px; font-weight:700; }
  .stat .l { font-size:12px; color:var(--muted); }
  .dist-bar { display:flex; height:24px; border-radius:6px; overflow:hidden; margin-bottom:20px; }
  .dist-seg { display:flex; align-items:center; justify-content:center; font-size:12px; color:#fff; min-width:2px; }
  .dist-critical{background:#dc2626;} .dist-high{background:#ea580c;} .dist-medium{background:#d97706;}
  .dist-low{background:#0891b2;} .dist-info{background:#475569;}
  h2 { font-size:15px; margin:20px 0 10px; border-left:3px solid var(--accent); padding-left:8px; }
  .mod-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(120px,1fr)); gap:8px; margin-bottom:20px; }
  .mod { background:var(--card); border-radius:8px; padding:10px; text-align:center; }
  .mod-name { font-size:12px; color:var(--muted); margin-bottom:4px; }
  .mod-count { font-size:18px; font-weight:600; }
  .mod-high { border:1px solid #dc2626; } .mod-ok { border:1px solid #16a34a; } .mod-empty { opacity:.5; }
  table { width:100%; border-collapse:collapse; background:var(--card); border-radius:10px; overflow:hidden; font-size:12px; }
  th, td { padding:8px 10px; text-align:left; border-bottom:1px solid #334155; vertical-align:top; }
  th { background:#0f172a; color:var(--muted); font-weight:600; position:sticky; top:0; }
  .sev { padding:2px 8px; border-radius:4px; font-size:11px; white-space:nowrap; }
  .sev-critical{background:#dc2626;color:#fff;} .sev-high{background:#ea580c;color:#fff;}
  .sev-medium{background:#d97706;color:#fff;} .sev-low{background:#0891b2;color:#fff;}
  .sev-info{background:#475569;color:#fff;}
  @media print { body { background:#fff; color:#000; } }
</style>
</head>
<body>
  <h1>🛡️ 灵眸渗透测试报告</h1>
  <div class="meta">时间: ${now} · 目标: ${escapeHtml(domains.join(', ') || '无')} · 扫描记录 ${entries.length} 条 · 发现 ${sorted.length} 项</div>

  <div class="summary">
    <div class="stat"><div class="n" style="color:#dc2626">${summary.critical}</div><div class="l">${severityLabel('critical')}</div></div>
    <div class="stat"><div class="n" style="color:#ea580c">${summary.high}</div><div class="l">${severityLabel('high')}</div></div>
    <div class="stat"><div class="n" style="color:#d97706">${summary.medium}</div><div class="l">${severityLabel('medium')}</div></div>
    <div class="stat"><div class="n" style="color:#0891b2">${summary.low}</div><div class="l">${severityLabel('low')}</div></div>
    <div class="stat"><div class="n" style="color:#94a3b8">${summary.info}</div><div class="l">${severityLabel('info')}</div></div>
  </div>

  <div class="dist-bar">${distBar}</div>

  <h2>模块覆盖（${modules.length}）</h2>
  <div class="mod-grid">${moduleGrid}</div>

  <h2>发现列表（${sorted.length}）</h2>
  <table>
    <thead><tr><th>#</th><th>级别</th><th>模块</th><th>标题</th><th>域名</th><th>详情</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="6" style="text-align:center;color:#94a3b8">无发现</td></tr>'}</tbody>
  </table>
</body>
</html>`;
}

