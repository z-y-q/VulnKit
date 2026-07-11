/**
 * 统一报告引擎 — 灵眸 v6.0
 * 纯函数：聚合 / 排序 / 导出（CSV / JSON / Markdown）
 * 不含 UI 逻辑，不依赖 Svelte store
 */
import type { ScanHistoryEntry, ScanFinding, ScanSeverity } from '@/stores/scan-history';
import { SEV_ORDER, MODULE_LABELS } from '@/stores/scan-history';

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

/** 导出为 JSON */
export function buildJson(entries: ScanHistoryEntry[]): string {
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
    version: '6.0.0',
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
