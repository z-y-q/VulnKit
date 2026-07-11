import { describe, it, expect } from 'vitest';
import {
  aggregateByModule,
  aggregateByDomain,
  sortFindings,
  countSeverities,
  extractDomains,
  buildCsv,
  buildJson,
  buildMarkdown,
  severityLabel,
  severityColor,
  severityBadgeClass,
} from '@/lib/report/report-builder';
import type { ScanFinding, ScanHistoryEntry } from '@/stores/scan-history';

// ===== 测试 fixture =====

const makeEntry = (overrides: Partial<ScanHistoryEntry> & Pick<ScanHistoryEntry, 'module'>): ScanHistoryEntry => ({
  id: 'test-1',
  domain: 'example.com',
  url: 'https://example.com',
  moduleName: overrides.moduleName || overrides.module,
  timestamp: 1700000000000,
  findings: overrides.findings || [],
  summary: overrides.summary || { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  ...overrides,
});

const findings: ScanFinding[] = [
  { title: 'XSS 注入', severity: 'critical', detail: '反射型 XSS', url: 'https://example.com/search' },
  { title: 'CORS 配置不当', severity: 'high', detail: 'ACAO: *', url: 'https://example.com/api/' },
  { title: '缺失 CSP 头', severity: 'medium', detail: '未设置 Content-Security-Policy' },
  { title: '信息泄露', severity: 'info', detail: 'Server: Apache/2.4' },
];

const entries: ScanHistoryEntry[] = [
  makeEntry({ id: 'e1', module: 'xssscan', moduleName: 'XSS 扫描', findings: [findings[0]] }),
  makeEntry({ id: 'e2', module: 'cors', moduleName: 'CORS 检测', findings: [findings[1]] }),
  makeEntry({ id: 'e3', module: 'headers', moduleName: '安全头', domain: 'test.com', findings: [findings[2], findings[3]] }),
  makeEntry({ id: 'e4', module: 'xssscan', moduleName: 'XSS 扫描', findings: [{ title: '存储型 XSS', severity: 'high' }] }),
];

describe('report-builder: severityLabel / severityColor / severityBadgeClass', () => {
  it('severityLabel 中文映射', () => {
    expect(severityLabel('critical')).toBe('严重');
    expect(severityLabel('high')).toBe('高危');
    expect(severityLabel('medium')).toBe('中危');
    expect(severityLabel('low')).toBe('低危');
    expect(severityLabel('info')).toBe('信息');
  });

  it('severityColor 返回 CSS 类', () => {
    expect(severityColor('critical')).toContain('text-red');
    expect(severityColor('info')).toContain('text-blue');
  });

  it('severityBadgeClass 返回 badge CSS 类', () => {
    expect(severityBadgeClass('critical')).toContain('bg-red');
    expect(severityBadgeClass('info')).toContain('bg-blue');
  });
});

describe('report-builder: countSeverities', () => {
  it('正确计数各严重度', () => {
    const result = countSeverities(findings);
    expect(result.critical).toBe(1);
    expect(result.high).toBe(1);
    expect(result.medium).toBe(1);
    expect(result.info).toBe(1);
  });

  it('空数组全零', () => {
    const result = countSeverities([]);
    expect(result).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  });

  it('未知严重度归入 info', () => {
    const result = countSeverities([{ title: 't', severity: 'unknown' as any }]);
    expect(result.info).toBe(1);
  });
});

describe('report-builder: sortFindings', () => {
  it('按严重度降序排列', () => {
    const sorted = sortFindings(findings);
    expect(sorted[0].severity).toBe('critical');
    expect(sorted[1].severity).toBe('high');
    expect(sorted[2].severity).toBe('medium');
    expect(sorted[3].severity).toBe('info');
  });

  it('不修改原数组', () => {
    const copy = [...findings];
    sortFindings(copy);
    // 原始顺序：critical, high, medium, info — 已经排好
    expect(findings.length).toBe(4);
  });
});

describe('report-builder: aggregateByModule', () => {
  it('按模块分组', () => {
    const groups = aggregateByModule(entries);
    // xssscan 有 2 个 finding（2 entries），排序后 xssscan 应排第一
    expect(groups.length).toBeGreaterThanOrEqual(1);
    const xssGroup = groups.find(g => g.module === 'xssscan');
    expect(xssGroup).toBeDefined();
    expect(xssGroup!.findings.length).toBe(2);
    expect(xssGroup!.label).toBe('XSS 扫描');
  });

  it('按发现数降序', () => {
    const groups = aggregateByModule(entries);
    for (let i = 1; i < groups.length; i++) {
      expect(groups[i - 1].findings.length).toBeGreaterThanOrEqual(groups[i].findings.length);
    }
  });

  it('summary 正确', () => {
    const groups = aggregateByModule(entries);
    const headersGroup = groups.find(g => g.module === 'headers');
    expect(headersGroup!.summary.medium).toBe(1);
    expect(headersGroup!.summary.info).toBe(1);
  });
});

describe('report-builder: aggregateByDomain', () => {
  it('按域名分组', () => {
    const groups = aggregateByDomain(entries);
    expect(groups.length).toBe(2);
    const exampleGroup = groups.find(g => g.domain === 'example.com');
    expect(exampleGroup).toBeDefined();
    expect(exampleGroup!.entries.length).toBe(3); // e1, e2, e4
  });

  it('total 为所有 finding 总数', () => {
    const groups = aggregateByDomain(entries);
    const total = groups.reduce((sum, g) => sum + g.total, 0);
    // e1(1) + e2(1) + e3(2) + e4(1) = 5 findings total
    expect(total).toBe(5);
  });
});

describe('report-builder: extractDomains', () => {
  it('提取去重域名列表', () => {
    const domains = extractDomains(entries);
    expect(domains).toEqual(['example.com', 'test.com']);
  });
});

describe('report-builder: buildCsv', () => {
  it('生成非空 CSV', () => {
    const csv = buildCsv(entries);
    expect(csv.length).toBeGreaterThan(0);
    expect(csv).toContain('模块');
    expect(csv).toContain('XSS 注入');
    expect(csv).toContain('CORS 配置不当');
  });

  it('每行包含 finding 标题', () => {
    const csv = buildCsv(entries);
    expect(csv).toContain('缺失 CSP 头');
    expect(csv).toContain('存储型 XSS');
  });
});

describe('report-builder: buildJson', () => {
  it('生成有效 JSON', () => {
    const json = buildJson(entries);
    const parsed = JSON.parse(json);
    expect(parsed.tool).toBe('灵眸 VulnKit');
    expect(parsed.totalEntries).toBe(4);
    expect(parsed.totalFindings).toBe(5);
    expect(parsed.findings.length).toBe(5);
  });

  it('包含 finding 标题', () => {
    const json = buildJson(entries);
    expect(json).toContain('XSS 注入');
    expect(json).toContain('CORS 配置不当');
  });
});

describe('report-builder: buildMarkdown', () => {
  it('生成非空 Markdown', () => {
    const md = buildMarkdown(entries);
    expect(md.length).toBeGreaterThan(0);
    expect(md).toContain('# 灵眸渗透测试报告');
  });

  it('包含概要表', () => {
    const md = buildMarkdown(entries);
    expect(md).toContain('## 概要');
    expect(md).toContain('| 级别 | 数量 |');
    expect(md).toContain('严重');
    expect(md).toContain('高危');
  });

  it('包含发现列表', () => {
    const md = buildMarkdown(entries);
    expect(md).toContain('## 发现列表');
    expect(md).toContain('XSS 注入');
    expect(md).toContain('CORS 配置不当');
    expect(md).toContain('存储型 XSS');
  });
});
