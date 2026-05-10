import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { utils } from '../src/popup/vk-namespace.js';
import { renderReport, buildSummary } from '../src/popup/vk-report.js';

function createEl(id) {
  const el = document.createElement('div');
  el.id = id;
  document.body.appendChild(el);
  return el;
}

const SEV_LABELS = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' };
const SEV_COLORS = {
  critical: '#e74c3c',
  high: '#e67e22',
  medium: '#f39c12',
  low: '#27ae60',
  info: '#4A90E2',
};
const MODULE_LABELS = {
  xss: 'XSS 扫描',
  cors: 'CORS 检测',
  waf: 'WAF 检测',
  cookie: 'Cookie 审计',
  sniff: '技术栈识别',
  leak: '信息泄露',
  headers: '安全头检测',
};

describe('buildSummary', () => {
  it('returns zero counts for empty findings', () => {
    const summary = buildSummary([]);
    expect(summary).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  });

  it('counts each severity correctly', () => {
    const findings = [
      { severity: 'critical', title: 'a' },
      { severity: 'critical', title: 'b' },
      { severity: 'high', title: 'c' },
      { severity: 'medium', title: 'd' },
      { severity: 'low', title: 'e' },
      { severity: 'info', title: 'f' },
      { severity: 'info', title: 'g' },
    ];
    const summary = buildSummary(findings);
    expect(summary).toEqual({ critical: 2, high: 1, medium: 1, low: 1, info: 2 });
  });

  it('ignores unknown severity values', () => {
    const findings = [
      { severity: 'unknown', title: 'x' },
      { severity: 'critical', title: 'y' },
    ];
    const summary = buildSummary(findings);
    expect(summary).toEqual({ critical: 1, high: 0, medium: 0, low: 0, info: 0 });
  });
});

describe('renderReport', () => {
  let contentEl, summaryEl;

  beforeEach(() => {
    utils.cache.clear();
    contentEl = createEl('report-content');
    summaryEl = createEl('report-summary');
  });

  afterEach(() => {
    contentEl.remove();
    summaryEl.remove();
  });

  it('renders empty state when no findings', () => {
    renderReport([]);
    expect(summaryEl.innerHTML).toContain('暂无发现');
    expect(contentEl.innerHTML).toBe('');
  });

  it('renders severity stat-badges in summary', () => {
    renderReport([
      { severity: 'critical', title: 'SQLi', module: 'xss', detail: '', url: '' },
      { severity: 'high', title: 'XSS', module: 'cors', detail: '', url: '' },
    ]);
    expect(summaryEl.innerHTML).toContain('stat-badge');
    expect(summaryEl.innerHTML).toContain('严重');
    expect(summaryEl.innerHTML).toContain('高危');
  });

  it('renders correct stat-badge class per severity', () => {
    renderReport([
      { severity: 'critical', title: 'a', module: 'xss', detail: '', url: '' },
      { severity: 'medium', title: 'b', module: 'waf', detail: '', url: '' },
    ]);
    expect(summaryEl.innerHTML).toContain('stat-vuln');
    expect(summaryEl.innerHTML).toContain('stat-warn');
  });

  it('renders findings count in header', () => {
    renderReport([
      { severity: 'info', title: 'a', module: 'xss', detail: '', url: '' },
      { severity: 'info', title: 'b', module: 'cors', detail: '', url: '' },
      { severity: 'info', title: 'c', module: 'waf', detail: '', url: '' },
    ]);
    expect(contentEl.innerHTML).toContain('stat-badge stat-total');
    expect(contentEl.innerHTML).toContain('共 3 项发现');
  });

  it('renders finding cards with severity label', () => {
    renderReport([
      {
        severity: 'high',
        title: 'XSS Found',
        module: 'xss',
        detail: 'param is injectable',
        url: 'https://example.com',
      },
    ]);
    const finding = contentEl.querySelector('.report-finding-item');
    expect(finding).not.toBeNull();
    expect(contentEl.innerHTML).toContain('高危');
    expect(contentEl.innerHTML).toContain('XSS Found');
  });

  it('renders module label using MODULE_LABELS mapping', () => {
    renderReport([{ severity: 'info', title: 'Headers', module: 'headers', detail: '', url: '' }]);
    expect(contentEl.innerHTML).toContain('安全头检测');
  });

  it('renders finding detail and URL', () => {
    renderReport([
      {
        severity: 'medium',
        title: 'CORS',
        module: 'cors',
        detail: 'Missing ACAC header',
        url: 'https://example.com/api',
      },
    ]);
    expect(contentEl.innerHTML).toContain('Missing ACAC header');
    expect(contentEl.innerHTML).toContain('https://example.com/api');
  });

  it('omits URL div when finding has no URL', () => {
    renderReport([
      { severity: 'low', title: 'Cookie', module: 'cookie', detail: 'no secure flag', url: '' },
    ]);
    const urlEl = contentEl.querySelector('.report-finding-url');
    expect(urlEl).toBeNull();
  });

  it('escapes HTML in title, detail, and URL', () => {
    renderReport([
      {
        severity: 'high',
        title: '<script>alert(1)</script>',
        module: 'xss',
        detail: 'param "q" is injectable',
        url: 'https://example.com/?q=<script>',
      },
    ]);
    const titleEl = contentEl.querySelector('.report-finding-title');
    const detailEl = contentEl.querySelector('.report-finding-detail');
    const urlEl = contentEl.querySelector('.report-finding-url');
    expect(titleEl.textContent).toContain('<script>alert(1)</script>');
    expect(detailEl.textContent).toContain('param "q" is injectable');
    expect(urlEl.textContent).toContain('<script>');
    expect(contentEl.querySelectorAll('script').length).toBe(0);
  });

  it('uses raw module name when not in MODULE_LABELS', () => {
    renderReport([
      { severity: 'info', title: 'Custom', module: 'custom-module', detail: '', url: '' },
    ]);
    expect(contentEl.innerHTML).toContain('custom-module');
  });

  it('returns early when container is missing', () => {
    contentEl.remove();
    expect(() =>
      renderReport([{ severity: 'info', title: 't', module: 'x', detail: '', url: '' }])
    ).not.toThrow();
  });

  it('renders all 5 severity badges even when some are zero', () => {
    renderReport([{ severity: 'critical', title: 'a', module: 'xss', detail: '', url: '' }]);
    expect(summaryEl.innerHTML).toContain('严重');
    expect(summaryEl.innerHTML).toContain('高危');
    expect(summaryEl.innerHTML).toContain('中危');
    expect(summaryEl.innerHTML).toContain('低危');
    expect(summaryEl.innerHTML).toContain('信息');
  });
});
