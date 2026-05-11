// 灵眸 - Unified Report Generation
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SEV_LABELS = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' };
const SEV_COLORS = {
  critical: '#e74c3c',
  high: '#e67e22',
  medium: '#f39c12',
  low: '#27ae60',
  info: '#4A90E2',
};
const SEV_BG = {
  critical: 'rgba(231,76,60,0.15)',
  high: 'rgba(230,126,34,0.15)',
  medium: 'rgba(243,156,18,0.15)',
  low: 'rgba(39,174,96,0.15)',
  info: 'rgba(74,144,226,0.15)',
};

const MODULE_LABELS = {
  xss: 'XSS 扫描',
  cors: 'CORS 检测',
  waf: 'WAF 检测',
  cookie: 'Cookie 审计',
  sniff: '技术栈识别',
  leak: '信息泄露',
  subdomain: '子域名收集',
  headers: '安全头检测',
  redirect: '重定向检测',
  fuzz: '目录扫描',
  jwt: 'JWT 分析',
  'storage-check': '存储检查',
};

function normalizeSeverity(raw) {
  if (SEV_ORDER[raw] !== undefined) return raw;
  if (raw === 'danger') return 'critical';
  if (raw === 'warning') return 'medium';
  return 'info';
}

async function collectAllFindings() {
  var allFindings = [];
  var moduleMap = {
    xss: './vk-xss.js',
    cors: './vk-cors.js',
    waf: './vk-waf.js',
    cookie: './vk-cookie-audit.js',
    sniff: './vk-sniff-scanner.js',
    subdomain: './vk-subdomain.js',
    headers: './vk-headers.js',
    redirect: './vk-redirect.js',
    fuzz: './vk-fuzz.js',
    graphql: './vk-graphql.js',
    jwt: './vk-jwt.js',
    'storage-check': './vk-storage-check.js',
  };

  for (var key in moduleMap) {
    if (!moduleMap.hasOwnProperty(key)) continue;
    try {
      var mod = await import(moduleMap[key]);
      if (typeof mod.getFindings !== 'function') continue;
      var items = mod.getFindings();
      if (!Array.isArray(items)) continue;
      for (var i = 0; i < items.length; i++) {
        var f = items[i];
        if (!f || !f.module) continue;
        allFindings.push({
          severity: normalizeSeverity(f.severity),
          title: f.title || '未知发现',
          detail: f.detail || '',
          module: f.module,
          url: f.url || '',
        });
      }
    } catch (e) {
      console.debug('[Report] Failed to load module:', key, e.message);
    }
  }

  allFindings.sort(function (a, b) {
    return (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0);
  });

  return allFindings;
}

function buildSummary(findings) {
  var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (var i = 0; i < findings.length; i++) {
    var sev = findings[i].severity;
    if (counts.hasOwnProperty(sev)) counts[sev]++;
  }
  return counts;
}

function generateHtmlReport(findings) {
  var summary = buildSummary(findings);
  var now = new Date().toISOString().replace('T', ' ').substring(0, 19);
  var domain = '';
  try {
    var tab = utils.getActiveTab ? utils.getActiveTab() : null;
    if (tab && tab.url) domain = new URL(tab.url).hostname;
  } catch (_) {
    /* noop */
  }

  var html =
    '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8">' +
    '<title>灵眸渗透测试报告 - ' +
    utils.escapeHtml(domain) +
    '</title>' +
    '<style>' +
    '*{margin:0;padding:0;box-sizing:border-box}' +
    'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#1a1a2e;color:#e0e0e0;padding:24px;line-height:1.6}' +
    '.report-header{background:linear-gradient(135deg,#16213e,#0f3460);padding:24px;border-radius:8px;margin-bottom:24px}' +
    '.report-header h1{font-size:22px;color:#fff;margin-bottom:8px}' +
    '.report-header .meta{font-size:13px;color:#aaa}' +
    '.summary-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}' +
    '.summary-card{padding:16px;border-radius:8px;text-align:center}' +
    '.summary-card .count{font-size:28px;font-weight:bold}' +
    '.summary-card .label{font-size:12px;margin-top:4px}' +
    '.findings{background:#16213e;border-radius:8px;overflow:hidden}' +
    '.findings h2{padding:16px;font-size:16px;border-bottom:1px solid #2a2a4a}' +
    '.finding{padding:12px 16px;border-bottom:1px solid #1e1e3a}' +
    '.finding:last-child{border-bottom:none}' +
    '.finding .sev-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;margin-right:8px}' +
    '.finding .module-tag{display:inline-block;padding:2px 6px;border-radius:3px;font-size:10px;background:rgba(74,144,226,0.2);color:#4A90E2;margin-right:8px}' +
    '.finding .title{font-weight:bold;font-size:13px}' +
    '.finding .detail{font-size:12px;color:#aaa;margin-top:4px}' +
    '.finding .url{font-size:11px;color:#666;margin-top:2px;word-break:break-all}' +
    '@media print{body{background:#fff;color:#222}.report-header{background:#2c3e50}.findings{background:#f8f9fa}.finding{border-color:#eee}.finding .detail{color:#666}.finding .url{color:#999}}' +
    '</style></head><body>';

  html +=
    '<div class="report-header"><h1>灵眸渗透测试报告</h1>' +
    '<div class="meta">目标: ' +
    utils.escapeHtml(domain || '未知') +
    ' | 时间: ' +
    now +
    ' | 发现: ' +
    findings.length +
    ' 项</div></div>';

  html += '<div class="summary-grid">';
  var sevKeys = ['critical', 'high', 'medium', 'low', 'info'];
  for (var s = 0; s < sevKeys.length; s++) {
    var sk = sevKeys[s];
    html +=
      '<div class="summary-card" style="background:' +
      SEV_BG[sk] +
      '">' +
      '<div class="count" style="color:' +
      SEV_COLORS[sk] +
      '">' +
      summary[sk] +
      '</div>' +
      '<div class="label">' +
      SEV_LABELS[sk] +
      '</div></div>';
  }
  html += '</div>';

  html += '<div class="findings"><h2>发现列表</h2>';
  for (var i = 0; i < findings.length; i++) {
    var f = findings[i];
    html +=
      '<div class="finding">' +
      '<span class="sev-badge" style="background:' +
      SEV_BG[f.severity] +
      ';color:' +
      SEV_COLORS[f.severity] +
      '">' +
      SEV_LABELS[f.severity] +
      '</span>' +
      '<span class="module-tag">' +
      utils.escapeHtml(MODULE_LABELS[f.module] || f.module) +
      '</span>' +
      '<div class="title">' +
      utils.escapeHtml(f.title) +
      '</div>' +
      '<div class="detail">' +
      utils.escapeHtml(f.detail) +
      '</div>' +
      (f.url ? '<div class="url">' + utils.escapeHtml(f.url) + '</div>' : '') +
      '</div>';
  }
  html += '</div></body></html>';

  return html;
}

function generateMarkdownReport(findings) {
  var summary = buildSummary(findings);
  var now = new Date().toISOString().replace('T', ' ').substring(0, 19);
  var domain = '';
  try {
    var tab = utils.getActiveTab ? utils.getActiveTab() : null;
    if (tab && tab.url) domain = new URL(tab.url).hostname;
  } catch (_) {
    /* noop */
  }

  var lines = [];
  lines.push('# 灵眸渗透测试报告');
  lines.push('');
  lines.push('**目标**: ' + (domain || '未知') + '  ');
  lines.push('**时间**: ' + now + '  ');
  lines.push('**发现总数**: ' + findings.length);
  lines.push('');

  lines.push('## 概要');
  lines.push('');
  lines.push('| 级别 | 数量 |');
  lines.push('|------|------|');
  lines.push('| 严重 | ' + summary.critical + ' |');
  lines.push('| 高危 | ' + summary.high + ' |');
  lines.push('| 中危 | ' + summary.medium + ' |');
  lines.push('| 低危 | ' + summary.low + ' |');
  lines.push('| 信息 | ' + summary.info + ' |');
  lines.push('');

  if (findings.length > 0) {
    lines.push('## 发现列表');
    lines.push('');
    for (var i = 0; i < findings.length; i++) {
      var f = findings[i];
      lines.push('### ' + (i + 1) + '. [' + SEV_LABELS[f.severity] + '] ' + f.title);
      lines.push('- **模块**: ' + (MODULE_LABELS[f.module] || f.module));
      lines.push('- **详情**: ' + f.detail);
      if (f.url) lines.push('- **URL**: ' + f.url);
      lines.push('');
    }
  }

  return lines.join('\n');
}

function renderReport(findings) {
  var container = utils.get('report-content');
  var summaryContainer = utils.get('report-summary');
  if (!container) return;

  var summary = buildSummary(findings);

  if (summaryContainer) {
    var html = '<div class="report-summary">';
    var sevKeys = ['critical', 'high', 'medium', 'low', 'info'];
    for (var s = 0; s < sevKeys.length; s++) {
      var sk = sevKeys[s];
      html +=
        '<span class="stat-badge stat-' +
        (sk === 'info' ? 'total' : sk === 'low' ? 'safe' : sk === 'medium' ? 'warn' : 'vuln') +
        '">' +
        SEV_LABELS[sk] +
        ' ' +
        summary[sk] +
        '</span>';
    }
    if (findings.length === 0) {
      html +=
        '<div class="report-findings-empty">暂无发现 — 请先运行扫描模块或点击「一键审计」</div>';
    }
    html += '</div>';
    summaryContainer.innerHTML = html;
  }

  if (findings.length === 0) {
    container.innerHTML = '';
    return;
  }

  var listHtml =
    '<div class="report-findings-header"><span class="stat-badge stat-total">共 ' +
    findings.length +
    ' 项发现</span></div>';
  listHtml += '<div class="report-findings-list">';
  for (var i = 0; i < findings.length; i++) {
    var f = findings[i];
    listHtml +=
      '<div class="report-finding-item">' +
      '<div class="report-finding-header">' +
      '<span class="report-finding-sev" style="color:' +
      SEV_COLORS[f.severity] +
      '">' +
      SEV_LABELS[f.severity] +
      '</span>' +
      '<span class="report-finding-module">' +
      utils.escapeHtml(MODULE_LABELS[f.module] || f.module) +
      '</span>' +
      '</div>' +
      '<div class="report-finding-title">' +
      utils.escapeHtml(f.title) +
      '</div>' +
      '<div class="report-finding-detail">' +
      utils.escapeHtml(f.detail) +
      '</div>' +
      (f.url ? '<div class="report-finding-url">' + utils.escapeHtml(f.url) + '</div>' : '') +
      '</div>';
  }
  listHtml += '</div>';
  container.innerHTML = listHtml;
}

function exportHtml(findings) {
  var html = generateHtmlReport(findings);
  var blob = new Blob([html], { type: 'text/html;charset=utf-8' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'lingmou-report-' + Date.now() + '.html';
  a.click();
  setTimeout(function () {
    URL.revokeObjectURL(url);
  }, 1000);
  utils.showToast('HTML 报告已导出', 'success');
}

function exportMarkdown(findings) {
  var md = generateMarkdownReport(findings);
  var blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'lingmou-report-' + Date.now() + '.md';
  a.click();
  setTimeout(function () {
    URL.revokeObjectURL(url);
  }, 1000);
  utils.showToast('Markdown 报告已导出', 'success');
}

var _lastCollectedFindings = null;

async function handleCollectFindings() {
  var statusEl = utils.get('report-status');
  if (statusEl) {
    statusEl.textContent = '正在收集各模块结果...';
    statusEl.style.color = '#4A90E2';
  }
  try {
    var findings = await collectAllFindings();
    _lastCollectedFindings = findings;
    renderReport(findings);
    var summary = buildSummary(findings);
    if (statusEl) {
      statusEl.textContent =
        '收集完成: ' +
        findings.length +
        ' 个发现（严重 ' +
        summary.critical +
        ' / 高危 ' +
        summary.high +
        ' / 中危 ' +
        summary.medium +
        '）';
      statusEl.style.color = findings.length > 0 ? '#27ae60' : '#999';
    }
  } catch (e) {
    if (statusEl) {
      statusEl.textContent = '收集失败: ' + e.message;
      statusEl.style.color = '#e74c3c';
    }
  }
}

async function runFullAudit() {
  var statusEl = utils.get('report-status');
  var progressEl = utils.get('report-progress');
  var progressBar = utils.get('report-progress-bar');
  var progressText = utils.get('report-progress-text');

  if (statusEl) {
    statusEl.textContent = '一键审计启动中...';
    statusEl.style.color = '#4A90E2';
  }
  if (progressEl) progressEl.style.display = '';
  if (progressBar) progressBar.style.width = '0%';
  if (progressText) progressText.textContent = '0/5';

  var steps = [
    { importPath: './vk-sniff-scanner.js', runFn: 'runSniffScan', label: '技术栈识别' },
    { importPath: './vk-xss.js', runFn: 'handleXssHarvest', label: 'XSS 注入点采集' },
    { importPath: './vk-cors.js', runFn: 'scanCors', label: 'CORS 配置检测' },
    { importPath: './vk-waf.js', runFn: 'scanWaf', label: 'WAF 指纹检测' },
    { importPath: './vk-cookie-audit.js', runFn: 'auditCookies', label: 'Cookie 安全审计' },
  ];

  for (var i = 0; i < steps.length; i++) {
    var step = steps[i];
    var pct = Math.round((i / steps.length) * 100);
    if (progressBar) progressBar.style.width = pct + '%';
    if (progressText) progressText.textContent = i + 1 + '/' + steps.length;
    if (statusEl) statusEl.textContent = '审计中: ' + step.label + '...';

    try {
      var mod = await import(step.importPath);
      if (typeof mod[step.runFn] === 'function') {
        await mod[step.runFn]();
      }
    } catch (e) {
      console.debug('[Report] Audit step failed:', step.label, e.message);
    }

    await new Promise(function (resolve) {
      setTimeout(resolve, 500);
    });
  }

  if (progressBar) progressBar.style.width = '100%';
  if (progressText) progressText.textContent = steps.length + '/' + steps.length;

  await new Promise(function (resolve) {
    setTimeout(resolve, 1000);
  });
  await handleCollectFindings();

  if (statusEl) {
    statusEl.textContent = '一键审计完成';
    statusEl.style.color = '#27ae60';
  }
}

function getLastFindings() {
  return _lastCollectedFindings;
}

export {
  collectAllFindings,
  buildSummary,
  generateHtmlReport,
  generateMarkdownReport,
  renderReport,
  exportHtml,
  exportMarkdown,
  handleCollectFindings,
  runFullAudit,
  getLastFindings,
};
