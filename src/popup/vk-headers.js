// vk-headers.js -- 灵眸 Chrome Extension
// HTTP Security Headers Analysis — barrel + core logic

import { utilsProxy as utils } from './vk-namespace.js';
import { saveScanResult } from './vk-scan-history.js';
import { getSecurityHeaders, getServerSignatures } from './vk-headers-data.js';
import { HEADER_CHECKERS, deepAnalyzeCSP } from './vk-headers-checkers.js';
import { renderHeadersResults, groupByCategory, applyHeaderFilter } from './vk-headers-render.js';

var lastAnalysisResult = null;
var scanning = false;
var currentFilter = 'all';
var currentSearch = '';
var currentSort = '';
var HEADERS_SORT_FNS = {
  status: function (a, b) {
    var o = { missing: 0, warn: 1, pass: 2 };
    return (o[a.status] || 2) - (o[b.status] || 2);
  },
  name: function (a, b) {
    return (a.header || '').localeCompare(b.header || '');
  },
};

// ====== Info leak detection ======

async function detectInfoLeaks(parsedHeaders) {
  var leaks = [];
  var serverVal = parsedHeaders['server'] || '';
  var signatures = await getServerSignatures();
  if (serverVal) {
    var serverLower = serverVal.toLowerCase();
    var detected = [];
    for (var i = 0; i < signatures.length; i++) {
      if (serverLower.indexOf(signatures[i]) !== -1) detected.push(signatures[i]);
    }
    if (detected.length > 0) {
      leaks.push({
        name: 'Server',
        detail: serverVal,
        info: '服务器信息泄露: ' + detected.join(', '),
      });
    }
  }

  var poweredBy = parsedHeaders['x-powered-by'] || '';
  if (poweredBy) {
    leaks.push({ name: 'X-Powered-By', detail: poweredBy, info: '技术栈泄露: ' + poweredBy });
  }

  var xAspNet = parsedHeaders['x-aspnet-version'] || '';
  if (xAspNet) {
    leaks.push({ name: 'X-AspNet-Version', detail: xAspNet, info: 'ASP.NET 版本泄露' });
  }

  var xGenerator = parsedHeaders['x-generator'] || '';
  if (xGenerator) {
    leaks.push({
      name: 'X-Generator',
      detail: xGenerator,
      info: 'CMS/框架信息泄露: ' + xGenerator,
    });
  }

  return leaks;
}

// ====== Cookie analysis ======

function analyzeCookieSecurity(setCookies) {
  if (!setCookies || setCookies.length === 0) return [];
  var findings = [];
  for (var i = 0; i < setCookies.length; i++) {
    var cookie = setCookies[i];
    var name = cookie.name || '';
    var flags = cookie.flags || {};
    var issues = [];
    if (!flags.secure) issues.push('缺少 Secure');
    if (!flags.httponly) issues.push('缺少 HttpOnly');
    if (!flags.samesite || flags.samesite === 'none') {
      if (!flags.secure) issues.push('SameSite=None 但无 Secure');
      else issues.push('SameSite=None（跨站可访问）');
    }
    if (issues.length > 0) {
      findings.push({ name: name, issues: issues, flags: flags });
    }
  }
  return findings;
}

function parseSetCookies(parsedHeaders) {
  var raw = parsedHeaders['set-cookie'];
  if (!raw) return [];
  if (Array.isArray(raw)) {
    var all = [];
    for (var i = 0; i < raw.length; i++) all.push(parseOneCookie(raw[i]));
    return all;
  }
  return [parseOneCookie(raw)];
}

function parseOneCookie(str) {
  var parts = str.split(';');
  var nameVal = (parts[0] || '').trim();
  var eqIdx = nameVal.indexOf('=');
  var name = eqIdx !== -1 ? nameVal.substring(0, eqIdx).trim() : nameVal;
  var flags = {};
  for (var i = 1; i < parts.length; i++) {
    var flag = parts[i].trim().toLowerCase();
    if (flag.indexOf('secure') === 0) flags.secure = true;
    else if (flag.indexOf('httponly') === 0) flags.httponly = true;
    else if (flag.indexOf('samesite=') === 0) flags.samesite = flag.substring(9).trim();
  }
  return { name: name, flags: flags };
}

// ====== Core scan logic ======

async function fetchHeaders(url) {
  return new Promise(function (resolve) {
    chrome.runtime.sendMessage({ type: 'FETCH_HEADER_PROBE', url: url }, function (resp) {
      if (chrome.runtime.lastError) {
        resolve(null);
        return;
      }
      resolve(resp || null);
    });
  });
}

async function fetchWithCookies(url) {
  return new Promise(function (resolve) {
    chrome.runtime.sendMessage(
      { type: 'FETCH_PROBE', url: url, includeBody: false },
      function (resp) {
        if (chrome.runtime.lastError) {
          resolve(null);
          return;
        }
        resolve(resp || null);
      }
    );
  });
}

function parseHeaders(headerResult) {
  var headers = {};
  if (!headerResult || headerResult.error) return headers;
  var raw = headerResult.headers;
  if (!raw) return headers;
  if (Array.isArray(raw)) {
    for (var i = 0; i < raw.length; i++) {
      headers[raw[i].name.toLowerCase()] = raw[i].value;
    }
  } else if (typeof raw === 'object') {
    var keys = Object.keys(raw);
    for (var j = 0; j < keys.length; j++) {
      headers[keys[j].toLowerCase()] = raw[keys[j]];
    }
  }
  return headers;
}

async function analyzeHeaders(parsedHeaders) {
  var SECURITY_HEADERS = await getSecurityHeaders();
  var totalWeight = 0;
  var earnedWeight = 0;
  var passedCount = 0;
  var warnCount = 0;
  var missCount = 0;
  var results = [];

  for (var i = 0; i < SECURITY_HEADERS.length; i++) {
    var rule = SECURITY_HEADERS[i];
    totalWeight += rule.weight;
    var headerValue = parsedHeaders[rule.name.toLowerCase()] || null;
    var checker = HEADER_CHECKERS[rule.name];
    var checkResult = checker
      ? checker(headerValue)
      : { status: 'miss', detail: '未设置', recommendation: '' };

    if (checkResult.status === 'pass') {
      earnedWeight += rule.weight;
      passedCount++;
    } else if (checkResult.status === 'warn') {
      earnedWeight += rule.weight * 0.5;
      warnCount++;
    } else {
      missCount++;
    }

    results.push({
      name: rule.name,
      category: rule.category,
      weight: rule.weight,
      status: checkResult.status,
      value: headerValue,
      detail: checkResult.detail,
      recommendation: checkResult.recommendation,
    });
  }

  var score = totalWeight > 0 ? Math.round((earnedWeight / totalWeight) * 100) : 0;
  var grade;
  if (score >= 90) grade = 'A';
  else if (score >= 75) grade = 'B';
  else if (score >= 60) grade = 'C';
  else if (score >= 40) grade = 'D';
  else grade = 'F';

  return {
    score: score,
    grade: grade,
    passed: passedCount,
    warning: warnCount,
    missing: missCount,
    results: results,
  };
}

// ====== Scan entry point ======

async function scanSecurityHeaders(url) {
  if (scanning) return null;
  scanning = true;

  try {
    var headerResult = await fetchHeaders(url);
    if (!headerResult || headerResult.error) {
      utils.showToast(
        '获取响应头失败: ' + (headerResult ? headerResult.error : '无响应'),
        'warning'
      );
      return null;
    }

    var parsed = parseHeaders(headerResult);
    var analysis = await analyzeHeaders(parsed);

    var infoLeaks = await detectInfoLeaks(parsed);

    var cookieResp = await fetchWithCookies(url);
    var cookieHeaders = cookieResp ? parseHeaders(cookieResp) : {};
    var setCookies = parseSetCookies(cookieHeaders);
    var cookieAnalysis = analyzeCookieSecurity(setCookies);

    var cspDeep = deepAnalyzeCSP(parsed['content-security-policy'] || null);

    lastAnalysisResult = {
      url: url,
      analysis: analysis,
      infoLeaks: infoLeaks,
      cookieAnalysis: cookieAnalysis,
      cspDeep: cspDeep,
      grouped: groupByCategory(analysis.results),
    };
    utils.getCurrentDomain().then(function (d) {
      if (d) saveScanResult('headers', d, getFindings());
    });
    return analysis;
  } catch (e) {
    console.debug('[Security Headers] scan error:', e.message);
    utils.showToast('扫描出错: ' + e.message, 'warning');
    return null;
  } finally {
    scanning = false;
  }
}

// ====== Filter / Search ======

function setFilter(filter) {
  currentFilter = filter;
  if (lastAnalysisResult)
    renderHeadersResults(
      lastAnalysisResult.analysis,
      lastAnalysisResult,
      currentFilter,
      currentSearch,
      currentSort
    );
}

function setSearch(query) {
  currentSearch = (query || '').toLowerCase();
  if (lastAnalysisResult)
    renderHeadersResults(
      lastAnalysisResult.analysis,
      lastAnalysisResult,
      currentFilter,
      currentSearch,
      currentSort
    );
}

function renderHeadersResultsWrapper(analysis) {
  renderHeadersResults(analysis, lastAnalysisResult, currentFilter, currentSearch, currentSort);
}

// ====== Export ======

function exportTxt() {
  if (!lastAnalysisResult) return;
  var a = lastAnalysisResult.analysis;
  var lines = [
    '安全头分析报告',
    '==================',
    '目标: ' + lastAnalysisResult.url,
    '评分: ' + a.score + ' (' + a.grade + ')',
    '',
    '结果:',
  ];
  for (var i = 0; i < a.results.length; i++) {
    var r = a.results[i];
    var statusText = r.status === 'pass' ? '[通过]' : r.status === 'warn' ? '[警告]' : '[缺失]';
    lines.push(statusText + ' ' + r.name + ': ' + (r.detail || '-'));
    if (r.recommendation) lines.push('  建议: ' + r.recommendation);
  }
  if (lastAnalysisResult.infoLeaks) {
    for (var j = 0; j < lastAnalysisResult.infoLeaks.length; j++) {
      var l = lastAnalysisResult.infoLeaks[j];
      lines.push('[泄露] ' + l.name + ': ' + l.detail + ' (' + l.info + ')');
    }
  }
  utils.downloadBlob(
    new Blob([lines.join('\n')], { type: 'text/plain' }),
    'security-headers-' + Date.now() + '.txt'
  );
  utils.showToast('TXT 报告已导出', 'success');
}

function exportCsv() {
  if (!lastAnalysisResult) return;
  var a = lastAnalysisResult.analysis;
  var rows = [['Header', 'Status', 'Weight', 'Value', 'Recommendation']];
  for (var i = 0; i < a.results.length; i++) {
    var r = a.results[i];
    rows.push([r.name, r.status, String(r.weight), r.detail || '', r.recommendation || '']);
  }
  if (lastAnalysisResult.infoLeaks) {
    for (var j = 0; j < lastAnalysisResult.infoLeaks.length; j++) {
      var l = lastAnalysisResult.infoLeaks[j];
      rows.push([l.name, 'infoleak', '0', l.detail, l.info]);
    }
  }
  utils.downloadBlob(
    new Blob([utils.buildCsv(rows)], { type: 'text/csv;charset=utf-8' }),
    'security-headers-' + Date.now() + '.csv'
  );
  utils.showToast('CSV 报告已导出', 'success');
}

function exportHeadersResults(format) {
  if (format === 'csv') {
    exportCsv();
  } else {
    exportTxt();
  }
}

function copyMarkdown() {
  if (
    !lastAnalysisResult ||
    !lastAnalysisResult.analysis ||
    !lastAnalysisResult.analysis.results.length
  ) {
    utils.showToast('没有检测结果', 'warning');
    return;
  }
  var results = lastAnalysisResult.analysis.results;
  var rows = results.map(function (r) {
    return [r.name, r.status, r.detail || '-', r.recommendation || '-'];
  });
  var md = '# Security Headers Report\n\n';
  md += '**Target:** ' + (lastAnalysisResult.url || '') + '\n';
  md +=
    '**Score:** ' +
    lastAnalysisResult.analysis.score +
    ' (' +
    lastAnalysisResult.analysis.grade +
    ')\n\n';
  md += utils.buildMarkdownTable(['Header', 'Status', 'Value', 'Description'], rows);
  utils.copyAndToast(md, '已复制 Markdown', 'success');
}

// ====== getFindings for unified report ======

function getFindings() {
  if (!lastAnalysisResult || !lastAnalysisResult.analysis) return [];
  var findings = [];
  var results = lastAnalysisResult.analysis.results;
  for (var i = 0; i < results.length; i++) {
    var r = results[i];
    if (r.status === 'pass') continue;
    var severity;
    if (r.status === 'miss') {
      severity = r.weight >= 7 ? 'high' : r.weight >= 4 ? 'medium' : 'low';
    } else {
      severity = 'low';
    }
    findings.push({
      severity: severity,
      title: '安全头 ' + (r.status === 'miss' ? '缺失' : '警告') + ': ' + r.name,
      detail: (r.detail || '') + (r.recommendation ? ' | ' + r.recommendation : ''),
      module: 'headers',
      url: lastAnalysisResult.url || '',
    });
  }

  if (lastAnalysisResult.infoLeaks) {
    for (var j = 0; j < lastAnalysisResult.infoLeaks.length; j++) {
      var l = lastAnalysisResult.infoLeaks[j];
      findings.push({
        severity: 'medium',
        title: '信息泄露: ' + l.name,
        detail: l.info + ' | 值: ' + l.detail,
        module: 'headers',
        url: lastAnalysisResult.url || '',
      });
    }
  }

  if (lastAnalysisResult.cookieAnalysis) {
    for (var k = 0; k < lastAnalysisResult.cookieAnalysis.length; k++) {
      var cf = lastAnalysisResult.cookieAnalysis[k];
      findings.push({
        severity: 'medium',
        title: 'Cookie 不安全: ' + cf.name,
        detail: cf.issues.join('；'),
        module: 'headers',
        url: lastAnalysisResult.url || '',
      });
    }
  }

  if (lastAnalysisResult.cspDeep) {
    var cspDeep = lastAnalysisResult.cspDeep;
    if (cspDeep.missingCritical) {
      for (var m = 0; m < cspDeep.missingCritical.length; m++) {
        var mc = cspDeep.missingCritical[m];
        findings.push({
          severity: mc.severity || 'medium',
          title: 'CSP 缺失指令: ' + mc.directive,
          detail: mc.impact,
          module: 'headers',
          url: lastAnalysisResult.url || '',
        });
      }
    }
    if (cspDeep.bypasses) {
      for (var n = 0; n < cspDeep.bypasses.length; n++) {
        var bp = cspDeep.bypasses[n];
        findings.push({
          severity: bp.severity || 'medium',
          title: 'CSP 绕过: ' + bp.type,
          detail: bp.description,
          module: 'headers',
          url: lastAnalysisResult.url || '',
        });
      }
    }
  }

  findings.sort(function (a, b) {
    var order = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    return (order[b.severity] || 0) - (order[a.severity] || 0);
  });
  return findings;
}

function sortResults(key) {
  currentSort = key;
  if (lastAnalysisResult)
    renderHeadersResults(
      lastAnalysisResult.analysis,
      lastAnalysisResult,
      currentFilter,
      currentSearch,
      currentSort
    );
}

export {
  lastAnalysisResult,
  scanning,
  scanSecurityHeaders,
  renderHeadersResultsWrapper as renderHeadersResults,
  exportHeadersResults,
  copyMarkdown,
  getFindings,
  setFilter,
  setSearch,
  sortResults,
};
