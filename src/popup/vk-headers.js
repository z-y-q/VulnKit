// vk-headers.js -- 灵眸 Chrome Extension
// HTTP Security Headers Analysis with scoring

import { utilsProxy as utils } from './vk-namespace.js';

var lastAnalysisResult = null;
var scanning = false;

// ====== Header rule definitions ======

var SECURITY_HEADERS = [
  {
    name: 'Content-Security-Policy',
    weight: 10,
    category: 'security',
  },
  {
    name: 'Strict-Transport-Security',
    weight: 8,
    category: 'security',
  },
  {
    name: 'X-Frame-Options',
    weight: 7,
    category: 'security',
  },
  {
    name: 'X-Content-Type-Options',
    weight: 5,
    category: 'security',
  },
  {
    name: 'Referrer-Policy',
    weight: 6,
    category: 'privacy',
  },
  {
    name: 'Permissions-Policy',
    weight: 5,
    category: 'privacy',
  },
  {
    name: 'Cross-Origin-Opener-Policy',
    weight: 4,
    category: 'cross-origin',
  },
  {
    name: 'Cross-Origin-Resource-Policy',
    weight: 4,
    category: 'cross-origin',
  },
  {
    name: 'Cross-Origin-Embedder-Policy',
    weight: 4,
    category: 'cross-origin',
  },
  {
    name: 'X-XSS-Protection',
    weight: 3,
    category: 'legacy',
  },
  {
    name: 'Cache-Control',
    weight: 3,
    category: 'caching',
  },
  {
    name: 'Pragma',
    weight: 2,
    category: 'legacy',
  },
];

// ====== Individual header checkers ======
// Each returns { status: 'pass'|'warn'|'miss', detail, recommendation }

function checkCSP(value) {
  if (!value) return { status: 'miss', detail: '未设置', recommendation: '添加 Content-Security-Policy 头，限制资源加载来源' };
  var issues = [];
  if (value.indexOf("'unsafe-inline'") !== -1) issues.push('包含 unsafe-inline');
  if (value.indexOf("'unsafe-eval'") !== -1) issues.push('包含 unsafe-eval');
  if (value.indexOf('data:') !== -1) issues.push('允许 data: URI');
  if (value.indexOf('*') !== -1 && value.indexOf('default-src') !== -1) issues.push('default-src 使用通配符');
  if (issues.length > 0) return { status: 'warn', detail: value.substring(0, 200), recommendation: '移除 ' + issues.join('、') + ' 以增强安全性' };
  return { status: 'pass', detail: value.substring(0, 200), recommendation: '' };
}

function checkHSTS(value) {
  if (!value) return { status: 'miss', detail: '未设置', recommendation: '添加 Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' };
  var maxAgeMatch = value.match(/max-age=(\d+)/i);
  var maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
  var issues = [];
  if (maxAge < 2592000) issues.push('max-age 不足 30 天（当前 ' + maxAge + 's）');
  if (value.indexOf('includeSubDomains') === -1) issues.push('缺少 includeSubDomains');
  if (value.indexOf('preload') === -1) issues.push('未加入 HSTS Preload');
  if (issues.length > 0) return { status: 'warn', detail: value.substring(0, 200), recommendation: issues.join('；') };
  return { status: 'pass', detail: value.substring(0, 200), recommendation: '' };
}

function checkXFO(value) {
  if (!value) return { status: 'miss', detail: '未设置', recommendation: '添加 X-Frame-Options: DENY 或 SAMEORIGIN 防止点击劫持' };
  var upper = value.toUpperCase().trim();
  if (upper === 'DENY' || upper === 'SAMEORIGIN') return { status: 'pass', detail: value, recommendation: '' };
  return { status: 'warn', detail: value, recommendation: '建议使用 DENY 或 SAMEORIGIN' };
}

function checkXCTO(value) {
  if (!value) return { status: 'miss', detail: '未设置', recommendation: '添加 X-Content-Type-Options: nosniff 防止 MIME 嗅探' };
  if (value.toLowerCase().trim() === 'nosniff') return { status: 'pass', detail: value, recommendation: '' };
  return { status: 'warn', detail: value, recommendation: '应为 nosniff' };
}

function checkXXP(value) {
  if (!value) return { status: 'miss', detail: '未设置（现代浏览器已弃用，建议用 CSP 替代）', recommendation: 'X-XSS-Protection 已被现代浏览器弃用，请使用 CSP 替代' };
  if (value.indexOf('0') === 0) return { status: 'warn', detail: value, recommendation: '已禁用 XSS 过滤器，请确保有 CSP 保护' };
  return { status: 'pass', detail: value, recommendation: '注意：该头已被现代浏览器弃用' };
}

function checkRP(value) {
  if (!value) return { status: 'miss', detail: '未设置', recommendation: '添加 Referrer-Policy: strict-origin-when-cross-origin' };
  var lower = value.toLowerCase().trim();
  var safeValues = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin'];
  if (safeValues.indexOf(lower) !== -1) return { status: 'pass', detail: value, recommendation: '' };
  return { status: 'warn', detail: value, recommendation: '建议使用 strict-origin-when-cross-origin 或 no-referrer' };
}

function checkPP(value) {
  if (!value) return { status: 'miss', detail: '未设置', recommendation: '添加 Permissions-Policy 限制浏览器功能（geolocation, camera, microphone 等）' };
  return { status: 'pass', detail: value.substring(0, 200), recommendation: '' };
}

function checkCOOP(value) {
  if (!value) return { status: 'miss', detail: '未设置', recommendation: '添加 Cross-Origin-Opener-Policy: same-origin 防止 window.opener 泄露' };
  var lower = value.toLowerCase().trim();
  if (lower === 'same-origin' || lower === 'same-origin-allow-popups') return { status: 'pass', detail: value, recommendation: '' };
  return { status: 'warn', detail: value, recommendation: '建议使用 same-origin' };
}

function checkCORP(value) {
  if (!value) return { status: 'miss', detail: '未设置', recommendation: '添加 Cross-Origin-Resource-Policy: same-origin 防止跨域资源泄露' };
  var lower = value.toLowerCase().trim();
  if (lower === 'same-origin' || lower === 'same-site') return { status: 'pass', detail: value, recommendation: '' };
  return { status: 'warn', detail: value, recommendation: '建议使用 same-origin' };
}

function checkCOEP(value) {
  if (!value) return { status: 'miss', detail: '未设置', recommendation: '添加 Cross-Origin-Embedder-Policy: require-corp 防止跨域嵌入攻击' };
  var lower = value.toLowerCase().trim();
  if (lower === 'require-corp' || lower === 'credentialless') return { status: 'pass', detail: value, recommendation: '' };
  return { status: 'warn', detail: value, recommendation: '建议使用 require-corp' };
}

function checkCC(value) {
  if (!value) return { status: 'miss', detail: '未设置', recommendation: '添加 Cache-Control: no-store 或 no-cache 防止敏感页面缓存' };
  var lower = value.toLowerCase();
  if (lower.indexOf('no-store') !== -1) return { status: 'pass', detail: value, recommendation: '' };
  if (lower.indexOf('no-cache') !== -1 || lower.indexOf('private') !== -1) return { status: 'pass', detail: value, recommendation: '' };
  if (lower.indexOf('max-age=0') !== -1) return { status: 'pass', detail: value, recommendation: '' };
  return { status: 'warn', detail: value, recommendation: '建议添加 no-store 或 no-cache' };
}

function checkPragma(value) {
  if (!value) return { status: 'miss', detail: '未设置（HTTP/1.0 兼容头）', recommendation: '添加 Pragma: no-cache 以兼容 HTTP/1.0 缓存控制' };
  if (value.toLowerCase().trim() === 'no-cache') return { status: 'pass', detail: value, recommendation: '' };
  return { status: 'warn', detail: value, recommendation: '应为 no-cache' };
}

var HEADER_CHECKERS = {
  'Content-Security-Policy': checkCSP,
  'Strict-Transport-Security': checkHSTS,
  'X-Frame-Options': checkXFO,
  'X-Content-Type-Options': checkXCTO,
  'X-XSS-Protection': checkXXP,
  'Referrer-Policy': checkRP,
  'Permissions-Policy': checkPP,
  'Cross-Origin-Opener-Policy': checkCOOP,
  'Cross-Origin-Resource-Policy': checkCORP,
  'Cross-Origin-Embedder-Policy': checkCOEP,
  'Cache-Control': checkCC,
  'Pragma': checkPragma,
};

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

function analyzeHeaders(parsedHeaders) {
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
    var checkResult = checker ? checker(headerValue) : { status: 'miss', detail: '未设置', recommendation: '' };

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
      utils.showToast('获取响应头失败: ' + (headerResult ? headerResult.error : '无响应'), 'warning');
      return null;
    }

    var parsed = parseHeaders(headerResult);
    var analysis = analyzeHeaders(parsed);
    lastAnalysisResult = { url: url, analysis: analysis };
    return analysis;
  } catch (e) {
    console.debug('[Security Headers] scan error:', e.message);
    utils.showToast('扫描出错: ' + e.message, 'warning');
    return null;
  } finally {
    scanning = false;
  }
}

// ====== Render ======

function renderHeadersResults(analysis) {
  var container = utils.get('headers-results');
  var scoreContainer = utils.get('headers-score-container');
  var gradeEl = utils.get('headers-grade');
  var scoreRing = utils.get('headers-score-ring');
  var scoreText = utils.get('headers-score-text');
  var summaryEl = utils.get('headers-summary');
  var exportBtn = utils.get('headers-export-btn');

  if (!container || !analysis) return;

  scoreContainer.style.display = 'flex';

  var gradeClass = 'grade-' + analysis.grade.toLowerCase();
  gradeEl.className = 'headers-grade ' + gradeClass;
  gradeEl.textContent = analysis.grade;

  scoreText.textContent = analysis.score;

  var circumference = 2 * Math.PI * 54;
  var offset = circumference - (analysis.score / 100) * circumference;
  scoreRing.style.strokeDashoffset = String(offset);
  scoreRing.className = 'score-ring-fg ' + (analysis.score >= 75 ? 'score-high' : analysis.score >= 50 ? 'score-medium' : 'score-low');

  summaryEl.innerHTML = utils.escapeHtml(
    '通过 ' + analysis.passed + ' | 警告 ' + analysis.warning + ' | 缺失 ' + analysis.missing
  );

  var html = '';
  for (var i = 0; i < analysis.results.length; i++) {
    var r = analysis.results[i];
    html += '<div class="headers-result-item">';
    html += '<span class="headers-status ' + r.status + '"></span>';
    html += '<span class="headers-header-name">' + utils.escapeHtml(r.name) + '</span>';
    html += '<span class="headers-header-value">' + utils.escapeHtml(r.detail || '-') + '</span>';
    html += '</div>';
    if (r.recommendation) {
      html += '<div class="headers-header-rec">' + utils.escapeHtml(r.recommendation) + '</div>';
    }
  }
  container.innerHTML = html;
  if (exportBtn) exportBtn.style.display = '';
}

// ====== Export ======

function exportHeadersResults() {
  if (!lastAnalysisResult) return;
  var a = lastAnalysisResult.analysis;
  var lines = ['安全头分析报告', '=', '目标: ' + lastAnalysisResult.url, '评分: ' + a.score + ' (' + a.grade + ')', '', '结果:'];
  for (var i = 0; i < a.results.length; i++) {
    var r = a.results[i];
    var statusText = r.status === 'pass' ? '[通过]' : r.status === 'warn' ? '[警告]' : '[缺失]';
    lines.push(statusText + ' ' + r.name + ': ' + (r.detail || '-'));
    if (r.recommendation) lines.push('  建议: ' + r.recommendation);
  }
  utils.downloadBlob(new Blob([lines.join('\n')], { type: 'text/plain' }), 'security-headers-' + Date.now() + '.txt');
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
  findings.sort(function (a, b) {
    var order = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    return (order[b.severity] || 0) - (order[a.severity] || 0);
  });
  return findings;
}

export { lastAnalysisResult, scanning, scanSecurityHeaders, renderHeadersResults, exportHeadersResults, getFindings };
