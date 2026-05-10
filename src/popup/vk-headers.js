// vk-headers.js -- 灵眸 Chrome Extension
// HTTP Security Headers Analysis with scoring

import { utilsProxy as utils } from './vk-namespace.js';

var lastAnalysisResult = null;
var scanning = false;
var currentFilter = 'all';
var currentSearch = '';

var CATEGORY_LABELS = {
  security: '安全防护',
  privacy: '隐私保护',
  'cross-origin': '跨域控制',
  caching: '缓存控制',
  legacy: '遗留兼容',
  infoleak: '信息泄露',
  monitoring: '监控报告',
};

// ====== Header rule definitions ======

var SECURITY_HEADERS = [
  { name: 'Content-Security-Policy', weight: 10, category: 'security' },
  { name: 'Strict-Transport-Security', weight: 8, category: 'security' },
  { name: 'X-Frame-Options', weight: 7, category: 'security' },
  { name: 'X-Content-Type-Options', weight: 5, category: 'security' },
  { name: 'Content-Security-Policy-Report-Only', weight: 5, category: 'security' },
  { name: 'Clear-Site-Data', weight: 3, category: 'privacy' },
  { name: 'Referrer-Policy', weight: 6, category: 'privacy' },
  { name: 'Permissions-Policy', weight: 5, category: 'privacy' },
  { name: 'X-Robots-Tag', weight: 2, category: 'privacy' },
  { name: 'Cross-Origin-Opener-Policy', weight: 4, category: 'cross-origin' },
  { name: 'Cross-Origin-Resource-Policy', weight: 4, category: 'cross-origin' },
  { name: 'Cross-Origin-Embedder-Policy', weight: 4, category: 'cross-origin' },
  { name: 'X-Permitted-Cross-Domain-Policies', weight: 3, category: 'cross-origin' },
  { name: 'Cache-Control', weight: 3, category: 'caching' },
  { name: 'Pragma', weight: 2, category: 'legacy' },
  { name: 'X-XSS-Protection', weight: 3, category: 'legacy' },
  { name: 'X-Download-Options', weight: 2, category: 'security' },
  { name: 'Report-To', weight: 2, category: 'monitoring' },
  { name: 'NEL', weight: 2, category: 'monitoring' },
];

// ====== CSP Deep Parser ======

function parseCSP(value) {
  if (!value) return { directives: {}, raw: '' };
  var directives = {};
  var parts = value.split(';');
  for (var i = 0; i < parts.length; i++) {
    var trimmed = parts[i].trim();
    if (!trimmed) continue;
    var tokens = trimmed.split(/\s+/);
    var name = (tokens[0] || '').toLowerCase();
    var values = tokens.slice(1);
    directives[name] = values;
  }
  return { directives: directives, raw: value };
}

function checkCSP(value) {
  if (!value)
    return {
      status: 'miss',
      detail: '未设置',
      recommendation: '添加 Content-Security-Policy 头，限制资源加载来源',
    };
  var issues = [];
  var csp = parseCSP(value);
  var d = csp.directives;

  if (!d['default-src'] && !d['script-src']) {
    issues.push('缺少 default-src 和 script-src');
  }

  var defaultSrc = d['default-src'] || [];
  if (defaultSrc.indexOf('*') !== -1) issues.push('default-src 使用通配符 *');
  if (defaultSrc.indexOf("'none'") === -1 && defaultSrc.length === 0 && !d['script-src']) {
    issues.push('default-src 未限制');
  }

  var scriptSrc = d['script-src'] || [];
  if (scriptSrc.indexOf("'unsafe-inline'") !== -1)
    issues.push('script-src 包含 unsafe-inline（允许内联脚本）');
  if (scriptSrc.indexOf("'unsafe-eval'") !== -1)
    issues.push('script-src 包含 unsafe-eval（允许 eval）');
  if (scriptSrc.indexOf('data:') !== -1) issues.push('script-src 允许 data: URI');

  var styleSrc = d['style-src'] || defaultSrc;
  if (styleSrc.indexOf("'unsafe-inline'") !== -1) issues.push('style-src 包含 unsafe-inline');

  var imgSrc = d['img-src'] || defaultSrc;
  if (imgSrc.indexOf('data:') !== -1) issues.push('img-src 允许 data: URI');

  var connectSrc = d['connect-src'] || [];
  if (connectSrc.indexOf('*') !== -1) issues.push('connect-src 使用通配符');

  if (!d['frame-ancestors']) issues.push('缺少 frame-ancestors（防止点击劫持）');
  if (!d['form-action']) issues.push('缺少 form-action（防止表单劫持）');

  if (issues.length > 0) {
    return {
      status: 'warn',
      detail: value.substring(0, 200),
      recommendation: '移除或修复: ' + issues.join('；'),
    };
  }
  return { status: 'pass', detail: value.substring(0, 200), recommendation: '' };
}

// ====== Individual header checkers ======

function checkHSTS(value) {
  if (!value)
    return {
      status: 'miss',
      detail: '未设置',
      recommendation:
        '添加 Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    };
  var maxAgeMatch = value.match(/max-age=(\d+)/i);
  var maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
  var issues = [];
  if (maxAge < 2592000) issues.push('max-age 不足 30 天（当前 ' + maxAge + 's）');
  if (value.indexOf('includeSubDomains') === -1) issues.push('缺少 includeSubDomains');
  if (value.indexOf('preload') === -1) issues.push('未加入 HSTS Preload');
  if (issues.length > 0)
    return { status: 'warn', detail: value.substring(0, 200), recommendation: issues.join('；') };
  return { status: 'pass', detail: value.substring(0, 200), recommendation: '' };
}

function checkXFO(value) {
  if (!value)
    return {
      status: 'miss',
      detail: '未设置',
      recommendation: '添加 X-Frame-Options: DENY 或 SAMEORIGIN 防止点击劫持',
    };
  var upper = value.toUpperCase().trim();
  if (upper === 'DENY' || upper === 'SAMEORIGIN')
    return { status: 'pass', detail: value, recommendation: '' };
  return { status: 'warn', detail: value, recommendation: '建议使用 DENY 或 SAMEORIGIN' };
}

function checkXCTO(value) {
  if (!value)
    return {
      status: 'miss',
      detail: '未设置',
      recommendation: '添加 X-Content-Type-Options: nosniff 防止 MIME 嗅探',
    };
  if (value.toLowerCase().trim() === 'nosniff')
    return { status: 'pass', detail: value, recommendation: '' };
  return { status: 'warn', detail: value, recommendation: '应为 nosniff' };
}

function checkXXP(value) {
  if (!value)
    return {
      status: 'miss',
      detail: '未设置（现代浏览器已弃用，建议用 CSP 替代）',
      recommendation: 'X-XSS-Protection 已被现代浏览器弃用，请使用 CSP 替代',
    };
  if (value.indexOf('0') === 0)
    return {
      status: 'warn',
      detail: value,
      recommendation: '已禁用 XSS 过滤器，请确保有 CSP 保护',
    };
  return { status: 'pass', detail: value, recommendation: '注意：该头已被现代浏览器弃用' };
}

function checkRP(value) {
  if (!value)
    return {
      status: 'miss',
      detail: '未设置',
      recommendation: '添加 Referrer-Policy: strict-origin-when-cross-origin',
    };
  var lower = value.toLowerCase().trim();
  var safeValues = [
    'no-referrer',
    'strict-origin',
    'strict-origin-when-cross-origin',
    'same-origin',
  ];
  if (safeValues.indexOf(lower) !== -1)
    return { status: 'pass', detail: value, recommendation: '' };
  return {
    status: 'warn',
    detail: value,
    recommendation: '建议使用 strict-origin-when-cross-origin 或 no-referrer',
  };
}

function checkPP(value) {
  if (!value)
    return {
      status: 'miss',
      detail: '未设置',
      recommendation:
        '添加 Permissions-Policy 限制浏览器功能（geolocation, camera, microphone 等）',
    };
  return { status: 'pass', detail: value.substring(0, 200), recommendation: '' };
}

function checkCOOP(value) {
  if (!value)
    return {
      status: 'miss',
      detail: '未设置',
      recommendation: '添加 Cross-Origin-Opener-Policy: same-origin 防止 window.opener 泄露',
    };
  var lower = value.toLowerCase().trim();
  if (lower === 'same-origin' || lower === 'same-origin-allow-popups')
    return { status: 'pass', detail: value, recommendation: '' };
  return { status: 'warn', detail: value, recommendation: '建议使用 same-origin' };
}

function checkCORP(value) {
  if (!value)
    return {
      status: 'miss',
      detail: '未设置',
      recommendation: '添加 Cross-Origin-Resource-Policy: same-origin 防止跨域资源泄露',
    };
  var lower = value.toLowerCase().trim();
  if (lower === 'same-origin' || lower === 'same-site')
    return { status: 'pass', detail: value, recommendation: '' };
  return { status: 'warn', detail: value, recommendation: '建议使用 same-origin' };
}

function checkCOEP(value) {
  if (!value)
    return {
      status: 'miss',
      detail: '未设置',
      recommendation: '添加 Cross-Origin-Embedder-Policy: require-corp 防止跨域嵌入攻击',
    };
  var lower = value.toLowerCase().trim();
  if (lower === 'require-corp' || lower === 'credentialless')
    return { status: 'pass', detail: value, recommendation: '' };
  return { status: 'warn', detail: value, recommendation: '建议使用 require-corp' };
}

function checkCC(value) {
  if (!value)
    return {
      status: 'miss',
      detail: '未设置',
      recommendation: '添加 Cache-Control: no-store 或 no-cache 防止敏感页面缓存',
    };
  var lower = value.toLowerCase();
  if (lower.indexOf('no-store') !== -1)
    return { status: 'pass', detail: value, recommendation: '' };
  if (lower.indexOf('no-cache') !== -1 || lower.indexOf('private') !== -1)
    return { status: 'pass', detail: value, recommendation: '' };
  if (lower.indexOf('max-age=0') !== -1)
    return { status: 'pass', detail: value, recommendation: '' };
  return { status: 'warn', detail: value, recommendation: '建议添加 no-store 或 no-cache' };
}

function checkPragma(value) {
  if (!value)
    return {
      status: 'miss',
      detail: '未设置（HTTP/1.0 兼容头）',
      recommendation: '添加 Pragma: no-cache 以兼容 HTTP/1.0 缓存控制',
    };
  if (value.toLowerCase().trim() === 'no-cache')
    return { status: 'pass', detail: value, recommendation: '' };
  return { status: 'warn', detail: value, recommendation: '应为 no-cache' };
}

function checkCSPReportOnly(value) {
  if (!value) return { status: 'pass', detail: '未设置', recommendation: '' };
  return {
    status: 'warn',
    detail: value.substring(0, 200),
    recommendation:
      '检测到 CSP Report-Only 模式 — 策略违规不会被阻止，仅上报。生产环境应使用 Content-Security-Policy',
  };
}

function checkClearSiteData(value) {
  if (!value)
    return {
      status: 'pass',
      detail: '未设置',
      recommendation: '敏感应用可考虑添加 Clear-Site-Data 控制客户端数据清除',
    };
  return { status: 'pass', detail: value, recommendation: '' };
}

function checkXRobots(value) {
  if (!value) return { status: 'pass', detail: '未设置', recommendation: '' };
  var lower = value.toLowerCase();
  if (lower.indexOf('noindex') !== -1) return { status: 'pass', detail: value, recommendation: '' };
  return { status: 'pass', detail: value, recommendation: '' };
}

function checkXPCD(value) {
  if (!value) return { status: 'pass', detail: '未设置', recommendation: '' };
  return { status: 'pass', detail: value, recommendation: '' };
}

function checkReportTo(value) {
  if (!value) return { status: 'pass', detail: '未设置', recommendation: '' };
  return { status: 'pass', detail: value.substring(0, 100), recommendation: '' };
}

function checkNEL(value) {
  if (!value) return { status: 'pass', detail: '未设置', recommendation: '' };
  return { status: 'pass', detail: value.substring(0, 100), recommendation: '' };
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
  Pragma: checkPragma,
  'Content-Security-Policy-Report-Only': checkCSPReportOnly,
  'Clear-Site-Data': checkClearSiteData,
  'X-Robots-Tag': checkXRobots,
  'X-Permitted-Cross-Domain-Policies': checkXPCD,
  'X-Download-Options': checkXPCD,
  'Report-To': checkReportTo,
  NEL: checkNEL,
};

// ====== Info leak detection ======

var SERVER_SIGNATURES = [
  'apache',
  'nginx',
  'iis',
  'tomcat',
  'express',
  'openresty',
  'caddy',
  'liteSpeed',
  'cloudflare',
  'microsoft',
  'jetty',
  'weblogic',
  'websphere',
];
var FRAMEWORK_SIGNATURES = [
  'php',
  'asp.net',
  'django',
  'rails',
  'spring',
  'laravel',
  'next.js',
  'nuxt',
  'struts',
];

function detectInfoLeaks(parsedHeaders) {
  var leaks = [];
  var serverVal = parsedHeaders['server'] || '';
  if (serverVal) {
    var serverLower = serverVal.toLowerCase();
    var detected = [];
    for (var i = 0; i < SERVER_SIGNATURES.length; i++) {
      if (serverLower.indexOf(SERVER_SIGNATURES[i]) !== -1) detected.push(SERVER_SIGNATURES[i]);
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

function groupByCategory(results) {
  var groups = {};
  for (var i = 0; i < results.length; i++) {
    var r = results[i];
    var cat = r.category || 'other';
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(r);
  }
  return groups;
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
    var analysis = analyzeHeaders(parsed);

    var infoLeaks = detectInfoLeaks(parsed);

    var cookieResp = await fetchWithCookies(url);
    var cookieHeaders = cookieResp ? parseHeaders(cookieResp) : {};
    var setCookies = parseSetCookies(cookieHeaders);
    var cookieAnalysis = analyzeCookieSecurity(setCookies);

    lastAnalysisResult = {
      url: url,
      analysis: analysis,
      infoLeaks: infoLeaks,
      cookieAnalysis: cookieAnalysis,
      grouped: groupByCategory(analysis.results),
    };
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
  if (lastAnalysisResult) renderHeadersResults(lastAnalysisResult.analysis);
}

function setSearch(query) {
  currentSearch = (query || '').toLowerCase();
  if (lastAnalysisResult) renderHeadersResults(lastAnalysisResult.analysis);
}

function applyHeaderFilter(result) {
  var f = currentFilter;
  if (f === 'missing' && result.status !== 'miss') return false;
  if (f === 'warn' && result.status !== 'warn') return false;
  if (f === 'pass' && result.status !== 'pass') return false;
  var q = currentSearch;
  if (q) {
    var text = (
      (result.name || '') +
      ' ' +
      (result.detail || '') +
      ' ' +
      (result.recommendation || '')
    ).toLowerCase();
    return text.indexOf(q) !== -1;
  }
  return true;
}

// ====== Render ======

var CATEGORY_ICONS = {
  security:
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
  privacy:
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
  'cross-origin':
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
  caching:
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>',
  legacy:
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
  monitoring:
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
};

var STATUS_ICONS = {
  pass: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#27ae60" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
  warn: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#f39c12" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  miss: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#e74c3c" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
};

function renderHeadersResults(analysis) {
  var container = utils.get('headers-results');
  var scoreContainer = utils.get('headers-score-container');
  var gradeEl = utils.get('headers-grade');
  var scoreRing = utils.get('headers-score-ring');
  var scoreText = utils.get('headers-score-text');
  var summaryEl = utils.get('headers-summary');
  var exportBtn = utils.get('headers-export-btn');

  if (!container || !analysis) return;

  scoreContainer.hidden = false;

  var gradeClass = 'grade-' + analysis.grade.toLowerCase();
  gradeEl.className = 'headers-grade ' + gradeClass;
  gradeEl.textContent = analysis.grade;

  scoreText.textContent = analysis.score;

  var circumference = 2 * Math.PI * 54;
  var offset = circumference - (analysis.score / 100) * circumference;
  scoreRing.style.strokeDashoffset = String(offset);
  scoreRing.classList.remove('score-high', 'score-medium', 'score-low');
  scoreRing.classList.add(
    analysis.score >= 75 ? 'score-high' : analysis.score >= 50 ? 'score-medium' : 'score-low'
  );

  summaryEl.innerHTML =
    '<span class="stat-badge stat-found">通过 ' +
    analysis.passed +
    '</span> ' +
    '<span class="stat-badge stat-warn">警告 ' +
    analysis.warning +
    '</span> ' +
    '<span class="stat-badge stat-vuln">缺失 ' +
    analysis.missing +
    '</span>';

  var filtered = analysis.results.filter(applyHeaderFilter);
  var grouped = groupByCategory(filtered);

  var html = '';
  var catOrder = ['security', 'privacy', 'cross-origin', 'caching', 'legacy', 'monitoring'];
  for (var c = 0; c < catOrder.length; c++) {
    var cat = catOrder[c];
    var items = grouped[cat];
    if (!items || items.length === 0) continue;
    html += '<div class="headers-category">';
    html +=
      '<div class="headers-category-title">' +
      (CATEGORY_ICONS[cat] || '') +
      ' ' +
      utils.escapeHtml(CATEGORY_LABELS[cat] || cat) +
      '</div>';
    for (var i = 0; i < items.length; i++) {
      var r = items[i];
      html += '<div class="headers-result-card">';
      html += '<div class="headers-result-row">';
      html +=
        '<span class="headers-status-icon">' +
        (STATUS_ICONS[r.status] || STATUS_ICONS.miss) +
        '</span>';
      html += '<span class="headers-header-name">' + utils.escapeHtml(r.name) + '</span>';
      html += '</div>';
      html +=
        '<div class="headers-header-value" data-truncate="true">' +
        utils.escapeHtml(r.detail || '-') +
        '</div>';
      if (r.recommendation) {
        html += '<div class="headers-header-rec">' + utils.escapeHtml(r.recommendation) + '</div>';
      }
      html += '</div>';
    }
    html += '</div>';
  }

  if (
    lastAnalysisResult &&
    lastAnalysisResult.infoLeaks &&
    lastAnalysisResult.infoLeaks.length > 0
  ) {
    html += '<div class="headers-category">';
    html +=
      '<div class="headers-category-title headers-category-infoleak">' +
      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/></svg> 信息泄露</div>';
    for (var li = 0; li < lastAnalysisResult.infoLeaks.length; li++) {
      var leak = lastAnalysisResult.infoLeaks[li];
      html += '<div class="headers-result-card headers-infoleak-card">';
      html += '<div class="headers-result-row">';
      html += '<span class="headers-status-icon">' + STATUS_ICONS.warn + '</span>';
      html += '<span class="headers-header-name">' + utils.escapeHtml(leak.name) + '</span>';
      html += '</div>';
      html += '<div class="headers-header-value">' + utils.escapeHtml(leak.detail) + '</div>';
      html += '<div class="headers-header-rec">' + utils.escapeHtml(leak.info) + '</div>';
      html += '</div>';
    }
    html += '</div>';
  }

  if (
    lastAnalysisResult &&
    lastAnalysisResult.cookieAnalysis &&
    lastAnalysisResult.cookieAnalysis.length > 0
  ) {
    html += '<div class="headers-category">';
    html +=
      '<div class="headers-category-title headers-category-cookie">' +
      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> Cookie 安全</div>';
    for (var ci = 0; ci < lastAnalysisResult.cookieAnalysis.length; ci++) {
      var cf = lastAnalysisResult.cookieAnalysis[ci];
      html += '<div class="headers-result-card">';
      html += '<div class="headers-cookie-name">' + utils.escapeHtml(cf.name) + '</div>';
      html += '<div class="headers-cookie-flags">';
      for (var fi = 0; fi < cf.issues.length; fi++) {
        html +=
          '<span class="headers-cookie-flag warn">' + utils.escapeHtml(cf.issues[fi]) + '</span>';
      }
      if (cf.flags.secure) html += '<span class="headers-cookie-flag pass">Secure</span>';
      if (cf.flags.httponly) html += '<span class="headers-cookie-flag pass">HttpOnly</span>';
      if (cf.flags.samesite) {
        html +=
          '<span class="headers-cookie-flag pass">SameSite=' +
          utils.escapeHtml(cf.flags.samesite) +
          '</span>';
      }
      html += '</div></div>';
    }
    html += '</div>';
  }

  if (!html) {
    html = '<div class="empty-state">无匹配结果</div>';
  }

  container.innerHTML = html;
  if (exportBtn) exportBtn.hidden = false;
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

  findings.sort(function (a, b) {
    var order = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    return (order[b.severity] || 0) - (order[a.severity] || 0);
  });
  return findings;
}

export {
  lastAnalysisResult,
  scanning,
  scanSecurityHeaders,
  renderHeadersResults,
  exportHeadersResults,
  getFindings,
  setFilter,
  setSearch,
};
