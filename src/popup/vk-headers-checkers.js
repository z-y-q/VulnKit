// vk-headers-checkers.js -- 灵眸 Chrome Extension
// Pure header checker functions — no shared state, no DOM

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

export {
  parseCSP,
  checkCSP,
  HEADER_CHECKERS,
  checkHSTS,
  checkXFO,
  checkXCTO,
  checkXXP,
  checkRP,
  checkPP,
  checkCOOP,
  checkCORP,
  checkCOEP,
  checkCC,
  checkPragma,
  checkCSPReportOnly,
  checkClearSiteData,
  checkXRobots,
  checkXPCD,
  checkReportTo,
  checkNEL,
};
