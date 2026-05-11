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

var RISK_ORDER = { safe: 0, low: 1, medium: 2, high: 3 };

function buildScriptSrcChecks(addBypass) {
  return [
    {
      check: function (v) {
        return v.indexOf("'unsafe-inline'") !== -1;
      },
      risk: 'high',
      issue: '允许内联脚本执行（unsafe-inline）',
      bypass: {
        type: 'xss-inline',
        desc: '直接注入 <script>alert(1)</script> 即可执行 XSS',
        severity: 'high',
      },
    },
    {
      check: function (v) {
        return v.indexOf("'unsafe-eval'") !== -1;
      },
      risk: 'high',
      issue: '允许 eval() 执行（unsafe-eval）',
      bypass: {
        type: 'eval-injection',
        desc: '通过 eval() / Function() 动态执行任意代码',
        severity: 'high',
      },
    },
    {
      check: function (v) {
        return v.indexOf('data:') !== -1;
      },
      risk: 'medium',
      issue: '允许 data: URI 加载脚本',
      bypass: {
        type: 'data-uri-script',
        desc: '通过 <script src="data:text/javascript,..."> 注入脚本',
        severity: 'medium',
      },
    },
  ];
}

function buildOtherDirectiveChecks() {
  return {
    'default-src': [
      {
        check: function (v) {
          return v.indexOf('*') !== -1;
        },
        risk: 'high',
        issue: '通配符 * 允许任意来源',
        bypass: {
          type: 'wildcard-default',
          desc: 'default-src * 几乎使所有 CSP 保护失效',
          severity: 'high',
        },
      },
    ],
    'style-src': [
      {
        check: function (v) {
          return v.indexOf("'unsafe-inline'") !== -1;
        },
        risk: 'low',
        issue: '允许内联样式（CSS 注入可窃取数据）',
        bypass: {
          type: 'css-exfil',
          desc: '通过 CSS 注入窃取 CSRF token 等敏感属性值',
          severity: 'low',
        },
      },
    ],
    'img-src': [
      {
        check: function (v) {
          return v.indexOf('*') !== -1 || v.indexOf('data:') !== -1;
        },
        risk: 'low',
        issue: 'img-src 限制宽松（可探测内网）',
        bypass: {
          type: 'ssrf-img',
          desc: '通过 <img src="http://192.168.x.x/"> 探测内网服务',
          severity: 'low',
        },
      },
    ],
    'connect-src': [
      {
        check: function (v) {
          return v.indexOf('*') !== -1;
        },
        risk: 'high',
        issue: 'connect-src 允许任意目标（数据外泄）',
        bypass: {
          type: 'data-exfil',
          desc: '通过 fetch/WebSocket 将数据发送到任意域名',
          severity: 'high',
        },
      },
    ],
  };
}

function buildMissingChecks() {
  return [
    {
      directive: 'base-uri',
      impact: '缺失 base-uri 允许攻击者注入 <base href="https://evil.com"> 劫持相对路径资源加载',
      severity: 'medium',
      bypassType: 'base-hijack',
      bypassDesc: '注入 <base href="https://evil.com"> 劫持所有相对路径资源',
    },
    {
      directive: 'object-src',
      impact: "缺失 object-src（默认非 'none'）允许加载 Flash/Java applet 等插件",
      severity: 'medium',
    },
    {
      directive: 'form-action',
      impact: '缺失 form-action 允许表单提交到任意 URL（钓鱼攻击）',
      severity: 'medium',
      bypassType: 'form-phish',
      bypassDesc: '表单数据可被引导提交到钓鱼站点',
    },
    {
      directive: 'frame-ancestors',
      impact: '缺失 frame-ancestors 允许页面被 iframe 嵌套（点击劫持）',
      severity: 'medium',
      bypassType: 'clickjack',
      bypassDesc: '页面可被嵌入恶意 iframe 进行点击劫持攻击',
    },
    {
      directive: 'upgrade-insecure-requests',
      impact: '缺失 upgrade-insecure-requests 存在混合内容风险',
      severity: 'low',
    },
  ];
}

function buildSummary(bypasses, missingCritical) {
  var parts = [];
  var highCount = 0;
  var medCount = 0;
  for (var i = 0; i < bypasses.length; i++) {
    if (bypasses[i].severity === 'high') highCount++;
    else if (bypasses[i].severity === 'medium') medCount++;
  }
  if (highCount > 0) parts.push('高危绕过 ' + highCount + ' 项');
  if (medCount > 0) parts.push('中危绕过 ' + medCount + ' 项');
  if (missingCritical.length > 0) parts.push('缺失指令 ' + missingCritical.length + ' 项');
  if (parts.length === 0) parts.push('CSP 配置良好');
  return parts.join('，');
}

function analyzeDirectiveValues(directives, name, values, riskIssues, addBypass) {
  var result = { values: values, risk: 'safe', issues: [] };
  for (var i = 0; i < riskIssues.length; i++) {
    var item = riskIssues[i];
    if (item.check(values)) {
      result.issues.push(item.issue);
      if ((RISK_ORDER[item.risk] || 0) > (RISK_ORDER[result.risk] || 0)) {
        result.risk = item.risk;
      }
      if (item.bypass) addBypass(item.bypass.type, item.bypass.desc, item.bypass.severity);
    }
  }
  directives[name] = result;
}

function checkScriptDomainSources(scriptSrc, directives, addBypass) {
  var domainValues = scriptSrc.filter(function (v) {
    return !v.startsWith("'") && v !== 'data:' && v !== '*' && v.indexOf('blob:') !== 0;
  });
  if (domainValues.length === 0) return;
  if (directives['script-src'].risk === 'safe') directives['script-src'].risk = 'medium';
  directives['script-src'].issues.push('允许加载外部域名脚本: ' + domainValues.join(', '));
  addBypass(
    'domain-takeover',
    '攻陷 ' + domainValues[0] + ' 后可注入恶意脚本到该域名，CSP 自动放行',
    'medium'
  );
}

function checkMissingDirectives(d, addBypass) {
  var missingCritical = [];
  var checks = buildMissingChecks();
  for (var i = 0; i < checks.length; i++) {
    var item = checks[i];
    if (!d[item.directive]) {
      missingCritical.push({
        directive: item.directive,
        impact: item.impact,
        severity: item.severity,
      });
      if (item.bypassType) addBypass(item.bypassType, item.bypassDesc, item.severity);
    }
  }
  return missingCritical;
}

function deepAnalyzeCSP(cspValue) {
  if (!cspValue) {
    return {
      directives: {},
      bypasses: [],
      missingCritical: [
        {
          directive: 'Content-Security-Policy',
          impact: '未设置 CSP，页面完全不受内容安全策略保护',
          severity: 'high',
        },
      ],
      summary: '未设置 Content-Security-Policy',
    };
  }

  var parsed = parseCSP(cspValue);
  var d = parsed.directives;
  var fallbackSrc = d['default-src'] ? d['default-src'] : [];
  var scriptSrc = d['script-src'] ? d['script-src'] : fallbackSrc;
  var styleSrc = d['style-src'] ? d['style-src'] : fallbackSrc;
  var imgSrc = d['img-src'] ? d['img-src'] : fallbackSrc;
  var connectSrc = d['connect-src'] ? d['connect-src'] : fallbackSrc;

  var directives = {};
  var bypasses = [];
  var bypassTypes = {};

  function addBypass(type, description, severity) {
    if (!bypassTypes[type]) {
      bypassTypes[type] = true;
      bypasses.push({ type: type, description: description, severity: severity });
    }
  }

  analyzeDirectiveValues(
    directives,
    'script-src',
    scriptSrc,
    buildScriptSrcChecks(addBypass),
    addBypass
  );
  checkScriptDomainSources(scriptSrc, directives, addBypass);

  var otherChecks = buildOtherDirectiveChecks();
  var otherMap = {
    'default-src': fallbackSrc,
    'style-src': styleSrc,
    'img-src': imgSrc,
    'connect-src': connectSrc,
  };
  var otherNames = ['default-src', 'style-src', 'img-src', 'connect-src'];
  for (var i = 0; i < otherNames.length; i++) {
    var name = otherNames[i];
    analyzeDirectiveValues(directives, name, otherMap[name], otherChecks[name], addBypass);
  }

  var missingCritical = checkMissingDirectives(d, addBypass);

  return {
    directives: directives,
    bypasses: bypasses,
    missingCritical: missingCritical,
    summary: buildSummary(bypasses, missingCritical),
  };
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
  deepAnalyzeCSP,
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
