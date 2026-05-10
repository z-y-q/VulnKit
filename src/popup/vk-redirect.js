// vk-redirect.js -- 灵眸 Chrome Extension
// Open Redirect vulnerability detection

import { utilsProxy as utils } from './vk-namespace.js';

var REDIRECT_PAYLOADS = [
  { param: 'url', pattern: '?url={URL}' },
  { param: 'redirect', pattern: '?redirect={URL}' },
  { param: 'next', pattern: '?next={URL}' },
  { param: 'return', pattern: '?return={URL}' },
  { param: 'returnUrl', pattern: '?returnUrl={URL}' },
  { param: 'dest', pattern: '?dest={URL}' },
  { param: 'destination', pattern: '?destination={URL}' },
  { param: 'rurl', pattern: '?rurl={URL}' },
  { param: 'redir', pattern: '?redir={URL}' },
  { param: 'redirect_uri', pattern: '?redirect_uri={URL}' },
  { param: 'continue', pattern: '?continue={URL}' },
  { param: 'goto', pattern: '?goto={URL}' },
  { param: 'target', pattern: '?target={URL}' },
  { param: 'link', pattern: '?link={URL}' },
  { param: 'callback', pattern: '?callback={URL}' },
  { param: 'forward', pattern: '?forward={URL}' },
  { param: 'out', pattern: '?out={URL}' },
  { param: 'logout', pattern: '?logout={URL}' },
  { param: 'login', pattern: '?login={URL}' },
  { param: 'ref', pattern: '?ref={URL}' },
  { param: 'redirect_url', pattern: '?redirect_url={URL}' },
  { param: 'target_url', pattern: '?target_url={URL}' },
  { param: 'next_url', pattern: '?next_url={URL}' },
  { param: 'redirection', pattern: '?redirection={URL}' },
  { param: 'return_to', pattern: '?return_to={URL}' },
  { param: 'returnPath', pattern: '?returnPath={URL}' },
  { param: 'checkout_url', pattern: '?checkout_url={URL}' },
  { param: 'success_url', pattern: '?success_url={URL}' },
  { param: 'cancel_url', pattern: '?cancel_url={URL}' },
  { param: 'origin', pattern: '?origin={URL}' },
];

var PROTOCOL_VARIANTS = [
  'https://example.com',
  '//evil.com',
  '/\\/evil.com',
  'https://evil.com',
  'https:///evil.com',
  '/evil.com',
  '\\\\evil.com',
  'http://evil.com',
  'https://evil.com%00.example.com',
  'javascript://evil.com',
];

var TEST_DOMAIN = 'example.com';

var redirectState = {
  scanning: false,
  aborted: false,
  results: [],
  lastResults: null,
  currentFilter: 'all',
  currentSearch: '',
};

function buildTestUrls(baseUrl) {
  var tests = [];
  var cleanBase = baseUrl.replace(/[?#].*$/, '');
  for (var p = 0; p < REDIRECT_PAYLOADS.length; p++) {
    var payload = REDIRECT_PAYLOADS[p];
    for (var v = 0; v < PROTOCOL_VARIANTS.length; v++) {
      var variant = PROTOCOL_VARIANTS[v];
      var fullUrl = cleanBase + payload.pattern.replace('{URL}', encodeURIComponent(variant));
      tests.push({
        param: payload.param,
        variant: variant,
        url: fullUrl,
      });
    }
  }
  return tests;
}

function probeRedirect(testUrl) {
  return new Promise(function (resolve) {
    chrome.runtime.sendMessage(
      { type: 'FETCH_PROBE', url: testUrl, includeBody: true },
      function (resp) {
        if (chrome.runtime.lastError) {
          resolve({ status: 0, headers: {}, body: '', time: 0 });
          return;
        }
        resolve(resp || { status: 0, headers: {}, body: '', time: 0 });
      }
    );
  });
}

function extractLocation(headers) {
  if (!headers) return '';
  if (Array.isArray(headers)) {
    for (var i = 0; i < headers.length; i++) {
      if (headers[i].name && headers[i].name.toLowerCase() === 'location') {
        return headers[i].value || '';
      }
    }
    return '';
  }
  if (typeof headers === 'object') {
    return headers['location'] || headers['Location'] || '';
  }
  return '';
}

function isRedirectVulnerable(response, variant) {
  if (!response) return false;

  var status = response.status || 0;

  if (status >= 300 && status < 400) {
    var location = extractLocation(response.headers);
    if (location.indexOf(TEST_DOMAIN) !== -1 || location.indexOf('evil.com') !== -1) {
      return true;
    }
  }

  if (response.redirected && response.url) {
    var finalUrl = response.url;
    if (finalUrl.indexOf('evil.com') !== -1 || finalUrl.indexOf(TEST_DOMAIN) !== -1) {
      return true;
    }
  }

  var body = response.body || response.responseText || '';
  if (body.indexOf('evil.com') !== -1 || body.indexOf(TEST_DOMAIN) !== -1) {
    if (
      body.indexOf('http-equiv="refresh"') !== -1 ||
      body.indexOf('location.replace') !== -1 ||
      body.indexOf('location.href') !== -1 ||
      body.indexOf('location =') !== -1
    ) {
      return true;
    }
  }

  return false;
}

function delay(ms) {
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function scanRedirects(baseUrl, concurrency, onProgress) {
  if (redirectState.scanning) return null;
  redirectState.scanning = true;
  redirectState.aborted = false;
  redirectState.results = [];

  try {
    var tests = buildTestUrls(baseUrl);
    var total = tests.length;
    var completed = 0;
    var vulnerable = [];
    var safe = [];
    var errors = [];
    var batchSize = concurrency || 5;

    for (var i = 0; i < tests.length; i += batchSize) {
      if (redirectState.aborted) break;

      var batch = tests.slice(i, Math.min(i + batchSize, tests.length));
      var promises = [];

      for (var b = 0; b < batch.length; b++) {
        promises.push(
          probeRedirect(batch[b].url).catch(function (e) {
            return { _error: e.message };
          })
        );
      }

      var batchResults = await Promise.all(promises);

      for (var r = 0; r < batchResults.length; r++) {
        var test = batch[r];
        var response = batchResults[r];

        if (response._error) {
          errors.push(Object.assign({}, test, { error: response._error }));
        } else {
          var isVuln = isRedirectVulnerable(response, test.variant);
          if (isVuln) {
            var vulnEntry = {
              param: test.param,
              variant: test.variant,
              url: test.url,
              status: response.status || 0,
              location: extractLocation(response.headers),
            };
            vulnerable.push(vulnEntry);
            redirectState.results.push(Object.assign({}, vulnEntry, { type: 'vulnerable' }));
          } else {
            safe.push({ param: test.param, variant: test.variant, status: response.status || 0 });
            redirectState.results.push(
              Object.assign({}, test, { type: 'safe', status: response.status || 0 })
            );
          }
        }

        completed++;
        if (onProgress) {
          onProgress({
            completed: completed,
            total: total,
            vulnerable: vulnerable.length,
            safe: safe.length,
          });
        }
      }

      if (i + batchSize < tests.length) {
        await delay(150);
      }
    }

    redirectState.lastResults = {
      url: baseUrl,
      vulnerable: vulnerable,
      safe: safe,
      errors: errors,
      total: total,
    };
    return redirectState.lastResults;
  } finally {
    redirectState.scanning = false;
  }
}

function stopRedirectScan() {
  redirectState.aborted = true;
}

var filterSearch = utils.createFilterSearch(
  redirectState,
  'currentFilter',
  'currentSearch',
  renderRedirectResults
);
var setFilter = filterSearch.setFilter;
var setSearch = filterSearch.setSearch;

function applyFilter(item) {
  var f = redirectState.currentFilter;
  if (f === 'vulnerable' && item.type !== 'vulnerable') return false;
  if (f === 'safe' && item.type !== 'safe') return false;
  var q = redirectState.currentSearch;
  if (q) {
    var text = (
      (item.param || '') +
      ' ' +
      (item.variant || '') +
      ' ' +
      (item.url || '') +
      ' ' +
      (item.location || '')
    ).toLowerCase();
    return text.indexOf(q) !== -1;
  }
  return true;
}

import { COPY_SVG } from './vk-icons.js';

var STATUS_LABELS = {
  200: 'OK',
  201: 'Created',
  301: 'Moved',
  302: 'Found',
  303: 'See Other',
  307: 'Temp Redirect',
  308: 'Perm Redirect',
};

function getStatusLabel(code) {
  return STATUS_LABELS[code] || String(code);
}

function renderRedirectResults(result) {
  var container = utils.get('redirect-results');
  var statsEl = utils.get('redirect-stats');
  var exportBtn = utils.get('redirect-export-btn');

  if (!container || !result) return;

  if (statsEl) {
    statsEl.hidden = false;
    statsEl.innerHTML =
      '<span class="stat-badge stat-total">总计 ' +
      result.total +
      '</span> ' +
      '<span class="stat-badge stat-vuln">可利用 ' +
      result.vulnerable.length +
      '</span> ' +
      '<span class="stat-badge stat-safe">安全 ' +
      result.safe.length +
      '</span>' +
      (result.errors.length > 0
        ? ' <span class="stat-badge stat-error">错误 ' + result.errors.length + '</span>'
        : '');
  }

  var filtered = redirectState.results.filter(applyFilter);

  if (filtered.length === 0) {
    container.innerHTML = '<div class="empty-state">无匹配结果</div>';
    if (exportBtn) exportBtn.hidden = false;
    return;
  }

  var html = '';
  var seenParams = {};
  for (var i = 0; i < filtered.length; i++) {
    var item = filtered[i];
    if (item.type === 'vulnerable' && seenParams[item.param]) continue;
    if (item.type === 'vulnerable') seenParams[item.param] = true;

    html += '<div class="redirect-card">';
    html += '<div class="redirect-card-header">';
    html += '<span class="redirect-param">' + utils.escapeHtml(item.param) + '</span>';
    if (item.type === 'vulnerable') {
      html += '<span class="stat-badge stat-vuln">可利用</span>';
    } else {
      html += '<span class="stat-badge stat-safe">安全</span>';
    }
    html += '</div>';
    html +=
      '<div class="redirect-card-variant"><code>' +
      utils.escapeHtml(item.variant) +
      '</code></div>';
    html += '<div class="redirect-card-payload">';
    html += '<span class="redirect-card-url">' + utils.escapeHtml(item.url) + '</span>';
    html +=
      '<button class="redirect-copy-btn" data-copy="' +
      utils.escapeHtml(item.url) +
      '" title="复制 URL">' +
      COPY_SVG +
      '</button>';
    html += '</div>';
    if (item.location) {
      html +=
        '<div class="redirect-card-location">Location: ' +
        utils.escapeHtml(item.location) +
        '</div>';
    }
    html += '</div>';
  }

  container.innerHTML = html;
  if (exportBtn) exportBtn.hidden = false;
}

function exportTxt() {
  if (!redirectState.lastResults) return;
  var r = redirectState.lastResults;
  var lines = [
    '开放重定向检测报告',
    '==================',
    '目标: ' + r.url,
    '可利用: ' + r.vulnerable.length + ' | 安全: ' + r.safe.length + ' | 错误: ' + r.errors.length,
    '',
  ];
  for (var i = 0; i < r.vulnerable.length; i++) {
    var v = r.vulnerable[i];
    lines.push('[可利用] ' + v.param + ' -> ' + v.url);
    if (v.location) lines.push('  Location: ' + v.location);
  }
  utils.downloadBlob(
    new Blob([lines.join('\n')], { type: 'text/plain' }),
    'redirect-scan-' + Date.now() + '.txt'
  );
  utils.showToast('TXT 报告已导出', 'success');
}

function exportCsv() {
  if (!redirectState.lastResults) return;
  var r = redirectState.lastResults;
  var rows = [['Parameter', 'Variant', 'URL', 'Status', 'Location', 'Type']];
  for (var i = 0; i < r.vulnerable.length; i++) {
    var v = r.vulnerable[i];
    rows.push([v.param, v.variant, v.url, v.status, v.location, 'vulnerable']);
  }
  for (var j = 0; j < r.safe.length; j++) {
    var s = r.safe[j];
    rows.push([s.param, s.variant, '', s.status, '', 'safe']);
  }
  for (var k = 0; k < r.errors.length; k++) {
    var e = r.errors[k];
    rows.push([e.param, e.variant, '', 0, e.error || '', 'error']);
  }
  utils.downloadBlob(
    new Blob([utils.buildCsv(rows)], { type: 'text/csv;charset=utf-8' }),
    'redirect-scan-' + Date.now() + '.csv'
  );
  utils.showToast('CSV 报告已导出', 'success');
}

function exportRedirectResults(format) {
  if (format === 'csv') {
    exportCsv();
  } else {
    exportTxt();
  }
}

function getFindings() {
  if (!redirectState.lastResults || !redirectState.lastResults.vulnerable) return [];
  var findings = [];
  var seenParams = {};
  for (var i = 0; i < redirectState.lastResults.vulnerable.length; i++) {
    var v = redirectState.lastResults.vulnerable[i];
    if (seenParams[v.param]) continue;
    seenParams[v.param] = true;
    findings.push({
      severity: 'high',
      title: '开放重定向: ' + v.param + ' 参数',
      detail: 'URL 参数 ' + v.param + ' 可被利用进行开放重定向攻击 | ' + v.url,
      module: 'redirect',
      url: redirectState.lastResults.url || '',
    });
  }
  return findings;
}

export {
  redirectState,
  scanRedirects,
  stopRedirectScan,
  renderRedirectResults,
  exportRedirectResults,
  getFindings,
  setFilter,
  setSearch,
};
