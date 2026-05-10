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
];

var PROTOCOL_VARIANTS = [
  'https://example.com',
  '//evil.com',
  '/\\/evil.com',
  'https://evil.com',
];

var TEST_DOMAIN = 'example.com';

var redirectState = {
  scanning: false,
  aborted: false,
  results: [],
  lastResults: null,
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
    chrome.runtime.sendMessage({ type: 'FETCH_PROBE', url: testUrl }, function (resp) {
      if (chrome.runtime.lastError) {
        resolve({ status: 0, headers: {}, body: '' });
        return;
      }
      resolve(resp || { status: 0, headers: {}, body: '' });
    });
  });
}

function isRedirectVulnerable(response, variant) {
  if (!response) return false;

  var status = response.status || 0;
  if (status >= 300 && status < 400) {
    var location = '';
    var headers = response.headers || {};
    if (Array.isArray(headers)) {
      for (var i = 0; i < headers.length; i++) {
        if (headers[i].name && headers[i].name.toLowerCase() === 'location') {
          location = headers[i].value || '';
          break;
        }
      }
    } else if (typeof headers === 'object') {
      location = headers['location'] || headers['Location'] || '';
    }
    if (location.indexOf(TEST_DOMAIN) !== -1 || location.indexOf('evil.com') !== -1) {
      return true;
    }
  }

  var body = response.body || response.responseText || '';
  if (body.indexOf('evil.com') !== -1 || body.indexOf(TEST_DOMAIN) !== -1) {
    if (body.indexOf('http-equiv="refresh"') !== -1 || body.indexOf('location.replace') !== -1 || body.indexOf('location.href') !== -1 || body.indexOf('location =') !== -1) {
      return true;
    }
  }

  return false;
}

async function scanRedirects(baseUrl, onProgress) {
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

    for (var i = 0; i < tests.length; i++) {
      if (redirectState.aborted) break;

      var test = tests[i];
      var response;
      try {
        response = await probeRedirect(test.url);
      } catch (e) {
        errors.push(Object.assign({}, test, { error: e.message }));
        completed++;
        if (onProgress) onProgress({ completed: completed, total: total, vulnerable: vulnerable.length, safe: safe.length });
        continue;
      }

      var isVuln = isRedirectVulnerable(response, test.variant);
      if (isVuln) {
        var vulnEntry = {
          param: test.param,
          variant: test.variant,
          url: test.url,
          status: response.status || 0,
          location: '',
        };
        var respHeaders = response.headers || {};
        if (Array.isArray(respHeaders)) {
          for (var h = 0; h < respHeaders.length; h++) {
            if (respHeaders[h].name && respHeaders[h].name.toLowerCase() === 'location') {
              vulnEntry.location = respHeaders[h].value || '';
              break;
            }
          }
        } else if (typeof respHeaders === 'object') {
          vulnEntry.location = respHeaders['location'] || respHeaders['Location'] || '';
        }
        vulnerable.push(vulnEntry);
        redirectState.results.push(Object.assign({}, vulnEntry, { type: 'vulnerable' }));
      } else {
        safe.push({ param: test.param, variant: test.variant });
        redirectState.results.push(Object.assign({}, test, { type: 'safe', status: response.status || 0 }));
      }

      completed++;
      if (onProgress) onProgress({ completed: completed, total: total, vulnerable: vulnerable.length, safe: safe.length });
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

function renderRedirectResults(result) {
  var container = utils.get('redirect-results');
  var statsEl = utils.get('redirect-stats');
  var exportBtn = utils.get('redirect-export-btn');

  if (!container || !result) return;

  if (statsEl) {
    statsEl.style.display = 'flex';
    statsEl.innerHTML =
      '<span>总计: ' + result.total + '</span>' +
      '<span class="stat-badge stat-vuln">可利用: ' + result.vulnerable.length + '</span>' +
      '<span class="stat-badge stat-safe">安全: ' + result.safe.length + '</span>' +
      (result.errors.length > 0 ? '<span class="stat-badge stat-error">错误: ' + result.errors.length + '</span>' : '');
  }

  var html = '';
  var seenParams = {};
  for (var i = 0; i < result.vulnerable.length; i++) {
    var v = result.vulnerable[i];
    if (seenParams[v.param]) continue;
    seenParams[v.param] = true;
    html += '<div class="redirect-item">';
    html += '<div><span class="redirect-param">' + utils.escapeHtml(v.param) + '</span>';
    html += '<span class="redirect-status vulnerable">可利用</span></div>';
    html += '<div class="redirect-payload">' + utils.escapeHtml(v.url) + '</div>';
    if (v.location) {
      html += '<div class="redirect-payload">Location: ' + utils.escapeHtml(v.location) + '</div>';
    }
    html += '</div>';
  }

  if (result.vulnerable.length === 0) {
    html += '<div class="empty-state">未发现开放重定向漏洞</div>';
  }

  container.innerHTML = html;
  if (exportBtn) exportBtn.style.display = '';
}

function exportRedirectResults() {
  if (!redirectState.lastResults) return;
  var r = redirectState.lastResults;
  var lines = ['开放重定向检测报告', '=', '目标: ' + r.url, '可利用: ' + r.vulnerable.length + ' | 安全: ' + r.safe.length + ' | 错误: ' + r.errors.length, ''];
  for (var i = 0; i < r.vulnerable.length; i++) {
    var v = r.vulnerable[i];
    lines.push('[可利用] ' + v.param + ' -> ' + v.url);
    if (v.location) lines.push('  Location: ' + v.location);
  }
  utils.downloadBlob(new Blob([lines.join('\n')], { type: 'text/plain' }), 'redirect-scan-' + Date.now() + '.txt');
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

export { redirectState, scanRedirects, stopRedirectScan, renderRedirectResults, exportRedirectResults, getFindings };
