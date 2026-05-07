// 灵眸 - CORS Configuration Detection
window.VulnKitCors = (function () {
  'use strict';

  var utils = window.VulnKitUtils.utilsProxy;
  var lastResult = null;
  var scanAborted = false;
  var scanActive = false;

  var PROBE_TIMEOUT_MS = 10000;

  var ORIGIN_VARIANTS = [
    { value: 'https://evil.example.com', label: '恶意子域' },
    { value: 'null', label: 'Null Origin' },
    { value: 'https://evil.com', label: '跨域恶意' },
  ];

  var METHOD_VARIANTS = ['GET', 'POST', 'PUT', 'DELETE'];

  var DEFAULT_ENDPOINTS = [
    { path: '/', label: '根路径' },
    { path: '/api/', label: '/api/' },
    { path: '/api/v1/', label: '/api/v1/' },
    { path: '/graphql', label: '/graphql' },
    { path: '/api/user', label: '/api/user' },
    { path: '/api/config', label: '/api/config' },
  ];

  function getAllEndpoints() {
    var customInput = utils.get('cors-custom-endpoint');
    var customVal = customInput ? customInput.value.trim() : '';
    var endpoints = DEFAULT_ENDPOINTS.slice();
    if (customVal) {
      var parts = customVal.split(',').map(function (s) {
        return s.trim().replace(/^\//, '');
      });
      parts.forEach(function (p) {
        if (p && !endpoints.some(function (e) { return e.path === '/' + p; })) {
          endpoints.push({ path: '/' + p, label: '/' + p });
        }
      });
    }
    return endpoints;
  }

  function getSelectedOrigins() {
    var customInput = utils.get('cors-custom-origin');
    var origins = ORIGIN_VARIANTS.slice();
    var customVal = customInput ? customInput.value.trim() : '';
    if (customVal) {
      origins.push({ value: customVal, label: customVal });
    }
    return origins;
  }

  function sendCorsProbe(url, method, origin, timeoutMs) {
    return new Promise(function (resolve) {
      var timer = setTimeout(function () {
        resolve({ error: 'timeout' });
      }, timeoutMs || PROBE_TIMEOUT_MS);

      var headers = { Origin: origin };
      if (origin !== 'null') {
        headers['X-Requested-With'] = 'XMLHttpRequest';
      }

      chrome.runtime.sendMessage(
        {
          type: 'FETCH_CORS_PROBE',
          url: url,
          method: method || 'GET',
          headers: headers,
          timeout: timeoutMs || PROBE_TIMEOUT_MS,
        },
        function (resp) {
          clearTimeout(timer);
          if (chrome.runtime.lastError) {
            resolve({ error: chrome.runtime.lastError.message });
            return;
          }
          resolve(resp || { error: 'no response' });
        }
      );
    });
  }

  async function scanCors() {
    if (scanActive) {
      scanAborted = true;
      return;
    }

    var statusEl = utils.get('cors-status');
    var resultsEl = utils.get('cors-results');
    var copyBtn = utils.get('cors-copy-btn');
    var scanBtn = utils.get('cors-scan-btn');

    if (statusEl) statusEl.textContent = '正在检测 CORS 配置...';
    if (resultsEl) resultsEl.innerHTML = '';
    scanAborted = false;
    scanActive = true;
    if (scanBtn) scanBtn.textContent = '停止检测';
    if (copyBtn) copyBtn.style.display = 'none';

    try {
      var tab = await utils.requireTabId();
      if (!tab || !/^https?:/.test(tab.url)) {
        if (statusEl) statusEl.textContent = '请打开一个网页';
        return;
      }

      var baseUrl = new URL(tab.url).origin;
      var endpoints = getAllEndpoints();
      var origins = getSelectedOrigins();

      var totalTasks = endpoints.length * origins.length + endpoints.length;
      var completed = 0;
      var allResults = [];
      var errors = [];

      for (var ei = 0; ei < endpoints.length; ei++) {
        if (scanAborted) break;
        var ep = endpoints[ei];
        var epUrl = baseUrl + ep.path;

        for (var oi = 0; oi < origins.length; oi++) {
          if (scanAborted) break;
          var origin = origins[oi];

          var resp = await sendCorsProbe(epUrl, 'GET', origin.value);
          completed++;
          if (statusEl) {
            statusEl.textContent = '检测中... (' + completed + '/' + totalTasks + ')';
          }

          if (resp && resp.error) {
            if (resp.error !== 'timeout') {
              errors.push({ url: epUrl, origin: origin.value, error: resp.error });
            }
            continue;
          }

          allResults.push({
            endpoint: ep,
            url: epUrl,
            origin: origin,
            method: 'GET',
            response: resp,
          });
        }

        if (scanAborted) break;

        var optionsResp = await sendCorsProbe(epUrl, 'OPTIONS', origins[0].value);
        completed++;
        if (statusEl) {
          statusEl.textContent = '检测中... (' + completed + '/' + totalTasks + ')';
        }
        if (!optionsResp || optionsResp.error) continue;

        allResults.push({
          endpoint: ep,
          url: epUrl,
          origin: origins[0],
          method: 'OPTIONS',
          response: optionsResp,
        });
      }

      if (!scanAborted) {
        var analysis = analyzeResults(allResults);
        analysis.errors = errors;
        lastResult = analysis;
        renderResults(analysis);
        if (statusEl) {
          statusEl.textContent = '检测完成: ' + completed + ' 个请求' +
            (errors.length > 0 ? '，' + errors.length + ' 个失败' : '');
        }
        if (copyBtn) copyBtn.style.display = '';
      } else {
        if (statusEl) statusEl.textContent = '检测已取消';
      }
    } catch (e) {
      if (statusEl) statusEl.textContent = '检测失败: ' + e.message;
    } finally {
      scanActive = false;
      if (scanBtn) scanBtn.textContent = 'CORS 配置检测';
    }
  }

  function analyzeResults(results) {
    var issues = [];
    var safeCount = 0;

    results.forEach(function (r) {
      var headers = r.response.headers || {};
      var acao = headers['access-control-allow-origin'] || '';
      var acac = headers['access-control-allow-credentials'] || '';
      var acam = headers['access-control-allow-methods'] || '';
      var acah = headers['access-control-allow-headers'] || '';
      var acae = headers['access-control-expose-headers'] || '';
      var acma = headers['access-control-max-age'] || '';

      var severity = 'safe';
      var findings = [];
      var isOptions = r.method === 'OPTIONS';

      // Opaque response (no-cors) — server didn't reflect our Origin
      if (r.response.type === 'opaque' && !acao) {
        findings.push('服务器未返回 CORS 头 (安全)');
        safeCount++;
        issues.push({
          endpoint: r.endpoint,
          url: r.url,
          origin: r.origin,
          method: r.method,
          acao: '',
          acac: '',
          acam: '',
          acah: '',
          acae: '',
          acma: '',
          severity: 'safe',
          findings: findings,
          statusCode: r.response.status || 0,
        });
        return;
      }

      if (!acao) {
        severity = 'safe';
        findings.push('未设置 Access-Control-Allow-Origin');
        safeCount++;
      } else if (acao === '*') {
        severity = 'warning';
        findings.push('ACAO: * (任意来源可访问)');
        if (acac && acac.toLowerCase() === 'true') {
          severity = 'critical';
          findings.push('Allow-Credentials: true + Origin: * — 浏览器会拒绝此配置');
        }
      } else if (acao === r.origin.value) {
        severity = 'danger';
        findings.push('Origin 被反射: ' + acao);
        if (acac && acac.toLowerCase() === 'true') {
          severity = 'critical';
          findings.push('Allow-Credentials: true + Origin 反射 — 可跨站窃取数据');
        }
        if (r.origin.value === 'null') {
          findings.push('Null Origin 被信任 — sandbox/iframe 可利用');
        }
        findings.push('恶意 Origin 被信任，可能导致 CSRF/数据泄露');
      } else {
        severity = 'warning';
        findings.push('ACAO: ' + acao + ' (非反射)');
      }

      if (acam && isOptions) {
        findings.push('预检允许方法: ' + acam);
      }
      if (acah && isOptions) {
        findings.push('预检允许头: ' + acah);
      }
      if (acae) {
        findings.push('暴露头: ' + acae);
      }
      if (acma) {
        findings.push('预检缓存: ' + acma + 's');
      }
      if (isOptions && !acam && acao) {
        findings.push('预检响应缺少 Allow-Methods');
      }

      issues.push({
        endpoint: r.endpoint,
        url: r.url,
        origin: r.origin,
        method: r.method,
        acao: acao,
        acac: acac,
        acam: acam,
        acah: acah,
        acae: acae,
        acma: acma,
        severity: severity,
        findings: findings,
        statusCode: r.response.status,
      });
    });

    return { issues: issues, safeCount: safeCount, total: results.length, errors: [] };
  }

  function renderResults(analysis) {
    var resultsEl = utils.get('cors-results');
    if (!resultsEl) return;

    var dangerItems = analysis.issues.filter(function (i) {
      return i.severity !== 'safe';
    });

    var html = '<div class="cors-summary">';
    html += '<strong>扫描结果:</strong> 共 ' + analysis.total + ' 个请求，';
    html += '<span style="color:#27ae60">' + analysis.safeCount + ' 安全</span>，';
    html += '<span style="color:#e74c3c">' + dangerItems.length + ' 存在风险</span>';
    if (analysis.errors && analysis.errors.length > 0) {
      html += '，<span style="color:#f39c12">' + analysis.errors.length + ' 请求失败</span>';
    }
    html += '</div>';

    if (analysis.errors && analysis.errors.length > 0) {
      html += '<div class="cors-error-info" style="color:#f39c12;font-size:11px;margin:4px 0 8px;padding:6px 8px;background:rgba(243,156,18,0.1);border-radius:4px">';
      html += '部分请求失败 (网络错误/CORS 阻止)。跨域探测需要目标服务器响应不同 Origin 的请求。';
      html += '</div>';
    }

    analysis.issues.forEach(function (issue) {
      html += '<div class="cors-endpoint-card">';
      html += '<div class="cors-endpoint-header">';
      html +=
        '<span class="cors-severity-badge ' +
        issue.severity +
        '">' +
        severityLabel(issue.severity) +
        '</span>';
      html += '<span class="cors-endpoint-url">' + utils.escapeHtml(issue.url) + '</span>';
      html += '<span class="cors-method-tag">' + issue.method + '</span>';
      html +=
        '<span class="cors-origin-tag">Origin: ' + utils.escapeHtml(issue.origin.value) + '</span>';
      html += '</div>';

      issue.findings.forEach(function (f) {
        html +=
          '<div class="cors-detail-row"><span class="cors-detail-value">' +
          utils.escapeHtml(f) +
          '</span></div>';
      });

      html +=
        '<div class="cors-detail-row"><span class="cors-detail-label">HTTP 状态</span><span class="cors-detail-value">' +
        issue.statusCode +
        '</span></div>';
      if (issue.acae) {
        html +=
          '<div class="cors-detail-row"><span class="cors-detail-label">暴露头</span><span class="cors-detail-value">' +
          utils.escapeHtml(issue.acae) +
          '</span></div>';
      }
      if (issue.acma) {
        html +=
          '<div class="cors-detail-row"><span class="cors-detail-label">预检缓存</span><span class="cors-detail-value">' +
          issue.acma +
          's</span></div>';
      }
      html += '</div>';
    });

    resultsEl.innerHTML = html;
  }

  function severityLabel(sev) {
    var labels = { safe: '安全', warning: '警告', danger: '危险', critical: '严重' };
    return labels[sev] || sev;
  }

  function copyResults() {
    if (!lastResult) {
      utils.showToast('没有检测结果', 'warning');
      return;
    }
    var lines = ['CORS Scan Results', '=================='];
    lines.push(
      'Total: ' +
        lastResult.total +
        ' | Safe: ' +
        lastResult.safeCount +
        ' | Issues: ' +
        (lastResult.total - lastResult.safeCount)
    );
    lines.push('');
    lastResult.issues.forEach(function (issue) {
      lines.push(
        '[' +
          issue.severity.toUpperCase() +
          '] ' +
          issue.method +
          ' ' +
          issue.url +
          ' (HTTP ' +
          issue.statusCode +
          ') Origin: ' +
          issue.origin.value
      );
      if (issue.acao) lines.push('  ACAO: ' + issue.acao);
      if (issue.acac) lines.push('  ACAC: ' + issue.acac);
      if (issue.acam) lines.push('  ACAM: ' + issue.acam);
      if (issue.acah) lines.push('  ACAH: ' + issue.acah);
      issue.findings.forEach(function (f) {
        lines.push('  - ' + f);
      });
      lines.push('');
    });
    utils.copyAndToast(lines.join('\n'));
  }

  function exportJson() {
    if (!lastResult) {
      utils.showToast('没有检测结果', 'warning');
      return;
    }
    var data = lastResult.issues.map(function (issue) {
      return {
        url: issue.url,
        method: issue.method,
        origin: issue.origin.value,
        status: issue.statusCode,
        severity: issue.severity,
        headers: {
          'access-control-allow-origin': issue.acao,
          'access-control-allow-credentials': issue.acac,
          'access-control-allow-methods': issue.acam,
          'access-control-allow-headers': issue.acah,
          'access-control-expose-headers': issue.acae,
          'access-control-max-age': issue.acma,
        },
        findings: issue.findings,
      };
    });
    var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'cors-results.json';
    a.click();
    URL.revokeObjectURL(url);
  }

  return {
    scanCors: scanCors,
    copyResults: copyResults,
    exportJson: exportJson,
    get lastResult() {
      return lastResult;
    },
  };
})();
