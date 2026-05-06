// 灵眸 - CORS Configuration Detection
window.VulnKitCors = (function () {
  'use strict';

  var utils = window.VulnKitUtils.utilsProxy;
  var lastResult = null;

  var CORS_PROBE_HEADERS = {
    Origin: 'https://evil.example.com',
    'X-Requested-With': 'XMLHttpRequest',
  };

  function scanCors() {
    var statusEl = utils.get('cors-status');
    var resultsEl = utils.get('cors-results');
    var copyBtn = utils.get('cors-copy-btn');

    if (statusEl) statusEl.textContent = '正在检测 CORS 配置...';
    if (resultsEl) resultsEl.innerHTML = '';

    utils.requireTabId().then(function (tab) {
      if (!tab || !/^https?:/.test(tab.url)) {
        if (statusEl) statusEl.textContent = '请打开一个网页';
        return;
      }

      var baseUrl = new URL(tab.url).origin;
      var endpoints = [
        { path: '/', label: '根路径' },
        { path: '/api/', label: '/api/' },
        { path: '/api/v1/', label: '/api/v1/' },
        { path: '/graphql', label: '/graphql' },
        { path: '/api/user', label: '/api/user' },
        { path: '/api/config', label: '/api/config' },
      ];

      var total = endpoints.length;
      var completed = 0;
      var allResults = [];

      endpoints.forEach(function (ep) {
        var probeUrl = baseUrl + ep.path;
        chrome.tabs.sendMessage(
          tab.id,
          {
            type: 'VK_WAF_PROBE',
            url: probeUrl,
            method: 'GET',
            headers: Object.assign({}, CORS_PROBE_HEADERS),
            timeout: 8000,
          },
          function (resp) {
            if (chrome.runtime.lastError) {
              completed++;
              if (completed === total) {
                if (statusEl) statusEl.textContent = '检测失败: 无法连接到页面';
              }
              return;
            }
            completed++;
            if (resp && !resp.error) {
              allResults.push({ endpoint: ep, url: probeUrl, response: resp });
            }

            if (statusEl) statusEl.textContent = '检测中... (' + completed + '/' + total + ')';

            if (completed === total) {
              var analysis = analyzeResults(allResults);
              lastResult = analysis;
              renderResults(analysis);
              if (statusEl) statusEl.textContent = '检测完成: ' + total + ' 个端点';
              if (copyBtn) copyBtn.style.display = '';
            }
          }
        );
      });
    });
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

      var severity = 'safe';
      var findings = [];

      if (!acao) {
        severity = 'safe';
        findings.push('未设置 Access-Control-Allow-Origin (正常)');
        safeCount++;
      } else if (acao === '*') {
        severity = 'warning';
        findings.push('Access-Control-Allow-Origin: * (任意来源可访问)');
        if (acac && acac.toLowerCase() === 'true') {
          severity = 'critical';
          findings.push('Allow-Credentials: true + Origin: * — 危险配置');
        }
      } else if (acao === CORS_PROBE_HEADERS.Origin || acao === 'https://evil.example.com') {
        severity = 'danger';
        findings.push('Origin 被反射: ' + acao);
        if (acac && acac.toLowerCase() === 'true') {
          severity = 'critical';
          findings.push('Allow-Credentials: true + Origin 反射 — 可跨站窃取数据');
        }
        findings.push('恶意 Origin 被信任，可能导致 CSRF/数据泄露');
      } else {
        severity = 'warning';
        findings.push('Access-Control-Allow-Origin: ' + acao);
      }

      if (acam) {
        findings.push('允许方法: ' + acam);
      }
      if (acah) {
        findings.push('允许头: ' + acah);
      }

      issues.push({
        endpoint: r.endpoint,
        url: r.url,
        acao: acao,
        acac: acac,
        acam: acam,
        acah: acah,
        severity: severity,
        findings: findings,
        statusCode: r.response.status,
      });
    });

    return { issues: issues, safeCount: safeCount, total: results.length };
  }

  function renderResults(analysis) {
    var resultsEl = utils.get('cors-results');
    if (!resultsEl) return;

    var dangerItems = analysis.issues.filter(function (i) {
      return i.severity !== 'safe';
    });

    var html = '';
    html += '<div class="cors-summary">';
    html += '<strong>扫描结果:</strong> 共 ' + analysis.total + ' 个端点，';
    html += '<span style="color:#27ae60">' + analysis.safeCount + ' 安全</span>，';
    html += '<span style="color:#e74c3c">' + dangerItems.length + ' 存在风险</span>';
    html += '</div>';

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
      html += '</div>';

      issue.findings.forEach(function (f) {
        html +=
          '<div class="cors-detail-row"><span class="cors-detail-label"></span><span class="cors-detail-value">' +
          utils.escapeHtml(f) +
          '</span></div>';
      });

      html +=
        '<div class="cors-detail-row"><span class="cors-detail-label">HTTP 状态</span><span class="cors-detail-value">' +
        issue.statusCode +
        '</span></div>';
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
        '[' + issue.severity.toUpperCase() + '] ' + issue.url + ' (HTTP ' + issue.statusCode + ')'
      );
      if (issue.acao) lines.push('  ACAO: ' + issue.acao);
      if (issue.acac) lines.push('  ACAC: ' + issue.acac);
      issue.findings.forEach(function (f) {
        lines.push('  - ' + f);
      });
      lines.push('');
    });
    utils.copyAndToast(lines.join('\n'));
  }

  return {
    scanCors: scanCors,
    copyResults: copyResults,
    get lastResult() {
      return lastResult;
    },
  };
})();
