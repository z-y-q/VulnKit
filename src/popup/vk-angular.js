// 灵眸 - Angular Detection
window.VulnKitAngular = (function () {
  'use strict';

  var utils = window.VulnKitUtils.utilsProxy;
  var lastResult = null;

  function exportResults() {
    if (!lastResult) {
      utils.showToast('没有可导出的结果', 'warning');
      return;
    }
    var report = { timestamp: new Date().toISOString(), result: lastResult };
    var blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'angular-analysis-' + Date.now() + '.json';
    a.click();
    URL.revokeObjectURL(url);
    utils.showToast('已导出 JSON', 'success');
  }

  function detectAngular() {
    var statusEl = utils.get('angular-status');
    var resultsEl = utils.get('angular-results');
    var copyBtn = utils.get('angular-copy-btn');
    var exportBtn = utils.get('angular-export-btn');

    if (statusEl) statusEl.textContent = '正在检测 Angular...';
    if (resultsEl) resultsEl.innerHTML = '';

    utils.requireTabId().then(function (tab) {
      if (!tab || !/^https?:/.test(tab.url)) {
        if (statusEl) statusEl.textContent = '请打开一个网页';
        return;
      }

      function handleMessage(response) {
        if (chrome.runtime.lastError || !response) {
          if (statusEl) statusEl.textContent = '检测失败: 请刷新目标网页后重试';
          return;
        }

        lastResult = response;
        if (response.detected) {
          if (statusEl) statusEl.textContent = '检测到 Angular';
          if (copyBtn) copyBtn.style.display = '';
          if (exportBtn) exportBtn.style.display = '';
        } else {
          if (statusEl) statusEl.textContent = '未检测到 Angular';
          if (copyBtn) copyBtn.style.display = 'none';
          if (exportBtn) exportBtn.style.display = 'none';
        }
        renderResult(response);
      }

      chrome.tabs.sendMessage(tab.id, { type: 'VK_ANGULAR_DETECT' }, function (response) {
        if (chrome.runtime.lastError || !response) {

          if (statusEl) statusEl.textContent = '正在注入检测脚本...';
          chrome.scripting.executeScript(
            {
              target: { tabId: tab.id },
              files: ['src/content/vk-content.js'],
            },
            function () {
              if (chrome.runtime.lastError) {
                if (statusEl)
                  statusEl.textContent =
                    '注入失败: ' + (chrome.runtime.lastError.message || '未知错误');
                return;
              }
              setTimeout(function () {
                chrome.tabs.sendMessage(tab.id, { type: 'VK_ANGULAR_DETECT' }, handleMessage);
              }, 200);
            }
          );
          return;
        }
        handleMessage(response);
      });
    });
  }

  function renderResult(data) {
    var resultsEl = utils.get('angular-results');
    if (!resultsEl) return;

    if (!data.detected && (!data.signals || data.signals.length === 0)) {
      resultsEl.innerHTML =
        '<div class="angular-not-detected">未在当前页面检测到 Angular 框架</div>';
      return;
    }

    var html = '<div class="angular-card">';
    html += '<div class="angular-card-header">';
    html +=
      '<span class="angular-badge ' +
      (data.detected ? 'detected' : 'not-detected') +
      '">' +
      (data.detected ? '已检测到' : '未检测到') +
      '</span>';
    var title = 'Angular';
    if (data.variant) title = data.variant;
    if (data.version) title += ' ' + data.version;
    html += '<span class="angular-card-title">' + utils.escapeHtml(title) + '</span>';
    html += '</div>';

    if (data.variant) {
      html +=
        '<div class="angular-info-row"><span class="angular-info-label">框架变体</span><span class="angular-info-value"><span class="angular-badge info">' +
        utils.escapeHtml(data.variant) +
        '</span></span></div>';
    }
    if (data.version) {
      html +=
        '<div class="angular-info-row"><span class="angular-info-label">版本</span><span class="angular-info-value">' +
        utils.escapeHtml(data.version) +
        '</span></div>';
    }

    if (data.mode) {
      var modeBadge = data.mode === 'development' ? 'warn' : 'ok';
      html +=
        '<div class="angular-info-row"><span class="angular-info-label">运行模式</span><span class="angular-info-value"><span class="angular-badge ' +
        modeBadge +
        '">' +
        utils.escapeHtml(data.mode) +
        '</span></span></div>';
    }

    if (data.modules && data.modules.length > 0) {
      var moduleLabel = data.variant === 'Angular' ? '组件/模块' : '模块';
      html +=
        '<div class="angular-info-row"><span class="angular-info-label">' +
        moduleLabel +
        ' (' +
        data.modules.length +
        ')</span><span class="angular-info-value angular-modules">';
      data.modules.forEach(function (m) {
        html += '<span class="angular-module-tag">' + utils.escapeHtml(m) + '</span>';
      });
      html += '</span></div>';
    }

    if (data.routes && data.routes.length > 0) {
      html +=
        '<div class="angular-info-row"><span class="angular-info-label">路由 (' +
        data.routes.length +
        ')</span><span class="angular-info-value">';
      data.routes.forEach(function (r) {
        html += '<div class="angular-route-item">' + utils.escapeHtml(r) + '</div>';
      });
      html += '</span></div>';
    }

    if (data.signals && data.signals.length > 0) {
      html +=
        '<div class="angular-info-row"><span class="angular-info-label">检测信号</span><span class="angular-info-value">' +
        data.signals
          .map(function (s) {
            return '<div>' + utils.escapeHtml(s) + '</div>';
          })
          .join('') +
        '</span></div>';
    }

    html += '</div>';
    resultsEl.innerHTML = html;
  }

  function copyResults() {
    if (!lastResult) {
      utils.showToast('没有检测结果', 'warning');
      return;
    }
    var lines = [];
    if (lastResult.detected) {
      var name = lastResult.variant || 'Angular';
      lines.push(name + ' Detected: ' + (lastResult.version || 'unknown'));
      if (lastResult.mode) lines.push('Mode: ' + lastResult.mode);
    } else {
      lines.push('Angular: Not detected');
    }
    if (lastResult.modules && lastResult.modules.length > 0) {
      lines.push('Modules: ' + lastResult.modules.join(', '));
    }
    if (lastResult.routes && lastResult.routes.length > 0) {
      lines.push('Routes:');
      lastResult.routes.forEach(function (r) {
        lines.push('  - ' + r);
      });
    }
    if (lastResult.signals && lastResult.signals.length > 0) {
      lines.push('Signals:');
      lastResult.signals.forEach(function (s) {
        lines.push('  - ' + s);
      });
    }
    utils.copyAndToast(lines.join('\n'));
  }

  return {
    detectAngular: detectAngular,
    copyResults: copyResults,
    exportResults: exportResults,
    get lastResult() {
      return lastResult;
    },
  };
})();
