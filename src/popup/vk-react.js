// 灵眸 - React Detection
window.VulnKitReact = (function () {
  'use strict';

  var utils = window.VulnKitUtils.utilsProxy;
  var lastResult = null;

  function detectReact() {
    var statusEl = utils.get('react-status');
    var resultsEl = utils.get('react-results');
    var copyBtn = utils.get('react-copy-btn');

    if (statusEl) statusEl.textContent = '正在检测 React...';
    if (resultsEl) resultsEl.innerHTML = '';

    utils.requireTabId().then(function (tab) {
      if (!tab || !/^https?:/.test(tab.url)) {
        if (statusEl) statusEl.textContent = '请打开一个网页';
        return;
      }

      chrome.tabs.sendMessage(tab.id, { type: 'VK_REACT_DETECT' }, function (response) {
        if (chrome.runtime.lastError) {
          if (statusEl) statusEl.textContent = '检测失败: ' + chrome.runtime.lastError.message;
          return;
        }
        if (!response) {
          if (statusEl) statusEl.textContent = '检测失败: 无响应';
          return;
        }

        lastResult = response;
        if (response.detected) {
          if (statusEl) statusEl.textContent = '检测到 React';
          if (copyBtn) copyBtn.style.display = '';
        } else {
          if (statusEl) statusEl.textContent = '未检测到 React';
          if (copyBtn) copyBtn.style.display = 'none';
        }
        renderResult(response);
      });
    });
  }

  function renderResult(data) {
    var resultsEl = utils.get('react-results');
    if (!resultsEl) return;

    if (!data.detected && (!data.signals || data.signals.length === 0)) {
      resultsEl.innerHTML = '<div class="react-not-detected">未在当前页面检测到 React 框架</div>';
      return;
    }

    var html = '<div class="react-card">';
    html += '<div class="react-card-header">';
    html += '<span class="react-badge ' + (data.detected ? 'detected' : 'not-detected') + '">' + (data.detected ? '已检测到' : '未检测到') + '</span>';
    if (data.version) {
      html += '<span class="react-card-title">React ' + utils.escapeHtml(data.version) + '</span>';
    } else {
      html += '<span class="react-card-title">React</span>';
    }
    html += '</div>';

    if (data.metaframework) {
      html += '<div class="react-info-row"><span class="react-info-label">元框架</span><span class="react-info-value"><span class="react-badge info">' + utils.escapeHtml(data.metaframework) + '</span></span></div>';
    }

    if (data.signals && data.signals.length > 0) {
      html += '<div class="react-info-row"><span class="react-info-label">检测信号</span><span class="react-info-value">' + data.signals.map(function (s) { return '<div>' + utils.escapeHtml(s) + '</div>'; }).join('') + '</span></div>';
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
      lines.push('React Detected: ' + (lastResult.version || 'unknown'));
      if (lastResult.metaframework) lines.push('Meta-framework: ' + lastResult.metaframework);
    } else {
      lines.push('React: Not detected');
    }
    if (lastResult.signals && lastResult.signals.length > 0) {
      lines.push('Signals:');
      lastResult.signals.forEach(function (s) { lines.push('  - ' + s); });
    }
    utils.copyAndToast(lines.join('\n'));
  }

  return { detectReact: detectReact, copyResults: copyResults, get lastResult() { return lastResult; } };
})();
