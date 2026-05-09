// 灵眸 - React Detection
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

let lastResult = null;

function exportResults() {
  if (!lastResult) {
    utils.showToast('没有可导出的结果', 'warning');
    return;
  }
  const report = { timestamp: new Date().toISOString(), result: lastResult };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `react-analysis-${Date.now()}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  utils.showToast('已导出 JSON', 'success');
}

function detectReact() {
  const statusEl = utils.get('react-status');
  let resultsEl = utils.get('react-results');
  const copyBtn = utils.get('react-copy-btn');
  const exportBtn = utils.get('react-export-btn');

  if (statusEl) statusEl.textContent = '正在检测 React...';
  if (resultsEl) resultsEl.innerHTML = '';

  utils
    .requireTabId()
    .then(function (tab) {
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
          if (statusEl) statusEl.textContent = '检测到 React';
          if (copyBtn) copyBtn.style.display = '';
          if (exportBtn) exportBtn.style.display = '';
        } else {
          if (statusEl) statusEl.textContent = '未检测到 React';
          if (copyBtn) copyBtn.style.display = 'none';
          if (exportBtn) exportBtn.style.display = 'none';
        }
        renderResult(response);
      }

      chrome.tabs.sendMessage(tab.id, { type: 'VK_REACT_DETECT' }, function (response) {
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
                  statusEl.textContent = `注入失败: ${chrome.runtime.lastError.message || '未知错误'}`;
                return;
              }
              function trySend(remaining) {
                chrome.tabs.sendMessage(tab.id, { type: 'VK_REACT_DETECT' }, function (resp) {
                  if (chrome.runtime.lastError) {
                    if (remaining > 0)
                      setTimeout(function () {
                        trySend(remaining - 1);
                      }, 100);
                    else if (statusEl) statusEl.textContent = '检测超时：内容脚本未响应';
                    return;
                  }
                  handleMessage(resp);
                });
              }
              trySend(5);
            }
          );
          return;
        }
        handleMessage(response);
      });
    })
    .catch(function () {
      if (statusEl) statusEl.textContent = '获取标签页失败';
    });
}

function renderResult(data) {
  const resultsEl = utils.get('react-results');
  if (!resultsEl) return;

  if (!data.detected && (!data.signals || data.signals.length === 0)) {
    resultsEl.innerHTML = '<div class="react-not-detected">未在当前页面检测到 React 框架</div>';
    return;
  }

  let html = `<div class="react-card"><div class="react-card-header"><span class="react-badge ${data.detected ? 'detected' : 'not-detected'}">${data.detected ? '已检测到' : '未检测到'}</span>`;
  if (data.version) {
    html += `<span class="react-card-title">React ${utils.escapeHtml(data.version)}</span>`;
  } else {
    html += '<span class="react-card-title">React</span>';
  }
  html += '</div>';

  if (data.mode) {
    const modeBadge = data.mode === 'development' ? 'warn' : 'ok';
    html += `<div class="react-info-row"><span class="react-info-label">运行模式</span><span class="react-info-value"><span class="react-badge ${modeBadge}">${utils.escapeHtml(data.mode)}</span></span></div>`;
  }

  if (data.metaframework) {
    html += `<div class="react-info-row"><span class="react-info-label">元框架</span><span class="react-info-value"><span class="react-badge info">${utils.escapeHtml(data.metaframework)}</span></span></div>`;
  }

  if (data.stateManager) {
    html += `<div class="react-info-row"><span class="react-info-label">状态管理</span><span class="react-info-value">${utils.escapeHtml(data.stateManager)}</span></div>`;
  }

  if (data.components && data.components.length > 0) {
    html += `<div class="react-info-row"><span class="react-info-label">组件树 (${data.components.length})</span><span class="react-info-value react-components">`;
    data.components.forEach(function (c) {
      html += `<span class="react-component-tag">${utils.escapeHtml(c)}</span>`;
    });
    html += '</span></div>';
  }

  if (data.routes && data.routes.length > 0) {
    html += `<div class="react-info-row"><span class="react-info-label">路由 (${data.routes.length})</span><span class="react-info-value">`;
    data.routes.forEach(function (r) {
      html += `<div class="react-route-item">${utils.escapeHtml(r)}</div>`;
    });
    html += '</span></div>';
  }

  if (data.signals && data.signals.length > 0) {
    html += `<div class="react-info-row"><span class="react-info-label">检测信号</span><span class="react-info-value">${data.signals
      .map(function (s) {
        return `<div>${utils.escapeHtml(s)}</div>`;
      })
      .join('')}</span></div>`;
  }

  html += '</div>';
  resultsEl.innerHTML = html;
}

function copyResults() {
  if (!lastResult) {
    utils.showToast('没有检测结果', 'warning');
    return;
  }
  const lines = [];
  if (lastResult.detected) {
    lines.push(`React Detected: ${lastResult.version || 'unknown'}`);
    if (lastResult.mode) lines.push(`Mode: ${lastResult.mode}`);
    if (lastResult.metaframework) lines.push(`Meta-framework: ${lastResult.metaframework}`);
    if (lastResult.stateManager) lines.push(`State: ${lastResult.stateManager}`);
  } else {
    lines.push('React: Not detected');
  }
  if (lastResult.components && lastResult.components.length > 0) {
    lines.push(`Components: ${lastResult.components.join(', ')}`);
  }
  if (lastResult.routes && lastResult.routes.length > 0) {
    lines.push('Routes:');
    lastResult.routes.forEach(function (r) {
      lines.push(`  - ${r}`);
    });
  }
  if (lastResult.signals && lastResult.signals.length > 0) {
    lines.push('Signals:');
    lastResult.signals.forEach(function (s) {
      lines.push(`  - ${s}`);
    });
  }
  utils.copyAndToast(lines.join('\n'));
}

export { detectReact, copyResults, exportResults };
