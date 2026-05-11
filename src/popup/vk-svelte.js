// 灵眸 - Svelte/SvelteKit Detection
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

let lastResult = null;

function detectSvelte() {
  var statusEl = utils.get('svelte-status');
  var resultsEl = utils.get('svelte-results');
  var copyBtn = utils.get('svelte-copy-btn');
  var exportBtn = utils.get('svelte-export-btn');

  if (statusEl) statusEl.textContent = '正在检测 Svelte...';
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
          if (statusEl) statusEl.textContent = '检测到 Svelte';
          if (copyBtn) copyBtn.style.display = '';
          if (exportBtn) exportBtn.style.display = '';
        } else {
          if (statusEl) statusEl.textContent = '未检测到 Svelte';
          if (copyBtn) copyBtn.style.display = 'none';
          if (exportBtn) exportBtn.style.display = 'none';
        }
        renderResult(response);
      }

      chrome.tabs.sendMessage(tab.id, { type: 'VK_SVELTE_DETECT' }, function (response) {
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
                  statusEl.textContent = '注入失败: ' + (chrome.runtime.lastError.message || '未知错误');
                return;
              }
              function trySend(remaining) {
                chrome.tabs.sendMessage(tab.id, { type: 'VK_SVELTE_DETECT' }, function (resp) {
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
  var resultsEl = utils.get('svelte-results');
  if (!resultsEl) return;

  if (!data.detected) {
    resultsEl.innerHTML = '<div class="angular-not-detected">未在当前页面检测到 Svelte 框架</div>';
    return;
  }

  var title = 'Svelte';
  if (data.version) title += ' ' + data.version;
  if (data.variant) title = data.variant + (data.version ? ' ' + data.version : '');

  var html =
    '<div class="angular-card">' +
    '<div class="angular-card-header">' +
    '<span class="angular-badge detected">已检测到</span>' +
    '<span class="angular-card-title">' + utils.escapeHtml(title) + '</span>' +
    '</div>';

  if (data.variant) {
    html += '<div class="angular-info-row"><span class="angular-info-label">框架变体</span><span class="angular-info-value"><span class="angular-badge info">' + utils.escapeHtml(data.variant) + '</span></span></div>';
  }
  if (data.version) {
    html += '<div class="angular-info-row"><span class="angular-info-label">版本</span><span class="angular-info-value">' + utils.escapeHtml(data.version) + '</span></div>';
  }
  if (data.isSvelteKit) {
    html += '<div class="angular-info-row"><span class="angular-info-label">SvelteKit</span><span class="angular-info-value"><span class="angular-badge ok">Yes</span></span></div>';
  }
  if (data.routingMode) {
    html += '<div class="angular-info-row"><span class="angular-info-label">路由模式</span><span class="angular-info-value">' + utils.escapeHtml(data.routingMode) + '</span></div>';
  }
  if (data.components && data.components.length > 0) {
    html += '<div class="angular-info-row"><span class="angular-info-label">组件 (' + data.components.length + ')</span><span class="angular-info-value angular-modules">';
    data.components.forEach(function (c) {
      html += '<span class="angular-module-tag">' + utils.escapeHtml(c) + '</span>';
    });
    html += '</span></div>';
  }
  if (data.stores && data.stores.length > 0) {
    html += '<div class="angular-info-row"><span class="angular-info-label">Store (' + data.stores.length + ')</span><span class="angular-info-value">';
    data.stores.forEach(function (s) {
      html += '<div class="angular-route-item">' + utils.escapeHtml(s) + '</div>';
    });
    html += '</span></div>';
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
    var name = lastResult.variant || 'Svelte';
    lines.push(name + ' Detected: ' + (lastResult.version || 'unknown'));
    if (lastResult.isSvelteKit) lines.push('SvelteKit: Yes');
    if (lastResult.routingMode) lines.push('Routing: ' + lastResult.routingMode);
  } else {
    lines.push('Svelte: Not detected');
  }
  if (lastResult.components && lastResult.components.length > 0) {
    lines.push('Components: ' + lastResult.components.join(', '));
  }
  if (lastResult.stores && lastResult.stores.length > 0) {
    lines.push('Stores: ' + lastResult.stores.join(', '));
  }
  utils.copyAndToast(lines.join('\n'));
}

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
  a.download = 'svelte-analysis-' + Date.now() + '.json';
  a.click();
  setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  utils.showToast('已导出 JSON', 'success');
}

function getFindings() {
  if (!lastResult || !lastResult.detected) return [];
  var findings = [];
  if (lastResult.version) {
    findings.push({
      severity: 'info',
      title: 'Svelte 版本泄露',
      detail: '检测到 Svelte 版本: ' + lastResult.version + '，攻击者可利用已知漏洞',
    });
  }
  if (lastResult.isSvelteKit && lastResult.routingMode) {
    findings.push({
      severity: 'low',
      title: 'SvelteKit 路由模式',
      detail: '路由模式: ' + lastResult.routingMode,
    });
  }
  return findings;
}

export { detectSvelte, copyResults, exportResults, getFindings };
