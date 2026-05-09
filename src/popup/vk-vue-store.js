// vk-vue-store.js -- 灵眸 Chrome Extension
// Store Explorer: explore, render, copy
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

async function exploreVueStore() {
  const statusEl = utils.get('vue-store-status');
  const resultsEl = utils.get('vue-store-results');
  const actionsEl = utils.get('vue-store-actions');
  const directivesEl = utils.get('vue-store-directives');
  if (!resultsEl) return;

  if (statusEl) statusEl.textContent = '正在探索 Store...';

  try {
    const tab = await utils.requireTabId();
    if (!tab) {
      if (statusEl) statusEl.textContent = '无法获取标签页';
      return;
    }

    const data = await chrome.tabs.sendMessage(tab.id, { type: 'VK_VUE_STORE_EXPLORE' });
    if (!data) {
      if (statusEl) statusEl.textContent = '无响应';
      resultsEl.innerHTML = utils.emptyHtml('未能获取 Store 数据');
      return;
    }

    if (data.error) {
      if (statusEl) statusEl.textContent = `错误: ${data.error}`;
      resultsEl.innerHTML = utils.emptyHtml(data.error);
      return;
    }

    const storeInfo = data.store || {};
    const actionsInfo = data.actions || {};
    const dirsInfo = data.directives || [];

    const frameworks = storeInfo.frameworks || [];
    const storeKeys = Object.keys(storeInfo.stores || {});
    if (statusEl) {
      if (frameworks.length > 0) {
        statusEl.textContent = `检测到 ${frameworks.join(', ')} | ${storeKeys.length} 个 Store`;
      } else {
        statusEl.textContent = '未检测到 Vuex/Pinia Store';
      }
    }

    let html = '';
    if (storeKeys.length === 0) {
      html += utils.emptyHtml('未发现 Vuex/Pinia Store 数据');
    } else {
      storeKeys.forEach(function (storeId) {
        const storeData = storeInfo.stores[storeId];
        html += `<div class="vue-store-card">
          <div class="vue-store-header">
            <span class="vue-store-name">${utils.escapeHtml(storeId)}</span>
            <span class="vue-store-type">${utils.escapeHtml(storeData.type || 'unknown')}</span>
          </div>
          ${renderStoreTree(storeData.state, '', 0)}
          ${renderTagList(storeData.getters, 'vue-store-tag', 'Getters')}
          ${renderTagList(storeData.mutations, 'vue-store-tag vue-store-tag-mut', 'Mutations')}
          ${renderTagList(storeData.actions, 'vue-store-tag vue-store-tag-act', 'Actions')}
        </div>`;
      });
    }
    resultsEl.innerHTML = html;

    if (actionsEl) {
      let actionHtml = '';
      const actionNames = actionsInfo.actionNames || [];
      const getterNames = actionsInfo.getterNames || [];
      const apiEndpoints = actionsInfo.apiEndpoints || [];

      if (actionNames.length === 0 && apiEndpoints.length === 0) {
        actionHtml = utils.emptyHtml('未发现 Action 或 API 端点');
      } else {
        if (apiEndpoints.length > 0) {
          let epItems = '';
          apiEndpoints.forEach(function (ep) {
            epItems += `<div class="vue-store-api-item" data-url="${utils.escapeHtml(ep)}">
              <code>${utils.escapeHtml(ep)}</code>
              <button class="btn btn-sm btn-outline vue-api-copy-btn" data-url="${utils.escapeHtml(ep)}">复制</button>
            </div>`;
          });
          actionHtml += `<div class="vue-store-section">
            <div class="vue-store-section-title">API 端点 (${apiEndpoints.length})</div>
            <div class="vue-store-api-list">${epItems}</div>
          </div>`;
        }
        if (actionNames.length > 0) {
          actionHtml += renderTagList(actionNames, 'vue-store-tag vue-store-tag-act', 'Actions');
        }
        if (getterNames.length > 0) {
          actionHtml += renderTagList(getterNames, 'vue-store-tag', 'Getters');
        }
      }
      actionsEl.innerHTML = actionHtml;

      actionsEl.querySelectorAll('.vue-api-copy-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
          const url = btn.getAttribute('data-url') || '';
          utils.copyAndToast(url, `已复制: ${url}`);
        });
      });
    }

    if (directivesEl) {
      let dirHtml = '';
      if (dirsInfo.length === 0) {
        dirHtml = utils.emptyHtml('未发现自定义指令');
      } else {
        dirHtml += `<div class="vue-dir-summary">发现 ${dirsInfo.length} 个自定义指令</div>`;
        dirsInfo.forEach(function (d) {
          let exHtml = '';
          if (d.examples && d.examples.length > 0) {
            d.examples.forEach(function (ex) {
              exHtml += `<code>${utils.escapeHtml(ex)}</code>`;
            });
          }
          dirHtml += `<div class="vue-dir-item">
            <span class="vue-dir-name">${utils.escapeHtml(d.name)}</span>
            <span class="vue-dir-count">${d.count} 次</span>
            ${exHtml ? `<div class="vue-dir-examples">${exHtml}</div>` : ''}
          </div>`;
        });
      }
      directivesEl.innerHTML = dirHtml;
    }

    const storeErrors = storeInfo.errors || [];
    if (storeErrors.length > 0 && statusEl) {
      statusEl.textContent += ` | 错误: ${storeErrors.join('; ')}`;
    }
  } catch (e) {
    if (statusEl) statusEl.textContent = '探索失败';
    if (resultsEl) resultsEl.innerHTML = utils.emptyHtml(`错误: ${e.message}`);
  }
}

function renderTagList(items, tagClass, label) {
  if (!items || items.length === 0) return '';
  let tags = '';
  items.forEach(function (item) {
    tags += `<span class="${tagClass}">${utils.escapeHtml(item)}</span>`;
  });
  return `<div class="vue-store-section">
    <div class="vue-store-section-title">${label} (${items.length})</div>
    <div class="vue-store-tags">${tags}</div>
  </div>`;
}

function renderStoreTree(obj, prefix, depth) {
  if (depth > 5) return '<div class="vue-store-node vue-store-truncated">...</div>';
  if (obj === null || obj === undefined) return '';
  if (typeof obj !== 'object') return '';

  let html = '';
  const keys = Object.keys(obj);
  const maxShow = 30;
  let shown = 0;

  keys.forEach(function (key) {
    if (shown >= maxShow) return;
    shown++;
    let val = obj[key];
    const path = prefix ? `${prefix}.${key}` : key;
    const isExpandable =
      val !== null && typeof val === 'object' && !Array.isArray(val) && Object.keys(val).length > 0;
    const isArr = Array.isArray(val);

    const toggleIcon = isExpandable
      ? '<span class="vue-store-toggle vue-store-toggle-collapsed">&#9654;</span>'
      : '<span class="vue-store-toggle vue-store-toggle-leaf"></span>';

    let valHtml = '';
    if (isArr) {
      valHtml = `<span class="vue-store-type-badge">Array[${val.length}]</span><span class="vue-store-val">${utils.escapeHtml(JSON.stringify(val).substring(0, 120))}</span>`;
    } else if (typeof val === 'string') {
      valHtml = `<span class="vue-store-val">"${utils.escapeHtml(val.substring(0, 100))}${val.length > 100 ? '...' : ''}"</span>`;
    } else if (typeof val === 'number' || typeof val === 'boolean') {
      valHtml = `<span class="vue-store-val">${String(val)}</span>`;
    } else if (val === null) {
      valHtml = '<span class="vue-store-val vue-store-null">null</span>';
    }

    const childrenHtml = isExpandable
      ? `<div class="vue-store-children hidden">${renderStoreTree(val, path, depth + 1)}</div>`
      : '';

    html += `<div class="vue-store-node">
      <div class="vue-store-key-row" data-path="${utils.escapeHtml(path)}">
        ${toggleIcon}
        <span class="vue-store-key">${utils.escapeHtml(key)}</span>
        ${valHtml}
      </div>
      ${childrenHtml}
    </div>`;
  });

  if (keys.length > maxShow) {
    html += `<div class="vue-store-more">... 还有 ${keys.length - maxShow} 个键</div>`;
  }

  return html;
}

async function copyFullStoreJson() {
  try {
    return utils.withTab(async function (tab) {
      const data = await chrome.tabs.sendMessage(tab.id, { type: 'VK_VUE_STORE_EXPLORE' });
      if (!data || data.error) {
        utils.showToast('获取 Store 失败', 'error');
        return;
      }
      const json = JSON.stringify(data.store ? data.store.stores : {}, null, 2);
      await utils.copyText(json);
      utils.showToast(`Store JSON 已复制 (${json.length} 字符)`, 'success');
    });
  } catch (e) {
    utils.showToast(`复制失败: ${e.message}`, 'error');
  }
}

function initStoreExplorerEvents() {
  const resultsEl = utils.get('vue-store-results');
  if (!resultsEl) return;

  resultsEl.addEventListener('click', function (e) {
    const toggle = e.target.closest('.vue-store-toggle-collapsed, .vue-store-toggle-expanded');
    if (toggle) {
      const node = toggle.closest('.vue-store-node');
      if (!node) return;
      const children = node.querySelector('.vue-store-children');
      if (!children) return;
      const isHidden = children.classList.contains('hidden');
      children.classList.toggle('hidden');
      toggle.classList.toggle('vue-store-toggle-collapsed');
      toggle.classList.toggle('vue-store-toggle-expanded');
      toggle.textContent = isHidden ? '▼' : '▶';
    }
  });
}

export { exploreVueStore, copyFullStoreJson, initStoreExplorerEvents };
