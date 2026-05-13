// 灵眸 - React Store Explorer (popup module)
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';
import { createRenderStoreTree, createInitStoreExplorerEvents, createCopyStoreJson } from './vk-store-tree-utils.js';

var renderStoreTree = createRenderStoreTree('react-store');
let lastReactStores = null;

async function exploreReactStore() {
  const statusEl = utils.get('react-store-status');
  const storeEl = utils.get('react-store-results');
  const routesEl = utils.get('react-routes-results');
  const apiEl = utils.get('react-api-results');
  if (!storeEl) return;

  if (statusEl) statusEl.textContent = '正在探索 React Store...';

  try {
    const tab = await utils.requireTabId();
    if (!tab) {
      if (statusEl) statusEl.textContent = '无法获取标签页';
      return;
    }

    const data = await chrome.tabs.sendMessage(tab.id, { type: 'VK_REACT_STORE_EXPLORE' });
    if (!data) {
      if (statusEl) statusEl.textContent = '无响应';
      storeEl.innerHTML = utils.emptyHtml('未能获取 Store 数据');
      return;
    }

    if (data.error) {
      if (statusEl) statusEl.textContent = '错误: ' + data.error;
      storeEl.innerHTML = utils.emptyHtml(data.error);
      return;
    }

    const stores = data.stores || {};
    const routes = data.routes || [];
    const apiEndpoints = data.apiEndpoints || [];
    const errors = data.errors || [];
    lastReactStores = stores;

    const storeKeys = Object.keys(stores);
    if (statusEl) {
      if (storeKeys.length > 0) {
        const types = [];
        const typeSeen = {};
        storeKeys.forEach(function (k) {
          var t = (stores[k] || {}).type || 'unknown';
          if (!typeSeen[t]) {
            typeSeen[t] = true;
            types.push(t);
          }
        });
        statusEl.textContent = types.join(', ') + ' | ' + storeKeys.length + ' 个 Store';
      } else {
        statusEl.textContent = '未检测到 React Store';
      }
    }

    renderStores(storeEl, stores, storeKeys, '');

    var searchInput = utils.get('react-store-search');
    if (searchInput) searchInput.style.display = storeKeys.length > 0 ? '' : 'none';

    if (routesEl) renderRoutes(routesEl, routes);
    if (apiEl) renderApiEndpoints(apiEl, apiEndpoints);

    if (errors.length > 0 && statusEl) {
      statusEl.textContent += ' | ' + errors.slice(0, 2).join('; ');
    }
  } catch (e) {
    if (statusEl) statusEl.textContent = '探索失败';
    if (storeEl) storeEl.innerHTML = utils.emptyHtml('错误: ' + e.message);
  }
}

function renderStores(container, stores, storeKeys, filter) {
  if (storeKeys.length === 0) {
    container.innerHTML = utils.emptyHtml('未发现 Redux/Zustand/Jotai Store');
    return;
  }

  let html = '';
  storeKeys.forEach(function (storeId) {
    var storeData = stores[storeId] || {};
    var state = storeData.state || {};
    var storeType = storeData.type || 'unknown';

    var treeHtml = renderStoreTree(state, '', 0, filter);
    if (filter && !treeHtml) return;

    html += '<div class="react-store-card">';
    html += '<div class="react-store-header">';
    html += '<span class="react-store-name">' + utils.escapeHtml(storeId) + '</span>';
    html +=
      '<span class="react-store-type-badge type-' +
      utils.escapeHtml(storeType) +
      '">' +
      utils.escapeHtml(storeType) +
      '</span>';
    html += '</div>';
    html += treeHtml;
    html += '</div>';
  });
  container.innerHTML = filter && !html ? utils.emptyHtml('没有匹配的结果') : html;
}

function renderRoutes(container, routes) {
  if (routes.length === 0) {
    container.innerHTML = utils.emptyHtml('未发现路由');
    return;
  }

  var grouped = {};
  routes.forEach(function (r) {
    var src = r.source || 'unknown';
    if (!grouped[src]) grouped[src] = [];
    grouped[src].push(r);
  });

  let html = '<div class="react-store-section">';
  html += '<div class="react-store-section-title">路由 (' + routes.length + ')</div>';
  Object.keys(grouped).forEach(function (src) {
    html += '<div class="react-route-group">';
    html +=
      '<div class="react-route-source">' +
      utils.escapeHtml(src) +
      ' (' +
      grouped[src].length +
      ')</div>';
    grouped[src].forEach(function (r) {
      html += '<div class="react-route-item">';
      html += '<code class="react-route-path">' + utils.escapeHtml(r.path) + '</code>';
      if (r.hasElement) {
        html += '<span class="react-route-attr">component</span>';
      }
      html += '</div>';
    });
    html += '</div>';
  });
  html += '</div>';
  container.innerHTML = html;
}

function renderApiEndpoints(container, endpoints) {
  if (endpoints.length === 0) {
    container.innerHTML = utils.emptyHtml('未发现 API 端点');
    return;
  }

  let html = '<div class="react-store-section">';
  html += '<div class="react-store-section-title">API 端点 (' + endpoints.length + ')</div>';
  html += '<div class="react-api-list">';
  endpoints.forEach(function (ep) {
    var isAction = ep.indexOf('[Action]') === 0;
    var displayUrl = isAction ? ep.substring(8) : ep;
    var copyClass = isAction ? 'react-api-item react-api-action' : 'react-api-item';
    html += '<div class="' + copyClass + '" data-url="' + utils.escapeHtml(displayUrl) + '">';
    html +=
      '<code>' +
      utils.escapeHtml(displayUrl.length > 100 ? displayUrl.substring(0, 97) + '...' : displayUrl) +
      '</code>';
    html +=
      '<button class="btn btn-sm btn-outline react-api-copy-btn" data-url="' +
      utils.escapeHtml(displayUrl) +
      '">复制</button>';
    html += '</div>';
  });
  html += '</div>';
  html += '</div>';
  container.innerHTML = html;

  container.querySelectorAll('.react-api-copy-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var url = btn.getAttribute('data-url') || '';
      utils.copyAndToast(url, '已复制: ' + url);
    });
  });
}

function searchReactStore(text) {
  if (!lastReactStores) return;
  var storeEl = utils.get('react-store-results');
  if (!storeEl) return;
  var storeKeys = Object.keys(lastReactStores);
  renderStores(storeEl, lastReactStores, storeKeys, text);
}

var copyReactStoreJson = createCopyStoreJson('VK_REACT_STORE_EXPLORE', function (data) {
  return data.stores || {};
});

var initStoreExplorerEvents = createInitStoreExplorerEvents({
  resultsId: 'react-store-results',
  searchId: 'react-store-search',
  prefix: 'react-store',
  searchFn: searchReactStore,
});

export { exploreReactStore, copyReactStoreJson, initStoreExplorerEvents };
