// 灵眸 - React Store Explorer (popup module)
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

let lastReactStores = null;

function nodeMatches(key, val, filter) {
  if (!filter) return true;
  var lower = filter.toLowerCase();
  if (key.toLowerCase().indexOf(lower) !== -1) return true;
  if (typeof val === 'string' && val.toLowerCase().indexOf(lower) !== -1) return true;
  if (typeof val === 'number' || typeof val === 'boolean') {
    if (String(val).toLowerCase().indexOf(lower) !== -1) return true;
  }
  return false;
}

function subtreeHasMatch(obj, filter) {
  if (!filter || !obj || typeof obj !== 'object') return false;
  return Object.keys(obj).some(function (k) {
    var v = obj[k];
    if (nodeMatches(k, v, filter)) return true;
    if (v && typeof v === 'object') return subtreeHasMatch(v, filter);
    return false;
  });
}

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

    // Render stores
    renderStores(storeEl, stores, storeKeys, '');

    var searchInput = utils.get('react-store-search');
    if (searchInput) searchInput.style.display = storeKeys.length > 0 ? '' : 'none';

    // Render routes
    if (routesEl) renderRoutes(routesEl, routes);

    // Render API endpoints
    if (apiEl) renderApiEndpoints(apiEl, apiEndpoints);

    // Show errors in status
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

  // Group by source
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

function renderStoreTree(obj, prefix, depth, filter) {
  if (depth > 5) return '<div class="react-store-node react-store-truncated">...</div>';
  if (obj === null || obj === undefined) return '';
  if (typeof obj !== 'object') return '';
  if (Array.isArray(obj)) {
    return (
      '<div class="react-store-node"><div class="react-store-key-row">' +
      '<span class="react-store-toggle react-store-toggle-leaf"></span>' +
      '<span class="react-store-type-badge">Array[' +
      obj.length +
      ']</span>' +
      '<span class="react-store-val">' +
      utils.escapeHtml(JSON.stringify(obj).substring(0, 120)) +
      '</span>' +
      '</div></div>'
    );
  }

  let html = '';
  var keys = Object.keys(obj);
  var maxShow = 30;
  var shown = 0;

  keys.forEach(function (key) {
    if (shown >= maxShow) return;
    var val = obj[key];
    if (filter) {
      var directMatch = nodeMatches(key, val, filter);
      var childMatch = val && typeof val === 'object' && subtreeHasMatch(val, filter);
      if (!directMatch && !childMatch) return;
    }
    shown++;
    var path = prefix ? prefix + '.' + key : key;
    var isExpandable =
      val !== null && typeof val === 'object' && !Array.isArray(val) && Object.keys(val).length > 0;
    var isArr = Array.isArray(val);

    var toggleIcon = isExpandable
      ? '<span class="react-store-toggle react-store-toggle-collapsed">&#9654;</span>'
      : '<span class="react-store-toggle react-store-toggle-leaf"></span>';

    var valHtml = '';
    if (isArr) {
      valHtml =
        '<span class="react-store-type-badge">Array[' +
        val.length +
        ']</span>' +
        '<span class="react-store-val">' +
        utils.escapeHtml(JSON.stringify(val).substring(0, 120)) +
        '</span>';
    } else if (typeof val === 'string') {
      valHtml =
        '<span class="react-store-val">"' +
        utils.escapeHtml(val.substring(0, 100)) +
        (val.length > 100 ? '...' : '') +
        '"</span>';
    } else if (typeof val === 'number' || typeof val === 'boolean') {
      valHtml = '<span class="react-store-val">' + String(val) + '</span>';
    } else if (val === null) {
      valHtml = '<span class="react-store-val react-store-null">null</span>';
    }

    var childrenHtml = isExpandable
      ? '<div class="react-store-children hidden">' +
        renderStoreTree(val, path, depth + 1, filter) +
        '</div>'
      : '';

    html +=
      '<div class="react-store-node">' +
      '<div class="react-store-key-row" data-path="' +
      utils.escapeHtml(path) +
      '">' +
      toggleIcon +
      '<span class="react-store-key">' +
      utils.escapeHtml(key) +
      '</span>' +
      valHtml +
      '</div>' +
      childrenHtml +
      '</div>';
  });

  if (keys.length > maxShow) {
    html += '<div class="react-store-more">... 还有 ' + (keys.length - maxShow) + ' 个键</div>';
  }

  return html;
}

function initStoreExplorerEvents() {
  var storeEl = utils.get('react-store-results');
  if (!storeEl) return;

  var searchInput = utils.get('react-store-search');
  if (searchInput) {
    var searchTimer = null;
    searchInput.addEventListener('input', function () {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(function () {
        searchReactStore(searchInput.value.trim());
      }, 200);
    });
  }

  storeEl.addEventListener('click', function (e) {
    var toggle = e.target.closest('.react-store-toggle-collapsed, .react-store-toggle-expanded');
    if (!toggle) return;
    var node = toggle.closest('.react-store-node');
    if (!node) return;
    var children = node.querySelector('.react-store-children');
    if (!children) return;
    var isHidden = children.classList.contains('hidden');
    children.classList.toggle('hidden');
    toggle.classList.toggle('react-store-toggle-collapsed');
    toggle.classList.toggle('react-store-toggle-expanded');
    toggle.textContent = isHidden ? '▼' : '▶';
  });
}

async function copyReactStoreJson() {
  try {
    return utils.withTab(async function (tab) {
      var data = await chrome.tabs.sendMessage(tab.id, { type: 'VK_REACT_STORE_EXPLORE' });
      if (!data || data.error) {
        utils.showToast('获取 Store 失败', 'error');
        return;
      }
      var json = JSON.stringify(data.stores || {}, null, 2);
      await utils.copyText(json);
      utils.showToast('Store JSON 已复制 (' + json.length + ' 字符)', 'success');
    });
  } catch (e) {
    utils.showToast('复制失败: ' + e.message, 'error');
  }
}

function searchReactStore(text) {
  if (!lastReactStores) return;
  var storeEl = utils.get('react-store-results');
  if (!storeEl) return;
  var storeKeys = Object.keys(lastReactStores);
  renderStores(storeEl, lastReactStores, storeKeys, text);
}

export { exploreReactStore, copyReactStoreJson, initStoreExplorerEvents };
