// 灵眸 - Angular Store/Router Explorer (popup module)
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

let lastAngularStores = null;
let lastAngularRoutes = null;

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

async function exploreAngularStore() {
  var statusEl = utils.get('angular-store-status');
  var storeEl = utils.get('angular-store-results');
  if (!storeEl) return;

  if (statusEl) statusEl.textContent = '正在探索 Angular Store...';

  try {
    var tab = await utils.requireTabId();
    if (!tab) {
      if (statusEl) statusEl.textContent = '无法获取标签页';
      return;
    }

    var data = await chrome.tabs.sendMessage(tab.id, { type: 'VK_ANGULAR_STORE_EXPLORE' });
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

    var stores = data.stores || {};
    var signals = data.signals || [];
    var apiEndpoints = data.apiEndpoints || [];
    var errors = data.errors || [];
    lastAngularStores = stores;

    var storeKeys = Object.keys(stores);
    if (statusEl) {
      if (storeKeys.length > 0) {
        statusEl.textContent = storeKeys.length + ' 个 Store';
        if (signals.length > 0) statusEl.textContent += ' | ' + signals.length + ' 个 Signal';
      } else if (signals.length > 0) {
        statusEl.textContent = signals.length + ' 个 Signal';
      } else {
        statusEl.textContent = '未检测到 Angular Store';
      }
    }

    renderStores(storeEl, stores, storeKeys, '', signals);

    var searchInput = utils.get('angular-store-search');
    if (searchInput) searchInput.style.display = storeKeys.length > 0 ? '' : 'none';

    var apiEl = utils.get('angular-api-results');
    if (apiEl) renderApiEndpoints(apiEl, apiEndpoints);

    if (errors.length > 0 && statusEl) {
      statusEl.textContent += ' | ' + errors.slice(0, 2).join('; ');
    }
  } catch (e) {
    if (statusEl) statusEl.textContent = '探索失败';
    if (storeEl) storeEl.innerHTML = utils.emptyHtml('错误: ' + e.message);
  }
}

function renderStores(container, stores, storeKeys, filter, signals) {
  if (storeKeys.length === 0 && (!signals || signals.length === 0)) {
    container.innerHTML = utils.emptyHtml('未发现 NgRx Store / Signal');
    return;
  }

  var html = '';
  storeKeys.forEach(function (storeId) {
    var storeData = stores[storeId] || {};
    var state = storeData.state || {};
    var storeType = storeData.type || 'unknown';

    var treeHtml = renderStoreTree(state, '', 0, filter);
    if (filter && !treeHtml) return;

    html += '<div class="ng-store-card">';
    html += '<div class="ng-store-header">';
    html += '<span class="ng-store-name">' + utils.escapeHtml(storeId) + '</span>';
    html +=
      '<span class="ng-store-type-badge type-' +
      utils.escapeHtml(storeType) +
      '">' +
      utils.escapeHtml(storeType) +
      '</span>';
    html += '</div>';
    html += treeHtml;
    html += '</div>';
  });

  if (signals && signals.length > 0) {
    html += '<div class="ng-store-card">';
    html += '<div class="ng-store-header"><span class="ng-store-name">Signals</span></div>';
    signals.forEach(function (s) {
      html +=
        '<div class="ng-store-node"><div class="ng-store-key-row">' +
        '<span class="ng-store-key">' + utils.escapeHtml(s.name || 'unknown') + '</span>' +
        '<span class="ng-store-type-badge type-signal">' + utils.escapeHtml(s.component || 'global') + '</span>' +
        '</div></div>';
    });
    html += '</div>';
  }

  container.innerHTML = filter && !html ? utils.emptyHtml('没有匹配的结果') : html;
}

function renderApiEndpoints(container, endpoints) {
  if (endpoints.length === 0) {
    container.innerHTML = utils.emptyHtml('未发现 API 端点');
    return;
  }

  var html = '<div class="ng-store-section">';
  html += '<div class="ng-store-section-title">API 端点 (' + endpoints.length + ')</div>';
  html += '<div class="ng-api-list">';
  endpoints.forEach(function (ep) {
    html += '<div class="ng-api-item" data-url="' + utils.escapeHtml(ep) + '">';
    html += '<code>' + utils.escapeHtml(ep.length > 100 ? ep.substring(0, 97) + '...' : ep) + '</code>';
    html +=
      '<button class="btn btn-sm btn-outline ng-api-copy-btn" data-url="' +
      utils.escapeHtml(ep) +
      '">复制</button>';
    html += '</div>';
  });
  html += '</div></div>';
  container.innerHTML = html;

  container.querySelectorAll('.ng-api-copy-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var url = btn.getAttribute('data-url') || '';
      utils.copyAndToast(url, '已复制: ' + url);
    });
  });
}

function renderStoreTree(obj, prefix, depth, filter) {
  if (depth > 5) return '<div class="ng-store-node ng-store-truncated">...</div>';
  if (obj === null || obj === undefined) return '';
  if (typeof obj !== 'object') return '';
  if (Array.isArray(obj)) {
    return (
      '<div class="ng-store-node"><div class="ng-store-key-row">' +
      '<span class="ng-store-toggle ng-store-toggle-leaf"></span>' +
      '<span class="ng-store-type-badge">Array[' +
      obj.length +
      ']</span>' +
      '<span class="ng-store-val">' +
      utils.escapeHtml(JSON.stringify(obj).substring(0, 120)) +
      '</span>' +
      '</div></div>'
    );
  }

  var html = '';
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
      ? '<span class="ng-store-toggle ng-store-toggle-collapsed">&#9654;</span>'
      : '<span class="ng-store-toggle ng-store-toggle-leaf"></span>';

    var valHtml = '';
    if (isArr) {
      valHtml =
        '<span class="ng-store-type-badge">Array[' +
        val.length +
        ']</span>' +
        '<span class="ng-store-val">' +
        utils.escapeHtml(JSON.stringify(val).substring(0, 120)) +
        '</span>';
    } else if (typeof val === 'string') {
      valHtml =
        '<span class="ng-store-val">"' +
        utils.escapeHtml(val.substring(0, 100)) +
        (val.length > 100 ? '...' : '') +
        '"</span>';
    } else if (typeof val === 'number' || typeof val === 'boolean') {
      valHtml = '<span class="ng-store-val">' + String(val) + '</span>';
    } else if (val === null) {
      valHtml = '<span class="ng-store-val ng-store-null">null</span>';
    }

    var childrenHtml = isExpandable
      ? '<div class="ng-store-children hidden">' +
        renderStoreTree(val, path, depth + 1, filter) +
        '</div>'
      : '';

    html +=
      '<div class="ng-store-node">' +
      '<div class="ng-store-key-row" data-path="' +
      utils.escapeHtml(path) +
      '">' +
      toggleIcon +
      '<span class="ng-store-key">' +
      utils.escapeHtml(key) +
      '</span>' +
      valHtml +
      '</div>' +
      childrenHtml +
      '</div>';
  });

  if (keys.length > maxShow) {
    html += '<div class="ng-store-more">... 还有 ' + (keys.length - maxShow) + ' 个键</div>';
  }

  return html;
}

function renderAngularRoutes(routes) {
  var routesEl = utils.get('angular-routes-results');
  var statusEl = utils.get('angular-router-status');
  if (!routesEl) return;

  if (statusEl) statusEl.textContent = '发现 ' + routes.length + ' 个路由';

  if (routes.length === 0) {
    routesEl.innerHTML = utils.emptyHtml('未发现路由');
    return;
  }

  var html = '<div class="ng-route-list">';
  routes.forEach(function (r) {
    html += '<div class="ng-route-item">';
    html += '<code class="ng-route-path">' + utils.escapeHtml(r.path || '/') + '</code>';
    if (r.component) {
      html += '<span class="ng-route-attr">' + utils.escapeHtml(r.component) + '</span>';
    }
    if (r.lazy) {
      html += '<span class="ng-route-lazy">懒加载</span>';
    }
    if (r.guards && r.guards.length > 0) {
      r.guards.forEach(function (g) {
        html += '<span class="ng-route-guard">' + utils.escapeHtml(g) + '</span>';
      });
    }
    if (r.data) {
      html += '<span class="ng-route-attr">data</span>';
    }
    html += '</div>';
  });
  html += '</div>';
  routesEl.innerHTML = html;
}

function initStoreExplorerEvents() {
  var storeEl = utils.get('angular-store-results');
  if (!storeEl) return;

  var searchInput = utils.get('angular-store-search');
  if (searchInput) {
    var searchTimer = null;
    searchInput.addEventListener('input', function () {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(function () {
        searchAngularStore(searchInput.value.trim());
      }, 200);
    });
  }

  storeEl.addEventListener('click', function (e) {
    var toggle = e.target.closest('.ng-store-toggle-collapsed, .ng-store-toggle-expanded');
    if (!toggle) return;
    var node = toggle.closest('.ng-store-node');
    if (!node) return;
    var children = node.querySelector('.ng-store-children');
    if (!children) return;
    var isHidden = children.classList.contains('hidden');
    children.classList.toggle('hidden');
    toggle.classList.toggle('ng-store-toggle-collapsed');
    toggle.classList.toggle('ng-store-toggle-expanded');
    toggle.textContent = isHidden ? '▼' : '▶';
  });
}

async function copyAngularStoreJson() {
  try {
    return utils.withTab(async function (tab) {
      var data = await chrome.tabs.sendMessage(tab.id, { type: 'VK_ANGULAR_STORE_EXPLORE' });
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

async function copyAngularRoutesJson() {
  try {
    return utils.withTab(async function (tab) {
      var data = await chrome.tabs.sendMessage(tab.id, { type: 'VK_ANGULAR_STORE_EXPLORE' });
      if (!data || data.error || !data.routes || data.routes.length === 0) {
        utils.showToast('没有路由数据', 'warning');
        return;
      }
      var json = JSON.stringify(data.routes, null, 2);
      await utils.copyText(json);
      utils.showToast('路由 JSON 已复制 (' + data.routes.length + ' 条)', 'success');
    });
  } catch (e) {
    utils.showToast('复制失败: ' + e.message, 'error');
  }
}

function searchAngularStore(text) {
  if (!lastAngularStores) return;
  var storeEl = utils.get('angular-store-results');
  if (!storeEl) return;
  var storeKeys = Object.keys(lastAngularStores);
  renderStores(storeEl, lastAngularStores, storeKeys, text, []);
}

function handleRouterRead() {
  var statusEl = utils.get('angular-router-status');
  var routesEl = utils.get('angular-routes-results');
  if (statusEl) statusEl.textContent = '正在读取路由...';
  if (routesEl) routesEl.innerHTML = '';

  utils.requireTabId().then(function (tab) {
    if (!tab) {
      if (statusEl) statusEl.textContent = '无法获取标签页';
      return;
    }
    chrome.tabs.sendMessage(tab.id, { type: 'VK_ANGULAR_STORE_EXPLORE' }, function (data) {
      if (chrome.runtime.lastError || !data) {
        if (statusEl) statusEl.textContent = '无响应，请刷新页面后重试';
        return;
      }
      if (data.error) {
        if (statusEl) statusEl.textContent = '错误: ' + data.error;
        return;
      }
      var routes = data.routes || [];
      lastAngularRoutes = routes;
      renderAngularRoutes(routes);
    });
  }).catch(function () {
    if (statusEl) statusEl.textContent = '获取标签页失败';
  });
}

export {
  exploreAngularStore,
  copyAngularStoreJson,
  copyAngularRoutesJson,
  initStoreExplorerEvents,
  handleRouterRead,
};
