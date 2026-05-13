// 灵眸 - Angular Store/Router Explorer (popup module)
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';
import { createRenderStoreTree, createInitStoreExplorerEvents, createCopyStoreJson } from './vk-store-tree-utils.js';

var renderStoreTree = createRenderStoreTree('ng-store');
let lastAngularStores = null;
let lastAngularRoutes = null;

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

function searchAngularStore(text) {
  if (!lastAngularStores) return;
  var storeEl = utils.get('angular-store-results');
  if (!storeEl) return;
  var storeKeys = Object.keys(lastAngularStores);
  renderStores(storeEl, lastAngularStores, storeKeys, text, []);
}

var copyAngularStoreJson = createCopyStoreJson('VK_ANGULAR_STORE_EXPLORE', function (data) {
  return data.stores || {};
});

var initStoreExplorerEvents = createInitStoreExplorerEvents({
  resultsId: 'angular-store-results',
  searchId: 'angular-store-search',
  prefix: 'ng-store',
  searchFn: searchAngularStore,
});

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

function handleRouterRead() {
  var statusEl = utils.get('angular-router-status');
  var routesEl = utils.get('angular-routes-results');
  if (statusEl) statusEl.textContent = '正在读取路由...';
  if (routesEl) routesEl.innerHTML = '';

  utils
    .requireTabId()
    .then(function (tab) {
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
    })
    .catch(function () {
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
