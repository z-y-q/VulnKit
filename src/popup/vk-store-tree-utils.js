// 灵眸 - Store Explorer shared tree utilities
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

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

function createRenderStoreTree(prefix) {
  function renderStoreTree(obj, pathPrefix, depth, filter) {
    if (depth > 5) return '<div class="' + prefix + '-node ' + prefix + '-truncated">...</div>';
    if (obj === null || obj === undefined) return '';
    if (typeof obj !== 'object') return '';
    if (Array.isArray(obj)) {
      return (
        '<div class="' + prefix + '-node"><div class="' + prefix + '-key-row">' +
        '<span class="' + prefix + '-toggle ' + prefix + '-toggle-leaf"></span>' +
        '<span class="' + prefix + '-type-badge">Array[' +
        obj.length +
        ']</span>' +
        '<span class="' + prefix + '-val">' +
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
      var path = pathPrefix ? pathPrefix + '.' + key : key;
      var isExpandable =
        val !== null && typeof val === 'object' && !Array.isArray(val) && Object.keys(val).length > 0;
      var isArr = Array.isArray(val);

      var toggleIcon = isExpandable
        ? '<span class="' + prefix + '-toggle ' + prefix + '-toggle-collapsed">&#9654;</span>'
        : '<span class="' + prefix + '-toggle ' + prefix + '-toggle-leaf"></span>';

      var valHtml = '';
      if (isArr) {
        valHtml =
          '<span class="' + prefix + '-type-badge">Array[' +
          val.length +
          ']</span>' +
          '<span class="' + prefix + '-val">' +
          utils.escapeHtml(JSON.stringify(val).substring(0, 120)) +
          '</span>';
      } else if (typeof val === 'string') {
        valHtml =
          '<span class="' + prefix + '-val">"' +
          utils.escapeHtml(val.substring(0, 100)) +
          (val.length > 100 ? '...' : '') +
          '"</span>';
      } else if (typeof val === 'number' || typeof val === 'boolean') {
        valHtml = '<span class="' + prefix + '-val">' + String(val) + '</span>';
      } else if (val === null) {
        valHtml = '<span class="' + prefix + '-val ' + prefix + '-null">null</span>';
      }

      var childrenHtml = isExpandable
        ? '<div class="' + prefix + '-children hidden">' +
          renderStoreTree(val, path, depth + 1, filter) +
          '</div>'
        : '';

      html +=
        '<div class="' + prefix + '-node">' +
        '<div class="' + prefix + '-key-row" data-path="' +
        utils.escapeHtml(path) +
        '">' +
        toggleIcon +
        '<span class="' + prefix + '-key">' +
        utils.escapeHtml(key) +
        '</span>' +
        valHtml +
        '</div>' +
        childrenHtml +
        '</div>';
    });

    if (keys.length > maxShow) {
      html += '<div class="' + prefix + '-more">... 还有 ' + (keys.length - maxShow) + ' 个键</div>';
    }

    return html;
  }

  return renderStoreTree;
}

function createInitStoreExplorerEvents(config) {
  return function initStoreExplorerEvents() {
    var resultsEl = utils.get(config.resultsId);
    if (!resultsEl) return;

    var searchInput = utils.get(config.searchId);
    if (searchInput) {
      var searchTimer = null;
      searchInput.addEventListener('input', function () {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(function () {
          config.searchFn(searchInput.value.trim());
        }, 200);
      });
    }

    resultsEl.addEventListener('click', function (e) {
      var toggle = e.target.closest('.' + config.prefix + '-toggle-collapsed, .' + config.prefix + '-toggle-expanded');
      if (!toggle) return;
      var node = toggle.closest('.' + config.prefix + '-node');
      if (!node) return;
      var children = node.querySelector('.' + config.prefix + '-children');
      if (!children) return;
      var isHidden = children.classList.contains('hidden');
      children.classList.toggle('hidden');
      toggle.classList.toggle(config.prefix + '-toggle-collapsed');
      toggle.classList.toggle(config.prefix + '-toggle-expanded');
      toggle.textContent = isHidden ? '▼' : '▶';
    });
  };
}

function createCopyStoreJson(messageType, extractStores) {
  return async function copyStoreJson() {
    try {
      return utils.withTab(async function (tab) {
        var data = await chrome.tabs.sendMessage(tab.id, { type: messageType });
        if (!data || data.error) {
          utils.showToast('获取 Store 失败', 'error');
          return;
        }
        var json = JSON.stringify(extractStores(data), null, 2);
        await utils.copyText(json);
        utils.showToast('Store JSON 已复制 (' + json.length + ' 字符)', 'success');
      });
    } catch (e) {
      utils.showToast('复制失败: ' + e.message, 'error');
    }
  };
}

export { nodeMatches, subtreeHasMatch, createRenderStoreTree, createInitStoreExplorerEvents, createCopyStoreJson };
