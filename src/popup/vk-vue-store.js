// vk-vue-store.js -- 灵眸 Chrome Extension
// Store Explorer: explore, render, copy
(function () {
  'use strict';

  var S = window.VulnKitVueState;
  var utils = S.utils;

  async function exploreVueStore() {
    var statusEl = utils.get('vue-store-status');
    var resultsEl = utils.get('vue-store-results');
    var actionsEl = utils.get('vue-store-actions');
    var directivesEl = utils.get('vue-store-directives');
    if (!resultsEl) return;

    if (statusEl) statusEl.textContent = '正在探索 Store...';

    try {
      var tab = await utils.requireTabId();
      if (!tab) {
        if (statusEl) statusEl.textContent = '无法获取标签页';
        return;
      }

      var data = await chrome.tabs.sendMessage(tab.id, { type: 'VK_VUE_STORE_EXPLORE' });
      if (!data) {
        if (statusEl) statusEl.textContent = '无响应';
        resultsEl.innerHTML = utils.emptyHtml('未能获取 Store 数据');
        return;
      }

      if (data.error) {
        if (statusEl) statusEl.textContent = '错误: ' + data.error;
        resultsEl.innerHTML = utils.emptyHtml(data.error);
        return;
      }

      var storeInfo = data.store || {};
      var actionsInfo = data.actions || {};
      var dirsInfo = data.directives || [];

      var frameworks = storeInfo.frameworks || [];
      var storeKeys = Object.keys(storeInfo.stores || {});
      if (statusEl) {
        if (frameworks.length > 0) {
          statusEl.textContent =
            '检测到 ' + frameworks.join(', ') + ' | ' + storeKeys.length + ' 个 Store';
        } else {
          statusEl.textContent = '未检测到 Vuex/Pinia Store';
        }
      }

      var html = '';
      if (storeKeys.length === 0) {
        html += utils.emptyHtml('未发现 Vuex/Pinia Store 数据');
      } else {
        storeKeys.forEach(function (storeId) {
          var storeData = storeInfo.stores[storeId];
          html += '<div class="vue-store-card">';
          html += '<div class="vue-store-header">';
          html += '<span class="vue-store-name">' + utils.escapeHtml(storeId) + '</span>';
          html +=
            '<span class="vue-store-type">' +
            utils.escapeHtml(storeData.type || 'unknown') +
            '</span>';
          html += '</div>';
          html += renderStoreTree(storeData.state, '', 0);
          html += renderTagList(storeData.getters, 'vue-store-tag', 'Getters');
          html += renderTagList(
            storeData.mutations,
            'vue-store-tag vue-store-tag-mut',
            'Mutations'
          );
          html += renderTagList(storeData.actions, 'vue-store-tag vue-store-tag-act', 'Actions');
          html += '</div>';
        });
      }
      resultsEl.innerHTML = html;

      if (actionsEl) {
        var actionHtml = '';
        var actionNames = actionsInfo.actionNames || [];
        var getterNames = actionsInfo.getterNames || [];
        var apiEndpoints = actionsInfo.apiEndpoints || [];

        if (actionNames.length === 0 && apiEndpoints.length === 0) {
          actionHtml = utils.emptyHtml('未发现 Action 或 API 端点');
        } else {
          if (apiEndpoints.length > 0) {
            actionHtml += '<div class="vue-store-section">';
            actionHtml +=
              '<div class="vue-store-section-title">API 端点 (' + apiEndpoints.length + ')</div>';
            actionHtml += '<div class="vue-store-api-list">';
            apiEndpoints.forEach(function (ep) {
              actionHtml +=
                '<div class="vue-store-api-item" data-url="' + utils.escapeHtml(ep) + '">';
              actionHtml += '<code>' + utils.escapeHtml(ep) + '</code>';
              actionHtml +=
                '<button class="btn btn-sm btn-outline vue-api-copy-btn" data-url="' +
                utils.escapeHtml(ep) +
                '">复制</button>';
              actionHtml += '</div>';
            });
            actionHtml += '</div></div>';
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
            var url = btn.getAttribute('data-url') || '';
            utils.copyAndToast(url, '已复制: ' + url);
          });
        });
      }

      if (directivesEl) {
        var dirHtml = '';
        if (dirsInfo.length === 0) {
          dirHtml = utils.emptyHtml('未发现自定义指令');
        } else {
          dirHtml += '<div class="vue-dir-summary">发现 ' + dirsInfo.length + ' 个自定义指令</div>';
          dirsInfo.forEach(function (d) {
            dirHtml += '<div class="vue-dir-item">';
            dirHtml += '<span class="vue-dir-name">' + utils.escapeHtml(d.name) + '</span>';
            dirHtml += '<span class="vue-dir-count">' + d.count + ' 次</span>';
            if (d.examples && d.examples.length > 0) {
              dirHtml += '<div class="vue-dir-examples">';
              d.examples.forEach(function (ex) {
                dirHtml += '<code>' + utils.escapeHtml(ex) + '</code>';
              });
              dirHtml += '</div>';
            }
            dirHtml += '</div>';
          });
        }
        directivesEl.innerHTML = dirHtml;
      }

      var storeErrors = storeInfo.errors || [];
      if (storeErrors.length > 0 && statusEl) {
        statusEl.textContent += ' | 错误: ' + storeErrors.join('; ');
      }
    } catch (e) {
      if (statusEl) statusEl.textContent = '探索失败';
      if (resultsEl) resultsEl.innerHTML = utils.emptyHtml('错误: ' + e.message);
    }
  }

  function renderTagList(items, tagClass, label) {
    if (!items || items.length === 0) return '';
    var h = '<div class="vue-store-section">';
    h += '<div class="vue-store-section-title">' + label + ' (' + items.length + ')</div>';
    h += '<div class="vue-store-tags">';
    items.forEach(function (item) {
      h += '<span class="' + tagClass + '">' + utils.escapeHtml(item) + '</span>';
    });
    h += '</div></div>';
    return h;
  }

  function renderStoreTree(obj, prefix, depth) {
    if (depth > 5) return '<div class="vue-store-node vue-store-truncated">...</div>';
    if (obj === null || obj === undefined) return '';
    if (typeof obj !== 'object') return '';

    var html = '';
    var keys = Object.keys(obj);
    var maxShow = 30;
    var shown = 0;

    keys.forEach(function (key) {
      if (shown >= maxShow) return;
      shown++;
      var val = obj[key];
      var path = prefix ? prefix + '.' + key : key;
      var isExpandable =
        val !== null &&
        typeof val === 'object' &&
        !Array.isArray(val) &&
        Object.keys(val).length > 0;
      var isArr = Array.isArray(val);

      html += '<div class="vue-store-node">';
      html += '<div class="vue-store-key-row" data-path="' + utils.escapeHtml(path) + '">';

      if (isExpandable) {
        html += '<span class="vue-store-toggle vue-store-toggle-collapsed">&#9654;</span>';
      } else {
        html += '<span class="vue-store-toggle vue-store-toggle-leaf"></span>';
      }

      html += '<span class="vue-store-key">' + utils.escapeHtml(key) + '</span>';

      if (isArr) {
        html += '<span class="vue-store-type-badge">Array[' + val.length + ']</span>';
        html +=
          '<span class="vue-store-val">' +
          utils.escapeHtml(JSON.stringify(val).substring(0, 120)) +
          '</span>';
      } else if (typeof val === 'string') {
        html +=
          '<span class="vue-store-val">"' +
          utils.escapeHtml(val.substring(0, 100)) +
          (val.length > 100 ? '...' : '') +
          '"</span>';
      } else if (typeof val === 'number' || typeof val === 'boolean') {
        html += '<span class="vue-store-val">' + String(val) + '</span>';
      } else if (val === null) {
        html += '<span class="vue-store-val vue-store-null">null</span>';
      }

      html += '</div>';

      if (isExpandable) {
        html += '<div class="vue-store-children hidden">';
        html += renderStoreTree(val, path, depth + 1);
        html += '</div>';
      }

      html += '</div>';
    });

    if (keys.length > maxShow) {
      html += '<div class="vue-store-more">... 还有 ' + (keys.length - maxShow) + ' 个键</div>';
    }

    return html;
  }

  async function copyFullStoreJson() {
    try {
      return utils.withTab(async function (tab) {
        var data = await chrome.tabs.sendMessage(tab.id, { type: 'VK_VUE_STORE_EXPLORE' });
        if (!data || data.error) {
          utils.showToast('获取 Store 失败', 'error');
          return;
        }
        var json = JSON.stringify(data.store ? data.store.stores : {}, null, 2);
        await utils.copyText(json);
        utils.showToast('Store JSON 已复制 (' + json.length + ' 字符)');
      });
    } catch (e) {
      utils.showToast('复制失败: ' + e.message, 'error');
    }
  }

  function initStoreExplorerEvents() {
    var resultsEl = utils.get('vue-store-results');
    if (!resultsEl) return;

    resultsEl.addEventListener('click', function (e) {
      var toggle = e.target.closest('.vue-store-toggle-collapsed, .vue-store-toggle-expanded');
      if (toggle) {
        var node = toggle.closest('.vue-store-node');
        if (!node) return;
        var children = node.querySelector('.vue-store-children');
        if (!children) return;
        var isHidden = children.classList.contains('hidden');
        children.classList.toggle('hidden');
        toggle.classList.toggle('vue-store-toggle-collapsed');
        toggle.classList.toggle('vue-store-toggle-expanded');
        toggle.textContent = isHidden ? '▼' : '▶';
      }
    });
  }

  S.Store = {
    exploreVueStore: exploreVueStore,
    copyFullStoreJson: copyFullStoreJson,
    initStoreExplorerEvents: initStoreExplorerEvents,
  };
})();
