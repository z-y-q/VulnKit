// vk-vue-perm.js -- 灵眸 Chrome Extension
// Permission interception UI, classification, transforms, override
(function () {
  'use strict';

  var S = window.VulnKitVueState;
  var utils = S.utils;
  var ROLE_VALS_RE = S.ROLE_VALS_RE;
  var MENU_KEYWORDS = S.MENU_KEYWORDS;

  var ROLE_CONTROL_RE =
    /^(isadmin|admin|is_superuser|isvip|vip|role|isSuperAdmin|userType|user_type|level|grade)$/i;
  var MENU_ID_LIST_RE = /^menuIds$|^menu_ids$|^menuIdList$|^permissionIds$|^permIds$/i;

  function startPermAutoRefresh() {
    stopPermAutoRefresh();
    S.permRefreshTimer = setInterval(function () {
      if (S.permInterceptActive && S.permViewMode === 'list') {
        refreshPermCaptured();
      }
    }, 5000);
  }

  function stopPermAutoRefresh() {
    if (S.permRefreshTimer) {
      clearInterval(S.permRefreshTimer);
      S.permRefreshTimer = null;
    }
  }

  async function startPermInterception() {
    var statusEl = utils.get('perm-status');
    try {
      var tab = await utils.requireTabId();
      if (!tab) {
        if (statusEl) statusEl.textContent = '无法获取当前标签页';
        return;
      }
      var status = await utils.execInTabData(tab.id, S.PermInject.permInterceptorFunc, {
        args: [MENU_KEYWORDS],
      });
      if (status === 'already_injected') {
        await utils.execInTab(tab.id, function () {
          if (window.__PERM_INTERCEPTOR__) window.__PERM_INTERCEPTOR__.start();
        });
      }
      S.permInterceptActive = true;
      chrome.storage.local.set({ permInterceptTabId: tab.id });
      utils.toggleBtnPair('perm-start-btn', 'perm-stop-btn', true);
      if (statusEl) statusEl.textContent = '拦截中... 请操作页面触发菜单API请求，或刷新页面';
      utils.showToast('拦截已启动，请操作页面或刷新页面', 'success');
      try {
        await utils.execInTab(tab.id, S.PermInject.permStoreReaderFunc, { args: [MENU_KEYWORDS] });
      } catch (e) {
        /* ignore */
      }
      renderPermList();
      startPermAutoRefresh();
    } catch (e) {
      if (statusEl) statusEl.textContent = '启动失败: ' + e.message;
    }
  }

  async function stopPermInterception() {
    stopPermAutoRefresh();
    try {
      var tab = await utils.requireTabId();
      if (!tab) return;
      await utils.execInTab(tab.id, function () {
        if (window.__PERM_INTERCEPTOR__) window.__PERM_INTERCEPTOR__.stop();
      });
      S.permInterceptActive = false;
      chrome.storage.local.remove('permInterceptTabId');
      utils.toggleBtnPair('perm-start-btn', 'perm-stop-btn', false);
      utils.setStatus('perm-status', '拦截已停止');
      utils.showToast('拦截已停止', 'info');
    } catch (e) {
      S.permInterceptActive = false;
      chrome.storage.local.remove('permInterceptTabId');
      utils.setStatus('perm-status', '停止失败: ' + (e.message || '未知错误'));
      utils.showToast('停止拦截失败', 'error');
    }
  }

  async function refreshPermCaptured() {
    try {
      var tab = await utils.requireTabId();
      if (!tab) return;
      var result = (await utils.execInTabData(tab.id, function () {
        if (!window.__PERM_INTERCEPTOR__) return { items: [], length: 0 };
        var captured = window.__PERM_INTERCEPTOR__.getCaptured();
        return { items: captured, length: captured.length };
      })) || { items: [], length: 0 };
      if (result.length === S.permCapturedLength) return;
      S.permCapturedLength = result.length;
      S.permCapturedData = result.items || [];
      renderPermList();
    } catch (e) {
      utils.showToast('获取捕获数据失败', 'error');
    }
  }

  function renderPermList() {
    var container = utils.get('perm-captured-list');
    var countEl = utils.get('perm-count');
    if (!container) return;
    var filterVal = (utils.get('perm-filter') ? utils.get('perm-filter').value : '').toLowerCase();
    var typeFilter = utils.get('perm-type-filter') ? utils.get('perm-type-filter').value : 'all';

    var permCapturedData = S.permCapturedData;
    var filtered = permCapturedData.filter(function (item) {
      if (filterVal && item.url.toLowerCase().indexOf(filterVal) === -1) return false;
      if (typeFilter !== 'all' && item.type !== typeFilter) return false;
      return true;
    });

    if (filtered.length === 0) {
      utils.setEmpty('perm-captured-list', '暂无捕获数据，请先操作页面触发菜单请求');
      if (countEl)
        countEl.textContent =
          permCapturedData.length > 0 ? '共 ' + permCapturedData.length + ' 条 (筛选后 0)' : '';
      return;
    }

    if (countEl)
      countEl.textContent =
        '共 ' +
        permCapturedData.length +
        ' 条' +
        (filtered.length < permCapturedData.length ? ' (显示 ' + filtered.length + ')' : '');

    var html = '';
    for (var i = 0; i < filtered.length; i++) {
      var item = filtered[i];
      var realIdx = permCapturedData.indexOf(item);
      var cls = classifyPermType(item.data);
      var clsLabel = cls.label.split(' - ')[0];
      html += '<div class="perm-item" data-idx="' + realIdx + '">';
      html += '<span class="perm-item-type type-' + item.type + '">' + item.type + '</span>';
      html += '<span class="perm-item-cls ' + cls.cssClass + '">' + clsLabel + '</span>';
      html += '<span class="perm-item-url" title="' + utils.escapeHtml(item.url) + '">';
      html += utils.escapeHtml(item.url) + '</span>';
      html += '<span class="perm-item-size">' + (item.size / 1024).toFixed(1) + 'KB</span>';
      html += '</div>';
    }
    container.innerHTML = html;

    container.querySelectorAll('.perm-item').forEach(function (el) {
      el.addEventListener('click', function () {
        S.permSelectedIndex = parseInt(this.dataset.idx);
        showPermDetail(S.permSelectedIndex);
      });
    });
  }

  function showPermDetail(idx) {
    var item = S.permCapturedData[idx];
    if (!item) return;
    S.permViewMode = 'detail';
    var capturedList = utils.get('perm-captured-list');
    if (capturedList) capturedList.classList.add('hidden');
    var filterRow = utils.get('perm-filter-row');
    if (filterRow) filterRow.classList.add('hidden');
    var detailPanel = utils.get('perm-detail');
    if (!detailPanel) return;
    detailPanel.classList.remove('hidden');
    var urlEl = utils.get('perm-detail-url');
    if (urlEl) urlEl.textContent = item.url;
    var typeEl = utils.get('perm-detail-type');
    if (typeEl) typeEl.textContent = item.type.toUpperCase();

    var classification = classifyPermType(item.data);
    var classifyEl = utils.get('perm-classify');
    if (classifyEl) {
      classifyEl.textContent = classification.label;
      classifyEl.className = 'perm-classify ' + classification.cssClass;
    }

    showPermSuggestions(classification);

    var permEditor = utils.get('perm-json-editor');
    if (permEditor) permEditor.value = JSON.stringify(item.data, null, 2);
  }

  function classifyPermType(data) {
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      var keys = Object.keys(data);
      for (var k = 0; k < keys.length; k++) {
        var key = keys[k];
        if (ROLE_CONTROL_RE.test(key)) {
          var val = data[key];
          if (val === 0 || val === false || val === '0' || val === '' || val === null) {
            return {
              label: '特殊0开放 - ' + key + '=' + val + '，可修改为1/true/admin',
              cssClass: 'perm-classify-danger',
              type: 'special-zero',
            };
          }
          return {
            label: '特殊0开放 - 检测到角色控制字段',
            cssClass: 'perm-classify-warning',
            type: 'special-zero',
          };
        }
        if (/^type$/i.test(key)) {
          var tval = data[key];
          if (
            (typeof tval === 'string' && ROLE_VALS_RE.test(tval)) ||
            (typeof tval === 'number' && tval >= 0 && tval <= 10)
          ) {
            if (tval === 0 || /^(user|normal|guest)$/i.test(String(tval))) {
              return {
                label: '特殊0开放 - ' + key + '=' + tval + '，可修改为admin/1',
                cssClass: 'perm-classify-danger',
                type: 'special-zero',
              };
            }
            return {
              label: '特殊0开放 - 检测到角色控制字段 type=' + tval,
              cssClass: 'perm-classify-warning',
              type: 'special-zero',
            };
          }
        }
        if (MENU_ID_LIST_RE.test(key)) {
          var arr = data[key];
          if (
            Array.isArray(arr) &&
            arr.length > 0 &&
            arr.every(function (v) {
              return typeof v === 'number';
            })
          ) {
            return {
              label: '菜单ID限制 - ' + key + ': [' + arr.join(',') + ']，可展开范围',
              cssClass: 'perm-classify-info',
              type: 'menuid-limit',
            };
          }
        }
      }
    }
    if (Array.isArray(data) && data.length > 0) {
      var allHaveShowField = data.every(function (item) {
        return (
          item &&
          typeof item === 'object' &&
          ('isshow' in item ||
            'isShow' in item ||
            'hidden' in item ||
            'display' in item ||
            'status' in item)
        );
      });
      if (allHaveShowField) {
        var hasHidden = data.some(function (item) {
          return (
            item.isshow === '0' ||
            item.isShow === '0' ||
            item.hidden === true ||
            item.display === false ||
            item.status === 0
          );
        });
        if (hasHidden) {
          return {
            label: '全开放 - 所有菜单已返回，部分标记为隐藏 (isshow/display)',
            cssClass: 'perm-classify-success',
            type: 'full-open',
          };
        }
        return {
          label: '全开放 - 所有菜单已返回且均已显示',
          cssClass: 'perm-classify-success',
          type: 'full-open',
        };
      }
      return {
        label: '半开放 - 返回了部分菜单列表',
        cssClass: 'perm-classify-info',
        type: 'semi-open',
      };
    }
    if (Array.isArray(data) && data.length === 0) {
      return {
        label: '0开放 - 菜单返回为空，需要搜索JS源码',
        cssClass: 'perm-classify-danger',
        type: 'zero-open',
      };
    }
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      var inner = data.data || data.result || data.Data;
      if (Array.isArray(inner) && inner.length === 0) {
        return {
          label: '0开放 - 菜单返回为空，需要搜索JS源码',
          cssClass: 'perm-classify-danger',
          type: 'zero-open',
        };
      }
    }
    return {
      label: '未知类型 - 请手动检查数据结构',
      cssClass: 'perm-classify-unknown',
      type: 'unknown',
    };
  }

  function showPermSuggestions(classification) {
    var sugEl = utils.get('perm-suggestions');
    if (!sugEl) return;
    var cType = classification.type || 'unknown';
    var html = '<span class="perm-suggestion-hint">建议操作：</span>';

    var actionBtns = document.querySelectorAll('.perm-detail-actions .btn');
    actionBtns.forEach(function (b) {
      b.classList.remove('btn-suggested');
    });

    if (cType === 'full-open') {
      var openAllBtn = utils.get('perm-open-all');
      if (openAllBtn) openAllBtn.classList.add('btn-suggested');
      html += '<span class="perm-suggestion-hint">点击上方高亮的「全部显示」按钮</span>';
    } else if (cType === 'semi-open') {
      html +=
        '<button class="btn btn-sm btn-primary" id="sug-compare-inject">对比并补全缺失菜单</button>';
    } else if (cType === 'zero-open') {
      html +=
        '<button class="btn btn-sm btn-primary" id="sug-auto-search">自动搜索JS菜单定义</button>';
    } else if (cType === 'special-zero') {
      var adminBtn = utils.get('perm-change-admin');
      if (adminBtn) adminBtn.classList.add('btn-suggested');
      html += '<span class="perm-suggestion-hint">点击上方高亮的「提权至管理员」按钮</span>';
    } else if (cType === 'menuid-limit') {
      var expandBtn = utils.get('perm-expand-ids');
      if (expandBtn) expandBtn.classList.add('btn-suggested');
      html += '<span class="perm-suggestion-hint">点击上方高亮的「展开menuIds」按钮</span>';
    } else {
      sugEl.innerHTML = '';
      sugEl.classList.add('hidden');
      return;
    }
    sugEl.innerHTML = html;
    sugEl.classList.remove('hidden');

    var sugCompareInject = utils.get('sug-compare-inject');
    if (sugCompareInject)
      sugCompareInject.addEventListener('click', async function () {
        try {
          S.switchVueSubTab('compare');
          await S.Compare.compareRoutesAndMenu();
          if (S.lastCompareHiddenRoutes.length > 0) {
            S.switchVueSubTab('perm');
            if (S.permSelectedIndex < 0 && S.permCapturedData.length > 0) {
              S.permSelectedIndex = 0;
              showPermDetail(0);
            }
            S.Compare.autoInjectHiddenRoutes();
          } else {
            utils.showToast('路由对比未发现隐藏路由', 'info');
            S.switchVueSubTab('perm');
          }
        } catch (e) {
          utils.showToast('对比执行失败: ' + (e instanceof Error ? e.message : String(e)), 'error');
        }
      });
    var sugAutoSearch = utils.get('sug-auto-search');
    if (sugAutoSearch)
      sugAutoSearch.addEventListener('click', function () {
        S.JsSearch.autoSearchForZeroOpen();
      });
  }

  function transformShowAll(data) {
    if (Array.isArray(data)) {
      return data.map(function (item) {
        if (item && typeof item === 'object') {
          var c = {};
          for (var k in item) {
            if (item.hasOwnProperty(k)) c[k] = item[k];
          }
          if ('isshow' in c) c.isshow = '1';
          if ('isShow' in c) c.isShow = '1';
          if ('hidden' in c) c.hidden = false;
          if ('display' in c) c.display = true;
          if ('status' in c) c.status = 1;
          if ('visible' in c) c.visible = true;
          if (c.children) c.children = transformShowAll(c.children);
          if (c.child) c.child = transformShowAll(c.child);
          if (c.subList) c.subList = transformShowAll(c.subList);
          return c;
        }
        return item;
      });
    }
    if (data && typeof data === 'object') {
      var c = {};
      for (var k in data) {
        if (data.hasOwnProperty(k)) c[k] = transformShowAll(data[k]);
      }
      return c;
    }
    return data;
  }

  function applyEditorTransform(transformFn, successMsg) {
    var editor = utils.get('perm-json-editor');
    if (!editor) return;
    try {
      var data = JSON.parse(editor.value);
      data = transformFn(data);
      editor.value = JSON.stringify(data, null, 2);
      utils.showToast(successMsg, 'success');
    } catch (e) {
      utils.showToast('JSON 解析失败', 'error');
    }
  }

  function permOpenAll() {
    applyEditorTransform(transformShowAll, '已将所有 isshow/display 改为显示');
  }

  function transformAdmin(data) {
    if (typeof data !== 'object' || data === null) return data;
    if (Array.isArray(data)) return data.map(transformAdmin);
    var c = {};
    for (var k in data) {
      if (!data.hasOwnProperty(k)) continue;
      if (
        /^(isadmin|admin|is_superuser|isvip|vip|role|isSuperAdmin|userType|user_type|level|grade)$/i.test(
          k
        )
      ) {
        c[k] = typeof data[k] === 'string' ? '1' : 1;
      } else if (k === 'roleId' || k === 'role_id') {
        c[k] = 1;
      } else if (/^type$/i.test(k)) {
        var tv = data[k];
        if (
          (typeof tv === 'string' && ROLE_VALS_RE.test(tv)) ||
          (typeof tv === 'number' && tv >= 0 && tv <= 10)
        ) {
          c[k] = typeof tv === 'string' ? 'admin' : 1;
        } else {
          c[k] = tv;
        }
      } else if (typeof data[k] === 'object') {
        c[k] = transformAdmin(data[k]);
      } else {
        c[k] = data[k];
      }
    }
    return c;
  }

  function permChangeAdmin() {
    applyEditorTransform(transformAdmin, '已提权：角色/管理员字段已修改');
  }

  function expandMenuIds(data) {
    if (typeof data !== 'object' || data === null) return data;
    if (Array.isArray(data)) return data.map(expandMenuIds);
    var c = {};
    for (var k in data) {
      if (!data.hasOwnProperty(k)) continue;
      if (/menuIds|menu_ids|menuIdList|permissionIds|permIds/i.test(k) && Array.isArray(data[k])) {
        var allNum = data[k].every(function (v) {
          return typeof v === 'number';
        });
        if (allNum && data[k].length > 0) {
          var max = Math.max.apply(null, data[k]);
          var end = Math.max(max, 50);
          var expanded = [];
          for (var i = 1; i <= end; i++) expanded.push(i);
          c[k] = expanded;
          if (data.hasOwnProperty('total') || data.hasOwnProperty('Total')) {
            var tKey = data.hasOwnProperty('total') ? 'total' : 'Total';
            c[tKey] = expanded.length;
          }
          continue;
        }
      }
      if (typeof data[k] === 'object') {
        c[k] = expandMenuIds(data[k]);
      } else {
        c[k] = data[k];
      }
    }
    return c;
  }

  function permExpandMenuIds() {
    applyEditorTransform(expandMenuIds, '已展开菜单ID范围');
  }

  async function applyPermOverride() {
    var editor = utils.get('perm-json-editor');
    if (!editor) {
      utils.showToast('编辑器未就绪', 'error');
      return;
    }
    var modifiedData;
    try {
      modifiedData = JSON.parse(editor.value);
    } catch (e) {
      utils.showToast('JSON 格式错误', 'error');
      return;
    }

    try {
      var tab = await utils.requireTabId();
      if (!tab) {
        utils.showToast('无法获取当前标签页', 'error');
        return;
      }
      var overrideResult = await utils.execInTabData(
        tab.id,
        function (overrideData) {
          if (!window.__PERM_INTERCEPTOR__) return false;
          window.__PERM_INTERCEPTOR__.setOverride(overrideData);

          function patchDeepState(state, override) {
            if (!state || typeof state !== 'object' || Array.isArray(state)) return false;
            for (var key in state) {
              if (!state.hasOwnProperty(key)) continue;
              if (!/menu|permission|route|nav|sidebar/i.test(key)) continue;
              var val = state[key];
              if (Array.isArray(val)) {
                if (typeof state.__ob__ === 'object' && state.__ob__) {
                  try {
                    state[key].splice(0, state[key].length);
                  } catch (e) {
                    /* ignore */
                  }
                  try {
                    override.forEach(function (item) {
                      state[key].push(item);
                    });
                  } catch (e) {
                    /* ignore */
                  }
                } else {
                  state[key] = override;
                }
                return true;
              }
              if (val && typeof val === 'object' && !Array.isArray(val)) {
                if (patchDeepState(val, override)) return true;
              }
            }
            return false;
          }

          var appEl = document.querySelector(S.VUE_ROOT_SELECTOR);
          if (appEl && appEl.__vue_app__) {
            var pinia = appEl.__vue_app__.config.globalProperties.$pinia;
            if (pinia && pinia._s) {
              pinia._s.forEach(function (store) {
                var state = store.$state;
                for (var key in state) {
                  if (!state.hasOwnProperty(key)) continue;
                  if (!/menu|permission|route|nav|sidebar/i.test(key)) continue;
                  var val = state[key];
                  if (Array.isArray(val)) {
                    if (store.$patch) {
                      var patch = {};
                      patch[key] = overrideData;
                      store.$patch(patch);
                    } else {
                      state[key] = overrideData;
                    }
                  } else if (val && typeof val === 'object') {
                    patchDeepState(val, overrideData);
                  }
                }
              });
            }
          }

          var allEls = document.querySelectorAll('*');
          for (var i = 0; i < allEls.length; i++) {
            if (allEls[i].__vue__) {
              var vm = allEls[i].__vue__.$root || allEls[i].__vue__;
              if (vm.$store && vm.$store.state) {
                patchDeepState(vm.$store.state, overrideData);
              }
              break;
            }
          }

          var storagePatchCount = 0;
          var storagePrefixes = ['menu', 'permission', 'routes', 'nav', 'sidebar', 'role', 'auth'];
          var storageTargets = [localStorage, sessionStorage];
          for (var st = 0; st < storageTargets.length; st++) {
            var storage = storageTargets[st];
            try {
              for (var si = 0; si < storage.length; si++) {
                var sKey = storage.key(si);
                if (!sKey) continue;
                var sKeyLower = sKey.toLowerCase();
                var matched = false;
                for (var sp = 0; sp < storagePrefixes.length; sp++) {
                  if (sKeyLower.indexOf(storagePrefixes[sp]) !== -1) {
                    matched = true;
                    break;
                  }
                }
                if (!matched) continue;
                try {
                  var sVal = storage.getItem(sKey);
                  var sParsed = JSON.parse(sVal);
                  if (Array.isArray(sParsed)) {
                    storage.setItem(sKey, JSON.stringify(overrideData));
                    storagePatchCount++;
                  } else if (sParsed && typeof sParsed === 'object' && !Array.isArray(sParsed)) {
                    var patched = false;
                    for (var sk in sParsed) {
                      if (!sParsed.hasOwnProperty(sk)) continue;
                      if (
                        /menu|permission|route|nav|sidebar/i.test(sk) &&
                        Array.isArray(sParsed[sk])
                      ) {
                        sParsed[sk] = overrideData;
                        patched = true;
                      }
                    }
                    if (patched) {
                      storage.setItem(sKey, JSON.stringify(sParsed));
                      storagePatchCount++;
                    }
                  }
                } catch (e) {
                  /* ignore */
                }
              }
            } catch (e) {
              /* ignore */
            }
          }
          return { success: true, storagePatchCount: storagePatchCount };
        },
        { args: [modifiedData] }
      );
      if (!overrideResult || !overrideResult.success) {
        utils.showToast('拦截器未注入，请先启动权限拦截', 'error');
        return;
      }
      var msg = '已应用修改（拦截器 + Vue存储';
      if (overrideResult.storagePatchCount > 0) {
        msg += ' + ' + overrideResult.storagePatchCount + '个本地缓存';
      }
      msg += '）→ 请在页面上点击菜单或刷新页面，检查是否出现新菜单项';
      utils.showToast(msg, 'success');
    } catch (e) {
      utils.showToast('应用失败: ' + e.message, 'error');
    }
  }

  S.Perm = {
    startPermInterception: startPermInterception,
    stopPermInterception: stopPermInterception,
    refreshPermCaptured: refreshPermCaptured,
    renderPermList: renderPermList,
    showPermDetail: showPermDetail,
    classifyPermType: classifyPermType,
    showPermSuggestions: showPermSuggestions,
    permOpenAll: permOpenAll,
    permChangeAdmin: permChangeAdmin,
    permExpandMenuIds: permExpandMenuIds,
    applyPermOverride: applyPermOverride,
    startPermAutoRefresh: startPermAutoRefresh,
    stopPermAutoRefresh: stopPermAutoRefresh,
  };
})();
