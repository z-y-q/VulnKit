// VulnKit - RuoYi Hook Sub-module
// Route hook install/remove/check, request log, route rendering, export functions
window.VulnKitRuoYiHook = (function () {
  'use strict';

  var state = null;
  var common = window.VulnKitRuoYiCommon;
  var utils = common ? common.utils : {};
  var updateWorkflowStep = common ? common.updateWorkflowStep : null;

  // ====== Route Hook ======

  function setHookUI(active) {
    var installBtn = utils.get('ruoyi-hook-install-btn');
    var removeBtn = utils.get('ruoyi-hook-remove-btn');
    if (installBtn) installBtn.disabled = active;
    if (removeBtn) removeBtn.disabled = !active;
  }

  async function injectHookCode(tabId) {
    try {
      await utils.execInTab(tabId, ['src/inject/ruoyi-route-hook.js']);
      return 'files';
    } catch (e) {
      try {
        await chrome.tabs.sendMessage(tabId, { type: 'VK_RUOYI_INJECT_HOOK' });
        for (var i = 0; i < 10; i++) {
          await new Promise(function (r) {
            setTimeout(r, 100);
          });
          var check = await utils.execInTab(tabId, function () {
            return !!window.__VK_RUOYI_HOOK__;
          });
          if (utils.execResult(check)) return 'content-script';
        }
        return null;
      } catch (e2) {
        return null;
      }
    }
  }

  function enableHookFunc(opts) {
    if (window.__VK_RUOYI_HOOK__) {
      window.__VK_RUOYI_HOOK__.enabled = true;
      window.__VK_RUOYI_HOOK__.augmentMode = opts.mode || 'auto';
      window.__VK_RUOYI_HOOK__.requestLog = [];
      if (opts.customUrl) {
        window.__VK_RUOYI_HOOK__.customRouterUrls = [opts.customUrl];
      }
      if (typeof window.__VK_RUOYI_HOOK__.saveConfig === 'function') {
        window.__VK_RUOYI_HOOK__.saveConfig();
      }
      return true;
    }
    return false;
  }

  async function installRouteHook() {
    var augmentMode = state ? state.augmentMode : 'auto';
    try {
      var tab = await utils.requireTabId();
      if (!tab) {
        utils.setStatus('ruoyi-hook-status', '无法获取当前标签页');
        return;
      }

      utils.setStatus('ruoyi-hook-status', '启用钩子中...');

      var customUrlInput = utils.get('ruoyi-custom-url');
      var customUrl = (customUrlInput && customUrlInput.value.trim()) || '';

      var hookResult = await utils.execInTab(tab.id, enableHookFunc, {
        args: [{ mode: augmentMode, customUrl: customUrl }],
      });

      if (utils.execResult(hookResult)) {
        if (state) {
          state.ruoyiHookActive = true;
          state.ruoyiTabId = tab.id;
          state.hookStatus = 'active';
        }
        chrome.storage.local.set({ ruoyiHookTabId: tab.id, ruoyiHookEnabled: true });
        setHookUI(true);

        var capCheck = await utils.execInTab(tab.id, function () {
          var hook = window.__VK_RUOYI_HOOK__;
          return {
            captured: !!hook.capturedRouters,
            logCount: (hook.requestLog || []).length,
          };
        });
        var capData = utils.execResult(capCheck);

        if (capData && capData.captured) {
          utils.setStatus('ruoyi-hook-status', '钩子已启用 — 路由数据已被动捕获');
          utils.showToast('路由数据已捕获', 'success');
          await checkHookStatus();
        } else {
          utils.setStatus(
            'ruoyi-hook-status',
            '钩子已启用，等待 /getRouters 请求（刷新页面或登录后自动捕获）'
          );
          utils.showToast('钩子已启用，刷新页面或登录以触发 /getRouters', 'success');
        }
        return;
      }

      utils.setStatus('ruoyi-hook-status', '动态注入钩子中...');
      var method = await injectHookCode(tab.id);

      if (!method) {
        utils.setStatus('ruoyi-hook-status', '所有注入方式均失败');
        utils.showToast('注入失败 — 请刷新目标页面后重试', 'error');
        return;
      }

      await new Promise(function (r) {
        setTimeout(r, 400);
      });

      var retryResult = await utils.execInTab(tab.id, enableHookFunc, {
        args: [{ mode: augmentMode, customUrl: customUrl }],
      });

      if (!utils.execResult(retryResult)) {
        utils.setStatus('ruoyi-hook-status', '注入后未检测到钩子');
        utils.showToast('钩子注入失败 [' + method + ']，请刷新页面后重试', 'warning');
        return;
      }

      if (state) {
        state.ruoyiHookActive = true;
        state.ruoyiTabId = tab.id;
        state.hookStatus = 'active';
      }
      chrome.storage.local.set({ ruoyiHookTabId: tab.id, ruoyiHookEnabled: true });
      setHookUI(true);
      updateWorkflowStep(2);
      utils.setStatus('ruoyi-hook-status', '钩子已启用，正在刷新页面...');
      utils.showToast('钩子已启用，刷新页面以捕获 /getRouters', 'success');
      await chrome.tabs.reload(tab.id);
    } catch (e) {
      if (state) state.hookStatus = 'idle';
      utils.setStatus('ruoyi-hook-status', '安装失败');
      utils.showToast('安装失败: ' + e.message, 'error');
    }
  }

  async function removeRouteHook() {
    try {
      return utils.withTab(async function (tab) {
        await utils.execInTab(tab.id, function () {
          if (window.__VK_RUOYI_HOOK__) {
            window.__VK_RUOYI_HOOK__.enabled = false;
            window.__VK_RUOYI_HOOK__.extraRoutes = [];
            window.__VK_RUOYI_HOOK__.capturedRouters = null;
            window.__VK_RUOYI_HOOK__.requestLog = [];
            window.__VK_RUOYI_HOOK__.customRouterUrls = [];
            if (typeof window.__VK_RUOYI_HOOK__.clearConfig === 'function') {
              window.__VK_RUOYI_HOOK__.clearConfig();
            }
          }
        });

        if (state) {
          state.ruoyiHookActive = false;
          state.ruoyiTabId = null;
          state.hookStatus = 'idle';
        }
        chrome.storage.local.remove(['ruoyiHookTabId', 'ruoyiHookEnabled']);

        setHookUI(false);
        utils.setStatus('ruoyi-hook-status', '钩子已禁用');
        utils.showToast('路由钩子已禁用', 'info');
      });
    } catch (e) {
      utils.showToast('移除失败: ' + e.message, 'error');
    }
  }

  async function checkHookStatus() {
    var panelEl = utils.get('ruoyi-captured-panel');
    try {
      return utils.withTab(async function (tab) {
        var results = await utils.execInTab(tab.id, function () {
          var hook = window.__VK_RUOYI_HOOK__;
          if (!hook) return { installed: false, pageUrl: location.href };
          return {
            installed: true,
            pageUrl: location.href,
            enabled: hook.enabled,
            alwaysCapture: !!hook.alwaysCapture,
            captured: !!hook.capturedRouters,
            augmentMode: hook.augmentMode,
            extraRouteCount: (hook.extraRoutes || []).length,
            logCount: (hook.requestLog || []).length,
            customUrls: hook.customRouterUrls || [],
            restored: !!hook.restoredFromStorage,
          };
        });

        var data = utils.execResult(results) || { installed: false };

        if (!data.installed) {
          var urlHint = data.pageUrl ? ' [' + utils.escapeHtml(data.pageUrl) + ']' : '';
          utils.setStatus('ruoyi-hook-status', '钩子未安装，页面: ' + (data.pageUrl || '未知'));
          if (state) state.hookStatus = 'idle';
          if (panelEl)
            panelEl.innerHTML = utils.emptyHtml('钩子未注入 — 请先点击「安装钩子」' + urlHint);
        } else if (data.captured) {
          if (state) state.hookStatus = data.enabled ? 'captured' : 'passive-captured';
          updateWorkflowStep(2);
          setHookUI(data.enabled);
          var modeText = data.enabled ? data.augmentMode || 'auto' : '被动捕获';
          var extras =
            data.enabled && data.extraRouteCount > 0
              ? '，' + data.extraRouteCount + ' 条额外路由'
              : '';
          utils.setStatus(
            'ruoyi-hook-status',
            '已捕获路由数据 (' + modeText + ' 模式' + extras + ')'
          );
          // Delegate to detect module for data fetching
          if (
            window.VulnKitRuoYiDetect &&
            typeof window.VulnKitRuoYiDetect.fetchCapturedRoutes === 'function'
          ) {
            await window.VulnKitRuoYiDetect.fetchCapturedRoutes();
          }
        } else if (!data.enabled) {
          utils.setStatus(
            'ruoyi-hook-status',
            data.alwaysCapture
              ? '钩子已注入（被动捕获模式），等待 /getRouters...'
              : '钩子已安装但未启用'
          );
          if (state) state.hookStatus = 'idle';
          setHookUI(false);
          renderRequestLog(tab.id);
        } else {
          var logInfo = data.logCount > 0 ? '，已拦截 ' + data.logCount + ' 个请求' : '';
          utils.setStatus('ruoyi-hook-status', '监听中，等待 /getRouters 请求...' + logInfo);
          if (state) state.hookStatus = 'active';
          setHookUI(true);
          renderRequestLog(tab.id);
        }
      });
    } catch (e) {
      utils.setStatus('ruoyi-hook-status', '检查失败');
    }
  }

  // ====== Request Log ======

  async function renderRequestLog(tabId) {
    try {
      var results = await utils.execInTab(tabId, function () {
        var hook = window.__VK_RUOYI_HOOK__;
        if (!hook || !hook.requestLog) return [];
        return hook.requestLog.slice(-20);
      });

      var log = utils.execResult(results) || [];
      if (log.length === 0) return;

      var panelEl = utils.get('ruoyi-captured-panel');
      if (!panelEl) return;

      var html = '<div class="ruoyi-log-section">';
      html += '<div class="ruoyi-log-title">请求拦截日志 (' + log.length + ')</div>';
      html += '<div class="ruoyi-log-list">';
      log.forEach(function (entry) {
        var cls = 'log-info';
        if (entry.type === 'router') cls = 'log-router';
        else if (entry.type === 'router-error') cls = 'log-error';
        else if (entry.type === 'userinfo') cls = 'log-userinfo';
        html += '<div class="ruoyi-log-entry ' + cls + '">';
        html +=
          '<span class="ruoyi-log-type">' + utils.escapeHtml(entry.method || 'GET') + '</span>';
        html += '<span class="ruoyi-log-url">' + utils.escapeHtml(entry.url || '') + '</span>';
        html +=
          '<span class="ruoyi-log-status">' +
          utils.escapeHtml(String(entry.status || '')) +
          '</span>';
        html += '<span class="ruoyi-log-time">' + utils.escapeHtml(entry.time || '') + '</span>';
        html += '</div>';
      });
      html += '</div></div>';
      panelEl.innerHTML = html;
    } catch (e) {
      // ignore
    }
  }

  // ====== Route Rendering ======

  function renderRouterData(data, containerEl) {
    if (!containerEl) return;
    var routes = data.data || data;
    if (!Array.isArray(routes)) {
      containerEl.innerHTML = utils.emptyHtml(data._raw ? '响应解析失败' : '无路由数据');
      return;
    }

    var totalPaths = 0;
    var hiddenCount = 0;
    (function count(rts) {
      rts.forEach(function (r) {
        totalPaths++;
        if (r.hidden) hiddenCount++;
        if (r.children) count(r.children);
      });
    })(routes);

    var html = '<div class="ruoyi-route-toolbar">';
    html +=
      '<div class="ruoyi-route-summary">' +
      routes.length +
      ' 个顶级路由，' +
      totalPaths +
      ' 个节点' +
      (hiddenCount > 0
        ? '，<span class="ruoyi-hidden-count">' + hiddenCount + ' 个隐藏</span>'
        : '') +
      '</div>';
    html += '<div class="ruoyi-route-actions">';
    html += '<button class="btn btn-xs btn-outline" id="ruoyi-expand-all">全部展开</button>';
    html += '<button class="btn btn-xs btn-outline" id="ruoyi-collapse-all">全部收起</button>';
    html +=
      '<input type="text" class="ruoyi-search-input" id="ruoyi-route-search" placeholder="搜索路由...">';
    html += '</div></div>';
    html += '<div class="ruoyi-route-tree">';
    routes.forEach(function (r) {
      html += renderRouteNode(r, 0);
    });
    html += '</div>';
    containerEl.innerHTML = html;

    containerEl.querySelectorAll('.ruoyi-route-toggle').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var children = btn.closest('.ruoyi-route-node').querySelector('.ruoyi-route-children');
        if (children) {
          var hidden = children.style.display === 'none';
          children.style.display = hidden ? '' : 'none';
          btn.textContent = hidden ? '▼' : '▶';
        }
      });
    });

    var expandBtn = containerEl.querySelector('#ruoyi-expand-all');
    var collapseBtn = containerEl.querySelector('#ruoyi-collapse-all');
    if (expandBtn) {
      expandBtn.addEventListener('click', function () {
        containerEl.querySelectorAll('.ruoyi-route-children').forEach(function (c) {
          c.style.display = '';
        });
        containerEl.querySelectorAll('.ruoyi-route-toggle').forEach(function (t) {
          t.textContent = '▼';
        });
      });
    }
    if (collapseBtn) {
      collapseBtn.addEventListener('click', function () {
        containerEl.querySelectorAll('.ruoyi-route-children').forEach(function (c) {
          c.style.display = 'none';
        });
        containerEl.querySelectorAll('.ruoyi-route-toggle').forEach(function (t) {
          if (t.textContent === '▼') t.textContent = '▶';
        });
      });
    }

    var searchInput = containerEl.querySelector('#ruoyi-route-search');
    if (searchInput) {
      searchInput.addEventListener('input', function () {
        var query = this.value.toLowerCase().trim();
        containerEl.querySelectorAll('.ruoyi-route-node').forEach(function (node) {
          if (!query) {
            node.style.display = '';
            return;
          }
          var path = (node.querySelector('.ruoyi-route-path') || {}).textContent || '';
          var name = (node.querySelector('.ruoyi-route-name') || {}).textContent || '';
          var title = (node.querySelector('.ruoyi-route-title') || {}).textContent || '';
          var match =
            path.toLowerCase().indexOf(query) !== -1 ||
            name.toLowerCase().indexOf(query) !== -1 ||
            title.toLowerCase().indexOf(query) !== -1;
          node.style.display = match ? '' : 'none';
          if (match) {
            var parent = node.parentElement;
            while (parent) {
              if (parent.classList && parent.classList.contains('ruoyi-route-children')) {
                parent.style.display = '';
                var toggle = parent.previousElementSibling;
                if (toggle && toggle.classList.contains('ruoyi-route-toggle')) {
                  toggle.textContent = '▼';
                }
              }
              if (parent.classList && parent.classList.contains('ruoyi-route-node')) {
                parent.style.display = '';
              }
              parent = parent.parentElement;
            }
          }
        });
      });
    }
  }

  function renderRouteNode(route, depth) {
    var indent = depth * 16;
    var path = route.path || '/';
    var name = route.name || '';
    var title = (route.meta && route.meta.title) || '';
    var hidden = route.hidden;
    var hasChildren = route.children && route.children.length > 0;
    var component = route.component || '';

    var html =
      '<div class="ruoyi-route-node' +
      (hidden ? ' node-hidden' : '') +
      '" ' +
      'style="padding-left:' +
      indent +
      'px" data-path="' +
      utils.escapeHtml(path) +
      '">';
    html += '<span class="ruoyi-route-toggle">' + (hasChildren ? '▼' : '►') + '</span>';
    if (hidden) html += '<span class="ruoyi-route-hidden" title="hidden">H</span>';
    var metaType = route.meta && route.meta.type;
    if (metaType) {
      var typeLabels = { M: '目录', C: '菜单', F: '按钮' };
      var typeLabel = typeLabels[metaType] || metaType;
      html +=
        '<span class="ruoyi-route-type" title="type:' +
        utils.escapeHtml(metaType) +
        '">' +
        utils.escapeHtml(typeLabel) +
        '</span>';
    }
    if (route.meta && route.meta.noCache) {
      html += '<span class="ruoyi-route-nocache" title="noCache">NC</span>';
    }
    html += '<span class="ruoyi-route-path">' + utils.escapeHtml(path) + '</span>';
    if (name) html += '<span class="ruoyi-route-name">' + utils.escapeHtml(name) + '</span>';
    if (title) html += '<span class="ruoyi-route-title">' + utils.escapeHtml(title) + '</span>';
    if (component && typeof component === 'string') {
      html +=
        '<span class="ruoyi-route-component">' +
        utils.escapeHtml(component.split('/').pop()) +
        '</span>';
    }
    if (route.meta && route.meta.roles) {
      var roles = Array.isArray(route.meta.roles) ? route.meta.roles : [route.meta.roles];
      if (roles.length > 0) {
        html +=
          '<span class="ruoyi-route-roles" title="' +
          utils.escapeHtml(roles.join(', ')) +
          '">' +
          utils.escapeHtml(roles.length > 2 ? roles[0] + ',...' : roles.join(', ')) +
          '</span>';
      }
    }
    if (route.meta && route.meta.perms) {
      var perms = Array.isArray(route.meta.perms) ? route.meta.perms : [route.meta.perms];
      if (perms.length > 0) {
        html +=
          '<span class="ruoyi-route-perms" title="' +
          utils.escapeHtml(perms.join(', ')) +
          '">' +
          utils.escapeHtml(perms.length > 2 ? perms[0] + ',...' : perms.join(', ')) +
          '</span>';
      }
    }
    if (hasChildren) {
      html += '<div class="ruoyi-route-children">';
      route.children.forEach(function (child) {
        html += renderRouteNode(child, depth + 1);
      });
      html += '</div>';
    }
    html += '</div>';
    return html;
  }

  // ====== Export Functions ======

  function extractPathsFromData(routes, out) {
    if (!Array.isArray(routes)) return;
    routes.forEach(function (r) {
      if (
        r.path &&
        r.path !== '/' &&
        r.component &&
        r.component !== 'Layout' &&
        r.component !== 'ParentView'
      ) {
        out.push(r.path);
      }
      if (r.children) extractPathsFromData(r.children, out);
    });
  }

  async function exportCurlCommands() {
    var capturedRouterData = state ? state.capturedRouterData : null;
    if (!capturedRouterData) {
      utils.showToast('没有捕获的路由数据', 'warning');
      return;
    }

    try {
      var tab = await utils.requireTabId();
      if (!tab) {
        utils.showToast('无法获取当前标签页', 'warning');
        return;
      }
      var baseUrl = tab.url ? new URL(tab.url).origin : 'http://target';
      var paths = [];
      extractPathsFromData(capturedRouterData.data || capturedRouterData, paths);

      var cookieHeader = '';
      try {
        var cookieResult = await utils.execInTab(tab.id, function () {
          var cookies = document.cookie || '';
          var match = cookies.match(/Admin-Token=[^;]*/i);
          return match ? match[0] : '';
        });
        var token = utils.execResult(cookieResult);
        if (token) {
          var safeToken = token.replace(/'/g, "'\\''");
          cookieHeader = " -H 'Cookie: " + safeToken + "'";
        }
      } catch (e) {
        // ignore
      }

      var cmds = paths.map(function (p) {
        var safePath = p.replace(/'/g, "'\\''");
        return (
          "curl -s '" +
          baseUrl +
          safePath +
          "'" +
          cookieHeader +
          " -o /dev/null -w '%{http_code} " +
          safePath +
          "\\n'"
        );
      });
      utils.copyText(cmds.join('\n'));
      utils.showToast(
        '已复制 ' + cmds.length + ' 条 curl 命令' + (cookieHeader ? ' (含认证)' : ''),
        'success'
      );
    } catch (e) {
      utils.showToast('导出失败: ' + e.message, 'error');
    }
  }

  async function exportHtmlReport() {
    var capturedRouterData = state ? state.capturedRouterData : null;
    var extraRoutes = state ? state.extraRoutes : [];
    if (!capturedRouterData && extraRoutes.length === 0) {
      utils.showToast('没有数据可导出', 'warning');
      return;
    }

    var routes = (capturedRouterData && capturedRouterData.data) || [];
    var html =
      '<!DOCTYPE html><html><head><meta charset="UTF-8">' +
      '<title>RuoYi Route Report</title>' +
      '<style>body{font-family:monospace;font-size:13px;padding:20px}table{border-collapse:collapse;width:100%}' +
      'th,td{border:1px solid #ddd;padding:6px 10px;text-align:left}th{background:#f5f5f5}' +
      '.hidden{color:#999;font-style:italic}.section{margin:20px 0 10px;font-weight:bold;font-size:15px}</style>' +
      '</head><body>';

    if (routes.length > 0) {
      html += '<div class="section">Captured Routes</div>';
      html +=
        '<table><tr><th>Path</th><th>Name</th><th>Title</th><th>Component</th><th>Hidden</th></tr>';
      renderFlatRoutes(routes, function (row) {
        html += row;
      });
      html += '</table>';
    }

    if (extraRoutes.length > 0) {
      html += '<div class="section">Extra Routes (Not Registered)</div>';
      html += '<table><tr><th>Path</th><th>Source</th><th>Type</th></tr>';
      extraRoutes.forEach(function (r) {
        html +=
          '<tr><td>' +
          utils.escapeHtml(r.path || r.component || '') +
          '</td>' +
          '<td>' +
          utils.escapeHtml(r.source || '') +
          '</td><td>' +
          utils.escapeHtml(r.type || '') +
          '</td></tr>';
      });
      html += '</table>';
    }

    html += '</body></html>';
    utils.copyAndToast(html, 'HTML 报告已复制到剪贴板');
  }

  function renderFlatRoutes(routes, emit) {
    routes.forEach(function (r) {
      var hidden = r.hidden ? ' class="hidden"' : '';
      emit(
        '<tr' +
          hidden +
          '><td>' +
          utils.escapeHtml(r.path || '') +
          '</td>' +
          '<td>' +
          utils.escapeHtml(r.name || '') +
          '</td>' +
          '<td>' +
          utils.escapeHtml((r.meta && r.meta.title) || '') +
          '</td>' +
          '<td>' +
          utils.escapeHtml(r.component || '') +
          '</td>' +
          '<td>' +
          (r.hidden ? 'Yes' : '') +
          '</td></tr>'
      );
      if (r.children) renderFlatRoutes(r.children, emit);
    });
  }

  // ====== Init ======

  function init(stateRef) {
    state = stateRef;
  }

  return {
    init: init,
    installRouteHook: installRouteHook,
    removeRouteHook: removeRouteHook,
    checkHookStatus: checkHookStatus,
    renderRouterData: renderRouterData,
    renderRequestLog: renderRequestLog,
    exportCurlCommands: exportCurlCommands,
    exportHtmlReport: exportHtmlReport,
    extractPathsFromData: extractPathsFromData,
  };
})();
