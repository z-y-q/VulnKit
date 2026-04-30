// VulnKit - RuoYi Dynamic Route Module (Main Orchestrator)
// State management, JS route analysis, batch probing, API traffic, public API facade
window.VulnKitRuoYi = (function () {
  'use strict';

  // ====== Shared State ======

  var state = {
    ruoyiHookActive: false,
    ruoyiTabId: null,
    capturedRouterData: null,
    discoveredRoutes: [],
    extraRoutes: [],
    hookStatus: 'idle',
    augmentMode: 'auto',
    marDynamicRoutes: [],
    marHiddenRoutes: [],
  };

  var common = window.VulnKitRuoYiCommon;
  var utils = common ? common.utils : {};
  var getActiveTab = common ? common.getActiveTab : null;
  var updateWorkflowStep = common ? common.updateWorkflowStep : null;

  // ====== Initialize Sub-modules ======

  var detect = window.VulnKitRuoYiDetect;
  var hook = window.VulnKitRuoYiHook;
  var mar = window.VulnKitRuoYiMar;

  if (detect && typeof detect.init === 'function') detect.init(state);
  if (hook && typeof hook.init === 'function') hook.init(state);
  if (mar && typeof mar.init === 'function') mar.init(state);

  // ====== JS Route Analysis ======

  async function analyzeJsRoutes() {
    var statusEl = utils.get('ruoyi-analyze-status');
    var resultsEl = utils.get('ruoyi-analyze-results');
    if (statusEl) statusEl.textContent = '分析JS路由中...';
    if (resultsEl) resultsEl.innerHTML = '';

    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) return;

      var discoverResults = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          if (
            window.__VK_RUOYI_HOOK__ &&
            typeof window.__VK_RUOYI_HOOK__.discoverRoutesFromJs === 'function'
          ) {
            return window.__VK_RUOYI_HOOK__.discoverRoutesFromJs();
          }
          return null;
        },
      });

      var result = (discoverResults && discoverResults[0] && discoverResults[0].result) || {
        discovered: [],
        extUrls: [],
      };
      state.discoveredRoutes = result.discovered || [];
      var extUrls = result.extUrls || [];

      if (statusEl)
        statusEl.textContent =
          '发现 ' +
          state.discoveredRoutes.length +
          ' 条路径，正在扫描外部JS (' +
          extUrls.length +
          ' 个文件)...';

      var CONCURRENCY = 5;
      var routePattern = /path\s*:\s*['"`](\/[a-zA-Z0-9_\-\/]+)['"`]/g;
      var compPattern = /component\s*:\s*['"`]([^'"`]+?)['"`]/g;
      var skipRe = /\/api\/|\.js$|\.css$|\.(png|jpg|svg|ico|woff|ttf)|\/login$|\/index$/i;

      var completedBatches = 0;
      var totalBatches = Math.ceil(extUrls.length / CONCURRENCY);

      for (var batchStart = 0; batchStart < extUrls.length; batchStart += CONCURRENCY) {
        var batch = extUrls.slice(batchStart, batchStart + CONCURRENCY);
        var batchResults = await Promise.all(
          batch.map(function (url) {
            return chrome.runtime.sendMessage({ type: 'FETCH_URL', url: url }).catch(function () {
              return null;
            });
          })
        );
        for (var b = 0; b < batchResults.length; b++) {
          var resp = batchResults[b];
          if (!resp || resp.error || !resp.data) continue;
          var text = resp.data;

          routePattern.lastIndex = 0;
          var m;
          while ((m = routePattern.exec(text)) !== null) {
            var p = m[1];
            if (skipRe.test(p) || p.length < 4) continue;
            var alreadyExists = state.discoveredRoutes.some(function (r) {
              return r.path === p;
            });
            if (!alreadyExists) {
              var shortUrl = batch[b];
              if (shortUrl.length > 50) shortUrl = '...' + shortUrl.substring(shortUrl.length - 47);
              state.discoveredRoutes.push({ path: p, source: shortUrl, type: 'route-def' });
            }
          }

          compPattern.lastIndex = 0;
          while ((m = compPattern.exec(text)) !== null) {
            var comp = m[1];
            if (!/^(views|pages|src)\//i.test(comp)) continue;
            if (
              state.discoveredRoutes.some(function (r) {
                return r.component === comp;
              })
            )
              continue;
            state.discoveredRoutes.push({
              path: '',
              source: '',
              type: 'component-ref',
              component: comp,
            });
          }
        }

        completedBatches++;
        if (totalBatches > 1) {
          var pct = Math.round((completedBatches / totalBatches) * 100);
          if (statusEl)
            statusEl.textContent =
              '扫描外部JS中... ' + pct + '% (' + completedBatches + '/' + totalBatches + ')';
        }
      }

      // Filter against captured router data
      var capturedPaths = {};
      var capturedComponents = {};
      if (state.capturedRouterData) {
        extractPaths(
          state.capturedRouterData.data || state.capturedRouterData,
          capturedPaths,
          capturedComponents
        );
      }

      state.extraRoutes = state.discoveredRoutes.filter(function (r) {
        if (r.type === 'component-ref') {
          return r.component && !capturedComponents[r.component];
        }
        return r.path && !capturedPaths[r.path];
      });

      var seen = {};
      state.extraRoutes = state.extraRoutes.filter(function (r) {
        var key = r.path || r.component;
        if (seen[key]) return false;
        seen[key] = true;
        return true;
      });

      state.extraRoutes.sort(function (a, b) {
        var pa = a.path || '';
        var pb = b.path || '';
        return pa.localeCompare(pb);
      });

      if (statusEl)
        statusEl.textContent = '分析完成，发现 ' + state.extraRoutes.length + ' 条额外路由';
      updateWorkflowStep(3);

      if (state.extraRoutes.length > 0) {
        var html =
          '<div class="ruoyi-discovery-summary">发现 ' +
          state.discoveredRoutes.length +
          ' 条路径，' +
          state.extraRoutes.length +
          ' 条不在当前路由中</div>';

        var routeCount = state.extraRoutes.filter(function (r) {
          return r.type === 'route-def';
        }).length;
        var compCount = state.extraRoutes.filter(function (r) {
          return r.type === 'component-ref';
        }).length;
        if (compCount > 0) {
          html += '<div class="ruoyi-discovery-stats">';
          html += '<span class="ruoyi-stat-item">路由定义: ' + routeCount + '</span>';
          html += '<span class="ruoyi-stat-item">组件引用: ' + compCount + '</span>';
          html += '</div>';
        }

        html += '<div class="ruoyi-extra-routes">';
        state.extraRoutes.forEach(function (r, i) {
          html += '<div class="ruoyi-extra-route-item">';
          html +=
            '<label><input type="checkbox" class="ruoyi-route-check" data-idx="' +
            i +
            '" checked> ';
          var displayPath = r.path || r.component;
          var typeLabel = r.type === 'component-ref' ? '[组件] ' : '';
          html +=
            '<span class="ruoyi-route-path">' +
            utils.escapeHtml(typeLabel + displayPath) +
            '</span></label>';
          if (r.source)
            html += '<span class="ruoyi-route-source">' + utils.escapeHtml(r.source) + '</span>';
          html += '</div>';
        });
        html += '</div>';

        if (resultsEl) resultsEl.innerHTML = html;
        utils.showToast('发现 ' + state.extraRoutes.length + ' 条额外路由', 'success');
      } else {
        updateWorkflowStep(3);
        if (resultsEl)
          resultsEl.innerHTML =
            '<div class="empty-state">' +
            (state.discoveredRoutes.length > 0 ? '所有发现的路径均已注册' : '未发现路由定义') +
            '</div>';
      }
    } catch (e) {
      if (statusEl) statusEl.textContent = '分析出错';
      utils.showToast('分析失败: ' + e.message, 'error');
    }
  }

  function extractPaths(routes, pathMap, compMap) {
    if (!routes || !Array.isArray(routes)) return;
    routes.forEach(function (r) {
      if (r.path) pathMap[r.path] = true;
      if (r.component && typeof r.component === 'string' && compMap) {
        compMap[r.component] = true;
      }
      if (r.children) extractPaths(r.children, pathMap, compMap);
    });
  }

  // ====== Apply Extra Routes ======

  async function applyExtraRoutes() {
    var statusEl = utils.get('ruoyi-analyze-status');
    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) return;

      var selected = [];
      document.querySelectorAll('.ruoyi-route-check:checked').forEach(function (cb) {
        var idx = parseInt(cb.dataset.idx, 10);
        if (state.extraRoutes[idx]) selected.push(state.extraRoutes[idx]);
      });

      if (selected.length === 0) {
        utils.showToast('请至少选择一条路由', 'warning');
        return;
      }

      var routesToApply = selected.map(function (r) {
        if (r.type === 'component-ref') {
          var compPath = r.component || '';
          var segs = compPath
            .replace(/^(views|pages|src)\//i, '')
            .replace(/\.\w+$/, '')
            .split('/');
          var routePath = '/' + segs.join('/');
          return {
            path: routePath,
            component: compPath,
            name: segs[segs.length - 1] || routePath,
            title: segs[segs.length - 1] || routePath,
          };
        }
        return r;
      });

      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function (routes) {
          if (window.__VK_RUOYI_HOOK__) {
            window.__VK_RUOYI_HOOK__.extraRoutes = routes;
            window.__VK_RUOYI_HOOK__.augmentMode = 'auto';
          }
        },
        args: [routesToApply],
      });

      state.extraRoutes = routesToApply;
      if (statusEl)
        statusEl.textContent = '已设置 ' + selected.length + ' 条额外路由，刷新页面生效';
      utils.showToast('已设置 ' + selected.length + ' 条路由，刷新页面即可生效', 'success');
    } catch (e) {
      utils.showToast('应用失败: ' + e.message, 'error');
    }
  }

  async function clearExtraRoutes() {
    try {
      var tab = await getActiveTab();
      if (tab && tab.id) {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          world: 'MAIN',
          func: function () {
            if (window.__VK_RUOYI_HOOK__) {
              window.__VK_RUOYI_HOOK__.extraRoutes = [];
              window.__VK_RUOYI_HOOK__.augmentMode = 'off';
            }
          },
        });
      }
      state.extraRoutes = [];
      state.augmentMode = 'off';
      var statusEl = utils.get('ruoyi-analyze-status');
      var resultsEl = utils.get('ruoyi-analyze-results');
      if (statusEl) statusEl.textContent = '';
      if (resultsEl) resultsEl.innerHTML = '<div class="empty-state">已清除</div>';
      utils.showToast('已清除额外路由', 'info');
    } catch (e) {
      // ignore
    }
  }

  async function setAugmentMode(mode) {
    state.augmentMode = mode;
    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) return;
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function (m) {
          if (window.__VK_RUOYI_HOOK__) window.__VK_RUOYI_HOOK__.augmentMode = m;
        },
        args: [mode],
      });
    } catch (e) {
      // ignore
    }
  }

  // ====== Unified Path Access ======

  function getAllPaths() {
    var seen = {};
    var paths = [];
    if (state.capturedRouterData && hook && typeof hook.extractPathsFromData === 'function') {
      hook.extractPathsFromData(state.capturedRouterData.data || state.capturedRouterData, paths);
    }
    [state.discoveredRoutes, state.extraRoutes, state.marHiddenRoutes].forEach(function (list) {
      list.forEach(function (r) {
        if (r.path && !seen[r.path]) {
          seen[r.path] = true;
          paths.push(r.path);
        }
      });
    });
    return paths;
  }

  // ====== Batch Route Probing ======

  var probeAbortFlag = false;
  var lastProbeResults = [];

  async function batchProbeRoutes() {
    var statusEl = utils.get('ruoyi-probe-progress');
    var resultsEl = utils.get('ruoyi-probe-results');
    var probeBtn = utils.get('ruoyi-probe-btn');
    var stopBtn = utils.get('ruoyi-probe-stop-btn');

    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) {
        utils.showToast('无法获取当前标签页', 'warning');
        return;
      }

      var origin;
      try {
        origin = new URL(tab.url).origin;
      } catch (e) {
        utils.showToast('无法解析页面URL', 'warning');
        return;
      }

      var paths = getAllPaths();

      if (paths.length === 0) {
        if (resultsEl) resultsEl.innerHTML = '<div class="empty-state">没有可探测的路由路径</div>';
        return;
      }

      var concurrency = parseInt((utils.get('ruoyi-probe-concurrency') || {}).value || '5', 10);
      var method = (utils.get('ruoyi-probe-method') || {}).value || 'GET';
      var timeout = parseInt((utils.get('ruoyi-probe-timeout') || {}).value || '5000', 10);
      var followRedirect = (utils.get('ruoyi-probe-follow-redirect') || {}).checked !== false;

      if (probeBtn) probeBtn.disabled = true;
      if (stopBtn) stopBtn.disabled = false;
      probeAbortFlag = false;

      var results = [];
      var completed = 0;

      for (var i = 0; i < paths.length; i += concurrency) {
        if (probeAbortFlag) break;
        var batch = paths.slice(i, i + concurrency);
        var batchResults = await Promise.allSettled(
          batch.map(function (p) {
            return chrome.runtime
              .sendMessage({
                type: 'FETCH_PROBE',
                url: origin + p,
                method: method,
                timeout: timeout,
                followRedirect: followRedirect,
              })
              .catch(function () {
                return { error: 'send failed', status: 0 };
              });
          })
        );

        for (var j = 0; j < batchResults.length; j++) {
          var r = batchResults[j];
          var val = r.status === 'fulfilled' ? r.value : r.reason;
          results.push({
            path: batch[j],
            status: (val && val.status) || 0,
            statusText: (val && val.statusText) || '',
            error: (val && val.error) || '',
            redirected: (val && val.redirected) || false,
          });
          completed++;
          if (statusEl)
            statusEl.textContent =
              '探测中... ' +
              completed +
              '/' +
              paths.length +
              ' (' +
              Math.round((completed / paths.length) * 100) +
              '%)';
        }
      }

      if (probeBtn) probeBtn.disabled = false;
      if (stopBtn) stopBtn.disabled = true;
      if (statusEl)
        statusEl.textContent = probeAbortFlag
          ? '已停止 (' + completed + '/' + paths.length + ')'
          : '完成 (' + completed + '/' + paths.length + ')';

      lastProbeResults = results.slice();
      renderProbeResults(results, resultsEl);
    } catch (e) {
      if (probeBtn) probeBtn.disabled = false;
      if (stopBtn) stopBtn.disabled = true;
      utils.showToast('探测失败: ' + e.message, 'error');
    }
  }

  function stopProbe() {
    probeAbortFlag = true;
  }

  function exportProbeResults() {
    if (!lastProbeResults || lastProbeResults.length === 0) {
      utils.showToast('没有可导出的探测结果', 'warning');
      return;
    }
    var json = JSON.stringify(lastProbeResults, null, 2);
    var blob = new Blob([json], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'ruoyi-probe-results.json';
    a.click();
    URL.revokeObjectURL(url);
    utils.showToast('已导出 ' + lastProbeResults.length + ' 条探测结果', 'success');
  }

  function renderProbeResults(results, containerEl) {
    if (!containerEl) return;
    if (results.length === 0) {
      containerEl.innerHTML = '<div class="empty-state">无结果</div>';
      return;
    }

    var stats = { ok: 0, redirect: 0, auth: 0, notfound: 0, error: 0, other: 0 };
    results.forEach(function (r) {
      if (r.status >= 200 && r.status < 300) stats.ok++;
      else if (r.status >= 300 && r.status < 400) stats.redirect++;
      else if (r.status === 401 || r.status === 403) stats.auth++;
      else if (r.status === 404) stats.notfound++;
      else if (r.status === 0) stats.error++;
      else stats.other++;
    });

    var html =
      '<div class="ruoyi-probe-stats">' +
      '<span class="probe-stat probe-ok">200: ' +
      stats.ok +
      '</span>' +
      '<span class="probe-stat probe-redirect">3xx: ' +
      stats.redirect +
      '</span>' +
      '<span class="probe-stat probe-auth">401/403: ' +
      stats.auth +
      '</span>' +
      '<span class="probe-stat probe-notfound">404: ' +
      stats.notfound +
      '</span>' +
      '<span class="probe-stat probe-error">ERR: ' +
      stats.error +
      '</span>' +
      (stats.other > 0
        ? '<span class="probe-stat probe-other">Other: ' + stats.other + '</span>'
        : '') +
      '</div>';

    html += '<div class="ruoyi-probe-list">';
    results.forEach(function (r) {
      var cls = 'probe-status-other';
      if (r.status >= 200 && r.status < 300) cls = 'probe-status-ok';
      else if (r.status >= 300 && r.status < 400) cls = 'probe-status-redirect';
      else if (r.status === 401 || r.status === 403) cls = 'probe-status-auth';
      else if (r.status === 404) cls = 'probe-status-notfound';
      else if (r.status === 0) cls = 'probe-status-error';
      else if (r.status >= 500) cls = 'probe-status-error';

      html += '<div class="ruoyi-probe-item">';
      html += '<span class="probe-code ' + cls + '">' + (r.status || 'ERR') + '</span>';
      html += '<span class="probe-path">' + utils.escapeHtml(r.path) + '</span>';
      if (r.redirected) html += '<span class="probe-badge">R</span>';
      if (r.error) html += '<span class="probe-error">' + utils.escapeHtml(r.error) + '</span>';
      html += '</div>';
    });
    html += '</div>';
    containerEl.innerHTML = html;
  }

  // ====== API Traffic Viewer ======

  async function loadApiTraffic() {
    var countEl = utils.get('ruoyi-traffic-count');
    var listEl = utils.get('ruoyi-traffic-list');
    try {
      var tab = await getActiveTab();
      if (!tab || !tab.id) return;

      var results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          var hook = window.__VK_RUOYI_HOOK__;
          if (!hook || !hook.apiLog) return [];
          return hook.apiLog.slice(-200);
        },
      });

      var log = (results && results[0] && results[0].result) || [];
      if (countEl) countEl.textContent = '已捕获 ' + log.length + ' 个API请求';

      if (log.length === 0) {
        if (listEl)
          listEl.innerHTML =
            '<div class="empty-state">安装路由钩子并浏览页面后，此处显示捕获的API请求</div>';
        return;
      }

      var html = '<div class="ruoyi-traffic-list-inner">';
      log.forEach(function (entry, i) {
        var statusCls = '';
        if (entry.status >= 200 && entry.status < 300) statusCls = 'traffic-ok';
        else if (entry.status >= 400) statusCls = 'traffic-err';
        else if (entry.status === 0) statusCls = 'traffic-err';

        html += '<div class="ruoyi-traffic-item" data-idx="' + i + '">';
        html +=
          '<span class="traffic-method">' + utils.escapeHtml(entry.method || 'GET') + '</span>';
        html +=
          '<span class="traffic-status ' + statusCls + '">' + (entry.status || '-') + '</span>';
        html += '<span class="traffic-url">' + utils.escapeHtml(entry.url || '') + '</span>';
        html += '<span class="traffic-time">' + utils.escapeHtml(entry.time || '') + '</span>';
        html += '</div>';
      });
      html += '</div>';
      if (listEl) listEl.innerHTML = html;

      listEl.querySelectorAll('.ruoyi-traffic-item').forEach(function (el) {
        el.addEventListener('click', function () {
          var idx = parseInt(el.dataset.idx, 10);
          var entry = log[idx];
          if (!entry || !entry.body) return;
          var preview = entry.body.substring(0, 500);
          var existing = listEl.querySelector('.traffic-preview');
          if (existing) existing.remove();
          var pre = document.createElement('div');
          pre.className = 'traffic-preview';
          pre.textContent = preview;
          el.after(pre);
        });
      });
    } catch (e) {
      // ignore
    }
  }

  function clearApiTraffic() {
    var listEl = utils.get('ruoyi-traffic-list');
    var countEl = utils.get('ruoyi-traffic-count');
    if (listEl)
      listEl.innerHTML =
        '<div class="empty-state">安装路由钩子并浏览页面后，此处显示捕获的API请求</div>';
    if (countEl) countEl.textContent = '';
    getActiveTab().then(function (tab) {
      if (!tab || !tab.id) return;
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function () {
          if (window.__VK_RUOYI_HOOK__) window.__VK_RUOYI_HOOK__.apiLog = [];
        },
      });
    });
  }

  function exportApiTraffic() {
    getActiveTab()
      .then(function (tab) {
        if (!tab || !tab.id) return;
        return chrome.scripting.executeScript({
          target: { tabId: tab.id },
          world: 'MAIN',
          func: function () {
            return (window.__VK_RUOYI_HOOK__ && window.__VK_RUOYI_HOOK__.apiLog) || [];
          },
        });
      })
      .then(function (results) {
        var log = (results && results[0] && results[0].result) || [];
        if (log.length === 0) {
          utils.showToast('没有API流量数据', 'warning');
          return;
        }
        utils.copyText(JSON.stringify(log, null, 2));
        utils.showToast('已导出 ' + log.length + ' 条API流量', 'success');
      });
  }

  function filterApiTraffic() {
    var filterEl = utils.get('ruoyi-traffic-filter');
    if (!filterEl) return;
    var query = (filterEl.value || '').toLowerCase().trim();
    var items = document.querySelectorAll('.ruoyi-traffic-item');
    items.forEach(function (el) {
      if (!query) {
        el.style.display = '';
        return;
      }
      var url = (el.querySelector('.traffic-url') || {}).textContent || '';
      el.style.display = url.toLowerCase().indexOf(query) !== -1 ? '' : 'none';
    });
  }

  // ====== Sub-tab Switching ======

  function switchRuoYiSubTab(tab) {
    document.querySelectorAll('.ruoyi-stab').forEach(function (b) {
      b.classList.toggle('active', b.dataset.rstab === tab);
    });
    document.querySelectorAll('.ruoyi-subpanel').forEach(function (p) {
      p.classList.remove('active');
    });
    var target = document.getElementById('rstab-' + tab);
    if (target) target.classList.add('active');
  }

  // ====== Utility Functions ======

  function copyRouteJson() {
    if (!state.capturedRouterData) {
      utils.showToast('没有捕获的路由数据', 'warning');
      return;
    }
    utils.copyText(JSON.stringify(state.capturedRouterData, null, 2));
    utils.showToast('已复制路由 JSON', 'success');
  }

  function copyExtraPaths() {
    if (state.extraRoutes.length === 0) {
      utils.showToast('没有额外路由', 'warning');
      return;
    }
    utils.copyText(
      state.extraRoutes
        .map(function (r) {
          return r.path || r.component;
        })
        .join('\n')
    );
    utils.showToast('已复制 ' + state.extraRoutes.length + ' 条路径', 'success');
  }

  function toggleSelectAll() {
    var checks = document.querySelectorAll('.ruoyi-route-check');
    var allChecked =
      checks.length > 0 &&
      Array.from(checks).every(function (cb) {
        return cb.checked;
      });
    checks.forEach(function (cb) {
      cb.checked = !allChecked;
    });
  }

  // ====== Public API ======

  return {
    detectRuoYi: detect ? detect.detectRuoYi : undefined,
    installRouteHook: hook ? hook.installRouteHook : undefined,
    removeRouteHook: hook ? hook.removeRouteHook : undefined,
    checkHookStatus: hook ? hook.checkHookStatus : undefined,
    analyzeJsRoutes: analyzeJsRoutes,
    applyExtraRoutes: applyExtraRoutes,
    clearExtraRoutes: clearExtraRoutes,
    setAugmentMode: setAugmentMode,
    switchRuoYiSubTab: switchRuoYiSubTab,
    copyRouteJson: copyRouteJson,
    copyExtraPaths: copyExtraPaths,
    toggleSelectAll: toggleSelectAll,
    exportCurlCommands: hook ? hook.exportCurlCommands : undefined,
    exportHtmlReport: hook ? hook.exportHtmlReport : undefined,
    batchProbeRoutes: batchProbeRoutes,
    stopProbe: stopProbe,
    exportProbeResults: exportProbeResults,
    loadApiTraffic: loadApiTraffic,
    clearApiTraffic: clearApiTraffic,
    exportApiTraffic: exportApiTraffic,
    filterApiTraffic: filterApiTraffic,
    lookupCve: detect ? detect.lookupCve : undefined,
    marScanDynamicRoutes: mar ? mar.marScanDynamicRoutes : undefined,
    marInjectToRouter: mar ? mar.marInjectToRouter : undefined,
    marToggleSelectAll: mar ? mar.marToggleSelectAll : undefined,
    marCopyHiddenPaths: mar ? mar.marCopyHiddenPaths : undefined,
    get ruoyiHookActive() {
      return state.ruoyiHookActive;
    },
    set ruoyiHookActive(v) {
      state.ruoyiHookActive = v;
    },
    get ruoyiTabId() {
      return state.ruoyiTabId;
    },
    set ruoyiTabId(v) {
      state.ruoyiTabId = v;
    },
    get hookStatus() {
      return state.hookStatus;
    },
    set hookStatus(v) {
      state.hookStatus = v;
    },
    get extraRoutes() {
      return state.extraRoutes;
    },
    set extraRoutes(v) {
      state.extraRoutes = v;
    },
    get augmentMode() {
      return state.augmentMode;
    },
    set augmentMode(v) {
      state.augmentMode = v;
    },
  };
})();
