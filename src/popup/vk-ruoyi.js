// 灵眸 - RuoYi Dynamic Route Module (Main Orchestrator)
// State management, JS route analysis, batch probing, API traffic, public API facade

import { utils, updateWorkflowStep, toggleSelectAll, copyRoutePaths } from './vk-ruoyi-common.js';
import * as detect from './vk-ruoyi-detect.js';
import * as hook from './vk-ruoyi-hook.js';
import * as mar from './vk-ruoyi-mar.js';
import * as CveDb from './vk-ruoyi-cve-db.js';

// ====== Shared State ======

const state = {
  ruoyiHookActive: false,
  ruoyiTabId: null,
  capturedRouterData: null,
  discoveredRoutes: [],
  extraRoutes: [],
  hookStatus: 'idle',
  augmentMode: 'auto',
  marDynamicRoutes: [],
  marHiddenRoutes: [],
  hooks: hook,
  detect: detect,
  mar: mar,
};

// ====== Initialize Sub-modules ======

detect.init(state);
hook.init(state);
mar.init(state);

// ====== JS Route Analysis ======

async function analyzeJsRoutes() {
  const resultsEl = utils.get('ruoyi-analyze-results');
  utils.setStatus('ruoyi-analyze-status', '分析JS路由中...');
  if (resultsEl) resultsEl.innerHTML = '';

  try {
    return utils.withTab(async function (tab) {
      const result = (await utils.execInTabData(tab.id, function () {
        if (
          window.__VK_RUOYI_HOOK__ &&
          typeof window.__VK_RUOYI_HOOK__.discoverRoutesFromJs === 'function'
        ) {
          return window.__VK_RUOYI_HOOK__.discoverRoutesFromJs();
        }
        return null;
      })) || {
        discovered: [],
        extUrls: [],
      };
      state.discoveredRoutes = result.discovered || [];
      const extUrls = result.extUrls || [];

      utils.setStatus(
        'ruoyi-analyze-status',
        `发现 ${state.discoveredRoutes.length} 条路径，正在扫描外部JS (${extUrls.length} 个文件)...`
      );

      const CONCURRENCY = 5;
      const routePattern = /path\s*:\s*['"`](\/[a-zA-Z0-9_\-\/]+)['"`]/g;
      const compPattern = /component\s*:\s*['"`]([^'"`]+?)['"`]/g;
      const skipRe = /\/api\/|\.js$|\.css$|\.(png|jpg|svg|ico|woff|ttf)|\/login$|\/index$/i;

      const totalBatches = Math.ceil(extUrls.length / CONCURRENCY);
      const allContent = await utils.batchFetch(extUrls, {
        concurrency: CONCURRENCY,
        onProgress: function (results, current, total) {
          if (totalBatches > 1) {
            const pct = Math.round((current / total) * 100);
            utils.setStatus(
              'ruoyi-analyze-status',
              `扫描外部JS中... ${pct}% (${current}/${total})`
            );
          }
        },
      });

      for (let b = 0; b < allContent.length; b++) {
        const text = allContent[b];
        if (!text) continue;

        routePattern.lastIndex = 0;
        let m;
        while ((m = routePattern.exec(text)) !== null) {
          let p = m[1];
          if (skipRe.test(p) || p.length < 4) continue;
          const alreadyExists = state.discoveredRoutes.some(function (r) {
            return r.path === p;
          });
          if (!alreadyExists) {
            let shortUrl = extUrls[b];
            if (shortUrl.length > 50) shortUrl = `...${shortUrl.substring(shortUrl.length - 47)}`;
            state.discoveredRoutes.push({ path: p, source: shortUrl, type: 'route-def' });
          }
        }

        compPattern.lastIndex = 0;
        while ((m = compPattern.exec(text)) !== null) {
          const comp = m[1];
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

      // Filter against captured router data
      const capturedPaths = {};
      const capturedComponents = {};
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

      const seen = {};
      state.extraRoutes = state.extraRoutes.filter(function (r) {
        const key = r.path || r.component;
        if (seen[key]) return false;
        seen[key] = true;
        return true;
      });

      state.extraRoutes.sort(function (a, b) {
        const pa = a.path || '';
        const pb = b.path || '';
        return pa.localeCompare(pb);
      });

      utils.setStatus(
        'ruoyi-analyze-status',
        `分析完成，发现 ${state.extraRoutes.length} 条额外路由`
      );
      updateWorkflowStep(3);

      if (state.extraRoutes.length > 0) {
        let html = `<div class="ruoyi-discovery-summary">发现 ${state.discoveredRoutes.length} 条路径，${state.extraRoutes.length} 条不在当前路由中</div>`;

        const routeCount = state.extraRoutes.filter(function (r) {
          return r.type === 'route-def';
        }).length;
        const compCount = state.extraRoutes.filter(function (r) {
          return r.type === 'component-ref';
        }).length;
        if (compCount > 0) {
          html += `<div class="ruoyi-discovery-stats">
            <span class="ruoyi-stat-item">路由定义: ${routeCount}</span>
            <span class="ruoyi-stat-item">组件引用: ${compCount}</span>
          </div>`;
        }

        html += '<div class="ruoyi-extra-routes">';
        state.extraRoutes.forEach(function (r, i) {
          const displayPath = r.path || r.component;
          const typeLabel = r.type === 'component-ref' ? '[组件] ' : '';
          html += `<div class="ruoyi-extra-route-item">
            <label><input type="checkbox" class="ruoyi-route-check" data-idx="${i}" checked>
            <span class="ruoyi-route-path">${utils.escapeHtml(typeLabel + displayPath)}</span></label>${r.source ? `<span class="ruoyi-route-source">${utils.escapeHtml(r.source)}</span>` : ''}
          </div>`;
        });
        html += '</div>';

        if (resultsEl) resultsEl.innerHTML = html;
        utils.showToast(`发现 ${state.extraRoutes.length} 条额外路由`, 'success');
      } else {
        updateWorkflowStep(3);
        if (resultsEl)
          resultsEl.innerHTML = utils.emptyHtml(
            state.discoveredRoutes.length > 0 ? '所有发现的路径均已注册' : '未发现路由定义'
          );
      }
    });
  } catch (e) {
    utils.setStatus('ruoyi-analyze-status', '分析出错');
    utils.showToast(`分析失败: ${e.message}`, 'error');
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
  try {
    return utils.withTab(async function (tab) {
      const selected = [];
      document.querySelectorAll('.ruoyi-route-check:checked').forEach(function (cb) {
        let idx = parseInt(cb.dataset.idx, 10);
        if (state.extraRoutes[idx]) selected.push(state.extraRoutes[idx]);
      });

      if (selected.length === 0) {
        utils.showToast('请至少选择一条路由', 'warning');
        return;
      }

      const routesToApply = selected.map(function (r) {
        if (r.type === 'component-ref') {
          const compPath = r.component || '';
          const segs = compPath
            .replace(/^(views|pages|src)\//i, '')
            .replace(/\.\w+$/, '')
            .split('/');
          const routePath = `/${segs.join('/')}`;
          return {
            path: routePath,
            component: compPath,
            name: segs[segs.length - 1] || routePath,
            title: segs[segs.length - 1] || routePath,
          };
        }
        return r;
      });

      await utils.execInTab(
        tab.id,
        function (routes) {
          if (window.__VK_RUOYI_HOOK__) {
            window.__VK_RUOYI_HOOK__.extraRoutes = routes;
            window.__VK_RUOYI_HOOK__.augmentMode = 'auto';
          }
        },
        { args: [routesToApply] }
      );

      state.extraRoutes = routesToApply;
      utils.setStatus('ruoyi-analyze-status', `已设置 ${selected.length} 条额外路由，刷新页面生效`);
      utils.showToast(`已设置 ${selected.length} 条路由，刷新页面即可生效`, 'success');
    });
  } catch (e) {
    utils.showToast(`应用失败: ${e.message}`, 'error');
  }
}

async function clearExtraRoutes() {
  try {
    const tab = await utils.requireTabId();
    if (tab) {
      await utils.execInTab(tab.id, function () {
        if (window.__VK_RUOYI_HOOK__) {
          window.__VK_RUOYI_HOOK__.extraRoutes = [];
          window.__VK_RUOYI_HOOK__.augmentMode = 'off';
        }
      });
    }
    state.extraRoutes = [];
    state.augmentMode = 'off';
    const resultsEl = utils.get('ruoyi-analyze-results');
    utils.setStatus('ruoyi-analyze-status', '');
    if (resultsEl) resultsEl.innerHTML = utils.emptyHtml('已清除');
    utils.showToast('已清除额外路由', 'info');
  } catch (e) {
    console.warn('[灵眸] clearExtraRoutes:', e);
  }
}

async function setAugmentMode(mode) {
  state.augmentMode = mode;
  try {
    return utils.withTab(async function (tab) {
      await utils.execInTab(
        tab.id,
        function (m) {
          if (window.__VK_RUOYI_HOOK__) window.__VK_RUOYI_HOOK__.augmentMode = m;
        },
        { args: [mode] }
      );
    });
  } catch (e) {
    console.warn('[灵眸] setAugmentMode:', e);
  }
}

// ====== Unified Path Access ======

function getAllPaths() {
  const seen = {};
  const paths = [];
  if (state.capturedRouterData) {
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

let probeAbortFlag = false;
let probeTimerInterval = null;
let probeStartTime = 0;
let lastProbeResults = [];

function probeStartTimer() {
  probeStopTimer();
  probeStartTime = Date.now();
  probeTimerInterval = setInterval(function () {
    let el = utils.get('ruoyi-probe-progress');
    if (el) {
      const base = el.textContent.replace(/\s*\d+s$/, '');
      el.textContent = `${base} ${Math.floor((Date.now() - probeStartTime) / 1000)}s`;
    }
  }, 1000);
}

function probeStopTimer() {
  if (probeTimerInterval) {
    clearInterval(probeTimerInterval);
    probeTimerInterval = null;
  }
}

function probeElapsed() {
  return Math.floor((Date.now() - probeStartTime) / 1000);
}

async function batchProbeRoutes() {
  const resultsEl = utils.get('ruoyi-probe-results');

  try {
    const tab = await utils.requireTabId();
    if (!tab) {
      utils.showToast('无法获取当前标签页', 'warning');
      return;
    }

    let origin;
    try {
      origin = new URL(tab.url).origin;
    } catch (e) {
      utils.showToast('无法解析页面URL', 'warning');
      return;
    }

    const paths = getAllPaths();

    if (paths.length === 0) {
      if (resultsEl) resultsEl.innerHTML = utils.emptyHtml('没有可探测的路由路径');
      return;
    }

    const concurrency = parseInt((utils.get('ruoyi-probe-concurrency') || {}).value || '5', 10);
    const method = (utils.get('ruoyi-probe-method') || {}).value || 'GET';
    const timeout = parseInt((utils.get('ruoyi-probe-timeout') || {}).value || '5000', 10);
    const followRedirect = (utils.get('ruoyi-probe-follow-redirect') || {}).checked !== false;

    utils.toggleBtnPair('ruoyi-probe-btn', 'ruoyi-probe-stop-btn', true);
    probeAbortFlag = false;
    probeStartTimer();

    const results = [];
    let completed = 0;

    for (let i = 0; i < paths.length; i += concurrency) {
      if (probeAbortFlag) break;
      const batch = paths.slice(i, i + concurrency);
      const batchResults = await Promise.allSettled(
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

      for (let j = 0; j < batchResults.length; j++) {
        let r = batchResults[j];
        let val = r.status === 'fulfilled' ? r.value : r.reason;
        results.push({
          path: batch[j],
          status: (val && val.status) || 0,
          statusText: (val && val.statusText) || '',
          error: (val && val.error) || '',
          redirected: (val && val.redirected) || false,
        });
        completed++;
        utils.setStatus(
          'ruoyi-probe-progress',
          `探测中... ${completed}/${paths.length} (${Math.round((completed / paths.length) * 100)}%)`
        );
      }
    }

    probeStopTimer();
    utils.toggleBtnPair('ruoyi-probe-btn', 'ruoyi-probe-stop-btn', false);
    utils.setStatus(
      'ruoyi-probe-progress',
      probeAbortFlag
        ? `已停止 (${completed}/${paths.length}, ${probeElapsed()}s)`
        : `完成 (${completed}/${paths.length}, ${probeElapsed()}s)`
    );

    lastProbeResults = results.slice();
    renderProbeResults(results, resultsEl);
  } catch (e) {
    probeStopTimer();
    utils.toggleBtnPair('ruoyi-probe-btn', 'ruoyi-probe-stop-btn', false);
    utils.showToast(`探测失败: ${e.message}`, 'error');
  }
}

function stopProbe() {
  probeAbortFlag = true;
}

function exportProbeResults() {
  exportJson(lastProbeResults, 'ruoyi-probe-results.json');
}

function renderProbeResults(results, containerEl) {
  if (!containerEl) return;
  if (results.length === 0) {
    containerEl.innerHTML = utils.emptyHtml('无结果');
    return;
  }

  const stats = { ok: 0, redirect: 0, auth: 0, notfound: 0, error: 0, other: 0 };
  results.forEach(function (r) {
    stats[classifyStatus(r.status)]++;
  });

  let html = `<div class="ruoyi-probe-stats">
    <span class="probe-stat probe-ok">200: ${stats.ok}</span>
    <span class="probe-stat probe-redirect">3xx: ${stats.redirect}</span>
    <span class="probe-stat probe-auth">401/403: ${stats.auth}</span>
    <span class="probe-stat probe-notfound">404: ${stats.notfound}</span>
    <span class="probe-stat probe-error">ERR: ${stats.error}</span>${stats.other > 0 ? `<span class="probe-stat probe-other">Other: ${stats.other}</span>` : ''}
  </div>`;

  html += '<div class="ruoyi-probe-list">';
  results.forEach(function (r) {
    const cls = `probe-status-${classifyStatus(r.status)}`;
    html += `<div class="ruoyi-probe-item">
      <span class="probe-code ${cls}">${r.status || 'ERR'}</span>
      <span class="probe-path">${utils.escapeHtml(r.path)}</span>${r.redirected ? '<span class="probe-badge">R</span>' : ''}${r.error ? `<span class="probe-error">${utils.escapeHtml(r.error)}</span>` : ''}
    </div>`;
  });
  html += '</div>';
  containerEl.innerHTML = html;
}

// ====== API Traffic Viewer ======

async function loadApiTraffic() {
  const countEl = utils.get('ruoyi-traffic-count');
  const listEl = utils.get('ruoyi-traffic-list');
  try {
    return utils.withTab(async function (tab) {
      const log =
        (await utils.execInTabData(tab.id, function () {
          const hook = window.__VK_RUOYI_HOOK__;
          if (!hook || !hook.apiLog) return [];
          return hook.apiLog.slice(-200);
        })) || [];
      if (countEl) countEl.textContent = `已捕获 ${log.length} 个API请求`;

      if (log.length === 0) {
        if (listEl)
          listEl.innerHTML = utils.emptyHtml('安装路由钩子并浏览页面后，此处显示捕获的API请求');
        return;
      }

      let html = '<div class="ruoyi-traffic-list-inner">';
      log.forEach(function (entry, i) {
        let statusCls = '';
        if (entry.status >= 200 && entry.status < 300) statusCls = 'traffic-ok';
        else if (entry.status >= 400) statusCls = 'traffic-err';
        else if (entry.status === 0) statusCls = 'traffic-err';

        html += `<div class="ruoyi-traffic-item" data-idx="${i}">
          <span class="traffic-method">${utils.escapeHtml(entry.method || 'GET')}</span>
          <span class="traffic-status ${statusCls}">${entry.status || '-'}</span>
          <span class="traffic-url">${utils.escapeHtml(entry.url || '')}</span>
          <span class="traffic-time">${utils.escapeHtml(entry.time || '')}</span>
        </div>`;
      });
      html += '</div>';
      if (listEl) {
        listEl.innerHTML = html;

        listEl.querySelectorAll('.ruoyi-traffic-item').forEach(function (el) {
          el.addEventListener('click', function () {
            let idx = parseInt(el.dataset.idx, 10);
            const entry = log[idx];
            if (!entry || !entry.body) return;
            const preview = entry.body.substring(0, 500);
            const existing = listEl.querySelector('.traffic-preview');
            if (existing) existing.remove();
            const pre = document.createElement('div');
            pre.className = 'traffic-preview';
            pre.textContent = preview;
            el.after(pre);
          });
        });
      }
    });
  } catch (e) {
    console.warn('[灵眸] loadApiTraffic:', e);
  }
}

function clearApiTraffic() {
  const listEl = utils.get('ruoyi-traffic-list');
  const countEl = utils.get('ruoyi-traffic-count');
  if (listEl) listEl.innerHTML = utils.emptyHtml('安装路由钩子并浏览页面后，此处显示捕获的API请求');
  if (countEl) countEl.textContent = '';
  utils.requireTabId().then(function (tab) {
    if (!tab) return;
    utils.execInTab(tab.id, function () {
      if (window.__VK_RUOYI_HOOK__) window.__VK_RUOYI_HOOK__.apiLog = [];
    });
  });
}

function exportApiTraffic() {
  utils
    .requireTabId()
    .then(function (tab) {
      if (!tab) return;
      return utils.execInTabData(tab.id, function () {
        return (window.__VK_RUOYI_HOOK__ && window.__VK_RUOYI_HOOK__.apiLog) || [];
      });
    })
    .then(function (log) {
      if (!log || log.length === 0) {
        utils.showToast('没有API流量数据', 'warning');
        return;
      }
      utils.copyText(JSON.stringify(log, null, 2));
      utils.showToast(`已导出 ${log.length} 条API流量`, 'success');
    });
}

function filterApiTraffic() {
  const filterEl = utils.get('ruoyi-traffic-filter');
  if (!filterEl) return;
  const query = (filterEl.value || '').toLowerCase().trim();
  const items = document.querySelectorAll('.ruoyi-traffic-item');
  items.forEach(function (el) {
    if (!query) {
      el.style.display = '';
      return;
    }
    const url = (el.querySelector('.traffic-url') || {}).textContent || '';
    el.style.display = url.toLowerCase().indexOf(query) !== -1 ? '' : 'none';
  });
}

// ====== Sub-tab Switching ======

function switchRuoYiSubTab(tab) {
  utils.switchSubTabs('ruoyi-stab', 'rstab', 'rstab', tab);
}

function classifyStatus(code) {
  if (code >= 200 && code < 300) return 'ok';
  if (code >= 300 && code < 400) return 'redirect';
  if (code === 401 || code === 403) return 'auth';
  if (code === 404) return 'notfound';
  if (code === 0 || code >= 500) return 'error';
  return 'other';
}

function exportJson(data, filename) {
  if (!data || data.length === 0) {
    utils.showToast('没有可导出的数据', 'warning');
    return;
  }
  const json = JSON.stringify(data, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  let a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  utils.showToast(`已导出 ${data.length} 条数据`, 'success');
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
  copyRoutePaths(state.extraRoutes, '没有额外路由');
}

function toggleSelectAllRoutes() {
  toggleSelectAll('.ruoyi-route-check');
}

// ====== Public API ======

const { detectRuoYi, autoCaptureRoutes, lookupCve, fetchCapturedRoutes } = detect;
const {
  installRouteHook,
  removeRouteHook,
  checkHookStatus,
  renderRouterData,
  exportCurlCommands,
  exportHtmlReport,
} = hook;
const { marScanDynamicRoutes, marInjectToRouter, marToggleSelectAll, marCopyHiddenPaths } = mar;

export {
  state as ruoyiState,
  detect,
  hook,
  mar,
  detectRuoYi,
  autoCaptureRoutes,
  lookupCve,
  fetchCapturedRoutes,
  installRouteHook,
  removeRouteHook,
  checkHookStatus,
  renderRouterData,
  exportCurlCommands,
  exportHtmlReport,
  marScanDynamicRoutes,
  marInjectToRouter,
  marToggleSelectAll,
  marCopyHiddenPaths,
  analyzeJsRoutes,
  applyExtraRoutes,
  clearExtraRoutes,
  setAugmentMode,
  switchRuoYiSubTab,
  copyRouteJson,
  copyExtraPaths,
  toggleSelectAllRoutes,
  batchProbeRoutes,
  stopProbe,
  exportProbeResults,
  loadApiTraffic,
  clearApiTraffic,
  exportApiTraffic,
  filterApiTraffic,
  getFindings,
};

function getFindings() {
  var findings = [];
  if (!state.detectedVariant) return findings;

  findings.push({
    severity: 'info',
    title: '若依框架检测',
    detail: '变体: ' + state.detectedVariant,
    module: 'ruoyi',
  });

  var nacosSvcs = state.nacosServices;
  if (Array.isArray(nacosSvcs) && nacosSvcs.length > 0) {
    findings.push({
      severity: 'critical',
      title: 'Nacos 服务发现暴露',
      detail: '暴露 ' + nacosSvcs.length + ' 个微服务: ' + nacosSvcs.slice(0, 5).join(', '),
      module: 'ruoyi',
    });
  }
  var gwRoutes = state.capturedGatewayRoutes;
  if (Array.isArray(gwRoutes) && gwRoutes.length > 0) {
    findings.push({
      severity: 'high',
      title: 'Spring Cloud Gateway 路由暴露',
      detail: '发现 ' + gwRoutes.length + ' 条网关路由规则',
      module: 'ruoyi',
    });
  }
  var backends = state.cloudBackendServices;
  if (Array.isArray(backends) && backends.length > 0) {
    findings.push({
      severity: 'medium',
      title: '后端服务 URI 暴露',
      detail: 'lb:// ' + backends.slice(0, 5).join(', '),
      module: 'ruoyi',
    });
  }
  var hiddenRoutes = state.marHiddenRoutes;
  if (Array.isArray(hiddenRoutes) && hiddenRoutes.length > 0) {
    findings.push({
      severity: 'high',
      title: '若依隐藏路由发现',
      detail: 'MAR 扫描发现 ' + hiddenRoutes.length + ' 个隐藏/动态路由',
      module: 'ruoyi',
    });
  }
  var extraRoutes = state.extraRoutes;
  if (Array.isArray(extraRoutes) && extraRoutes.length > 0) {
    findings.push({
      severity: 'medium',
      title: '未注册路由发现',
      detail: 'JS 分析发现 ' + extraRoutes.length + ' 条不在路由表中的路径',
      module: 'ruoyi',
    });
  }

  var cveMatches = CveDb.searchByVersion('');
  if (!cveMatches || cveMatches.length === 0) {
    cveMatches = CveDb.searchCve('RuoYi');
  }
  if (Array.isArray(cveMatches) && cveMatches.length > 0) {
    var criticalCves = cveMatches.filter(function (c) {
      return c.severity === 'critical';
    });
    var highCves = cveMatches.filter(function (c) {
      return c.severity === 'high';
    });
    if (criticalCves.length > 0) {
      findings.push({
        severity: 'critical',
        title: '若依严重漏洞 (' + criticalCves.length + ' 个)',
        detail: criticalCves
          .map(function (c) {
            return c.id + ': ' + c.title;
          })
          .join('; '),
        module: 'ruoyi',
      });
    }
    if (highCves.length > 0) {
      findings.push({
        severity: 'high',
        title: '若依高危漏洞 (' + highCves.length + ' 个)',
        detail: highCves
          .map(function (c) {
            return c.id + ': ' + c.title;
          })
          .join('; '),
        module: 'ruoyi',
      });
    }
  }
  return findings;
}
