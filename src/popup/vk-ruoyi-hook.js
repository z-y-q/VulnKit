// 灵眸 - RuoYi Hook Sub-module
// Route hook install/remove/check, request log, route rendering, export functions

import { utils, updateWorkflowStep } from './vk-ruoyi-common.js';

let state = null;

// ====== Route Hook ======

function setHookUI(active) {
  const installBtn = utils.get('ruoyi-hook-install-btn');
  const removeBtn = utils.get('ruoyi-hook-remove-btn');
  if (installBtn) installBtn.disabled = active;
  if (removeBtn) removeBtn.disabled = !active;
}

async function injectHookCode(tabId) {
  try {
    await utils.execInTab(tabId, ['src/inject/ruoyi-route-hook.js']);
    return 'files';
  } catch (e) {
    return null;
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
  const augmentMode = state ? state.augmentMode : 'auto';
  try {
    const tab = await utils.requireTabId();
    if (!tab) {
      utils.setStatus('ruoyi-hook-status', '无法获取当前标签页');
      return;
    }

    utils.setStatus('ruoyi-hook-status', '启用钩子中...');

    const customUrlInput = utils.get('ruoyi-custom-url');
    const customUrl = (customUrlInput && customUrlInput.value.trim()) || '';

    const hookResult = await utils.execInTabData(tab.id, enableHookFunc, {
      args: [{ mode: augmentMode, customUrl: customUrl }],
    });

    if (hookResult) {
      if (state) {
        state.ruoyiHookActive = true;
        state.ruoyiTabId = tab.id;
        state.hookStatus = 'active';
      }
      let origin = tab.url ? new URL(tab.url).origin : '';
      chrome.storage.local.set({
        ruoyiHookTabId: tab.id,
        ruoyiHookEnabled: true,
        ruoyiHookOrigin: origin,
      });
      if (origin) {
        chrome.runtime
          .sendMessage({ type: 'REGISTER_RUOYI_HOOK', origin: origin })
          .catch(function (e) {
            console.debug('register ruoyi hook failed', e);
          });
      }
      setHookUI(true);

      const capData = await utils.execInTabData(tab.id, function () {
        let hook = window.__VK_RUOYI_HOOK__;
        return {
          captured: !!hook.capturedRouters,
          logCount: (hook.requestLog || []).length,
        };
      });

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
    const method = await injectHookCode(tab.id);

    if (!method) {
      utils.setStatus('ruoyi-hook-status', '所有注入方式均失败');
      utils.showToast('注入失败 — 请刷新目标页面后重试', 'error');
      return;
    }

    await new Promise(function (r) {
      setTimeout(r, 400);
    });

    const retryResult = await utils.execInTabData(tab.id, enableHookFunc, {
      args: [{ mode: augmentMode, customUrl: customUrl }],
    });

    if (!retryResult) {
      utils.setStatus('ruoyi-hook-status', '注入后未检测到钩子');
      utils.showToast(`钩子注入失败 [${method}]，请刷新页面后重试`, 'warning');
      return;
    }

    if (state) {
      state.ruoyiHookActive = true;
      state.ruoyiTabId = tab.id;
      state.hookStatus = 'active';
    }
    const origin = tab.url ? new URL(tab.url).origin : '';
    chrome.storage.local.set({
      ruoyiHookTabId: tab.id,
      ruoyiHookEnabled: true,
      ruoyiHookOrigin: origin,
    });
    if (origin) {
      chrome.runtime
        .sendMessage({ type: 'REGISTER_RUOYI_HOOK', origin: origin })
        .catch(function (e) {
          console.debug('register ruoyi hook (reinject) failed', e);
        });
    }
    setHookUI(true);
    updateWorkflowStep(2);
    utils.setStatus('ruoyi-hook-status', '钩子已启用，正在刷新页面...');
    utils.showToast('钩子已启用，刷新页面以捕获 /getRouters', 'success');
    await chrome.tabs.reload(tab.id);
  } catch (e) {
    if (state) state.hookStatus = 'idle';
    utils.setStatus('ruoyi-hook-status', '安装失败');
    utils.showToast(`安装失败: ${e.message}`, 'error');
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
      chrome.storage.local.remove(['ruoyiHookTabId', 'ruoyiHookEnabled', 'ruoyiHookOrigin']);
      chrome.runtime.sendMessage({ type: 'UNREGISTER_RUOYI_HOOK' }).catch(function (e) {
        console.debug('unregister ruoyi hook failed', e);
      });

      setHookUI(false);
      utils.setStatus('ruoyi-hook-status', '钩子已禁用');
      utils.showToast('路由钩子已禁用', 'info');
    });
  } catch (e) {
    utils.showToast(`移除失败: ${e.message}`, 'error');
  }
}

async function checkHookStatus() {
  let panelEl = utils.get('ruoyi-captured-panel');
  try {
    return utils.withTab(async function (tab) {
      const data = (await utils.execInTabData(tab.id, function () {
        let hook = window.__VK_RUOYI_HOOK__;
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
      })) || { installed: false };

      if (!data.installed) {
        const urlHint = data.pageUrl ? ` [${utils.escapeHtml(data.pageUrl)}]` : '';
        utils.setStatus('ruoyi-hook-status', `钩子未安装，页面: ${data.pageUrl || '未知'}`);
        if (state) state.hookStatus = 'idle';
        if (panelEl)
          panelEl.innerHTML = utils.emptyHtml(`钩子未注入 — 请先点击「安装钩子」${urlHint}`);
      } else if (data.captured) {
        if (state) state.hookStatus = data.enabled ? 'captured' : 'passive-captured';
        updateWorkflowStep(2);
        setHookUI(data.enabled);
        const modeText = data.enabled ? data.augmentMode || 'auto' : '被动捕获';
        const extras =
          data.enabled && data.extraRouteCount > 0 ? `，${data.extraRouteCount} 条额外路由` : '';
        utils.setStatus('ruoyi-hook-status', `已捕获路由数据 (${modeText} 模式${extras})`);
        // Delegate to detect module for data fetching
        if (state && state.detect && typeof state.detect.fetchCapturedRoutes === 'function') {
          await state.detect.fetchCapturedRoutes();
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
        const logInfo = data.logCount > 0 ? `，已拦截 ${data.logCount} 个请求` : '';
        utils.setStatus('ruoyi-hook-status', `监听中，等待 /getRouters 请求...${logInfo}`);
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
    const log =
      (await utils.execInTabData(tabId, function () {
        const hook = window.__VK_RUOYI_HOOK__;
        if (!hook || !hook.requestLog) return [];
        return hook.requestLog.slice(-20);
      })) || [];
    if (log.length === 0) return;

    const panelEl = utils.get('ruoyi-captured-panel');
    if (!panelEl) return;

    let html = `<div class="ruoyi-log-section">
  <div class="ruoyi-log-title">请求拦截日志 (${log.length})</div>
  <div class="ruoyi-log-list">`;
    log.forEach(function (entry) {
      let cls = 'log-info';
      if (entry.type === 'router') cls = 'log-router';
      else if (entry.type === 'router-error') cls = 'log-error';
      else if (entry.type === 'userinfo') cls = 'log-userinfo';
      html += `
    <div class="ruoyi-log-entry ${cls}">
      <span class="ruoyi-log-type">${utils.escapeHtml(entry.method || 'GET')}</span>
      <span class="ruoyi-log-url">${utils.escapeHtml(entry.url || '')}</span>
      <span class="ruoyi-log-status">${utils.escapeHtml(String(entry.status || ''))}</span>
      <span class="ruoyi-log-time">${utils.escapeHtml(entry.time || '')}</span>
    </div>`;
    });
    html += `
  </div>
</div>`;
    panelEl.innerHTML = html;
  } catch (e) {
    // ignore
  }
}

// ====== Route Rendering ======

function renderRouterData(data, containerEl) {
  if (!containerEl) return;
  const routes = data.data || data;
  if (!Array.isArray(routes)) {
    containerEl.innerHTML = utils.emptyHtml(data._raw ? '响应解析失败' : '无路由数据');
    return;
  }

  let totalPaths = 0;
  let hiddenCount = 0;
  (function count(rts) {
    rts.forEach(function (r) {
      totalPaths++;
      if (r.hidden) hiddenCount++;
      if (r.children) count(r.children);
    });
  })(routes);

  let html = `<div class="ruoyi-route-toolbar">
  <div class="ruoyi-route-summary">${routes.length} 个顶级路由，${totalPaths} 个节点${hiddenCount > 0 ? `，<span class="ruoyi-hidden-count">${hiddenCount} 个隐藏</span>` : ''}</div>
  <div class="ruoyi-route-actions">
    <button class="btn btn-xs btn-outline" id="ruoyi-expand-all">全部展开</button>
    <button class="btn btn-xs btn-outline" id="ruoyi-collapse-all">全部收起</button>
    <input type="text" class="ruoyi-search-input" id="ruoyi-route-search" placeholder="搜索路由...">
  </div>
</div>`;
  html += '<div class="ruoyi-route-tree">';
  routes.forEach(function (r) {
    html += renderRouteNode(r, 0);
  });
  html += '</div>';
  containerEl.innerHTML = html;

  containerEl.querySelectorAll('.ruoyi-route-toggle').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const children = btn.closest('.ruoyi-route-node').querySelector('.ruoyi-route-children');
      if (children) {
        let hidden = children.style.display === 'none';
        children.style.display = hidden ? '' : 'none';
        btn.textContent = hidden ? '▼' : '▶';
      }
    });
  });

  const expandBtn = containerEl.querySelector('#ruoyi-expand-all');
  const collapseBtn = containerEl.querySelector('#ruoyi-collapse-all');
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

  const searchInput = containerEl.querySelector('#ruoyi-route-search');
  if (searchInput) {
    searchInput.addEventListener('input', function () {
      const query = this.value.toLowerCase().trim();
      containerEl.querySelectorAll('.ruoyi-route-node').forEach(function (node) {
        if (!query) {
          node.style.display = '';
          return;
        }
        let path = (node.querySelector('.ruoyi-route-path') || {}).textContent || '';
        let name = (node.querySelector('.ruoyi-route-name') || {}).textContent || '';
        let title = (node.querySelector('.ruoyi-route-title') || {}).textContent || '';
        let match =
          path.toLowerCase().indexOf(query) !== -1 ||
          name.toLowerCase().indexOf(query) !== -1 ||
          title.toLowerCase().indexOf(query) !== -1;
        node.style.display = match ? '' : 'none';
        if (match) {
          let parent = node.parentElement;
          while (parent) {
            if (parent.classList && parent.classList.contains('ruoyi-route-children')) {
              parent.style.display = '';
              const toggle = parent.previousElementSibling;
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
  const indent = depth * 16;
  const path = route.path || '/';
  const name = route.name || '';
  let title = (route.meta && route.meta.title) || '';
  const hidden = route.hidden;
  const hasChildren = route.children && route.children.length > 0;
  let component = route.component || '';

  let html = `<div class="ruoyi-route-node${hidden ? ' node-hidden' : ''}" style="padding-left:${indent}px" data-path="${utils.escapeHtml(path)}">`;
  html += `<span class="ruoyi-route-toggle">${hasChildren ? '▼' : '►'}</span>`;
  if (hidden) html += '<span class="ruoyi-route-hidden" title="hidden">H</span>';
  const metaType = route.meta && route.meta.type;
  if (metaType) {
    const typeLabels = { M: '目录', C: '菜单', F: '按钮' };
    const typeLabel = typeLabels[metaType] || metaType;
    html += `<span class="ruoyi-route-type" title="type:${utils.escapeHtml(metaType)}">${utils.escapeHtml(typeLabel)}</span>`;
  }
  if (route.meta && route.meta.noCache) {
    html += '<span class="ruoyi-route-nocache" title="noCache">NC</span>';
  }
  html += `<span class="ruoyi-route-path">${utils.escapeHtml(path)}</span>`;
  if (name) html += `<span class="ruoyi-route-name">${utils.escapeHtml(name)}</span>`;
  if (title) html += `<span class="ruoyi-route-title">${utils.escapeHtml(title)}</span>`;
  if (component && typeof component === 'string') {
    html += `<span class="ruoyi-route-component">${utils.escapeHtml(component.split('/').pop())}</span>`;
  }
  if (route.meta && route.meta.roles) {
    const roles = Array.isArray(route.meta.roles) ? route.meta.roles : [route.meta.roles];
    if (roles.length > 0) {
      html += `<span class="ruoyi-route-roles" title="${utils.escapeHtml(roles.join(', '))}">${utils.escapeHtml(roles.length > 2 ? `${roles[0]},...` : roles.join(', '))}</span>`;
    }
  }
  if (route.meta && route.meta.perms) {
    const perms = Array.isArray(route.meta.perms) ? route.meta.perms : [route.meta.perms];
    if (perms.length > 0) {
      html += `<span class="ruoyi-route-perms" title="${utils.escapeHtml(perms.join(', '))}">${utils.escapeHtml(perms.length > 2 ? `${perms[0]},...` : perms.join(', '))}</span>`;
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
  let capturedRouterData = state ? state.capturedRouterData : null;
  if (!capturedRouterData) {
    utils.showToast('没有捕获的路由数据', 'warning');
    return;
  }

  try {
    const tab = await utils.requireTabId();
    if (!tab) {
      utils.showToast('无法获取当前标签页', 'warning');
      return;
    }
    const baseUrl = tab.url ? new URL(tab.url).origin : 'http://target';
    const paths = [];
    extractPathsFromData(capturedRouterData.data || capturedRouterData, paths);

    let cookieHeader = '';
    try {
      const token = await utils.execInTabData(tab.id, function () {
        const cookies = document.cookie || '';
        const match = cookies.match(/Admin-Token=[^;]*/i);
        return match ? match[0] : '';
      });
      if (token) {
        const safeToken = token.replace(/'/g, "'\\''");
        cookieHeader = ` -H 'Cookie: ${safeToken}'`;
      }
    } catch (e) {
      // ignore
    }

    const cmds = paths.map(function (p) {
      const safePath = p.replace(/'/g, "'\\''");
      return `curl -s '${baseUrl}${safePath}'${cookieHeader} -o /dev/null -w '%{http_code} ${safePath}\\n'`;
    });
    utils.copyText(cmds.join('\n'));
    utils.showToast(
      `已复制 ${cmds.length} 条 curl 命令${cookieHeader ? ' (含认证)' : ''}`,
      'success'
    );
  } catch (e) {
    utils.showToast(`导出失败: ${e.message}`, 'error');
  }
}

async function exportHtmlReport() {
  const capturedRouterData = state ? state.capturedRouterData : null;
  const extraRoutes = state ? state.extraRoutes : [];
  if (!capturedRouterData && extraRoutes.length === 0) {
    utils.showToast('没有数据可导出', 'warning');
    return;
  }

  const routes = (capturedRouterData && capturedRouterData.data) || [];
  let html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>RuoYi Route Report</title><style>body{font-family:monospace;font-size:13px;padding:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:6px 10px;text-align:left}th{background:#f5f5f5}.hidden{color:#999;font-style:italic}.section{margin:20px 0 10px;font-weight:bold;font-size:15px}</style></head><body>`;

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
      html += `<tr><td>${utils.escapeHtml(r.path || r.component || '')}</td><td>${utils.escapeHtml(r.source || '')}</td><td>${utils.escapeHtml(r.type || '')}</td></tr>`;
    });
    html += '</table>';
  }

  html += '</body></html>';
  utils.copyAndToast(html, 'HTML 报告已复制到剪贴板');
}

function renderFlatRoutes(routes, emit) {
  routes.forEach(function (r) {
    const hidden = r.hidden ? ' class="hidden"' : '';
    emit(
      `<tr${hidden}><td>${utils.escapeHtml(r.path || '')}</td><td>${utils.escapeHtml(r.name || '')}</td><td>${utils.escapeHtml((r.meta && r.meta.title) || '')}</td><td>${utils.escapeHtml(r.component || '')}</td><td>${r.hidden ? 'Yes' : ''}</td></tr>`
    );
    if (r.children) renderFlatRoutes(r.children, emit);
  });
}

// ====== Init ======

function init(stateRef) {
  state = stateRef;
}

export {
  init,
  installRouteHook,
  removeRouteHook,
  checkHookStatus,
  renderRouterData,
  renderRequestLog,
  exportCurlCommands,
  exportHtmlReport,
  extractPathsFromData,
};
