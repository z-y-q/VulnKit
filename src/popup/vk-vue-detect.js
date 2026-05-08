// vk-vue-detect.js -- 灵眸 Chrome Extension
// Vue detection, route analysis, guard bypass, auth disable

import { utilsProxy as utils } from './vk-namespace.js';
import { vueState } from './vk-vue-state.js';

const S = vueState;

let lastRouterBase = '/';
let lastRouterMode = 'history';
let lastPageOrigin = '';

async function detectOnce(tabId) {
  try {
    let data = await chrome.tabs.sendMessage(tabId, { type: 'VK_VUE_DETECT' });
    if (!data || !data.detected) return data;
    return data;
  } catch (e) {
    try {
      await utils.execInTab(tabId, ['src/content/vk-content.js'], { world: 'ISOLATED' });
      await sleep(100);
      const data2 = await chrome.tabs.sendMessage(tabId, { type: 'VK_VUE_DETECT' });
      if (!data2 || !data2.detected) return data2;
      return data2;
    } catch (e2) {
      return null;
    }
  }
}

function sleep(ms) {
  return new Promise(function (r) {
    setTimeout(r, ms);
  });
}

async function detectWithRetry(tabId) {
  const delays = [0, 300, 600];
  for (let i = 0; i < delays.length; i++) {
    if (i > 0) await sleep(delays[i]);
    let result = await detectOnce(tabId);
    if (result && result.detected) return result;
  }
  return null;
}

async function detectVue() {
  const statusEl = utils.get('vue-status');
  const resultsEl = utils.get('vue-results');
  if (!statusEl || !resultsEl) return;

  statusEl.textContent = '检测中...';
  resultsEl.innerHTML = '';

  try {
    const tab = await utils.requireTabId();
    if (!tab) {
      statusEl.textContent = '无法获取当前标签页';
      return;
    }

    const data = await detectWithRetry(tab.id);

    if (!data) {
      statusEl.textContent = '未检测到 Vue';
      resultsEl.innerHTML = utils.emptyHtml('当前页面未使用 Vue 框架');
      return;
    }

    statusEl.textContent = `检测到 Vue ${data.version}`;

    const ri = data.routerInfo || {};
    lastRouterBase = ri.base || '/';
    lastRouterMode = ri.mode || 'history';
    lastPageOrigin = data.pageOrigin || '';

    let html = '';
    html += `<div class="vue-info-row"><span class="vue-info-label">版本</span><span class="vue-info-value"><span class="vue-badge vue-badge-ok">Vue ${utils.escapeHtml(data.version)}</span></span></div>`;
    html += `<div class="vue-info-row"><span class="vue-info-label">Vue Router</span><span class="vue-info-value">${data.router ? `<span class="vue-badge vue-badge-ok">已检测 (${utils.escapeHtml(ri.mode || '?')} 模式)</span>` : '未检测到'}</span></div>`;
    html += `<div class="vue-info-row"><span class="vue-info-label">Base Path</span><span class="vue-info-value">${utils.escapeHtml(ri.base || '/')}</span></div>`;
    html += `<div class="vue-info-row"><span class="vue-info-label">状态管理</span><span class="vue-info-value">${data.store ? '<span class="vue-badge vue-badge-warn">已检测</span>' : '未检测到'}</span></div>`;

    if (data.router && data.routes.length > 0) {
      html += `<div class="card-spacing"><div class="vue-route-toolbar"><span class="vue-route-count">路由列表 (${data.routes.length})</span><button class="btn btn-xs btn-outline vue-copy-hist-btn">复制 History URL</button><button class="btn btn-xs btn-outline vue-copy-hash-btn">复制 Hash URL</button></div></div>`;
      html += renderRouteTree(data.routes, 0, ri.base || '/', ri.mode || 'history');
    }

    resultsEl.innerHTML = html;
    S.lastVueResult = JSON.stringify(data, null, 2);
  } catch (e) {
    statusEl.textContent = '检测出错';
    resultsEl.innerHTML = utils.emptyHtml(e.message);
  }
}

function buildRouteUrl(path, base, mode) {
  const origin = lastPageOrigin || 'https://example.com';
  let basePath = base || '/';
  if (basePath.charAt(basePath.length - 1) !== '/') basePath += '/';
  const fullPath = basePath + (path || '/').replace(/^\//, '');
  if (mode === 'hash') {
    return `${origin}${basePath}#${path || '/'}`;
  }
  return `${origin}${fullPath}`;
}

function collectAllPaths(routes, prefix, base, mode) {
  let result = [];
  if (!routes || !Array.isArray(routes)) return result;
  routes.forEach(function (r) {
    let p = r.path || '/';
    if (p.charAt(0) !== '/' && prefix && prefix !== '/') {
      p = `${prefix}/${p}`;
    }
    let url = buildRouteUrl(p, base, mode);
    result.push({
      path: p,
      url: url,
      name: r.name || '',
      isParam: p.indexOf(':') !== -1 || p.indexOf('*') !== -1,
    });
    if (p.indexOf(':') !== -1 || p.indexOf('*') !== -1) {
      const probePath = p.replace(/:[^/]+/g, '1').replace(/\*/g, 'test');
      let probeUrl = buildRouteUrl(probePath, base, mode);
      result.push({
        path: probePath,
        url: probeUrl,
        name: `${r.name || ''}:probe`,
        isProbe: true,
      });
    }
    if (r.children && r.children.length > 0) {
      let childPaths = collectAllPaths(r.children, p === '/' ? '/' : p, base, mode);
      result = result.concat(childPaths);
    }
  });
  return result;
}

function renderRouteTree(routes, depth, base, mode) {
  let html = '';
  if (!routes || !Array.isArray(routes) || depth > 10) return html;
  base = base || '/';
  mode = mode || 'history';
  routes.forEach(function (route) {
    const routePath = route.path || '/';
    const histUrl = buildRouteUrl(routePath, base, 'history');
    const hashUrl = buildRouteUrl(routePath, base, 'hash');

    let metaHtml = '';
    if (route.meta) {
      try {
        const metaStr = JSON.stringify(route.meta).substring(0, 60);
        metaHtml = `<span class="vue-route-meta">meta: ${utils.escapeHtml(metaStr)}</span>`;
      } catch (e) {
        metaHtml = '<span class="vue-route-meta">meta: [无法序列化]</span>';
      }
    }
    html += `<div class="vue-route-item vue-depth-${depth}"><span class="vue-route-path">${utils.escapeHtml(routePath)}</span>${route.name ? `<span class="vue-route-name">${utils.escapeHtml(route.name)}</span>` : ''}${metaHtml}<span class="vue-route-urls"><button class="vue-route-open-btn" data-url="${utils.escapeHtml(histUrl)}" title="${utils.escapeHtml(histUrl)}">H</button><button class="vue-route-open-btn" data-url="${utils.escapeHtml(hashUrl)}" title="${utils.escapeHtml(hashUrl)}">#</button></span></div>`;
    if (route.children && route.children.length > 0) {
      html += renderRouteTree(route.children, depth + 1, base, mode);
    }
  });
  return html;
}

async function exportVueRoutes() {
  let tab = await utils.requireTabId();
  if (!tab) return;

  try {
    const routes = await utils.execInTabData(tab.id, function () {
      function safeSerialize(obj) {
        try {
          return JSON.parse(JSON.stringify(obj));
        } catch (e) {
          return null;
        }
      }
      function getRoutes(router) {
        if (!router) return null;
        if (typeof router.getRoutes === 'function') {
          return router.getRoutes().map(function (r) {
            return { path: r.path, name: r.name || '', meta: safeSerialize(r.meta) || {} };
          });
        }
        return router.options ? safeSerialize(router.options.routes) || null : null;
      }
      // VUE_ROOT_SELECTOR inlined: '#app,[data-v-app],[id^="app"],#root,#application,#main'
      let appEl = document.querySelector('#app,[data-v-app],[id^="app"],#root,#application,#main');
      if (appEl && appEl.__vue_app__) {
        const r = getRoutes(appEl.__vue_app__.config.globalProperties.$router);
        if (r) return r;
      }
      let allEls = document.querySelectorAll('*');
      for (let i = 0; i < allEls.length; i++) {
        if (allEls[i].__vue__) {
          let vm = allEls[i].__vue__.$root || allEls[i].__vue__;
          const r2 = getRoutes(vm.$router);
          if (r2) return r2;
        }
      }
      return null;
    });
    if (!routes) {
      utils.showToast('未找到 Vue Router', 'warning');
      return;
    }

    const json = JSON.stringify(routes, null, 2);
    utils.copyText(json);
    S.lastVueResult = json;
    utils.showToast(`路由已复制 (${routes.length} 条)`, 'success');
  } catch (e) {
    utils.showToast(`导出失败: ${e.message}`, 'error');
  }
}

async function bypassVueGuards() {
  const ok = await utils.confirmDanger(
    '即将清除所有 Vue Router 导航守卫，此操作不可逆，是否继续？'
  );
  if (!ok) return;
  let tab = await utils.requireTabId();
  if (!tab) return;

  try {
    let result = await utils.execInTabData(tab.id, function () {
      // VUE_ROOT_SELECTOR inlined: '#app,[data-v-app],[id^="app"],#root,#application,#main'
      let appEl = document.querySelector('#app,[data-v-app],[id^="app"],#root,#application,#main');
      if (appEl && appEl.__vue_app__) {
        let router = appEl.__vue_app__.config.globalProperties.$router;
        if (router) {
          if (Array.isArray(router.beforeGuards)) router.beforeGuards.length = 0;
          if (Array.isArray(router.afterGuards)) router.afterGuards.length = 0;
          if (Array.isArray(router.beforeResolveGuards)) router.beforeResolveGuards.length = 0;
          if (router.options && Array.isArray(router.options.routes)) {
            (function clearRouteGuards(routes) {
              for (let i = 0; i < routes.length; i++) {
                if (typeof routes[i].beforeEnter === 'function') {
                  routes[i].beforeEnter = undefined;
                }
                if (routes[i].children) clearRouteGuards(routes[i].children);
              }
            })(router.options.routes);
          }
          return 'vue3';
        }
      }
      let allEls = document.querySelectorAll('*');
      for (let n = 0; n < allEls.length; n++) {
        if (allEls[n].__vue__) {
          let vm = allEls[n].__vue__.$root || allEls[n].__vue__;
          if (vm.$router) {
            if (Array.isArray(vm.$router.beforeHooks)) vm.$router.beforeHooks.length = 0;
            if (Array.isArray(vm.$router.afterHooks)) vm.$router.afterHooks.length = 0;
            if (Array.isArray(vm.$router.beforeResolveHooks))
              vm.$router.beforeResolveHooks.length = 0;
            return 'vue2';
          }
        }
      }
      return null;
    });
    if (!result) {
      utils.showToast('未找到 Vue Router', 'warning');
      return;
    }
    utils.showToast(`路由守卫已清除 (Vue ${result === 'vue3' ? '3' : '2'})`, 'success');
  } catch (e) {
    utils.showToast(`绕过失败: ${e.message}`, 'error');
  }
}

async function disableRouteAuth() {
  const tab = await utils.requireTabId();
  if (!tab) return;

  try {
    const result = await utils.execInTabData(tab.id, function () {
      const authKeys = [
        'auth',
        'requireAuth',
        'requiresAuth',
        'login',
        'needLogin',
        'requiresLogin',
      ];
      let changed = 0;

      function clearAuthMeta(routes, depth) {
        if (!routes || !Array.isArray(routes) || depth > 20) return;
        for (let i = 0; i < routes.length; i++) {
          const route = routes[i];
          if (route.meta && typeof route.meta === 'object') {
            for (let j = 0; j < authKeys.length; j++) {
              if (authKeys[j] in route.meta && route.meta[authKeys[j]]) {
                route.meta[authKeys[j]] = false;
                changed++;
              }
            }
          }
          if (route.children) clearAuthMeta(route.children, depth + 1);
        }
      }

      // VUE_ROOT_SELECTOR inlined: '#app,[data-v-app],[id^="app"],#root,#application,#main'
      const appEl = document.querySelector('#app,[data-v-app],[id^="app"],#root,#application,#main');
      if (appEl && appEl.__vue_app__) {
        const router = appEl.__vue_app__.config.globalProperties.$router;
        if (router) {
          if (router.options && router.options.routes) clearAuthMeta(router.options.routes, 0);
          let flatRoutes;
          try {
            flatRoutes = router.getRoutes();
          } catch (e) {
            /* ignore */
          }
          if (flatRoutes) {
            for (let k = 0; k < flatRoutes.length; k++) {
              if (flatRoutes[k].meta && typeof flatRoutes[k].meta === 'object') {
                for (let m = 0; m < authKeys.length; m++) {
                  if (authKeys[m] in flatRoutes[k].meta && flatRoutes[k].meta[authKeys[m]]) {
                    flatRoutes[k].meta[authKeys[m]] = false;
                    changed++;
                  }
                }
              }
            }
          }
          return { version: 'vue3', changed: changed };
        }
      }

      const allEls = document.querySelectorAll('*');
      for (let n = 0; n < allEls.length; n++) {
        if (allEls[n].__vue__) {
          const vm = allEls[n].__vue__.$root || allEls[n].__vue__;
          if (vm.$router && vm.$router.options && vm.$router.options.routes) {
            clearAuthMeta(vm.$router.options.routes, 0);
            return { version: 'vue2', changed: changed };
          }
        }
      }
      return null;
    });
    if (!result) {
      utils.showToast('未找到 Vue Router', 'warning');
      return;
    }
    if (result.changed > 0) {
      utils.showToast(
        `已修改 ${result.changed} 条路由 auth (Vue ${result.version === 'vue3' ? '3' : '2'})`,
        'success'
      );
    } else {
      utils.showToast('未发现需要修改的 auth 字段', 'warning');
    }
  } catch (e) {
    utils.showToast(`修改失败: ${e.message}`, 'error');
  }
}

// Register on shared state for cross-module references
S.Detect = {
  detectVue: detectVue,
  exportVueRoutes: exportVueRoutes,
  bypassVueGuards: bypassVueGuards,
  disableRouteAuth: disableRouteAuth,
  collectAllPaths: collectAllPaths,
  sleep: sleep,
};

export {
  detectVue,
  exportVueRoutes,
  bypassVueGuards,
  disableRouteAuth,
  collectAllPaths,
  sleep,
};
