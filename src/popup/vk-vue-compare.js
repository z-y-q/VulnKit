// vk-vue-compare.js -- 灵眸 Chrome Extension
// Route vs menu comparison, hidden route injection, auto-traverse

import { utilsProxy as utils } from './vk-namespace.js';
import { vueState } from './vk-vue-state.js';

const S = vueState;

let traverseActive = false;

// ====== Route vs Menu Comparison helpers ======

function extractMenuPaths(data, paths) {
  if (typeof data !== 'object' || data === null) return;
  let pathKeys = ['path', 'url', 'href', 'menuUrl', 'menuPath', 'link', 'index'];
  if (Array.isArray(data)) {
    for (let i = 0; i < data.length; i++) extractMenuPaths(data[i], paths);
    return;
  }
  for (let k = 0; k < pathKeys.length; k++) {
    let val = data[pathKeys[k]];
    if (val && typeof val === 'string' && (val === '/' || /^\/[a-zA-Z0-9_\-]/.test(val)))
      paths.add(val);
  }
  if (data.children) extractMenuPaths(data.children, paths);
  if (data.subList) extractMenuPaths(data.subList, paths);
  if (data.child) extractMenuPaths(data.child, paths);
  if (data.childList) extractMenuPaths(data.childList, paths);
  if (data.items) extractMenuPaths(data.items, paths);
}

function isPathInMenu(routePath, menuPaths) {
  if (menuPaths.has(routePath)) return true;
  let iter = menuPaths.values();
  let mp = iter.next();
  while (!mp.done) {
    let menuPath = mp.value;
    if (routePath.indexOf(menuPath) === 0 && routePath !== menuPath) {
      let nextChar = routePath.charAt(menuPath.length);
      if (nextChar === '/' || !nextChar) return true;
    }
    mp = iter.next();
  }
  return false;
}

function findMenuArray(data, depth) {
  if (depth === undefined) depth = 0;
  if (depth > 3 || data === null || data === undefined) return null;
  if (Array.isArray(data) && data.length > 0 && typeof data[0] === 'object' && data[0] !== null) {
    return data;
  }
  if (typeof data === 'object' && !Array.isArray(data)) {
    let keys = Object.keys(data);
    for (let i = 0; i < keys.length; i++) {
      if (
        Array.isArray(data[keys[i]]) &&
        data[keys[i]].length > 0 &&
        typeof data[keys[i]][0] === 'object' &&
        data[keys[i]][0] !== null
      ) {
        return data[keys[i]];
      }
    }
    for (let j = 0; j < keys.length; j++) {
      if (
        typeof data[keys[j]] === 'object' &&
        data[keys[j]] !== null &&
        !Array.isArray(data[keys[j]])
      ) {
        let found = findMenuArray(data[keys[j]], depth + 1);
        if (found) return found;
      }
    }
  }
  return null;
}

function getTemplateFromMenuData(data) {
  let arr = findMenuArray(data);
  if (!arr || arr.length === 0) return null;
  let item = {};
  for (let k in arr[0]) {
    if (arr[0].hasOwnProperty(k)) item[k] = arr[0][k];
  }
  return item;
}

function constructMenuItemFromRoute(route, templateItem) {
  if (!templateItem || typeof templateItem !== 'object') {
    return {
      path: route.path,
      name: route.name || route.path,
      title: route.name || route.path,
      isshow: '1',
      status: 1,
    };
  }
  let item = {};
  for (let k in templateItem) {
    if (!templateItem.hasOwnProperty(k)) continue;
    if (k === 'path' || k === 'url' || k === 'href' || k === 'menuUrl' || k === 'menuPath') {
      item[k] = route.path;
    } else if (k === 'name' || k === 'menuName') {
      item[k] = route.name || route.path;
    } else if (k === 'title' || k === 'label' || k === 'text') {
      item[k] = route.name || route.path;
    } else if (k === 'id' || k === 'menuId' || k === 'key') {
      item[k] = Math.floor(Math.random() * 90000) + 10000;
    } else if (k === 'isshow' || k === 'isShow') {
      item[k] = '1';
    } else if (k === 'hidden') {
      item[k] = false;
    } else if (k === 'display' || k === 'visible') {
      item[k] = true;
    } else if (k === 'status') {
      item[k] = 1;
    } else if (
      k === 'children' ||
      k === 'child' ||
      k === 'subList' ||
      k === 'childList' ||
      k === 'items'
    ) {
      item[k] = [];
    } else if (k === 'meta' || k === 'component') {
      continue;
    } else {
      item[k] = templateItem[k];
    }
  }
  if (!item.path) item.path = route.path;
  return item;
}

function autoInjectHiddenRoutes() {
  let editor = utils.get('perm-json-editor');
  if (!editor) return;
  let text = editor.value;
  if (!text) {
    utils.showToast('请先选择一条捕获数据', 'warning');
    return;
  }
  if (S.lastCompareHiddenRoutes.length === 0) {
    utils.showToast('无缓存的路由对比结果，请先执行「路由对比」', 'warning');
    return;
  }
  try {
    let parsed = JSON.parse(text);
  } catch (e) {
    utils.showToast('JSON 格式错误', 'error');
    return;
  }
  let template = getTemplateFromMenuData(parsed);
  let targetArray = Array.isArray(parsed) ? parsed : findMenuArray(parsed);
  if (!targetArray) {
    utils.showToast('无法定位菜单数组，请检查 JSON 结构', 'warning');
    return;
  }
  let menuPaths = new Set();
  extractMenuPaths(parsed, menuPaths);
  let injected = 0;
  for (let h = 0; h < S.lastCompareHiddenRoutes.length; h++) {
    let route = S.lastCompareHiddenRoutes[h];
    if (!isPathInMenu(route.path, menuPaths)) {
      let newItem = constructMenuItemFromRoute(route, template);
      targetArray.push(newItem);
      injected++;
    }
  }
  editor.value = JSON.stringify(parsed, null, 2);
  utils.showToast(`已注入 ${injected} 条缺失路由到菜单数据`, 'success');
}

// ====== Auto-traverse routes ======

function addTraverseLog(idx, path, status) {
  let logEl = utils.get('traverse-log');
  if (!logEl) return;
  let statusClass = status === 'ok' ? 'log-ok' : status === 'fail' ? 'log-fail' : 'log-skip';
  let statusText = status === 'ok' ? '✓' : status === 'fail' ? '✗' : '–';
  let div = document.createElement('div');
  div.className = 'traverse-log-entry';
  div.innerHTML =
    `<span class="log-idx">${idx}</span>` +
    `<span class="log-path">${utils.escapeHtml(path)}</span>` +
    `<span class="${statusClass}">${statusText}</span>`;
  logEl.appendChild(div);
  logEl.scrollTop = logEl.scrollHeight;
}

function updateTraverseProgress(current, total, path) {
  let progressEl = utils.get('traverse-progress');
  if (progressEl) progressEl.textContent = `${current}/${total}${path ? ` → ${path}` : ''}`;
}

function stopTraverse() {
  traverseActive = false;
  utils.toggleBtnPair('traverse-start-btn', 'traverse-stop-btn', false);
  let progressEl = utils.get('traverse-progress');
  if (progressEl && !progressEl.textContent.includes('完成')) {
    progressEl.textContent += ' (已停止)';
  }
  utils.requireTabId().then(function (tab) {
    if (!tab) return;
    utils
      .execInTab(tab.id, function () {
        window.__VULN_TRAVERSE_ACTIVE__ = false;
      })
      .catch(function () {});
  });
}

async function startTraverseRoutes() {
  if (traverseActive) return;

  let hiddenOnly = utils.get('traverse-hidden-only');
  let useHiddenOnly = hiddenOnly ? hiddenOnly.checked : true;
  let delaySelect = utils.get('traverse-delay');
  let delay = delaySelect ? parseInt(delaySelect.value) : 3000;

  let routes = [];
  if (useHiddenOnly) {
    if (S.lastCompareHiddenRoutes.length === 0) {
      utils.showToast('没有隐藏路由，请先执行「路由对比」', 'warning');
      return;
    }
    routes = S.lastCompareHiddenRoutes.map(function (r) {
      return r.path;
    });
  } else {
    try {
      let tab = await utils.requireTabId();
      if (!tab) {
        utils.showToast('无法获取当前标签页', 'error');
        return;
      }
      routes =
        (await utils.execInTabData(tab.id, function () {
          let routes = [];
          let seen = {};
          function extract(rts, prefix) {
            rts.forEach(function (r) {
              let childPath = r.path || '/';
              let path;
              if (childPath.charAt(0) === '/') path = childPath;
              else if (prefix === '' || prefix === '/') path = `/${childPath}`;
              else path = `${prefix}/${childPath}`;
              if (r.path && r.path !== '*' && !seen[path]) {
                seen[path] = true;
                routes.push(path);
              }
              if (r.children) extract(r.children, path === '/' ? '/' : path);
            });
          }
          let appEl = document.querySelector(
            '#app,[data-v-app],[id^="app"],#root,#application,#main'
          );
          if (appEl && appEl.__vue_app__) {
            let router = appEl.__vue_app__.config.globalProperties.$router;
            if (router && typeof router.getRoutes === 'function') {
              router.getRoutes().forEach(function (r) {
                if (r.path && r.path !== '*' && !seen[r.path]) {
                  seen[r.path] = true;
                  routes.push(r.path);
                }
              });
            } else if (router && router.options && router.options.routes) {
              extract(router.options.routes, '');
            }
          } else {
            let els = document.querySelectorAll('*');
            for (let i = 0; i < els.length; i++) {
              if (els[i].__vue__) {
                let vm = els[i].__vue__.$root || els[i].__vue__;
                if (vm.$router) {
                  if (typeof vm.$router.getRoutes === 'function') {
                    vm.$router.getRoutes().forEach(function (r) {
                      if (r.path && r.path !== '*' && !seen[r.path]) {
                        seen[r.path] = true;
                        routes.push(r.path);
                      }
                    });
                  } else if (vm.$router.options && vm.$router.options.routes) {
                    extract(vm.$router.options.routes, '');
                  }
                }
                if (routes.length > 0) break;
              }
            }
          }
          return routes;
        })) || [];
    } catch (e) {
      utils.showToast(`获取路由失败: ${e.message}`, 'error');
      return;
    }
    if (routes.length === 0) {
      utils.showToast('未检测到路由，请先在「基础检测」中检测 Vue', 'warning');
      return;
    }
  }

  traverseActive = true;
  let logEl = utils.get('traverse-log');
  utils.toggleBtnPair('traverse-start-btn', 'traverse-stop-btn', true);
  if (logEl) logEl.innerHTML = '';
  updateTraverseProgress(0, routes.length, '准备中...');

  let tab = await utils.requireTabId();
  if (!tab) {
    stopTraverse();
    utils.showToast('无法获取当前标签页', 'error');
    return;
  }

  let tabId = tab.id;
  let currentIdx = 0;
  let total = routes.length;

  function navigateNext() {
    if (!traverseActive || currentIdx >= total) {
      if (traverseActive) {
        updateTraverseProgress(total, total, '遍历完成');
        let progressEl = utils.get('traverse-progress');
        if (progressEl) progressEl.textContent = `${total}/${total} 完成`;
        utils.showToast(`路由遍历完成，共 ${total} 条`, 'success');
      }
      stopTraverse();
      return;
    }

    let path = routes[currentIdx];
    updateTraverseProgress(currentIdx + 1, total, path);

    utils
      .execInTabData(
        tabId,
        function (p) {
          let router = null;
          let appEl = document.querySelector(
            '#app,[data-v-app],[id^="app"],#root,#application,#main'
          );
          if (appEl && appEl.__vue_app__) {
            router = appEl.__vue_app__.config.globalProperties.$router;
          } else {
            let els = document.querySelectorAll('*');
            for (let i = 0; i < els.length; i++) {
              if (els[i].__vue__) {
                let vm = els[i].__vue__.$root || els[i].__vue__;
                if (vm.$router) {
                  router = vm.$router;
                  break;
                }
              }
            }
          }
          if (router) {
            try {
              router.push(p);
              return { path: p, ok: true };
            } catch (e) {
              return { path: p, ok: false, error: e.message };
            }
          }
          return { path: p, ok: false, error: 'no router' };
        },
        { args: [path] }
      )
      .then(function (res) {
        if (res && res.ok) {
          addTraverseLog(currentIdx + 1, path, 'ok');
        } else {
          addTraverseLog(currentIdx + 1, path, res && res.error ? 'fail' : 'fail');
        }
        currentIdx++;
        if (traverseActive) setTimeout(navigateNext, delay);
      })
      .catch(function (err) {
        addTraverseLog(currentIdx + 1, path, 'fail');
        currentIdx++;
        if (traverseActive) setTimeout(navigateNext, delay);
      });
  }

  navigateNext();
}

// ====== Route vs Menu Comparison ======

async function compareRoutesAndMenu() {
  let statusEl = utils.get('compare-status');
  let resultsEl = utils.get('compare-results');
  if (statusEl) statusEl.textContent = '对比中...';

  try {
    let tab = await utils.requireTabId();
    if (!tab) {
      if (statusEl) statusEl.textContent = '无法获取当前标签页';
      return;
    }
    let routeList =
      (await utils.execInTabData(tab.id, function () {
        let routes = [];
        let seen = {};
        function extract(rts, prefix) {
          rts.forEach(function (r) {
            let childPath = r.path || '/';
            let path;
            if (childPath.charAt(0) === '/') path = childPath;
            else if (prefix === '' || prefix === '/') path = `/${childPath}`;
            else path = `${prefix}/${childPath}`;
            if (r.path && r.path !== '*' && !seen[path]) {
              seen[path] = true;
              routes.push({ path: path, name: r.name || '' });
            }
            if (r.children) extract(r.children, path === '/' ? '/' : path);
          });
        }
        function getAndExtract(router) {
          if (!router) return;
          if (typeof router.getRoutes === 'function') {
            let flat = router.getRoutes();
            for (let i = 0; i < flat.length; i++) {
              let p = flat[i].path;
              if (p && p !== '*' && !seen[p]) {
                seen[p] = true;
                routes.push({ path: p, name: flat[i].name || '' });
              }
            }
          } else if (router.options && router.options.routes) {
            extract(router.options.routes, '');
          }
        }
        let appEl = document.querySelector(
          '#app,[data-v-app],[id^="app"],#root,#application,#main'
        );
        if (appEl && appEl.__vue_app__) {
          getAndExtract(appEl.__vue_app__.config.globalProperties.$router);
        } else {
          let els = document.querySelectorAll('*');
          for (let i = 0; i < els.length; i++) {
            if (els[i].__vue__) {
              let vm = els[i].__vue__.$root || els[i].__vue__;
              getAndExtract(vm.$router);
              if (routes.length > 0) break;
            }
          }
        }
        return routes;
      })) || [];

    let captured =
      (await utils.execInTabData(tab.id, function () {
        return window.__PERM_INTERCEPTOR__ ? window.__PERM_INTERCEPTOR__.getCaptured() : [];
      })) || [];

    let menuPaths = new Set();
    for (let i = 0; i < captured.length; i++) extractMenuPaths(captured[i].data, menuPaths);

    if (routeList.length === 0) {
      if (statusEl) statusEl.textContent = '未找到路由';
      resultsEl.innerHTML = utils.emptyHtml('请先在「基础检测」中检测 Vue 路由');
      return;
    }

    let hiddenRoutes = [];
    let visibleRoutes = [];
    for (let j = 0; j < routeList.length; j++) {
      let r = routeList[j];
      if (isPathInMenu(r.path, menuPaths)) {
        visibleRoutes.push(r);
      } else {
        hiddenRoutes.push(r);
      }
    }
    S.lastCompareHiddenRoutes = hiddenRoutes.slice();

    function renderCompareSection(routes, cssClass, label) {
      if (!routes || routes.length === 0) return '';
      let h = `<div class="compare-section-title">${label} - ${routes.length} 条</div>`;
      for (let i = 0; i < routes.length; i++) {
        h +=
          `<div class="compare-route-item">` +
          `<span class="${cssClass}">[${cssClass.indexOf('hidden') !== -1 ? '隐藏' : '显示'}]</span> ` +
          `<span class="compare-route-path">${utils.escapeHtml(routes[i].path)}</span>` +
          (routes[i].name
            ? `<span class="compare-route-status">${utils.escapeHtml(routes[i].name)}</span>`
            : '') +
          `</div>`;
      }
      return h;
    }

    let html = '';
    html += renderCompareSection(
      hiddenRoutes,
      'compare-route-hidden',
      '隐藏路由 (路由存在但菜单中未显示)'
    );
    html += renderCompareSection(visibleRoutes, 'compare-route-visible', '已显示路由');
    if (captured.length === 0) {
      html += '<div class="compare-section-title compare-hint-title">提示</div>';
      html +=
        '<div class="compare-route-item compare-hint-text">未捕获菜单数据。请先在「权限菜单」标签中开始拦截，然后刷新页面。</div>';
    }

    if (statusEl)
      statusEl.textContent = `路由 ${routeList.length} 条，隐藏 ${hiddenRoutes.length} 条`;
    resultsEl.innerHTML = html;
  } catch (e) {
    if (statusEl) statusEl.textContent = '对比出错';
    utils.showToast(`对比失败: ${e.message}`, 'error');
  }
}

S.Compare = {
  extractMenuPaths: extractMenuPaths,
  isPathInMenu: isPathInMenu,
  findMenuArray: findMenuArray,
  getTemplateFromMenuData: getTemplateFromMenuData,
  constructMenuItemFromRoute: constructMenuItemFromRoute,
  autoInjectHiddenRoutes: autoInjectHiddenRoutes,
  compareRoutesAndMenu: compareRoutesAndMenu,
  startTraverseRoutes: startTraverseRoutes,
  stopTraverse: stopTraverse,
};

export {
  extractMenuPaths,
  isPathInMenu,
  findMenuArray,
  getTemplateFromMenuData,
  constructMenuItemFromRoute,
  autoInjectHiddenRoutes,
  compareRoutesAndMenu,
  startTraverseRoutes,
  stopTraverse,
};
