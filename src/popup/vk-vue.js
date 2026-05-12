// vk-vue.js -- 灵眸 Chrome Extension
// Barrel: aggregates all Vue sub-modules

import { vueState } from './vk-vue-state.js';
import { switchVueSubTab } from './vk-vue-state.js';

import {
  detectVue,
  exportVueRoutes,
  bypassVueGuards,
  disableRouteAuth,
  restoreVueRuntime,
  navigateVueRoute,
  jumpToRoute,
  filterRouteTree,
  collectAllPaths,
} from './vk-vue-detect.js';

import {
  startPermInterception,
  stopPermInterception,
  refreshPermCaptured,
  renderPermList,
  showPermDetail,
  classifyPermType,
  showPermSuggestions,
  permOpenAll,
  permChangeAdmin,
  permExpandMenuIds,
  applyPermOverride,
  startPermAutoRefresh,
  stopPermAutoRefresh,
} from './vk-vue-perm.js';

import {
  searchJsKeywords,
  extractPathsFromJsResults,
  autoFillFromJsPaths,
  extractKeywordsFromCapturedUrls,
  autoSearchForZeroOpen,
} from './vk-vue-jssearch.js';

import {
  extractMenuPaths,
  isPathInMenu,
  findMenuArray,
  getTemplateFromMenuData,
  constructMenuItemFromRoute,
  autoInjectHiddenRoutes,
  compareRoutesAndMenu,
  startTraverseRoutes,
  stopTraverse,
} from './vk-vue-compare.js';

import { exploreVueStore, copyFullStoreJson, initStoreExplorerEvents } from './vk-vue-store.js';

export {
  vueState,
  switchVueSubTab,
  detectVue,
  exportVueRoutes,
  bypassVueGuards,
  disableRouteAuth,
  restoreVueRuntime,
  navigateVueRoute,
  jumpToRoute,
  filterRouteTree,
  collectAllPaths,
  startPermInterception,
  stopPermInterception,
  refreshPermCaptured,
  renderPermList,
  showPermDetail,
  classifyPermType,
  showPermSuggestions,
  permOpenAll,
  permChangeAdmin,
  permExpandMenuIds,
  applyPermOverride,
  startPermAutoRefresh,
  stopPermAutoRefresh,
  searchJsKeywords,
  extractPathsFromJsResults,
  autoFillFromJsPaths,
  extractKeywordsFromCapturedUrls,
  autoSearchForZeroOpen,
  extractMenuPaths,
  isPathInMenu,
  findMenuArray,
  getTemplateFromMenuData,
  constructMenuItemFromRoute,
  autoInjectHiddenRoutes,
  compareRoutesAndMenu,
  startTraverseRoutes,
  stopTraverse,
  exploreVueStore,
  copyFullStoreJson,
  initStoreExplorerEvents,
  getFindings,
};

function getFindings() {
  var findings = [];
  var result = null;
  if (vueState.lastVueResult) {
    try {
      result =
        typeof vueState.lastVueResult === 'string'
          ? JSON.parse(vueState.lastVueResult)
          : vueState.lastVueResult;
    } catch (_) {
      /* noop */
    }
  }
  if (result && result.detected) {
    if (result.version) {
      findings.push({
        severity: 'info',
        title: 'Vue 版本泄露',
        detail: '检测到 Vue ' + result.version,
        module: 'vue',
      });
    }
    if (result.store) {
      findings.push({
        severity: 'low',
        title: 'Vuex/Pinia Store 已启用',
        detail: '前端状态管理暴露，可能泄露业务数据结构',
        module: 'vue',
      });
    }
  }
  var hiddenRoutes = vueState.lastCompareHiddenRoutes;
  if (Array.isArray(hiddenRoutes) && hiddenRoutes.length > 0) {
    findings.push({
      severity: 'high',
      title: '隐藏路由发现',
      detail: '路由中存在但菜单未显示的 ' + hiddenRoutes.length + ' 个页面',
      module: 'vue',
    });
  }
  var permData = vueState.permCapturedData;
  if (Array.isArray(permData)) {
    var zeroCount = 0;
    var roleCount = 0;
    for (var i = 0; i < permData.length; i++) {
      var cls = classifyPermType(permData[i].data);
      if (cls.type === 'special-zero') zeroCount++;
      if (cls.type === 'role-active') roleCount++;
    }
    if (zeroCount > 0) {
      findings.push({
        severity: 'critical',
        title: '零权限 API 可达',
        detail: '发现 ' + zeroCount + ' 个返回空权限的接口，可能存在越权',
        module: 'vue',
      });
    }
    if (roleCount > 0) {
      findings.push({
        severity: 'medium',
        title: '角色控制字段检测',
        detail: '发现 ' + roleCount + ' 个接口返回角色控制字段（isAdmin/role 等）',
        module: 'vue',
      });
    }
  }
  return findings;
}
