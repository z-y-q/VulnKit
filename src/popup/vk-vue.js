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
};
