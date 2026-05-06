// vk-vue.js -- 灵眸 Chrome Extension
// Re-exporter: aggregates all Vue sub-modules into window.VulnKitVue
window.VulnKitVue = (function () {
  'use strict';

  var S = window.VulnKitVueState;
  return {
    detectVue: S.Detect.detectVue,
    exportVueRoutes: S.Detect.exportVueRoutes,
    bypassVueGuards: S.Detect.bypassVueGuards,
    disableRouteAuth: S.Detect.disableRouteAuth,
    collectAllPaths: S.Detect.collectAllPaths,
    switchVueSubTab: S.switchVueSubTab,
    startPermInterception: S.Perm.startPermInterception,
    stopPermInterception: S.Perm.stopPermInterception,
    refreshPermCaptured: S.Perm.refreshPermCaptured,
    showPermDetail: S.Perm.showPermDetail,
    permOpenAll: S.Perm.permOpenAll,
    permChangeAdmin: S.Perm.permChangeAdmin,
    permExpandMenuIds: S.Perm.permExpandMenuIds,
    applyPermOverride: S.Perm.applyPermOverride,
    renderPermList: S.Perm.renderPermList,
    startPermAutoRefresh: S.Perm.startPermAutoRefresh,
    stopPermAutoRefresh: S.Perm.stopPermAutoRefresh,
    searchJsKeywords: S.JsSearch.searchJsKeywords,
    extractPathsFromJsResults: S.JsSearch.extractPathsFromJsResults,
    autoFillFromJsPaths: S.JsSearch.autoFillFromJsPaths,
    extractKeywordsFromCapturedUrls: S.JsSearch.extractKeywordsFromCapturedUrls,
    autoSearchForZeroOpen: S.JsSearch.autoSearchForZeroOpen,
    compareRoutesAndMenu: S.Compare.compareRoutesAndMenu,
    startTraverseRoutes: S.Compare.startTraverseRoutes,
    stopTraverse: S.Compare.stopTraverse,
    autoInjectHiddenRoutes: S.Compare.autoInjectHiddenRoutes,
    exploreVueStore: S.Store.exploreVueStore,
    copyFullStoreJson: S.Store.copyFullStoreJson,
    initStoreExplorerEvents: S.Store.initStoreExplorerEvents,
    get lastVueResult() { return S.lastVueResult; },
    set lastVueResult(v) { S.lastVueResult = v; },
    get permInterceptActive() { return S.permInterceptActive; },
    set permInterceptActive(v) { S.permInterceptActive = v; },
    get permCapturedData() { return S.permCapturedData; },
    set permCapturedData(v) { S.permCapturedData = v; },
    get permSelectedIndex() { return S.permSelectedIndex; },
    set permSelectedIndex(v) { S.permSelectedIndex = v; },
    get permViewMode() { return S.permViewMode; },
    set permViewMode(v) { S.permViewMode = v; },
  };
})();
