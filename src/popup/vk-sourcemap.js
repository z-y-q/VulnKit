// vk-sourcemap.js -- 灵眸 Chrome Extension
// Re-exporter: aggregates all sourcemap sub-modules into window.VulnKitSourcemap
(function () {
  'use strict';

  var S = window.VulnKitSourcemapState;

  window.VulnKitSourcemap = {
    scanWebpackModules: S.Scanner.scanWebpackModules,
    stopSourcemapScan: S.Utils.stopSourcemapScan,
    copyAllSourcemapPaths: S.Actions.copyAllSourcemapPaths,
    generateSourcemapTree: S.Actions.generateSourcemapTree,
    loadSourcesToDevTools: S.Actions.loadSourcesToDevTools,
    downloadAllSourcemapSources: S.Actions.downloadAllSourcemapSources,
    backToSourcemapList: S.Render.backToSourcemapList,
    copyModuleSource: S.Actions.copyModuleSource,
    renderSourcemapModules: S.Render.renderSourcemapModules,
    analyzeSourcemaps: S.Analysis.analyzeSourcemaps,
    downloadSingleModule: S.Actions.downloadSingleModule,
    showApiEndpoints: S.Analysis.showApiEndpoints,
    exportModulesJSON: S.Actions.exportModulesJSON,
    exportModulesCSV: S.Actions.exportModulesCSV,

    get sourcemapModules() {
      return S.sourcemapModules;
    },
    set sourcemapModules(val) {
      S.sourcemapModules = val;
    },
    get sourcemapSearchTerm() {
      return S.sourcemapSearchTerm;
    },
    set sourcemapSearchTerm(val) {
      S.sourcemapSearchTerm = val;
    },
    get sourcemapCurrentModule() {
      return S.sourcemapCurrentModule;
    },
    set sourcemapCurrentModule(val) {
      S.sourcemapCurrentModule = val;
    },
  };
})();
