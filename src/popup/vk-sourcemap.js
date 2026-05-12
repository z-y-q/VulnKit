// vk-sourcemap.js -- 灵眸 Chrome Extension
// Re-exporter: aggregates all sourcemap sub-modules
import { smState } from './vk-sourcemap-state.js';
import { stopSourcemapScan } from './vk-sourcemap-utils.js';
import { scanWebpackModules } from './vk-sourcemap-scanner.js';
import { renderSourcemapModules, backToSourcemapList } from './vk-sourcemap-render.js';
import { analyzeSourcemaps, showApiEndpoints } from './vk-sourcemap-analysis.js';
import {
  copyAllSourcemapPaths,
  generateSourcemapTree,
  loadSourcesToDevTools,
  downloadAllSourcemapSources,
  downloadSingleModule,
  copyModuleSource,
  exportModulesJSON,
  exportModulesCSV,
} from './vk-sourcemap-actions.js';

export {
  smState,
  scanWebpackModules,
  stopSourcemapScan,
  copyAllSourcemapPaths,
  generateSourcemapTree,
  loadSourcesToDevTools,
  downloadAllSourcemapSources,
  backToSourcemapList,
  copyModuleSource,
  renderSourcemapModules,
  analyzeSourcemaps,
  downloadSingleModule,
  showApiEndpoints,
  exportModulesJSON,
  exportModulesCSV,
  getFindings,
};

function getFindings() {
  var findings = [];
  var modules = smState.sourcemapModules;
  if (!Array.isArray(modules) || modules.length === 0) return findings;

  var sourcemapCount = modules.filter(function (m) {
    return m.sourceType === 'sourcemap';
  }).length;
  var criticalCount = modules.filter(function (m) {
    return m.severity === 'critical';
  }).length;
  var highCount = modules.filter(function (m) {
    return m.severity === 'high';
  }).length;
  var leakModules = modules.filter(function (m) {
    return m.severity === 'critical' || m.severity === 'high';
  });

  if (sourcemapCount > 0) {
    findings.push({
      severity: 'high',
      title: 'Source Map 泄露',
      detail: sourcemapCount + ' 个模块暴露源码映射文件，可还原原始源码',
      module: 'sourcemap',
    });
  }
  if (criticalCount > 0) {
    var detail = leakModules
      .slice(0, 3)
      .map(function (m) {
        return m.label || m.path;
      })
      .join(', ');
    findings.push({
      severity: 'critical',
      title: '源码敏感信息泄露 (' + criticalCount + ' 项)',
      detail: detail,
      module: 'sourcemap',
    });
  } else if (highCount > 0) {
    var detail = leakModules
      .slice(0, 3)
      .map(function (m) {
        return m.label || m.path;
      })
      .join(', ');
    findings.push({
      severity: 'high',
      title: '源码安全风险 (' + highCount + ' 项)',
      detail: detail,
      module: 'sourcemap',
    });
  }
  if (modules.length > 0 && sourcemapCount === 0) {
    findings.push({
      severity: 'medium',
      title: 'Webpack 模块枚举',
      detail: '识别 ' + modules.length + ' 个前端模块',
      module: 'sourcemap',
    });
  }
  return findings;
}
