// vk-sourcemap-actions.js -- 灵眸 Chrome Extension
// Copy, download, export, DevTools injection actions
(function () {
  'use strict';

  var S = window.VulnKitSourcemapState;
  var utils = S.utils;

  function copyAllSourcemapPaths() {
    if (S.sourcemapModules.length === 0) {
      utils.showToast('没有模块路径', 'warning');
      return;
    }
    var paths = S.sourcemapModules
      .map(function (m) {
        return m.path;
      })
      .filter(Boolean)
      .join('\n');
    utils.copyAndToast(paths, '已复制 ' + S.sourcemapModules.length + ' 个路径');
  }

  function generateSourcemapTree() {
    if (S.sourcemapModules.length === 0) {
      utils.showToast('没有模块路径', 'warning');
      return;
    }
    var tree = {};
    S.sourcemapModules.forEach(function (m) {
      if (!m.path) return;
      var parts = m.path.replace(/^\.\/?/, '').split('/');
      var node = tree;
      for (var i = 0; i < parts.length; i++) {
        if (!node[parts[i]]) node[parts[i]] = {};
        node = node[parts[i]];
      }
    });

    function renderTree(obj, prefix, isLast) {
      var lines = [];
      var keys = Object.keys(obj).sort();
      keys.forEach(function (key, idx) {
        var last = idx === keys.length - 1;
        var connector = last ? '... ' : '|-- ';
        var childPrefix = last ? '    ' : '|   ';
        lines.push(prefix + connector + key);
        if (Object.keys(obj[key]).length > 0) {
          lines = lines.concat(renderTree(obj[key], prefix + childPrefix, last));
        }
      });
      return lines;
    }

    var treeLines = renderTree(tree, '', true);
    var output = treeLines.join('\n');
    utils.copyAndToast(output, '目录树已复制');
  }

  async function loadSourcesToDevTools() {
    var jsUrls = [];
    S.sourcemapModules.forEach(function (m) {
      if (m.source === 'chunk' && m.path && m.path.indexOf('://') !== -1) {
        var url = m.path.split('?')[0];
        if (jsUrls.indexOf(url) === -1) jsUrls.push(url);
      }
    });
    if (jsUrls.length === 0) {
      utils.showToast('未找到可加载的 JS 文件', 'warning');
      return;
    }
    var ok = await utils.confirmDanger(
      '即将加载 ' + jsUrls.length + ' 个 JS 源文件到 DevTools Sources 面板，是否继续？'
    );
    if (!ok) return;
    try {
      var tab = await utils.requireTabId();
      if (!tab) {
        utils.showToast('无法获取当前标签页', 'warning');
        return;
      }
      var count =
        (await utils.execInTabData(
          tab.id,
          function (urls) {
            var existing = new Set();
            document.querySelectorAll('script[src]').forEach(function (s) {
              existing.add(s.src.split('?')[0]);
            });
            var injected = 0;
            urls.forEach(function (url) {
              if (existing.has(url)) return;
              var script = document.createElement('script');
              script.src = url;
              script.async = true;
              document.head.appendChild(script);
              injected++;
            });
            return injected;
          },
          { args: [jsUrls], world: 'MAIN' }
        )) || 0;
      if (count === 0) {
        utils.showToast('所有 JS 文件已在页面中加载', 'info');
      } else {
        utils.showToast(count + ' 个 JS 文件已注入页面，刷新 DevTools Sources 查看', 'success');
      }
    } catch (e) {
      utils.copyText(jsUrls.join('\n'));
      utils.showToast('注入失败，URL 已复制到剪贴板', 'warning');
    }
  }

  async function downloadAllSourcemapSources() {
    var resolved = S.sourcemapModules.filter(function (m) {
      return m.resolved || S.sourcemapSourceCache[m.path];
    });
    if (resolved.length === 0) {
      utils.showToast('没有可下载的源码', 'warning');
      return;
    }
    var content = '';
    resolved.forEach(function (m) {
      var src = S.sourcemapSourceCache[m.path] || '';
      content += '='.repeat(60) + '\n';
      content += 'FILE: ' + m.path + '\n';
      content += 'MODULE: ' + m.id + '\n';
      content += '='.repeat(60) + '\n';
      content += src + '\n\n';
    });
    var filename = 'webpack-sources-' + Date.now() + '.txt';
    utils.downloadBlob(content, filename, 'text/plain', '已下载 ' + resolved.length + ' 个源文件');
  }

  function downloadSingleModule(index) {
    var mod = S.sourcemapModules[index];
    if (!mod) return;
    var source = S.sourcemapSourceCache[mod.path] || '';
    if (!source) {
      utils.showToast('该模块没有可用的源码', 'warning');
      return;
    }
    var fileName = mod.path.split('/').pop() || 'module.js';
    utils.downloadBlob(source, fileName, 'text/javascript', '已下载 ' + fileName);
  }

  function copyModuleSource() {
    var codeEl = utils.get('sourcemap-source-code');
    if (codeEl && codeEl.value) {
      utils.copyAndToast(codeEl.value, '已复制源码');
    }
  }

  function exportModulesJSON() {
    if (S.sourcemapModules.length === 0) {
      utils.showToast('没有模块数据', 'warning');
      return;
    }
    var data = {
      exportedAt: new Date().toISOString(),
      moduleCount: S.sourcemapModules.length,
      modules: S.sourcemapModules.map(function (m) {
        return {
          path: m.path,
          source: m.source,
          type: S.SOURCE_TYPE_LABELS[m.source] || m.source,
          size: m.size || 0,
          deps: m.deps || [],
        };
      }),
    };
    utils.copyText(JSON.stringify(data, null, 2));
    utils.showToast('已导出 ' + S.sourcemapModules.length + ' 个模块 JSON', 'success');
  }

  function exportModulesCSV() {
    if (S.sourcemapModules.length === 0) {
      utils.showToast('没有模块数据', 'warning');
      return;
    }
    var lines = ['Path,Source,Size,Deps'];
    S.sourcemapModules.forEach(function (m) {
      lines.push(
        utils.csvField(m.path) +
          ',' +
          utils.csvField(m.source || '') +
          ',' +
          utils.csvField(String(m.size || 0)) +
          ',' +
          (m.deps ? m.deps.length : 0)
      );
    });
    utils.copyText(lines.join('\n'));
    utils.showToast('已导出 CSV', 'success');
  }

  S.Actions = {
    copyAllSourcemapPaths: copyAllSourcemapPaths,
    generateSourcemapTree: generateSourcemapTree,
    loadSourcesToDevTools: loadSourcesToDevTools,
    downloadAllSourcemapSources: downloadAllSourcemapSources,
    downloadSingleModule: downloadSingleModule,
    copyModuleSource: copyModuleSource,
    exportModulesJSON: exportModulesJSON,
    exportModulesCSV: exportModulesCSV,
  };
})();
