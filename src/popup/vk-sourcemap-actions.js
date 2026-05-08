// vk-sourcemap-actions.js -- 灵眸 Chrome Extension
// Copy, download, export, DevTools injection actions
import { utilsProxy as utils } from './vk-namespace.js';
import { smState } from './vk-sourcemap-state.js';

function copyAllSourcemapPaths() {
  if (smState.sourcemapModules.length === 0) {
    utils.showToast('没有模块路径', 'warning');
    return;
  }
  const paths = smState.sourcemapModules
    .map(function (m) {
      return m.path;
    })
    .filter(Boolean)
    .join('\n');
  utils.copyAndToast(paths, `已复制 ${smState.sourcemapModules.length} 个路径`);
}

function generateSourcemapTree() {
  if (smState.sourcemapModules.length === 0) {
    utils.showToast('没有模块路径', 'warning');
    return;
  }
  const tree = {};
  smState.sourcemapModules.forEach(function (m) {
    if (!m.path) return;
    const parts = m.path.replace(/^\.\/?/, '').split('/');
    let node = tree;
    for (let i = 0; i < parts.length; i++) {
      if (!node[parts[i]]) node[parts[i]] = {};
      node = node[parts[i]];
    }
  });

  function renderTree(obj, prefix, isLast) {
    let lines = [];
    const keys = Object.keys(obj).sort();
    keys.forEach(function (key, idx) {
      const last = idx === keys.length - 1;
      const connector = last ? '... ' : '|-- ';
      const childPrefix = last ? '    ' : '|   ';
      lines.push(prefix + connector + key);
      if (Object.keys(obj[key]).length > 0) {
        lines = lines.concat(renderTree(obj[key], prefix + childPrefix, last));
      }
    });
    return lines;
  }

  const treeLines = renderTree(tree, '', true);
  const output = treeLines.join('\n');
  utils.copyAndToast(output, '目录树已复制');
}

async function loadSourcesToDevTools() {
  const jsUrls = [];
  smState.sourcemapModules.forEach(function (m) {
    if (m.source === 'chunk' && m.path && m.path.indexOf('://') !== -1) {
      const url = m.path.split('?')[0];
      if (jsUrls.indexOf(url) === -1) jsUrls.push(url);
    }
  });
  if (jsUrls.length === 0) {
    utils.showToast('未找到可加载的 JS 文件', 'warning');
    return;
  }
  const ok = await utils.confirmDanger(
    `即将加载 ${jsUrls.length} 个 JS 源文件到 DevTools Sources 面板，是否继续？`
  );
  if (!ok) return;
  try {
    const tab = await utils.requireTabId();
    if (!tab) {
      utils.showToast('无法获取当前标签页', 'warning');
      return;
    }
    let count =
      (await utils.execInTabData(
        tab.id,
        function (urls) {
          const existing = new Set();
          document.querySelectorAll('script[src]').forEach(function (s) {
            existing.add(s.src.split('?')[0]);
          });
          let injected = 0;
          urls.forEach(function (url) {
            if (existing.has(url)) return;
            const script = document.createElement('script');
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
      utils.showToast(`${count} 个 JS 文件已注入页面，刷新 DevTools Sources 查看`, 'success');
    }
  } catch (e) {
    utils.copyText(jsUrls.join('\n'));
    utils.showToast('注入失败，URL 已复制到剪贴板', 'warning');
  }
}

async function downloadAllSourcemapSources() {
  const resolved = smState.sourcemapModules.filter(function (m) {
    return m.resolved || smState.sourcemapSourceCache[m.path];
  });
  if (resolved.length === 0) {
    utils.showToast('没有可下载的源码', 'warning');
    return;
  }
  let content = '';
  resolved.forEach(function (m) {
    const src = smState.sourcemapSourceCache[m.path] || '';
    content += `${'='.repeat(60)}\nFILE: ${m.path}\nMODULE: ${m.id}\n${'='.repeat(60)}\n${src}\n\n`;
  });
  const filename = `webpack-sources-${Date.now()}.txt`;
  utils.downloadBlob(content, filename, 'text/plain', `已下载 ${resolved.length} 个源文件`);
}

function downloadSingleModule(index) {
  const mod = smState.sourcemapModules[index];
  if (!mod) return;
  const source = smState.sourcemapSourceCache[mod.path] || '';
  if (!source) {
    utils.showToast('该模块没有可用的源码', 'warning');
    return;
  }
  const fileName = mod.path.split('/').pop() || 'module.js';
  utils.downloadBlob(source, fileName, 'text/javascript', `已下载 ${fileName}`);
}

function copyModuleSource() {
  const codeEl = utils.get('sourcemap-source-code');
  if (codeEl && codeEl.value) {
    utils.copyAndToast(codeEl.value, '已复制源码');
  }
}

function exportModulesJSON() {
  if (smState.sourcemapModules.length === 0) {
    utils.showToast('没有模块数据', 'warning');
    return;
  }
  const data = {
    exportedAt: new Date().toISOString(),
    moduleCount: smState.sourcemapModules.length,
    modules: smState.sourcemapModules.map(function (m) {
      return {
        path: m.path,
        source: m.source,
        type: smState.SOURCE_TYPE_LABELS[m.source] || m.source,
        size: m.size || 0,
        deps: m.deps || [],
      };
    }),
  };
  utils.copyText(JSON.stringify(data, null, 2));
  utils.showToast(`已导出 ${smState.sourcemapModules.length} 个模块 JSON`, 'success');
}

function exportModulesCSV() {
  if (smState.sourcemapModules.length === 0) {
    utils.showToast('没有模块数据', 'warning');
    return;
  }
  const lines = ['Path,Source,Size,Deps'];
  smState.sourcemapModules.forEach(function (m) {
    lines.push(
      `${utils.csvField(m.path)},${utils.csvField(m.source || '')},${utils.csvField(String(m.size || 0))},${m.deps ? m.deps.length : 0}`
    );
  });
  utils.copyText(lines.join('\n'));
  utils.showToast('已导出 CSV', 'success');
}

smState.Actions = {
  copyAllSourcemapPaths: copyAllSourcemapPaths,
  generateSourcemapTree: generateSourcemapTree,
  loadSourcesToDevTools: loadSourcesToDevTools,
  downloadAllSourcemapSources: downloadAllSourcemapSources,
  downloadSingleModule: downloadSingleModule,
  copyModuleSource: copyModuleSource,
  exportModulesJSON: exportModulesJSON,
  exportModulesCSV: exportModulesCSV,
};

export {
  copyAllSourcemapPaths,
  generateSourcemapTree,
  loadSourcesToDevTools,
  downloadAllSourcemapSources,
  downloadSingleModule,
  copyModuleSource,
  exportModulesJSON,
  exportModulesCSV,
};
