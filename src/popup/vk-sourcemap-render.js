// vk-sourcemap-render.js -- 灵眸 Chrome Extension
// Render sourcemap module list, detail card, back navigation
import { utilsProxy as utils } from './vk-namespace.js';
import { smState } from './vk-sourcemap-state.js';

function renderSourcemapModules() {
  const container = utils.get('sourcemap-results');
  if (!container) return;

  if (smState.sourcemapModules.length === 0) {
    container.innerHTML =
      '<div class="gather-empty-state"><div class="gather-empty-icon">&#128533;</div><div class="gather-empty-text">未找到 Webpack 模块</div></div>';
    return;
  }

  // Filter
  let filtered = smState.sourcemapModules;
  if (smState.sourcemapSearchTerm) {
    filtered = smState.sourcemapModules.filter(function (m) {
      return m.path.toLowerCase().indexOf(smState.sourcemapSearchTerm) !== -1;
    });
  }

  // Group by source
  const groups = { runtime: [], sourcemap: [], chunk: [] };
  for (let i = 0; i < filtered.length; i++) {
    const g = groups[filtered[i].source] || groups.chunk;
    g.push({ module: filtered[i], index: smState.sourcemapModules.indexOf(filtered[i]) });
  }

  // Enhanced stats bar
  function countBySource(src) {
    let c = 0;
    for (let i = 0; i < smState.sourcemapModules.length; i++) {
      if (smState.sourcemapModules[i].source === src) c++;
    }
    return c;
  }
  const stats = {
    total: smState.sourcemapModules.length,
    runtime: countBySource('runtime'),
    sourcemap: countBySource('sourcemap'),
    chunk: countBySource('chunk'),
    resolved: smState.sourcemapModules.filter(function (m) {
      return m.resolved;
    }).length,
  };
  let html = `<div class="sm-stats-bar">
    <span class="sm-stat-item sm-stat-total">共 ${stats.total} 个模块</span>
    ${stats.runtime > 0 ? `<span class="sm-stat-item sm-stat-rt">运行时 ${stats.runtime}</span>` : ''}
    ${stats.sourcemap > 0 ? `<span class="sm-stat-item sm-stat-sm">SourceMap ${stats.sourcemap}</span>` : ''}
    ${stats.chunk > 0 ? `<span class="sm-stat-item sm-stat-ch">JS解析 ${stats.chunk}</span>` : ''}
    ${stats.resolved > 0 ? `<span class="sm-stat-item sm-stat-src">可查看源码 ${stats.resolved}</span>` : ''}
    ${filtered.length !== smState.sourcemapModules.length ? `<span class="sm-stat-item">显示 ${filtered.length}</span>` : ''}
  </div>`;

  const groupLabels = smState.SOURCE_TYPE_LABELS;
  const groupClasses = {
    runtime: 'sourcemap-section',
    sourcemap: 'sourcemap-section sourcemap-section-resolved',
    chunk: 'sourcemap-section sourcemap-section-numeric',
  };

  ['runtime', 'sourcemap', 'chunk'].forEach(function (key) {
    const items = groups[key];
    if (items.length === 0) return;
    html += `<div class="${groupClasses[key]}">
      <div class="sourcemap-section-title">${utils.escapeHtml(groupLabels[key])} (${items.length})</div>`;
    items.forEach(function (item) {
      const m = item.module;
      // Extension badge -- skip for full URLs (extension already visible in URL)
      const extMatch = m.path.match(/\.[a-zA-Z0-9]+$/);
      let extBadge = '';
      if (extMatch && m.path.indexOf('://') === -1) {
        const ext = extMatch[0].toLowerCase();
        const extName = ext.replace('.', '');
        extBadge = `<span class="sm-ext-badge" data-ext="${extName}">${extName}</span>`;
      }
      let badges = `<span class="sourcemap-item-source">${m.source === 'runtime' ? 'RT' : m.source === 'sourcemap' ? 'SM' : 'CH'}</span>`;
      if (m.resolved) badges += '<span class="sourcemap-item-resolved">SRC</span>';
      let meta = '';
      if (m.deps && m.deps.length > 0) meta += `(${m.deps.length} deps)`;
      if (m.reverseDeps && m.reverseDeps.length > 0)
        meta += (meta ? ' ' : '') + `(${m.reverseDeps.length} used)`;
      html += `<div class="sourcemap-item" data-idx="${item.index}">
        <span class="sourcemap-item-name" title="${utils.escapeHtml(m.path)}">${utils.escapeHtml(m.path)}${extBadge}</span>
        <span class="sourcemap-item-meta">${badges} ${utils.escapeHtml(meta)}</span>
      </div>`;
    });
    html += '</div>';
  });

  container.innerHTML = html;

  // Hide detail card, show results
  let detailCard = utils.get('sourcemap-detail-card');
  if (detailCard) detailCard.classList.add('hidden');
  container.classList.remove('hidden');

  // Bind click handlers
  container.querySelectorAll('.sourcemap-item').forEach(function (el) {
    el.addEventListener('click', function () {
      const idx = parseInt(this.dataset.idx);
      if (!isNaN(idx)) showSourcemapModuleDetail(idx);
    });
  });
}

async function showSourcemapModuleDetail(index) {
  const mod = smState.sourcemapModules[index];
  if (!mod) return;
  smState.sourcemapCurrentModule = index;

  let detailCard = utils.get('sourcemap-detail-card');
  let resultsEl = utils.get('sourcemap-results');
  const titleEl = utils.get('sourcemap-detail-title');
  const depsEl = utils.get('sourcemap-deps-info');
  const codeEl = utils.get('sourcemap-source-code');

  if (!detailCard || !resultsEl || !titleEl || !depsEl || !codeEl) return;

  resultsEl.classList.add('hidden');
  detailCard.classList.remove('hidden');
  titleEl.textContent = mod.path;

  // Breadcrumb
  const sourceLabels = smState.SOURCE_TYPE_LABELS;
  const existingBc = detailCard.querySelector('.sm-breadcrumb');
  if (existingBc) existingBc.remove();
  let bcHtml = `<div class="sm-breadcrumb">
    <span class="sm-breadcrumb-source">${sourceLabels[mod.source] || mod.source}</span>
    <span>></span>
    <span>${utils.escapeHtml(mod.path)}</span>
  </div>`;
  titleEl.insertAdjacentHTML('afterend', bcHtml);

  // Render deps
  function renderDepTags(ids, labelText, cssClass) {
    if (!ids || ids.length === 0) return '';
    let html = `<div class="sourcemap-deps-section"><span class="sourcemap-deps-label">${labelText}</span>`;
    ids.forEach(function (id) {
      let found = null;
      for (let i = 0; i < smState.sourcemapModules.length; i++) {
        if (smState.sourcemapModules[i].id === String(id)) {
          found = smState.sourcemapModules[i];
          break;
        }
      }
      const label = found ? found.path : id;
      const display =
        label.length > smState.SM_MAX_LABEL_LEN
          ? `${label.substring(0, smState.SM_MAX_LABEL_LEN)}...`
          : label;
      html += `<span class="sourcemap-dep-tag ${cssClass}" title="${utils.escapeHtml(label)}">${utils.escapeHtml(display)}</span>`;
    });
    html += '</div>';
    return html;
  }

  depsEl.innerHTML =
    renderDepTags(mod.deps, '依赖:', '') +
    renderDepTags(mod.reverseDeps, '被引用:', 'sourcemap-dep-tag-reverse');

  // Load source code
  codeEl.value = '';
  let source = smState.sourcemapSourceCache[mod.path];
  if (source) {
    codeEl.value = source;
  } else if (mod.sourceUrl) {
    codeEl.value = '正在加载源码...';
    try {
      const mapJson = smState.sourcemapMapCache[mod.sourceUrl];
      if (mapJson && mapJson.sourcesContent) {
        let srcIdx = mapJson.sources.indexOf(mod.path);
        if (srcIdx === -1) srcIdx = mapJson.sources.indexOf(`webpack://${mod.path}`);
        if (srcIdx >= 0 && mapJson.sourcesContent[srcIdx]) {
          source = mapJson.sourcesContent[srcIdx];
          smState.sourcemapSourceCache[mod.path] = source;
          codeEl.value = source;
          mod.resolved = true;
        } else {
          codeEl.value = '// 源码未包含在 Source Map 中';
        }
      } else {
        codeEl.value = '// 源码不可用';
      }
    } catch (e) {
      codeEl.value = `// 加载失败: ${e.message}`;
    }
  } else {
    codeEl.value = '// 源码不可用（仅运行时检测到模块 ID）';
  }
}

function backToSourcemapList() {
  smState.sourcemapCurrentModule = null;
  const detailCard = utils.get('sourcemap-detail-card');
  const resultsEl = utils.get('sourcemap-results');
  if (detailCard) detailCard.classList.add('hidden');
  if (resultsEl) resultsEl.classList.remove('hidden');
}

smState.Render = {
  renderSourcemapModules: renderSourcemapModules,
  showSourcemapModuleDetail: showSourcemapModuleDetail,
  backToSourcemapList: backToSourcemapList,
};

export { renderSourcemapModules, showSourcemapModuleDetail, backToSourcemapList };
