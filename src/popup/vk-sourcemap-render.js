// vk-sourcemap-render.js -- 灵眸 Chrome Extension
// Render sourcemap module list, detail card, back navigation
(function () {
  'use strict';

  var S = window.VulnKitSourcemapState;
  var utils = S.utils;

  function renderSourcemapModules() {
    var container = utils.get('sourcemap-results');
    if (!container) return;

    if (S.sourcemapModules.length === 0) {
      container.innerHTML = utils.emptyHtml('未找到 Webpack 模块');
      return;
    }

    // Filter
    var filtered = S.sourcemapModules;
    if (S.sourcemapSearchTerm) {
      filtered = S.sourcemapModules.filter(function (m) {
        return m.path.toLowerCase().indexOf(S.sourcemapSearchTerm) !== -1;
      });
    }

    // Group by source
    var groups = { runtime: [], sourcemap: [], chunk: [] };
    for (var i = 0; i < filtered.length; i++) {
      var g = groups[filtered[i].source] || groups.chunk;
      g.push({ module: filtered[i], index: S.sourcemapModules.indexOf(filtered[i]) });
    }

    // Enhanced stats bar
    function countBySource(src) {
      var c = 0;
      for (var i = 0; i < S.sourcemapModules.length; i++) {
        if (S.sourcemapModules[i].source === src) c++;
      }
      return c;
    }
    var stats = {
      total: S.sourcemapModules.length,
      runtime: countBySource('runtime'),
      sourcemap: countBySource('sourcemap'),
      chunk: countBySource('chunk'),
      resolved: S.sourcemapModules.filter(function (m) {
        return m.resolved;
      }).length,
    };
    var html = '<div class="sm-stats-bar">';
    html += '<span class="sm-stat-item sm-stat-total">共 ' + stats.total + ' 个模块</span>';
    if (stats.runtime > 0)
      html += '<span class="sm-stat-item sm-stat-rt">运行时 ' + stats.runtime + '</span>';
    if (stats.sourcemap > 0)
      html += '<span class="sm-stat-item sm-stat-sm">SourceMap ' + stats.sourcemap + '</span>';
    if (stats.chunk > 0)
      html += '<span class="sm-stat-item sm-stat-ch">JS解析 ' + stats.chunk + '</span>';
    if (stats.resolved > 0)
      html += '<span class="sm-stat-item sm-stat-src">可查看源码 ' + stats.resolved + '</span>';
    if (filtered.length !== S.sourcemapModules.length) {
      html += '<span class="sm-stat-item">显示 ' + filtered.length + '</span>';
    }
    html += '</div>';

    var groupLabels = S.SOURCE_TYPE_LABELS;
    var groupClasses = {
      runtime: 'sourcemap-section',
      sourcemap: 'sourcemap-section sourcemap-section-resolved',
      chunk: 'sourcemap-section sourcemap-section-numeric',
    };

    ['runtime', 'sourcemap', 'chunk'].forEach(function (key) {
      var items = groups[key];
      if (items.length === 0) return;
      html += '<div class="' + groupClasses[key] + '">';
      html +=
        '<div class="sourcemap-section-title">' +
        utils.escapeHtml(groupLabels[key]) +
        ' (' +
        items.length +
        ')</div>';
      items.forEach(function (item) {
        var m = item.module;
        // Extension badge -- skip for full URLs (extension already visible in URL)
        var extMatch = m.path.match(/\.[a-zA-Z0-9]+$/);
        var extBadge = '';
        if (extMatch && m.path.indexOf('://') === -1) {
          var ext = extMatch[0].toLowerCase();
          var extName = ext.replace('.', '');
          extBadge = '<span class="sm-ext-badge" data-ext="' + extName + '">' + extName + '</span>';
        }
        var badges =
          '<span class="sourcemap-item-source">' +
          (m.source === 'runtime' ? 'RT' : m.source === 'sourcemap' ? 'SM' : 'CH') +
          '</span>';
        if (m.resolved) badges += '<span class="sourcemap-item-resolved">SRC</span>';
        var meta = '';
        if (m.deps && m.deps.length > 0) meta += '(' + m.deps.length + ' deps)';
        if (m.reverseDeps && m.reverseDeps.length > 0)
          meta += (meta ? ' ' : '') + '(' + m.reverseDeps.length + ' used)';
        html += '<div class="sourcemap-item" data-idx="' + item.index + '">';
        html +=
          '<span class="sourcemap-item-name" title="' +
          utils.escapeHtml(m.path) +
          '">' +
          utils.escapeHtml(m.path) +
          extBadge +
          '</span>';
        html +=
          '<span class="sourcemap-item-meta">' + badges + ' ' + utils.escapeHtml(meta) + '</span>';
        html += '</div>';
      });
      html += '</div>';
    });

    container.innerHTML = html;

    // Hide detail card, show results
    var detailCard = utils.get('sourcemap-detail-card');
    if (detailCard) detailCard.classList.add('hidden');
    container.classList.remove('hidden');

    // Bind click handlers
    container.querySelectorAll('.sourcemap-item').forEach(function (el) {
      el.addEventListener('click', function () {
        var idx = parseInt(this.dataset.idx);
        if (!isNaN(idx)) showSourcemapModuleDetail(idx);
      });
    });
  }

  async function showSourcemapModuleDetail(index) {
    var mod = S.sourcemapModules[index];
    if (!mod) return;
    S.sourcemapCurrentModule = index;

    var detailCard = utils.get('sourcemap-detail-card');
    var resultsEl = utils.get('sourcemap-results');
    var titleEl = utils.get('sourcemap-detail-title');
    var depsEl = utils.get('sourcemap-deps-info');
    var codeEl = utils.get('sourcemap-source-code');

    if (!detailCard || !resultsEl || !titleEl || !depsEl || !codeEl) return;

    resultsEl.classList.add('hidden');
    detailCard.classList.remove('hidden');
    titleEl.textContent = mod.path;

    // Breadcrumb
    var sourceLabels = S.SOURCE_TYPE_LABELS;
    var existingBc = detailCard.querySelector('.sm-breadcrumb');
    if (existingBc) existingBc.remove();
    var bcHtml = '<div class="sm-breadcrumb">';
    bcHtml +=
      '<span class="sm-breadcrumb-source">' + (sourceLabels[mod.source] || mod.source) + '</span>';
    bcHtml += '<span>></span>';
    bcHtml += '<span>' + utils.escapeHtml(mod.path) + '</span>';
    bcHtml += '</div>';
    titleEl.insertAdjacentHTML('afterend', bcHtml);

    // Render deps
    function renderDepTags(ids, labelText, cssClass) {
      if (!ids || ids.length === 0) return '';
      var html =
        '<div class="sourcemap-deps-section"><span class="sourcemap-deps-label">' +
        labelText +
        '</span>';
      ids.forEach(function (id) {
        var found = null;
        for (var i = 0; i < S.sourcemapModules.length; i++) {
          if (S.sourcemapModules[i].id === String(id)) {
            found = S.sourcemapModules[i];
            break;
          }
        }
        var label = found ? found.path : id;
        var display =
          label.length > S.SM_MAX_LABEL_LEN ? label.substring(0, S.SM_MAX_LABEL_LEN) + '...' : label;
        html +=
          '<span class="sourcemap-dep-tag ' +
          cssClass +
          '" title="' +
          utils.escapeHtml(label) +
          '">' +
          utils.escapeHtml(display) +
          '</span>';
      });
      html += '</div>';
      return html;
    }

    depsEl.innerHTML =
      renderDepTags(mod.deps, '依赖:', '') +
      renderDepTags(mod.reverseDeps, '被引用:', 'sourcemap-dep-tag-reverse');

    // Load source code
    codeEl.value = '';
    var source = S.sourcemapSourceCache[mod.path];
    if (source) {
      codeEl.value = source;
    } else if (mod.sourceUrl) {
      codeEl.value = '正在加载源码...';
      try {
        var mapJson = S.sourcemapMapCache[mod.sourceUrl];
        if (mapJson && mapJson.sourcesContent) {
          var srcIdx = mapJson.sources.indexOf(mod.path);
          if (srcIdx === -1) srcIdx = mapJson.sources.indexOf('webpack://' + mod.path);
          if (srcIdx >= 0 && mapJson.sourcesContent[srcIdx]) {
            source = mapJson.sourcesContent[srcIdx];
            S.sourcemapSourceCache[mod.path] = source;
            codeEl.value = source;
            mod.resolved = true;
          } else {
            codeEl.value = '// 源码未包含在 Source Map 中';
          }
        } else {
          codeEl.value = '// 源码不可用';
        }
      } catch (e) {
        codeEl.value = '// 加载失败: ' + e.message;
      }
    } else {
      codeEl.value = '// 源码不可用（仅运行时检测到模块 ID）';
    }
  }

  function backToSourcemapList() {
    S.sourcemapCurrentModule = null;
    var detailCard = utils.get('sourcemap-detail-card');
    var resultsEl = utils.get('sourcemap-results');
    if (detailCard) detailCard.classList.add('hidden');
    if (resultsEl) resultsEl.classList.remove('hidden');
  }

  S.Render = {
    renderSourcemapModules: renderSourcemapModules,
    showSourcemapModuleDetail: showSourcemapModuleDetail,
    backToSourcemapList: backToSourcemapList,
  };
})();
