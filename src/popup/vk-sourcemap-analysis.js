// vk-sourcemap-analysis.js -- 灵眸 Chrome Extension
// Security analysis, API endpoint extraction
(function () {
  'use strict';

  var S = window.VulnKitSourcemapState;
  var utils = S.utils;

  async function analyzeSourcemaps() {
    var analysisCard = utils.get('sm-analysis-card');
    var progressEl = utils.get('sm-analysis-progress');
    var resultsEl = utils.get('sm-analysis-results');
    if (!analysisCard || !progressEl || !resultsEl) return;

    // Collect modules with available source code (sourcemap cache) + chunk JS URLs to fetch
    var resolvedModules = S.sourcemapModules.filter(function (m) {
      return S.sourcemapSourceCache[m.path] && m.source !== 'chunk';
    });
    var chunkToFetch = S.sourcemapModules.filter(function (m) {
      return (
        m.source === 'chunk' &&
        m.path &&
        m.path.indexOf('://') !== -1 &&
        !S.sourcemapSourceCache[m.path]
      );
    });

    // Fetch chunk JS content for analysis
    if (chunkToFetch.length > 0) {
      progressEl.innerHTML =
        '<div class="sm-analysis-progress-text">正在获取 ' +
        chunkToFetch.length +
        ' 个 JS 文件源码...</div>';
      var chunkUrls = chunkToFetch.map(function (m) {
        return m.path.split('?')[0];
      });
      var contents = await S.Utils.smBatchFetch(
        chunkUrls.slice(0, S.SM_MAX_CHUNK_SAMPLES),
        false,
        S.sourcemapTabId
      );
      for (var ci = 0; ci < contents.length; ci++) {
        if (contents[ci]) {
          S.sourcemapSourceCache[chunkToFetch[ci].path] = contents[ci];
          chunkToFetch[ci].resolved = true;
          resolvedModules.push(chunkToFetch[ci]);
        }
      }
      await new Promise(function (r) {
        setTimeout(r, 0);
      });
    }

    if (resolvedModules.length === 0) {
      utils.showToast('没有可分析的源码模块', 'warning');
      return;
    }

    analysisCard.classList.remove('hidden');
    resultsEl.innerHTML = '';
    progressEl.innerHTML =
      '<div class="sm-analysis-progress-text">正在分析 ' +
      resolvedModules.length +
      ' 个源码模块（Source Map）...</div>';

    var securityRules = S.SM_SECURITY_RULES;

    var allFindings = [];

    for (var mi = 0; mi < resolvedModules.length; mi++) {
      var mod = resolvedModules[mi];
      var source = S.sourcemapSourceCache[mod.path];
      if (!source) continue;

      for (var ri = 0; ri < securityRules.length; ri++) {
        var rName = securityRules[ri][0];
        var rPattern = securityRules[ri][1];
        var rSeverity = securityRules[ri][2];
        var regex = new RegExp(rPattern.source, rPattern.flags);
        var match;
        var matchCount = 0;
        while ((match = regex.exec(source)) !== null) {
          matchCount++;
          if (matchCount > 20) break;
          allFindings.push({
            severity: rSeverity,
            name: rName,
            match: (match[1] || match[0]).substring(0, S.SM_MAX_MATCH_LEN),
            file: mod.path,
            moduleIndex: S.sourcemapModules.indexOf(mod),
          });
        }
      }

      if (mi % 10 === 0) {
        progressEl.innerHTML =
          '<div class="sm-analysis-progress-text">已分析 ' +
          (mi + 1) +
          '/' +
          resolvedModules.length +
          ' 个模块...</div>';
        await new Promise(function (r) {
          setTimeout(r, 0);
        });
      }
    }

    progressEl.innerHTML = '';

    var severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    allFindings.sort(function (a, b) {
      return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
    });

    var severityLabels = {
      critical: '严重',
      high: '高危',
      medium: '中危',
      low: '低危',
      info: '信息',
    };
    var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    allFindings.forEach(function (f) {
      counts[f.severity]++;
    });

    var summaryHtml = '<div class="sm-analysis-summary">共发现 ' + allFindings.length + ' 个问题：';
    var filterHtml = '<div class="sm-analysis-filters">';
    filterHtml += '<span class="sm-filter-btn active" data-severity="all">全部</span>';
    severityOrder.forEach(function (s) {
      if (counts[s] > 0) {
        filterHtml +=
          ' <span class="sm-filter-btn sm-severity-' +
          s +
          '" data-severity="' +
          s +
          '">' +
          severityLabels[s] +
          ' ' +
          counts[s] +
          '</span>';
      }
    });
    filterHtml += '</div>';
    summaryHtml += '</div>';
    resultsEl.innerHTML = summaryHtml + filterHtml;

    var itemsHtml = '';
    var displayFindings = allFindings.slice(0, S.SM_MAX_FINDINGS);
    for (var fi = 0; fi < displayFindings.length; fi++) {
      var f = displayFindings[fi];
      itemsHtml +=
        '<div class="sm-analysis-item" data-severity="' +
        f.severity +
        '" data-idx="' +
        f.moduleIndex +
        '">';
      itemsHtml +=
        '<span class="sm-analysis-severity sm-severity-' +
        f.severity +
        '">' +
        severityLabels[f.severity] +
        '</span> ';
      itemsHtml += utils.escapeHtml(f.name) + ' ';
      itemsHtml += '<span class="sm-analysis-match">' + utils.escapeHtml(f.match) + '</span> ';
      itemsHtml += '<span class="sm-analysis-file">' + utils.escapeHtml(f.file) + '</span>';
      itemsHtml += '</div>';
    }
    resultsEl.innerHTML += itemsHtml;

    // Bind click to jump to module detail
    resultsEl.querySelectorAll('.sm-analysis-item').forEach(function (el) {
      el.addEventListener('click', function () {
        var idx = parseInt(this.dataset.idx);
        analysisCard.classList.add('hidden');
        if (!isNaN(idx)) S.Render.showSourcemapModuleDetail(idx);
      });
    });

    // Bind severity filter buttons
    resultsEl.querySelectorAll('.sm-filter-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        resultsEl.querySelectorAll('.sm-filter-btn').forEach(function (b) {
          b.classList.remove('active');
        });
        this.classList.add('active');
        var severity = this.dataset.severity;
        resultsEl.querySelectorAll('.sm-analysis-item').forEach(function (item) {
          item.style.display =
            severity === 'all' || item.dataset.severity === severity ? '' : 'none';
        });
      });
    });
  }

  function extractApiEndpoints() {
    var endpoints = {};
    var patterns = [
      /(?:axios|http|request|api|fetch)\s*\.\s*(?:get|post|put|delete|patch|head|options)\s*\(\s*['"`]([^'"`\s)]+)['"`]/gi,
      /fetch\s*\(\s*['"`]([^'"`\s)]+)['"`]/gi,
      /(?:url|uri|endpoint|apiUrl|baseUrl)\s*[:=]\s*['"`]([^'"`\s)]+)['"`]/gi,
      /['"`](\/api\/[^\s'"`)]{2,})['"`]/gi,
      /['"`](\/(?:v[0-9]+)\/[^\s'"`)]{2,})['"`]/gi,
    ];

    var skipRe = /\.(css|png|jpg|jpeg|gif|svg|ico|woff|ttf|eot|map)(?:\?|$)/i;
    S.sourcemapModules.forEach(function (mod) {
      var source = S.sourcemapSourceCache[mod.path];
      if (!source) return;
      patterns.forEach(function (pat) {
        var regex = new RegExp(pat.source, pat.flags);
        var match;
        while ((match = regex.exec(source)) !== null) {
          var url = match[1];
          if (!url || url.length < 3 || skipRe.test(url)) continue;
          url = url.replace(/\$\{[^}]*\}/g, ':param').replace(/['"`]/g, '');
          if (!endpoints[url]) {
            endpoints[url] = [];
          }
          if (endpoints[url].indexOf(mod.path) === -1) {
            endpoints[url].push(mod.path);
          }
        }
      });
    });

    return endpoints;
  }

  function showApiEndpoints() {
    var card = utils.get('sm-api-card');
    var listEl = utils.get('sm-api-list');
    if (!card || !listEl) return;

    var endpoints = extractApiEndpoints();
    var urls = Object.keys(endpoints).sort();

    if (urls.length === 0) {
      utils.showToast('未提取到 API 端点', 'warning');
      return;
    }

    card.classList.remove('hidden');
    var html =
      '<div class="sm-api-summary">提取到 <strong>' + urls.length + '</strong> 个 API 端点</div>';
    html += '<div class="sm-api-list-inner">';
    urls.forEach(function (url) {
      html += '<div class="sm-api-item">';
      html += '<span class="sm-api-url">' + utils.escapeHtml(url) + '</span>';
      html +=
        '<span class="sm-api-source">' +
        utils.escapeHtml(endpoints[url][0].split('/').pop()) +
        '</span>';
      html += '</div>';
    });
    html += '</div>';
    html +=
      '<div class="panel-actions"><button class="btn btn-sm btn-outline" id="sm-api-copy-btn">复制全部</button></div>';
    listEl.innerHTML = html;

    var copyBtn = utils.get('sm-api-copy-btn');
    if (copyBtn) {
      copyBtn.addEventListener('click', function () {
        utils.copyText(urls.join('\n'));
        utils.showToast('已复制 ' + urls.length + ' 个端点', 'success');
      });
    }
  }

  S.Analysis = {
    analyzeSourcemaps: analyzeSourcemaps,
    extractApiEndpoints: extractApiEndpoints,
    showApiEndpoints: showApiEndpoints,
  };
})();
