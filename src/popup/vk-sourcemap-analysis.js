// vk-sourcemap-analysis.js -- 灵眸 Chrome Extension
// Security analysis, API endpoint extraction
import { utilsProxy as utils } from './vk-namespace.js';
import { smState } from './vk-sourcemap-state.js';
import { smBatchFetch } from './vk-sourcemap-utils.js';
import { showSourcemapModuleDetail } from './vk-sourcemap-render.js';

async function analyzeSourcemaps() {
  const analysisCard = utils.get('sm-analysis-card');
  const progressEl = utils.get('sm-analysis-progress');
  const resultsEl = utils.get('sm-analysis-results');
  if (!analysisCard || !progressEl || !resultsEl) return;

  // Collect modules with available source code (sourcemap cache) + chunk JS URLs to fetch
  const resolvedModules = smState.sourcemapModules.filter(function (m) {
    return smState.sourcemapSourceCache[m.path] && m.source !== 'chunk';
  });
  const chunkToFetch = smState.sourcemapModules.filter(function (m) {
    return (
      m.source === 'chunk' &&
      m.path &&
      m.path.indexOf('://') !== -1 &&
      !smState.sourcemapSourceCache[m.path]
    );
  });

  // Fetch chunk JS content for analysis
  if (chunkToFetch.length > 0) {
    progressEl.innerHTML = `<div class="sm-analysis-progress-text">正在获取 ${chunkToFetch.length} 个 JS 文件源码...</div>`;
    const chunkUrls = chunkToFetch.map(function (m) {
      return m.path.split('?')[0];
    });
    const contents = await smBatchFetch(
      chunkUrls.slice(0, smState.SM_MAX_CHUNK_SAMPLES),
      false,
      smState.sourcemapTabId
    );
    for (let ci = 0; ci < contents.length; ci++) {
      if (contents[ci]) {
        smState.sourcemapSourceCache[chunkToFetch[ci].path] = contents[ci];
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
  progressEl.innerHTML = `<div class="sm-analysis-progress-text">正在分析 ${resolvedModules.length} 个源码模块（Source Map）...</div>`;

  const securityRules = smState.SM_SECURITY_RULES;

  const allFindings = [];

  for (let mi = 0; mi < resolvedModules.length; mi++) {
    const mod = resolvedModules[mi];
    let source = smState.sourcemapSourceCache[mod.path];
    if (!source) continue;

    for (let ri = 0; ri < securityRules.length; ri++) {
      const rName = securityRules[ri][0];
      const rPattern = securityRules[ri][1];
      const rSeverity = securityRules[ri][2];
      let regex = new RegExp(rPattern.source, rPattern.flags);
      let match;
      let matchCount = 0;
      while ((match = regex.exec(source)) !== null) {
        matchCount++;
        if (matchCount > 20) break;
        allFindings.push({
          severity: rSeverity,
          name: rName,
          match: (match[1] || match[0]).substring(0, smState.SM_MAX_MATCH_LEN),
          file: mod.path,
          moduleIndex: smState.sourcemapModules.indexOf(mod),
        });
      }
    }

    if (mi % 10 === 0) {
      progressEl.innerHTML = `<div class="sm-analysis-progress-text">已分析 ${mi + 1}/${resolvedModules.length} 个模块...</div>`;
      await new Promise(function (r) {
        setTimeout(r, 0);
      });
    }
  }

  progressEl.innerHTML = '';

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  allFindings.sort(function (a, b) {
    return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
  });

  const severityLabels = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
  };
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  allFindings.forEach(function (f) {
    counts[f.severity]++;
  });

  let summaryHtml = `<div class="sm-analysis-summary">共发现 ${allFindings.length} 个问题：`;
  let filterHtml = '<div class="sm-analysis-filters">';
  filterHtml += '<span class="sm-filter-btn active" data-severity="all">全部</span>';
  severityOrder.forEach(function (s) {
    if (counts[s] > 0) {
      filterHtml += ` <span class="sm-filter-btn sm-severity-${s}" data-severity="${s}">${severityLabels[s]} ${counts[s]}</span>`;
    }
  });
  filterHtml += '</div>';
  summaryHtml += '</div>';
  resultsEl.innerHTML = summaryHtml + filterHtml;

  let itemsHtml = '';
  const displayFindings = allFindings.slice(0, smState.SM_MAX_FINDINGS);
  for (let fi = 0; fi < displayFindings.length; fi++) {
    const f = displayFindings[fi];
    itemsHtml += `<div class="sm-analysis-item" data-severity="${f.severity}" data-idx="${f.moduleIndex}"><span class="sm-analysis-severity sm-severity-${f.severity}">${severityLabels[f.severity]}</span> ${utils.escapeHtml(f.name)} <span class="sm-analysis-match">${utils.escapeHtml(f.match)}</span> <span class="sm-analysis-file">${utils.escapeHtml(f.file)}</span></div>`;
  }
  resultsEl.innerHTML += itemsHtml;

  // Bind click to jump to module detail
  resultsEl.querySelectorAll('.sm-analysis-item').forEach(function (el) {
    el.addEventListener('click', function () {
      const idx = parseInt(this.dataset.idx);
      analysisCard.classList.add('hidden');
      if (!isNaN(idx)) showSourcemapModuleDetail(idx);
    });
  });

  // Bind severity filter buttons
  resultsEl.querySelectorAll('.sm-filter-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      resultsEl.querySelectorAll('.sm-filter-btn').forEach(function (b) {
        b.classList.remove('active');
      });
      this.classList.add('active');
      let severity = this.dataset.severity;
      resultsEl.querySelectorAll('.sm-analysis-item').forEach(function (item) {
        item.style.display = severity === 'all' || item.dataset.severity === severity ? '' : 'none';
      });
    });
  });
}

function extractApiEndpoints() {
  let endpoints = {};
  const patterns = [
    /(?:axios|http|request|api|fetch)\s*\.\s*(?:get|post|put|delete|patch|head|options)\s*\(\s*['"`]([^'"`\s)]+)['"`]/gi,
    /fetch\s*\(\s*['"`]([^'"`\s)]+)['"`]/gi,
    /(?:url|uri|endpoint|apiUrl|baseUrl)\s*[:=]\s*['"`]([^'"`\s)]+)['"`]/gi,
    /['"`](\/api\/[^\s'"`)]{2,})['"`]/gi,
    /['"`](\/(?:v[0-9]+)\/[^\s'"`)]{2,})['"`]/gi,
    /['"`](\/graphql[^\s'"`)]*)['"`]/gi,
    /new\s+WebSocket\s*\(\s*['"`]([^'"`\s)]+)['"`]/gi,
    /['"`](wss?:\/\/[^\s'"`)]+)['"`]/gi,
    /socket\.io\s*\(\s*['"`]([^'"`\s)]+)['"`]/gi,
    /io\s*\(\s*['"`]([^'"`\s)]+)['"`]/gi,
  ];

  const skipRe = /\.(css|png|jpg|jpeg|gif|svg|ico|woff|ttf|eot|map)(?:\?|$)/i;
  smState.sourcemapModules.forEach(function (mod) {
    const source = smState.sourcemapSourceCache[mod.path];
    if (!source) return;
    patterns.forEach(function (pat) {
      const regex = new RegExp(pat.source, pat.flags);
      let match;
      while ((match = regex.exec(source)) !== null) {
        let url = match[1];
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

function extractGraphQLQueries() {
  var queries = [];
  var patterns = [
    /gql\s*`([\s\S]*?)`/g,
    /graphql\s*`([\s\S]*?)`/g,
    /(?:query|mutation|subscription)\s+(\w+)\s*\{([\s\S]*?)\}/g,
    /['"`]\s*(?:query|mutation|subscription)\s+\w+\s*\{[\s\S]*?\}\s*['"`]/g,
  ];

  smState.sourcemapModules.forEach(function (mod) {
    var source = smState.sourcemapSourceCache[mod.path];
    if (!source) return;
    patterns.forEach(function (pat) {
      var regex = new RegExp(pat.source, pat.flags);
      var match;
      var count = 0;
      while ((match = regex.exec(source)) !== null) {
        if (count++ > 10) break;
        var body = match[1] || match[0];
        if (!body || body.length < 5) continue;
        var cleaned = body.replace(/\s+/g, ' ').trim().substring(0, 300);
        if (cleaned.length < 10) continue;
        queries.push({
          body: cleaned,
          file: mod.path,
          moduleIndex: smState.sourcemapModules.indexOf(mod),
        });
      }
    });
  });

  return queries;
}

function extractWebSocketUrls() {
  var wsUrls = {};
  var patterns = [
    /new\s+WebSocket\s*\(\s*['"`]([^'"`\s)]+)['"`]/gi,
    /['"`](wss?:\/\/[^\s'"`)]+)['"`]/gi,
    /socket\.io\s*\(\s*\{?\s*url\s*:\s*['"`]([^'"`\s)]+)['"`]/gi,
  ];

  smState.sourcemapModules.forEach(function (mod) {
    var source = smState.sourcemapSourceCache[mod.path];
    if (!source) return;
    patterns.forEach(function (pat) {
      var regex = new RegExp(pat.source, pat.flags);
      var match;
      while ((match = regex.exec(source)) !== null) {
        var url = match[1];
        if (!url) continue;
        url = url.replace(/\$\{[^}]*\}/g, ':param').replace(/['"`]/g, '');
        if (!wsUrls[url]) {
          wsUrls[url] = [];
        }
        if (wsUrls[url].indexOf(mod.path) === -1) {
          wsUrls[url].push(mod.path);
        }
      }
    });
  });

  return wsUrls;
}

function showApiEndpoints() {
  const card = utils.get('sm-api-card');
  const listEl = utils.get('sm-api-list');
  if (!card || !listEl) return;

  const endpoints = extractApiEndpoints();
  const urls = Object.keys(endpoints).sort();

  if (urls.length === 0) {
    utils.showToast('未提取到 API 端点', 'warning');
    return;
  }

  card.classList.remove('hidden');
  let html = `<div class="sm-api-summary">提取到 <strong>${urls.length}</strong> 个 API 端点</div>`;
  html += '<div class="sm-api-list-inner">';
  urls.forEach(function (url) {
    html += `<div class="sm-api-item"><span class="sm-api-url">${utils.escapeHtml(url)}</span><span class="sm-api-source">${utils.escapeHtml(endpoints[url][0].split('/').pop())}</span></div>`;
  });
  html += '</div>';
  html +=
    '<div class="panel-actions"><button class="btn btn-sm btn-outline" id="sm-api-copy-btn">复制全部</button></div>';
  listEl.innerHTML = html;

  const copyBtn = utils.get('sm-api-copy-btn');
  if (copyBtn) {
    copyBtn.addEventListener('click', function () {
      utils.copyText(urls.join('\n'));
      utils.showToast(`已复制 ${urls.length} 个端点`, 'success');
    });
  }
}

smState.Analysis = {
  analyzeSourcemaps: analyzeSourcemaps,
  extractApiEndpoints: extractApiEndpoints,
  extractGraphQLQueries: extractGraphQLQueries,
  extractWebSocketUrls: extractWebSocketUrls,
  showApiEndpoints: showApiEndpoints,
};

export {
  analyzeSourcemaps,
  extractApiEndpoints,
  extractGraphQLQueries,
  extractWebSocketUrls,
  showApiEndpoints,
};
