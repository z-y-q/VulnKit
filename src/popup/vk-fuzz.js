// vk-fuzz.js -- 灵眸 Chrome Extension
// Directory / Path brute-force enumeration

import { utilsProxy as utils } from './vk-namespace.js';

var DEFAULT_WORDLISTS = {
  common: [
    '/admin/',
    '/admin/login',
    '/admin/dashboard',
    '/login/',
    '/console/',
    '/debug/',
    '/test/',
    '/tmp/',
    '/uploads/',
    '/upload/',
    '/backup/',
    '/config/',
    '/status/',
    '/info/',
    '/health',
    '/metrics/',
    '/api/',
    '/api/v1/',
    '/api/v2/',
    '/swagger-ui.html',
    '/swagger-ui/',
    '/doc.html',
    '/docs/',
    '/api-docs',
    '/graphiql',
    '/graphql',
    '/wp-admin/',
    '/wp-login.php',
    '/wp-json/',
    '/phpmyadmin/',
    '/manager/html',
    '/server-status',
    '/server-info',
    '/.env',
    '/.git/',
    '/.git/config',
    '/.svn/',
    '/.DS_Store',
    '/robots.txt',
    '/sitemap.xml',
    '/crossdomain.xml',
    '/WEB-INF/',
    '/WEB-INF/web.xml',
    '/actuator/',
    '/actuator/health',
    '/actuator/env',
    '/actuator/mappings',
    '/trace',
    '/console/',
    '/administrator/',
    '/manage/',
    '/user/',
    '/users/',
    '/setup/',
    '/install/',
    '/phpinfo.php',
    '/.htaccess',
    '/.htpasswd',
    '/web.config',
    '/config.php',
    '/config.yml',
    '/config.json',
    '/database.sql',
    '/db.sql',
    '/backup.sql',
    '/dump.sql',
    '/assets/',
    '/static/',
    '/public/',
    '/media/',
    '/files/',
    '/download/',
    '/export/',
    '/import/',
    '/log/',
    '/logs/',
    '/error/',
    '/errors/',
    '/exception/',
    '/trace/',
  ],
  backup: [
    '/.bak',
    '/.zip',
    '/.tar.gz',
    '/.tgz',
    '/.rar',
    '/.7z',
    '/backup.zip',
    '/backup.tar.gz',
    '/backup.sql',
    '/backup.gz',
    '/www.zip',
    '/www.tar.gz',
    '/web.zip',
    '/site.zip',
    '/db_backup.sql',
    '/database.sql',
    '/dump.sql',
    '/data.sql',
    '/backup/',
    '/backups/',
    '/old/',
    '/archive/',
    '/.git/HEAD',
    '/.git/config',
    '/.gitignore',
    '/.svn/entries',
    '/.hg/store',
    '/.env',
    '/.env.bak',
    '/.env.local',
    '/.env.production',
    '/.env.development',
    '/.env.staging',
    '/web.config.bak',
    '/web.config.old',
    '/web.config.save',
    '/config.php.bak',
    '/config.php.old',
    '/config.php.save',
    '/config.yml.bak',
    '/config.yml.old',
    '/wp-config.php.bak',
    '/wp-config.php~',
    '/source.zip',
    '/src.zip',
    '/code.zip',
    '/project.zip',
    '/1.zip',
    '/2.zip',
    '/wwwroot.zip',
  ],
  api: [
    '/api/',
    '/api/v1/',
    '/api/v2/',
    '/api/v3/',
    '/api/docs',
    '/api-docs',
    '/api/swagger',
    '/api/json',
    '/swagger-ui.html',
    '/swagger-ui/',
    '/swagger-ui/index.html',
    '/swagger.json',
    '/swagger.yaml',
    '/openapi.json',
    '/openapi.yaml',
    '/graphql',
    '/graphiql',
    '/playground',
    '/wp-json/',
    '/wp-json/wp/v2/',
    '/rest/',
    '/actuator/',
    '/actuator/health',
    '/actuator/info',
    '/actuator/env',
    '/actuator/mappings',
    '/actuator/beans',
    '/actuator/configprops',
    '/actuator/metrics',
    '/healthz',
    '/ready',
    '/livez',
    '/api/health',
    '/v1/',
    '/v2/',
    '/v3/',
    '/version',
    '/api/status',
    '/api/ping',
    '/api/version',
    '/rest/api',
    '/rest/v1/',
    '/services/',
  ],
  sensitive: [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/hosts',
    '/proc/self/environ',
    '/proc/self/cmdline',
    '/.DS_Store',
    '/Thumbs.db',
    '/desktop.ini',
    '/server-status',
    '/server-info',
    '/server-config',
    '/phpmyadmin/',
    '/pma/',
    '/adminer/',
    '/adminer.php',
    '/manager/html',
    '/manager/status',
    '/.env.bak',
    '/.env.local',
    '/.env.production',
    '/config.php.bak',
    '/config.yml.bak',
    '/database.sql',
    '/db.sql',
    '/dump.sql',
    '/WEB-INF/',
    '/WEB-INF/web.xml',
    '/META-INF/',
    '/.idea/',
    '/.vscode/',
    '/.github/',
    '/debug/default/view',
    '/actuator/heapdump',
    '/.dockerenv',
    '/Dockerfile',
    '/docker-compose.yml',
    '/.travis.yml',
    '/.gitlab-ci.yml',
    '/webpack.config.js',
    '/package.json',
    '/.npmrc',
    '/.yarnrc',
    '/.pypirc',
    '/credentials.json',
    '/secrets.json',
    '/keys.json',
  ],
};

var CONTENT_PATTERNS = [
  { regex: /<title[^>]*>(.*?)<\/title>/i, tag: 'HTML 页面', group: 'title' },
  { regex: /(?:login|sign.?in|登录|authenticat)/i, tag: '登录页面', group: 'feature' },
  { regex: /(?:admin|管理|dashboard|控制台|后台)/i, tag: '管理界面', group: 'feature' },
  { regex: /(?:api|endpoint|swagger|openapi)/i, tag: 'API 接口', group: 'feature' },
  { regex: /(?:error|exception|stack.?trace|错误)/i, tag: '错误信息', group: 'feature' },
  { regex: /(?:config|配置|setting|参数)/i, tag: '配置信息', group: 'feature' },
  { regex: /(?:database|mysql|postgres|mongodb|redis)/i, tag: '数据库', group: 'feature' },
  { regex: /(?:password|passwd|secret|token|key=)/i, tag: '敏感信息', group: 'feature' },
];

var fuzzState = {
  scanning: false,
  paused: false,
  aborted: false,
  results: [],
  lastResults: null,
  stats: { total: 0, completed: 0, found: 0, errors: 0 },
  currentFilter: 'all',
  currentSearch: '',
};

function extractHeader(headers, name) {
  if (!headers) return '';
  if (Array.isArray(headers)) {
    for (var i = 0; i < headers.length; i++) {
      if (headers[i].name && headers[i].name.toLowerCase() === name) return headers[i].value || '';
    }
    return '';
  }
  return headers[name] || headers[name.toLowerCase()] || '';
}

function extractContentLength(headers) {
  var val = extractHeader(headers, 'content-length');
  return val ? parseInt(val, 10) : 0;
}

function analyzeContent(body) {
  if (!body || body.length < 10) return null;
  var result = { title: '', tags: [] };
  for (var i = 0; i < CONTENT_PATTERNS.length; i++) {
    var pat = CONTENT_PATTERNS[i];
    var match = body.match(pat.regex);
    if (match) {
      if (pat.group === 'title') {
        result.title = match[1] ? match[1].trim().substring(0, 100) : '';
      } else {
        if (result.tags.indexOf(pat.tag) === -1) result.tags.push(pat.tag);
      }
    }
  }
  return result;
}

function probePath(fullUrl) {
  return new Promise(function (resolve) {
    chrome.runtime.sendMessage(
      { type: 'FETCH_PROBE', url: fullUrl, method: 'HEAD' },
      function (resp) {
        if (chrome.runtime.lastError) {
          resolve({ status: 0, body: '', headers: {}, time: 0 });
          return;
        }
        if (resp && resp.status === 405) {
          chrome.runtime.sendMessage(
            { type: 'FETCH_PROBE', url: fullUrl, method: 'GET', includeBody: true },
            function (getResp) {
              if (chrome.runtime.lastError) {
                resolve({
                  status: 405,
                  body: '',
                  headers: resp.headers || {},
                  time: 0,
                  _method: 'HEAD',
                });
                return;
              }
              var r = getResp || { status: 0, body: '', headers: {}, time: 0 };
              r._method = 'GET';
              resolve(r);
            }
          );
          return;
        }
        var r = resp || { status: 0, body: '', headers: {}, time: 0 };
        r._method = 'HEAD';
        resolve(r);
      }
    );
  });
}

function delay(ms) {
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function runFuzzScan(baseUrl, wordlistKey, concurrency, onProgress, onResult) {
  if (fuzzState.scanning) return null;
  fuzzState.scanning = true;
  fuzzState.paused = false;
  fuzzState.aborted = false;
  fuzzState.results = [];
  fuzzState.stats = { total: 0, completed: 0, found: 0, errors: 0 };

  try {
    var words = DEFAULT_WORDLISTS[wordlistKey] || DEFAULT_WORDLISTS.common;
    var cleanBase = baseUrl.replace(/\/+$/, '');
    var total = words.length;
    fuzzState.stats.total = total;
    var batchSize = concurrency || 5;
    var batchDelay = 200;
    var seenKeys = {};

    for (var i = 0; i < words.length; i += batchSize) {
      if (fuzzState.aborted) break;

      while (fuzzState.paused && !fuzzState.aborted) {
        await delay(500);
      }
      if (fuzzState.aborted) break;

      var batch = words.slice(i, Math.min(i + batchSize, words.length));
      var promises = [];

      for (var b = 0; b < batch.length; b++) {
        var path = batch[b];
        var fullUrl = cleanBase + path;
        promises.push(
          probePath(fullUrl).catch(function () {
            return { status: 0, body: '', headers: {}, time: 0, _method: 'HEAD' };
          })
        );
      }

      var batchResults = await Promise.all(promises);

      for (var r = 0; r < batchResults.length; r++) {
        var path = batch[r];
        var response = batchResults[r];
        var status = response.status || 0;
        var bodyLen = (response.body || '').length;
        var headerCL = extractContentLength(response.headers);
        var size = bodyLen > 0 ? bodyLen : headerCL;
        var time = response.time || 0;
        var method = response._method || 'HEAD';

        var content = method === 'GET' ? analyzeContent(response.body) : null;
        var title = content ? content.title : '';
        var tags = content ? content.tags : [];

        var dedupKey = status + ':' + size;
        var entry = {
          path: path,
          status: status,
          size: size,
          time: time,
          url: cleanBase + path,
          method: method,
          title: title,
          tags: tags,
          interesting: title.length > 0 || tags.length > 0,
        };

        if (seenKeys[dedupKey]) {
          entry.duplicate = true;
          entry.duplicateOf = seenKeys[dedupKey];
        } else if (status > 0 && status !== 404) {
          seenKeys[dedupKey] = path;
        }

        fuzzState.stats.completed++;
        fuzzState.results.push(entry);

        if (status > 0 && status !== 404) {
          fuzzState.stats.found++;
          if (onResult) onResult(entry);
        }
        if (status === 0) {
          fuzzState.stats.errors++;
        }
      }

      if (onProgress) onProgress(Object.assign({}, fuzzState.stats));

      if (i + batchSize < words.length) {
        await delay(batchDelay);
      }
    }

    fuzzState.lastResults = {
      url: baseUrl,
      wordlist: wordlistKey,
      results: fuzzState.results,
      stats: Object.assign({}, fuzzState.stats),
    };
    return fuzzState.lastResults;
  } finally {
    fuzzState.scanning = false;
  }
}

function pauseFuzzScan() {
  fuzzState.paused = !fuzzState.paused;
  return fuzzState.paused;
}

function stopFuzzScan() {
  fuzzState.aborted = true;
}

var filterSearch = utils.createFilterSearch(
  fuzzState,
  'currentFilter',
  'currentSearch',
  renderFuzzResults
);
var setFilter = filterSearch.setFilter;
var setSearch = filterSearch.setSearch;

function applyFuzzFilter(item) {
  if (item.status <= 0 || item.status === 404) return false;
  var f = fuzzState.currentFilter;
  if (f === '2xx' && (item.status < 200 || item.status >= 300)) return false;
  if (f === '3xx' && (item.status < 300 || item.status >= 400)) return false;
  if (f === '403' && item.status !== 403) return false;
  if (f === 'interesting' && !item.interesting) return false;
  var q = fuzzState.currentSearch;
  if (q) {
    var text = (
      (item.path || '') +
      ' ' +
      (item.title || '') +
      ' ' +
      (item.tags || []).join(' ')
    ).toLowerCase();
    return text.indexOf(q) !== -1;
  }
  return true;
}

import { COPY_SVG } from './vk-icons.js';

function formatSize(bytes) {
  if (bytes > 1024) return (bytes / 1024).toFixed(1) + 'K';
  return bytes + 'B';
}

function renderFuzzResults(result) {
  var container = utils.get('fuzz-results');
  var statsEl = utils.get('fuzz-stats');
  var exportBtn = utils.get('fuzz-export-btn');

  if (!container || !result) return;

  if (statsEl) {
    statsEl.hidden = false;
    var s = result.stats;
    statsEl.innerHTML =
      '<span class="stat-badge stat-total">扫描 ' +
      s.completed +
      '/' +
      s.total +
      '</span> ' +
      '<span class="stat-badge stat-found">发现 ' +
      s.found +
      '</span>' +
      (s.errors > 0 ? ' <span class="stat-badge stat-error">错误 ' + s.errors + '</span>' : '');
  }

  var found = result.results.filter(applyFuzzFilter);

  if (found.length === 0) {
    container.innerHTML = '<div class="empty-state">无匹配结果</div>';
    if (exportBtn) exportBtn.hidden = false;
    return;
  }

  found.sort(function (a, b) {
    if (a.status !== b.status) return a.status - b.status;
    return b.size - a.size;
  });

  var html = '';
  for (var i = 0; i < found.length; i++) {
    var r = found[i];
    var statusClass = 's-' + (r.status < 600 ? r.status : 'other');
    if (r.status >= 200 && r.status < 300) statusClass = 's-200';
    else if (r.status >= 300 && r.status < 400) statusClass = r.status === 301 ? 's-301' : 's-302';
    else if (r.status === 403) statusClass = 's-403';
    else if (r.status >= 500) statusClass = 's-500';

    var cardClass = 'fuzz-card';
    if (r.duplicate) cardClass += ' fuzz-card-duplicate';
    if (r.interesting) cardClass += ' fuzz-card-interesting';

    var hasDetail = r.title || r.tags.length > 0 || r.method === 'GET';

    html += '<div class="' + cardClass + '">';
    html += '<div class="fuzz-card-row">';
    html += '<span class="fuzz-path">' + utils.escapeHtml(r.path) + '</span>';
    html +=
      '<button class="fuzz-copy-btn" data-copy="' +
      utils.escapeHtml(r.url || r.path) +
      '" title="复制路径">' +
      COPY_SVG +
      '</button>';
    html += '</div>';
    html += '<div class="fuzz-card-meta">';
    html += '<span class="fuzz-status-code ' + statusClass + '">' + r.status + '</span>';
    html += '<span class="fuzz-size">' + formatSize(r.size) + '</span>';
    html += '<span class="fuzz-time">' + r.time + 'ms</span>';
    if (r.duplicate) html += '<span class="fuzz-dup-label">重复</span>';
    html += '</div>';
    if (hasDetail) {
      html += '<div class="fuzz-card-detail">';
      if (r.title)
        html += '<div class="fuzz-card-title">Title: ' + utils.escapeHtml(r.title) + '</div>';
      if (r.tags.length > 0) {
        html += '<div class="fuzz-card-tags">';
        for (var t = 0; t < r.tags.length; t++) {
          html += '<span class="fuzz-tag">' + utils.escapeHtml(r.tags[t]) + '</span>';
        }
        html += '</div>';
      }
      if (r.method === 'GET') html += '<div class="fuzz-card-method">GET (HEAD 405 fallback)</div>';
      html += '</div>';
    }
    html += '</div>';
  }

  container.innerHTML = html;
  if (exportBtn) exportBtn.hidden = false;
}

function exportTxt() {
  if (!fuzzState.lastResults) return;
  var r = fuzzState.lastResults;
  var found = r.results.filter(function (e) {
    return e.status > 0 && e.status !== 404;
  });
  var lines = [
    '目录扫描报告',
    '==================',
    '目标: ' + r.url,
    '字典: ' + r.wordlist,
    '发现: ' + found.length,
    '',
  ];
  for (var i = 0; i < found.length; i++) {
    var e = found[i];
    var line = '[' + e.status + '] ' + e.path + ' (' + e.size + 'B, ' + e.time + 'ms';
    if (e.method === 'GET') line += ', GET)';
    else line += ')';
    lines.push(line);
    if (e.title) lines.push('  Title: ' + e.title);
    if (e.tags.length > 0) lines.push('  Tags: ' + e.tags.join(', '));
  }
  utils.downloadBlob(
    new Blob([lines.join('\n')], { type: 'text/plain' }),
    'fuzz-scan-' + Date.now() + '.txt'
  );
  utils.showToast('TXT 报告已导出', 'success');
}

function exportCsv() {
  if (!fuzzState.lastResults) return;
  var r = fuzzState.lastResults;
  var found = r.results.filter(function (e) {
    return e.status > 0 && e.status !== 404;
  });
  var rows = [['Path', 'Status', 'Size', 'Time(ms)', 'Method', 'Title', 'Tags']];
  for (var i = 0; i < found.length; i++) {
    var e = found[i];
    rows.push([
      e.path,
      String(e.status),
      String(e.size),
      String(e.time),
      e.method,
      e.title,
      (e.tags || []).join(', '),
    ]);
  }
  utils.downloadBlob(
    new Blob([utils.buildCsv(rows)], { type: 'text/csv;charset=utf-8' }),
    'fuzz-scan-' + Date.now() + '.csv'
  );
  utils.showToast('CSV 报告已导出', 'success');
}

function exportFuzzResults(format) {
  if (format === 'csv') {
    exportCsv();
  } else {
    exportTxt();
  }
}

function getFindings() {
  if (!fuzzState.lastResults) return [];
  var findings = [];
  var found = fuzzState.lastResults.results.filter(function (r) {
    return r.status > 0 && r.status !== 404;
  });
  for (var i = 0; i < found.length; i++) {
    var r = found[i];
    var severity;
    if (r.status === 200) {
      severity = 'medium';
      if (
        r.path.indexOf('backup') !== -1 ||
        r.path.indexOf('.sql') !== -1 ||
        r.path.indexOf('.env') !== -1 ||
        r.path.indexOf('config') !== -1
      ) {
        severity = 'high';
      }
    } else if (r.status === 403) {
      severity = 'low';
    } else if (r.status >= 300 && r.status < 400) {
      severity = 'low';
    } else {
      severity = 'low';
    }
    var detail = '状态码 ' + r.status + ' | 大小 ' + r.size + 'B | 响应时间 ' + r.time + 'ms';
    if (r.title) detail += ' | Title: ' + r.title;
    if (r.tags.length > 0) detail += ' | ' + r.tags.join(', ');
    findings.push({
      severity: severity,
      title: '目录发现: ' + r.path,
      detail: detail,
      module: 'fuzz',
      url: fuzzState.lastResults.url + r.path,
    });
  }
  return findings;
}

export {
  DEFAULT_WORDLISTS,
  fuzzState,
  runFuzzScan,
  pauseFuzzScan,
  stopFuzzScan,
  renderFuzzResults,
  exportFuzzResults,
  getFindings,
  setFilter,
  setSearch,
};
