// vk-fuzz.js -- 灵眸 Chrome Extension
// Directory / Path brute-force enumeration

import { utilsProxy as utils } from './vk-namespace.js';

var DEFAULT_WORDLISTS = {
  common: [
    '/admin/', '/admin/login', '/admin/dashboard', '/login/', '/console/',
    '/debug/', '/test/', '/tmp/', '/uploads/', '/upload/', '/backup/',
    '/config/', '/status/', '/info/', '/health', '/metrics/', '/api/',
    '/api/v1/', '/api/v2/', '/swagger-ui.html', '/swagger-ui/',
    '/doc.html', '/docs/', '/api-docs', '/graphiql', '/graphql',
    '/wp-admin/', '/wp-login.php', '/wp-json/', '/phpmyadmin/',
    '/manager/html', '/server-status', '/server-info',
    '/.env', '/.git/', '/.git/config', '/.svn/', '/.DS_Store',
    '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
    '/WEB-INF/', '/WEB-INF/web.xml', '/actuator/', '/actuator/health',
    '/actuator/env', '/actuator/mappings', '/trace',
    '/console/', '/administrator/', '/manage/', '/user/', '/users/',
    '/setup/', '/install/', '/phpinfo.php', '/.htaccess', '/.htpasswd',
    '/web.config', '/config.php', '/config.yml', '/config.json',
    '/database.sql', '/db.sql', '/backup.sql', '/dump.sql',
    '/assets/', '/static/', '/public/', '/media/', '/files/',
    '/download/', '/export/', '/import/', '/log/', '/logs/',
    '/error/', '/errors/', '/exception/', '/trace/',
  ],
  backup: [
    '/.bak', '/.zip', '/.tar.gz', '/.tgz', '/.rar', '/.7z',
    '/backup.zip', '/backup.tar.gz', '/backup.sql', '/backup.gz',
    '/www.zip', '/www.tar.gz', '/web.zip', '/site.zip',
    '/db_backup.sql', '/database.sql', '/dump.sql', '/data.sql',
    '/backup/', '/backups/', '/old/', '/archive/',
    '/.git/HEAD', '/.git/config', '/.gitignore',
    '/.svn/entries', '/.hg/store',
    '/.env', '/.env.bak', '/.env.local', '/.env.production',
    '/.env.development', '/.env.staging',
    '/web.config.bak', '/web.config.old', '/web.config.save',
    '/config.php.bak', '/config.php.old', '/config.php.save',
    '/config.yml.bak', '/config.yml.old',
    '/wp-config.php.bak', '/wp-config.php~',
    '/source.zip', '/src.zip', '/code.zip', '/project.zip',
    '/1.zip', '/2.zip', '/wwwroot.zip',
  ],
  api: [
    '/api/', '/api/v1/', '/api/v2/', '/api/v3/',
    '/api/docs', '/api-docs', '/api/swagger', '/api/json',
    '/swagger-ui.html', '/swagger-ui/', '/swagger-ui/index.html',
    '/swagger.json', '/swagger.yaml', '/openapi.json', '/openapi.yaml',
    '/graphql', '/graphiql', '/playground',
    '/wp-json/', '/wp-json/wp/v2/', '/rest/',
    '/actuator/', '/actuator/health', '/actuator/info',
    '/actuator/env', '/actuator/mappings', '/actuator/beans',
    '/actuator/configprops', '/actuator/metrics',
    '/healthz', '/ready', '/livez', '/api/health',
    '/v1/', '/v2/', '/v3/', '/version',
    '/api/status', '/api/ping', '/api/version',
    '/rest/api', '/rest/v1/', '/services/',
  ],
  sensitive: [
    '/etc/passwd', '/etc/shadow', '/etc/hosts',
    '/proc/self/environ', '/proc/self/cmdline',
    '/.DS_Store', '/Thumbs.db', '/desktop.ini',
    '/server-status', '/server-info', '/server-config',
    '/phpmyadmin/', '/pma/', '/adminer/', '/adminer.php',
    '/manager/html', '/manager/status',
    '/.env.bak', '/.env.local', '/.env.production',
    '/config.php.bak', '/config.yml.bak',
    '/database.sql', '/db.sql', '/dump.sql',
    '/WEB-INF/', '/WEB-INF/web.xml', '/META-INF/',
    '/.idea/', '/.vscode/', '/.github/',
    '/debug/default/view', '/actuator/heapdump',
    '/.dockerenv', '/Dockerfile', '/docker-compose.yml',
    '/.travis.yml', '/.gitlab-ci.yml',
    '/webpack.config.js', '/package.json',
    '/.npmrc', '/.yarnrc', '/.pypirc',
    '/credentials.json', '/secrets.json', '/keys.json',
  ],
};

var fuzzState = {
  scanning: false,
  paused: false,
  aborted: false,
  results: [],
  lastResults: null,
  stats: { total: 0, completed: 0, found: 0, errors: 0 },
};

function probePath(fullUrl) {
  return new Promise(function (resolve) {
    chrome.runtime.sendMessage({ type: 'FETCH_PROBE', url: fullUrl, method: 'HEAD' }, function (resp) {
      if (chrome.runtime.lastError) {
        resolve({ status: 0, body: '', headers: {}, time: 0 });
        return;
      }
      resolve(resp || { status: 0, body: '', headers: {}, time: 0 });
    });
  });
}

function delay(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
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
          probePath(fullUrl).then(function (resp) {
            return resp;
          }).catch(function () {
            return { status: 0, body: '', headers: {}, time: 0 };
          })
        );
      }

      var batchResults = await Promise.all(promises);

      for (var r = 0; r < batchResults.length; r++) {
        var path = batch[r];
        var response = batchResults[r];
        var status = response.status || 0;
        var bodyLen = (response.body || '').length;
        var time = response.time || 0;

        var entry = {
          path: path,
          status: status,
          size: bodyLen,
          time: time,
          url: cleanBase + path,
        };

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

function renderFuzzResults(result) {
  var container = utils.get('fuzz-results');
  var statsEl = utils.get('fuzz-stats');
  var exportBtn = utils.get('fuzz-export-btn');

  if (!container || !result) return;

  if (statsEl) {
    statsEl.style.display = 'flex';
    var s = result.stats;
    statsEl.innerHTML =
      '<span>扫描: ' + s.completed + '/' + s.total + '</span>' +
      '<span>发现: ' + s.found + '</span>' +
      (s.errors > 0 ? '<span>错误: ' + s.errors + '</span>' : '');
  }

  var found = result.results.filter(function (r) { return r.status > 0 && r.status !== 404; });
  if (found.length === 0) {
    container.innerHTML = '<div class="empty-state">未发现有效路径</div>';
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
    else if (r.status === 404) statusClass = 's-404';
    else if (r.status >= 500) statusClass = 's-500';

    html += '<div class="fuzz-item">';
    html += '<span class="fuzz-path">' + utils.escapeHtml(r.path) + '</span>';
    html += '<span class="fuzz-status-code ' + statusClass + '">' + r.status + '</span>';
    html += '<span class="fuzz-size">' + (r.size > 1024 ? (r.size / 1024).toFixed(1) + 'K' : r.size + 'B') + '</span>';
    html += '<span class="fuzz-time">' + r.time + 'ms</span>';
    html += '</div>';
  }
  container.innerHTML = html;
  if (exportBtn) exportBtn.style.display = '';
}

function exportFuzzResults() {
  if (!fuzzState.lastResults) return;
  var r = fuzzState.lastResults;
  var found = r.results.filter(function (e) { return e.status > 0 && e.status !== 404; });
  var lines = ['目录扫描报告', '=', '目标: ' + r.url, '字典: ' + r.wordlist, '发现: ' + found.length, ''];
  for (var i = 0; i < found.length; i++) {
    var e = found[i];
    lines.push('[' + e.status + '] ' + e.path + ' (' + e.size + 'B, ' + e.time + 'ms)');
  }
  utils.downloadBlob(new Blob([lines.join('\n')], { type: 'text/plain' }), 'fuzz-scan-' + Date.now() + '.txt');
}

function getFindings() {
  if (!fuzzState.lastResults) return [];
  var findings = [];
  var found = fuzzState.lastResults.results.filter(function (r) { return r.status > 0 && r.status !== 404; });
  for (var i = 0; i < found.length; i++) {
    var r = found[i];
    var severity;
    if (r.status === 200) {
      severity = 'medium';
      if (r.path.indexOf('backup') !== -1 || r.path.indexOf('.sql') !== -1 || r.path.indexOf('.env') !== -1 || r.path.indexOf('config') !== -1) {
        severity = 'high';
      }
    } else if (r.status === 403) {
      severity = 'low';
    } else if (r.status >= 300 && r.status < 400) {
      severity = 'low';
    } else {
      severity = 'low';
    }
    findings.push({
      severity: severity,
      title: '目录发现: ' + r.path,
      detail: '状态码 ' + r.status + ' | 大小 ' + r.size + 'B | 响应时间 ' + r.time + 'ms',
      module: 'fuzz',
      url: fuzzState.lastResults.url + r.path,
    });
  }
  return findings;
}

export { DEFAULT_WORDLISTS, fuzzState, runFuzzScan, pauseFuzzScan, stopFuzzScan, renderFuzzResults, exportFuzzResults, getFindings };
