// vk-sniff-scanner.js -- 灵眸 Chrome Extension
// 3-source signal collection + matching engine for technology fingerprinting

import { TECH_SIGNATURES, scoreConfidence, extractVersion } from './vk-sniff-state.js';

var sniffState = {
  lastResults: null,
  scanning: false,
};

async function collectDomSignals(tabId) {
  return chrome.tabs
    .sendMessage(tabId, { type: 'VK_FINGERPRINT_DOM', timeout: 5000 })
    .catch(function () {
      return null;
    });
}

async function collectRuntimeSignals(tabId) {
  return chrome.tabs
    .sendMessage(tabId, {
      type: 'VK_PAGE_INSPECT',
      action: 'fingerprint',
      timeout: 5000,
    })
    .catch(function () {
      return null;
    });
}

async function collectHeaderSignals(tabId) {
  return new Promise(function (resolve) {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (!tabs[0] || !tabs[0].url) {
        resolve(null);
        return;
      }
      chrome.runtime.sendMessage({ type: 'FETCH_HEADER_PROBE', url: tabs[0].url }, function (resp) {
        if (chrome.runtime.lastError) {
          resolve(null);
          return;
        }
        resolve(resp || null);
      });
    });
  });
}

function buildSignalPool(domResult, runtimeResult, headerResult) {
  var pool = {
    headers: '',
    globals: [],
    globalSet: {},
    meta: '',
    body: '',
    cookies: '',
    classNames: '',
    ids: '',
    scriptSrc: '',
    versions: {},
  };

  if (headerResult && !headerResult.error) {
    var headerLines = [];
    if (headerResult.headers) {
      if (Array.isArray(headerResult.headers)) {
        for (var h = 0; h < headerResult.headers.length; h++) {
          headerLines.push(headerResult.headers[h].name + ': ' + headerResult.headers[h].value);
        }
      } else {
        var headerKeys = Object.keys(headerResult.headers);
        for (var h = 0; h < headerKeys.length; h++) {
          headerLines.push(headerKeys[h] + ': ' + headerResult.headers[headerKeys[h]]);
        }
      }
    }
    pool.headers = headerLines.join('\n').toLowerCase();
  }

  if (runtimeResult && !runtimeResult.error) {
    var globalEntries = runtimeResult.globals || [];
    for (var g = 0; g < globalEntries.length; g++) {
      var gName = typeof globalEntries[g] === 'string' ? globalEntries[g] : globalEntries[g].name;
      pool.globals.push(gName);
      pool.globalSet[gName] = true;
    }
    var versionEntries = runtimeResult.versions || {};
    var versionKeys = Object.keys(versionEntries);
    for (var v = 0; v < versionKeys.length; v++) {
      pool.versions[versionKeys[v]] = versionEntries[versionKeys[v]];
    }
    pool.cookies = runtimeResult.cookies || '';
    pool.classNames = runtimeResult.classNames || '';
    pool.ids = runtimeResult.ids || '';
  }

  if (domResult && !domResult.error) {
    var metaTags = domResult.metaTags || [];
    var metaLines = [];
    for (var m = 0; m < metaTags.length; m++) {
      var mt = metaTags[m];
      metaLines.push((mt.name || '') + '=' + (mt.content || ''));
    }
    pool.meta = metaLines.join('\n').toLowerCase();
    pool.body = (domResult.bodyHtml || '').toLowerCase();
    var scriptSrcs = domResult.scriptSrcs || [];
    pool.scriptSrc = scriptSrcs.join('\n').toLowerCase();
  }

  return pool;
}

function evaluateMatcher(matcher, pool) {
  var source = matcher.source;
  var type = matcher.type;
  var pattern = matcher.value;

  var haystack;
  if (source === 'headers') haystack = pool.headers;
  else if (source === 'globals') {
    if (type === 'equals') {
      return pool.globalSet[pattern] ? { matched: true, evidence: pattern } : { matched: false };
    }
    return { matched: false };
  } else if (source === 'meta') haystack = pool.meta;
  else if (source === 'body') haystack = pool.body;
  else if (source === 'cookies') haystack = pool.cookies;
  else if (source === 'classNames') haystack = pool.classNames;
  else if (source === 'ids') haystack = pool.ids;
  else if (source === 'scriptSrc') haystack = pool.scriptSrc;
  else return { matched: false };

  if (!haystack) return { matched: false };

  if (type === 'regex') {
    var re = new RegExp(pattern.source, pattern.flags);
    var match = re.exec(haystack);
    if (match) {
      var snippet = haystack.substring(
        Math.max(0, match.index - 30),
        Math.min(haystack.length, match.index + match[0].length + 30)
      );
      return { matched: true, evidence: snippet };
    }
    return { matched: false };
  }

  if (type === 'contains') {
    if (haystack.indexOf(String(pattern).toLowerCase()) !== -1) {
      return { matched: true, evidence: pattern };
    }
    return { matched: false };
  }

  return { matched: false };
}

function matchAllTechnologies(pool) {
  var results = [];

  for (var i = 0; i < TECH_SIGNATURES.length; i++) {
    var tech = TECH_SIGNATURES[i];
    var matchedMatchers = [];
    var evidences = [];

    for (var j = 0; j < tech.matchers.length; j++) {
      var result = evaluateMatcher(tech.matchers[j], pool);
      if (result.matched) {
        matchedMatchers.push({ source: tech.matchers[j].source, type: tech.matchers[j].type });
        evidences.push({ source: tech.matchers[j].source, evidence: result.evidence });
      }
    }

    if (matchedMatchers.length === 0) continue;

    var confidence = scoreConfidence(matchedMatchers);
    var version = null;
    if (tech.versionPatterns) {
      for (var k = 0; k < tech.versionPatterns.length; k++) {
        var vp = tech.versionPatterns[k];
        if (
          vp.source === 'globals' &&
          vp.type === 'property' &&
          pool.globalSet[vp.value.split('.')[0]]
        ) {
          version = extractVersion(tech.name, pool.versions);
          if (version) break;
        }
      }
    }

    results.push({
      name: tech.name,
      category: tech.category,
      confidence: confidence,
      version: version,
      matchedCount: matchedMatchers.length,
      evidences: evidences,
    });
  }

  results.sort(function (a, b) {
    var scoreDiff =
      (b.confidence ? b.confidence.score : 0) - (a.confidence ? a.confidence.score : 0);
    if (scoreDiff !== 0) return scoreDiff;
    return b.matchedCount - a.matchedCount;
  });

  return results;
}

async function runSniffScan() {
  if (sniffState.scanning) return null;
  sniffState.scanning = true;

  try {
    var tab = await new Promise(function (resolve) {
      chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        resolve(tabs[0] || null);
      });
    });
    if (!tab || !tab.id) {
      sniffState.scanning = false;
      return null;
    }

    var domResult = await collectDomSignals(tab.id);
    var runtimeResult = await collectRuntimeSignals(tab.id);
    var headerResult = await collectHeaderSignals(tab.id);

    var pool = buildSignalPool(domResult, runtimeResult, headerResult);
    var results = matchAllTechnologies(pool);

    sniffState.lastResults = results;
    return results;
  } finally {
    sniffState.scanning = false;
  }
}

function getFindings() {
  if (!sniffState.lastResults || sniffState.lastResults.length === 0) return [];
  return sniffState.lastResults.map(function (r) {
    var score = r.confidence ? r.confidence.score : 0;
    var severity = score > 80 ? 'high' : score > 50 ? 'medium' : 'low';
    var evText = r.evidences
      .map(function (e) {
        return '[' + e.source + '] ' + e.evidence;
      })
      .join('; ');
    return {
      severity: severity,
      title: '技术栈检测: ' + r.name,
      detail:
        (r.version ? '版本: ' + r.version + ' | ' : '') + '分类: ' + r.category + ' | ' + evText,
      module: 'sniff',
      url: '',
    };
  });
}

export { sniffState, runSniffScan, getFindings };
