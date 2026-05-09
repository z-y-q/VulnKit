// vk-sourcemap-utils.js -- 灵眸 Chrome Extension
// Timer, fetch, parsing utilities for sourcemap scanning
import { utilsProxy as utils } from './vk-namespace.js';
import { smState } from './vk-sourcemap-state.js';

function smStartTimer() {
  smStopTimer();
  smState.smStartTime = Date.now();
  const el = utils.get('sm-timer');
  if (el) {
    el.classList.remove('hidden');
    el.textContent = '0s';
  }
  smState.smTimerInterval = setInterval(function () {
    const elapsed = Math.floor((Date.now() - smState.smStartTime) / 1000);
    if (el) el.textContent = elapsed + 's';
  }, 1000);
}

function smStopTimer() {
  if (smState.smTimerInterval) {
    clearInterval(smState.smTimerInterval);
    smState.smTimerInterval = null;
  }
}

function smSingleFetch(url, tailOnly) {
  return chrome.runtime
    .sendMessage({ type: 'FETCH_URL', url: url, tailOnly: tailOnly })
    .then(function (r) {
      return r && !r.error ? r.data : null;
    })
    .catch(function () {
      return null;
    });
}

async function smBatchFetch(urls, tailOnly, tabId) {
  const concurrency = tailOnly ? 10 : 5;
  let results = [];
  for (let i = 0; i < urls.length; i += concurrency) {
    if (smState.smAbortFlag) return results;
    let batch = urls.slice(i, i + concurrency);
    let batchResults;
    if (tabId) {
      batchResults = await smBatchFetchInPage(batch, tailOnly, tabId);
    } else {
      batchResults = await Promise.all(
        batch.map(function (url) {
          return smSingleFetch(url, tailOnly);
        })
      );
    }
    results = results.concat(batchResults);
  }
  return results;
}

async function smBatchFetchInPage(urls, tailOnly, tabId) {
  try {
    const fetched = await utils.execInTabData(
      tabId,
      function (fetchParams) {
        const promises = fetchParams.map(function (p) {
          return fetch(p.url, p.tailOnly ? { headers: { Range: 'bytes=-500' } } : {})
            .then(function (r) {
              if (!r.ok) return null;
              return r.text();
            })
            .catch(function () {
              return null;
            });
        });
        return Promise.all(promises);
      },
      {
        world: 'ISOLATED',
        args: [
          urls.map(function (u) {
            return { url: u, tailOnly: !!tailOnly };
          }),
        ],
      }
    );
    if (fetched) {
      return fetched;
    }
  } catch (e) {
    // In-page fetch failed, fall back to background
  }
  return Promise.all(
    urls.map(function (url) {
      return smSingleFetch(url, tailOnly);
    })
  );
}

function smResolveUrl(relative, base) {
  try {
    return new URL(relative, base).href;
  } catch (e) {
    return relative;
  }
}

function smParseMapToModules(mapText, mapUrl, idPrefix, allModules, sourceCache, mapCache) {
  try {
    const mapJson = JSON.parse(mapText);
    if (mapCache) mapCache[mapUrl] = mapJson;
    const sources = mapJson.sources || [];
    const content = mapJson.sourcesContent || [];
    for (let i = 0; i < sources.length; i++) {
      let srcPath = sources[i];
      if (srcPath.indexOf('webpack://') === 0) srcPath = srcPath.replace('webpack://', '');
      let exists = false;
      for (let e = 0; e < allModules.length; e++) {
        if (allModules[e].path === srcPath) {
          exists = true;
          break;
        }
      }
      if (!exists) {
        const resolved = content[i] !== undefined && content[i] !== null;
        const mod = {
          id: idPrefix + i,
          path: srcPath,
          deps: [],
          source: 'sourcemap',
          resolved: resolved,
          sourceUrl: mapUrl,
        };
        if (resolved) sourceCache[srcPath] = content[i];
        allModules.push(mod);
      }
    }
  } catch (e) {
    // skip invalid source map
  }
}

function smAddDiscoveredChunk(chunkUrl, chunkId, chunkList, excludeUrls) {
  if (excludeUrls && excludeUrls.indexOf(chunkUrl) !== -1) return;
  for (let i = 0; i < chunkList.length; i++) {
    if (chunkList[i].url === chunkUrl) return;
  }
  chunkList.push({ chunkId: chunkId, url: chunkUrl });
}

function smParseHashPairs(text, regex) {
  let map = {};
  let m;
  while ((m = regex.exec(text)) !== null) {
    map[m[1]] = m[2];
  }
  return map;
}

function smExtractWebpackPublicPath(code) {
  if (!code) return null;
  let m = code.match(/\.p\s*=\s*"([^"]*\/)"/);
  if (m) return m[1];
  m = code.match(/__webpack_require__\.p\s*=\s*"([^"]+)"/);
  if (m) return m[1];
  m = code.match(/__webpack_public_path__\s*=\s*"([^"]+)"/);
  return m ? m[1] : null;
}

function smMergeHashMaps(hashArray, pairRe) {
  const map = {};
  if (!hashArray) return map;
  hashArray.forEach(function (obj) {
    const parsed = smParseHashPairs(obj, pairRe);
    Object.keys(parsed).forEach(function (k) {
      map[k] = parsed[k];
    });
  });
  return map;
}

function smResolveWebpackBase(rc, rcBase, tabUrl) {
  const pp = smExtractWebpackPublicPath(rc);
  const prefixMatch = rc.match(/return\s+["']([^"']*\/)["']/);
  const urlPrefix = prefixMatch ? prefixMatch[1] : '';
  const base = pp ? smResolveUrl(pp, tabUrl) : urlPrefix ? smResolveUrl(urlPrefix, rcBase) : rcBase;
  return { base: base, urlPrefix: urlPrefix, hasPublicPath: !!pp };
}

function smRegisterChunkUrls(chunkMap, baseInfo, target, excludeUrls) {
  Object.keys(chunkMap).forEach(function (cid) {
    const hash = chunkMap[cid];
    const url =
      (baseInfo.hasPublicPath ? baseInfo.base + baseInfo.urlPrefix : baseInfo.base) +
      cid +
      '.' +
      hash +
      '.js';
    smAddDiscoveredChunk(url, cid, target, excludeUrls);
  });
}

function smUpdateProgress(percent, activePhase) {
  const bar = utils.get('sm-progress-bar');
  const phases = document.querySelectorAll('#sm-phases .sm-phase');
  if (bar) bar.style.width = percent + '%';
  phases.forEach(function (el) {
    let p = parseInt(el.dataset.phase);
    el.classList.remove('active', 'done');
    if (p < activePhase) el.classList.add('done');
    else if (p === activePhase) el.classList.add('active');
  });
}

function setScanState(scanning) {
  const btn = utils.get('sourcemap-scan-btn');
  if (!btn) return;
  if (scanning) {
    smStartTimer();
    btn.disabled = false;
    btn.textContent = '停止扫描';
    btn.classList.add('scanning', 'btn-danger');
    btn.classList.remove('btn-primary');
  } else {
    smStopTimer();
    btn.disabled = false;
    btn.textContent = '扫描[v2]';
    btn.classList.remove('scanning', 'btn-danger');
    btn.classList.add('btn-primary');
  }
}

function stopSourcemapScan() {
  smState.smAbortFlag = true;
}

smState.Utils = {
  smStartTimer: smStartTimer,
  smStopTimer: smStopTimer,
  smSingleFetch: smSingleFetch,
  smBatchFetch: smBatchFetch,
  smBatchFetchInPage: smBatchFetchInPage,
  smResolveUrl: smResolveUrl,
  smParseMapToModules: smParseMapToModules,
  smAddDiscoveredChunk: smAddDiscoveredChunk,
  smParseHashPairs: smParseHashPairs,
  smExtractWebpackPublicPath: smExtractWebpackPublicPath,
  smMergeHashMaps: smMergeHashMaps,
  smResolveWebpackBase: smResolveWebpackBase,
  smRegisterChunkUrls: smRegisterChunkUrls,
  smUpdateProgress: smUpdateProgress,
  setScanState: setScanState,
  stopSourcemapScan: stopSourcemapScan,
};

export {
  smStartTimer,
  smStopTimer,
  smSingleFetch,
  smBatchFetch,
  smBatchFetchInPage,
  smResolveUrl,
  smParseMapToModules,
  smAddDiscoveredChunk,
  smParseHashPairs,
  smExtractWebpackPublicPath,
  smMergeHashMaps,
  smResolveWebpackBase,
  smRegisterChunkUrls,
  smUpdateProgress,
  setScanState,
  stopSourcemapScan,
};
