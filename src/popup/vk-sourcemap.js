window.VulnKitSourcemap = (function () {
  'use strict';

  var utils = window.VulnKitUtils.utilsProxy;

  // --- State ---
  let sourcemapModules = [];
  let sourcemapSearchTerm = '';
  let sourcemapCurrentModule = null;
  let sourcemapSourceCache = {};
  let sourcemapTabId = null;
  let sourcemapMapCache = {};

  var SOURCE_TYPE_LABELS = {
    runtime: 'Webpack 运行时',
    sourcemap: 'Source Map',
    chunk: 'JS 文件解析',
  };

  async function smBatchFetch(urls, tailOnly, tabId) {
    var concurrency = tailOnly ? 10 : 5;
    var results = [];
    for (var i = 0; i < urls.length; i += concurrency) {
      var batch = urls.slice(i, i + concurrency);
      var batchResults;
      if (tabId) {
        batchResults = await smBatchFetchInPage(batch, tailOnly, tabId);
      } else {
        batchResults = await Promise.all(
          batch.map(function (url) {
            return chrome.runtime
              .sendMessage({ type: 'FETCH_URL', url: url, tailOnly: tailOnly })
              .then(function (r) {
                return r && !r.error ? r.data : null;
              })
              .catch(function () {
                return null;
              });
          })
        );
      }
      results = results.concat(batchResults);
    }
    return results;
  }

  async function smBatchFetchInPage(urls, tailOnly, tabId) {
    try {
      var fetchResults = await chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: 'ISOLATED',
        func: function (fetchParams) {
          var promises = fetchParams.map(function (p) {
            return fetch(p.url, p.tailOnly ? { headers: { Range: 'bytes=-500' } } : {})
              .then(function (r) {
                if (!r.ok) return null;
                return p.tailOnly ? r.text() : r.text();
              })
              .catch(function () {
                return null;
              });
          });
          return Promise.all(promises);
        },
        args: [
          urls.map(function (u) {
            return { url: u, tailOnly: !!tailOnly };
          }),
        ],
      });
      if (fetchResults && fetchResults[0] && fetchResults[0].result) {
        return fetchResults[0].result;
      }
    } catch (e) {
      // In-page fetch failed, fall back to background
    }
    return Promise.all(
      urls.map(function (url) {
        return chrome.runtime
          .sendMessage({ type: 'FETCH_URL', url: url, tailOnly: tailOnly })
          .then(function (r) {
            return r && !r.error ? r.data : null;
          })
          .catch(function () {
            return null;
          });
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

  function smUpdateProgress(percent, activePhase) {
    var bar = utils.get('sm-progress-bar');
    var phases = document.querySelectorAll('#sm-phases .sm-phase');
    if (bar) bar.style.width = percent + '%';
    phases.forEach(function (el) {
      var p = parseInt(el.dataset.phase);
      el.classList.remove('active', 'done');
      if (p < activePhase) el.classList.add('done');
      else if (p === activePhase) el.classList.add('active');
    });
  }

  async function scanWebpackModules() {
    var statusEl = utils.get('sourcemap-status');
    var scanBtn = utils.get('sourcemap-scan-btn');
    var resultsEl = utils.get('sourcemap-results');
    if (!statusEl) return;

    sourcemapModules = [];
    sourcemapSourceCache = {};
    sourcemapMapCache = {};
    sourcemapTabId = null;
    if (scanBtn) {
      scanBtn.disabled = true;
      scanBtn.textContent = '扫描中...';
      scanBtn.classList.add('scanning');
    }
    if (resultsEl) resultsEl.innerHTML = '';

    // Show progress bar and phase indicator
    var progressEl = utils.get('sm-progress');
    var phasesEl = utils.get('sm-phases');
    if (progressEl) {
      progressEl.classList.remove('hidden');
    }
    if (phasesEl) {
      phasesEl.classList.remove('hidden');
    }
    smUpdateProgress(0, 1);

    try {
      var tab = await utils.getActiveTab();
      if (!tab || !tab.id || !tab.url || tab.url.startsWith('chrome')) {
        statusEl.textContent = '无法扫描此页面';
        if (scanBtn) {
          scanBtn.disabled = false;
          scanBtn.textContent = '扫描[v2]';
          scanBtn.classList.remove('scanning');
        }
        sourcemapTabId = null;
        return;
      }

      sourcemapTabId = tab.id;
      var allModules = [];
      var sourceMapUrls = [];
      var scriptUrls = [];
      var chunkManifest = null;
      var wpPublicPath = '';

      // Phase 1: MAIN world -- access webpack runtime
      statusEl.textContent = 'Phase 1: 检测 Webpack 运行时...';
      smUpdateProgress(10, 1);
      try {
        var wpResults = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          world: 'MAIN',
          func: function () {
            var modules = [];
            var hasWebpack = false;
            var capturedWpRequire = null;

            // Strategy 0: Intercept webpackChunk* to capture webpack require
            // Works even when __webpack_require__ is NOT on window (webpack 5 default)
            // Two sub-strategies:
            //   A) Hook push for future pushes (pages still loading)
            //   B) Fake-push to extract require from webpack's already-installed handler
            try {
              // Helper: hook an existing webpackChunk* array to capture require
              function hookWebpackPush(chunkArr) {
                if (!chunkArr || !Array.isArray(chunkArr)) return;
                if (chunkArr._vulnkitHooked) return;
                chunkArr._vulnkitHooked = true;
                var origPush = chunkArr.push.bind(chunkArr);
                chunkArr.push = function () {
                  var args = Array.prototype.slice.call(arguments);
                  if (args.length >= 2 && typeof args[1] === 'function') {
                    capturedWpRequire = args[1];
                  } else if (
                    args.length >= 1 &&
                    Array.isArray(args[0]) &&
                    args[0].length >= 3 &&
                    typeof args[0][2] === 'function'
                  ) {
                    capturedWpRequire = args[0][2];
                  }
                  return origPush.apply(this, args);
                };
              }

              // Strategy 0B: Fake-push on already-loaded webpackChunk* arrays
              // In webpack 5, the runtime replaces array.push with its jsonpCallback.
              // The jsonpCallback calls the 3rd tuple element with the require function:
              //   chunkArray.push([[chunkIds], modules, function(require) { ... }])
              // We push a fake entry with a large unused chunkId and a capture callback.
              for (var _wck in window) {
                if (_wck.indexOf('webpackChunk') !== 0) continue;
                if (!Array.isArray(window[_wck])) continue;
                var _arr = window[_wck];
                var _pushStr = _arr.push.toString();
                // If push is NOT native, webpack has replaced it -- we can exploit it
                if (_pushStr.indexOf('[native code]') !== -1) {
                  // Still native -- hook for future pushes
                  hookWebpackPush(_arr);
                  continue;
                }
                hasWebpack = true;
                // Fake push with a chunkId that definitely isn't installed (999999)
                // webpack's jsonpCallback will call our 3rd-element function with require
                try {
                  _arr.push([
                    [999999],
                    {},
                    function (wpRequire) {
                      capturedWpRequire = wpRequire;
                    },
                  ]);
                } catch (_fpErr) {
                  // Some webpack configs may reject unknown chunkIds; fallback to hook
                  hookWebpackPush(_arr);
                }
                if (capturedWpRequire) break;
              }
            } catch (e) {}

            // Webpack 4: __webpack_require__.c (module cache)
            if (typeof __webpack_require__ !== 'undefined' && __webpack_require__.c) {
              hasWebpack = true;
              var cache = __webpack_require__.c;
              for (var id in cache) {
                if (!cache.hasOwnProperty(id)) continue;
                var mod = cache[id];
                var path = '';
                if (mod.l) path = mod.l;
                var deps = [];
                if (mod.a && Array.isArray(mod.a)) deps = mod.a.slice();
                modules.push({ id: id, path: path, deps: deps, source: 'runtime' });
              }
            }

            // Webpack 4: __webpack_modules__
            if (typeof __webpack_modules__ !== 'undefined') {
              hasWebpack = true;
              for (var mid in __webpack_modules__) {
                if (!__webpack_modules__.hasOwnProperty(mid)) continue;
                var found = false;
                for (var k = 0; k < modules.length; k++) {
                  if (modules[k].id === mid) {
                    found = true;
                    break;
                  }
                }
                if (!found) modules.push({ id: mid, path: '', deps: [], source: 'runtime' });
              }
            }

            // Webpack 5: webpackChunk* arrays
            for (var key in window) {
              if (key.indexOf('webpackChunk') === 0 && Array.isArray(window[key])) {
                hasWebpack = true;
                var chunk = window[key];
                for (var ci = 0; ci < chunk.length; ci++) {
                  var item = chunk[ci];
                  if (!item || !Array.isArray(item) || item.length < 2) continue;
                  var modObj = item[1];
                  if (typeof modObj !== 'object' || modObj === null) continue;
                  for (var mId in modObj) {
                    if (!modObj.hasOwnProperty(mId)) continue;
                    var exists = false;
                    for (var e = 0; e < modules.length; e++) {
                      if (modules[e].id === mId) {
                        exists = true;
                        break;
                      }
                    }
                    if (!exists) modules.push({ id: mId, path: mId, deps: [], source: 'runtime' });
                  }
                }
              }
            }

            // Extract webpack chunk URL info
            var chunkInfo = null;
            try {
              // Try captured require first (works for obfuscated webpack 5),
              // then fall back to global __webpack_require__ (webpack 4 / non-obfuscated)
              var wpRequire = capturedWpRequire;
              if (!wpRequire && typeof __webpack_require__ !== 'undefined') {
                wpRequire = __webpack_require__;
              }
              if (wpRequire && typeof wpRequire.u === 'function') {
                var uBody = wpRequire.u.toString();
                var allChunkIds = [];

                // Pattern A: plain numeric keys -- {123:"abc", 456:"def"}
                var mapObjs = uBody.match(/\{[^}]{5,}\}/g);
                if (mapObjs) {
                  mapObjs.forEach(function (obj) {
                    var idPairs = obj.match(/(\d+)\s*:\s*"/g);
                    if (idPairs) {
                      idPairs.forEach(function (p) {
                        var id = p.match(/(\d+)/);
                        if (id && allChunkIds.indexOf(id[1]) === -1) allChunkIds.push(id[1]);
                      });
                    }
                  });
                }

                // Pattern B: hex keys from obfuscated code -- {0xcf:..., 0xd7:..., ...}
                // Obfuscators encode the hash map keys as hex literals
                if (allChunkIds.length === 0) {
                  var hexPairs = uBody.match(/0x([0-9a-f]+)\s*:/g);
                  if (hexPairs) {
                    var seenHex = {};
                    hexPairs.forEach(function (hp) {
                      var hv = hp.match(/0x([0-9a-f]+)/);
                      if (hv) {
                        var dec = parseInt(hv[1], 16);
                        if (dec > 0 && !seenHex[dec]) {
                          seenHex[dec] = true;
                          allChunkIds.push(String(dec));
                        }
                      }
                    });
                  }
                }

                // Also collect chunk IDs from webpackChunk push entries
                for (var wck2 in window) {
                  if (wck2.indexOf('webpackChunk') === 0 && Array.isArray(window[wck2])) {
                    var wcArr = window[wck2];
                    for (var wci = 0; wci < wcArr.length; wci++) {
                      if (wcArr[wci] && Array.isArray(wcArr[wci]) && Array.isArray(wcArr[wci][0])) {
                        wcArr[wci][0].forEach(function (cid) {
                          var cidStr = String(cid);
                          if (allChunkIds.indexOf(cidStr) === -1) allChunkIds.push(cidStr);
                        });
                      }
                    }
                  }
                }

                // Try calling .u() for numeric IDs, try range-based probing for obfuscated builds
                var chunkFilenames = {};
                // First: direct call for known IDs
                allChunkIds.forEach(function (id) {
                  try {
                    var filename = wpRequire.u(id);
                    if (filename && filename.length > 0) chunkFilenames[id] = filename;
                  } catch (e) {}
                });

                // If direct calls yielded nothing (hash values are encoded strings),
                // probe .u() with a range of IDs to find valid chunk filenames
                // Valid chunk IDs are typically 100-10000 in most webpack builds
                if (Object.keys(chunkFilenames).length === 0 && allChunkIds.length > 0) {
                  var maxProbe = 0;
                  allChunkIds.forEach(function (id) {
                    var n = parseInt(id, 10);
                    if (n > maxProbe) maxProbe = n;
                  });
                  // Probe from 1 to max known ID + buffer
                  var probeLimit = Math.min(maxProbe + 200, 100000);
                  for (var pid = 1; pid <= probeLimit; pid++) {
                    try {
                      var pfn = wpRequire.u(pid);
                      if (pfn && typeof pfn === 'string' && pfn.length > 3) {
                        // Filter out filenames that just echo the ID back (fallback path)
                        if (pfn.indexOf(String(pid) + '.') === -1) {
                          chunkFilenames[String(pid)] = pfn;
                        } else if (pfn !== String(pid) + '.js') {
                          chunkFilenames[String(pid)] = pfn;
                        }
                      }
                    } catch (e) {}
                  }
                }

                if (Object.keys(chunkFilenames).length > 0) {
                  chunkInfo = { chunkFilenames: chunkFilenames };
                }
              }
            } catch (e) {}

            // Strategy 0C: Decode obfuscated .u() via globally-accessible string decoder
            // Obfuscators (javascript-obfuscator) define decoder functions at top-level scope.
            // The .u() body uses a local alias: var _local=globalDecoder; return _local(prefixIdx)+{map1}[id]+"."+{map2}[id]+_local(suffixIdx)
            // We extract the local var name, find its global decoder, call it, and build chunk URLs.
            if (!chunkInfo && hasWebpack) {
              (function () {
                try {
                  var _scripts = document.querySelectorAll('script[src]');
                  var _bundleUrls = [];
                  _scripts.forEach(function (s) {
                    var _src = s.getAttribute('src') || '';
                    if (_src && /\.js(\?|$)/.test(_src) && _src.indexOf('node_modules') === -1)
                      _bundleUrls.push(_src);
                  });
                  var _rtUrl = null;
                  for (var _bi = 0; _bi < _bundleUrls.length; _bi++) {
                    if (/main|app|index|runtime/i.test(_bundleUrls[_bi])) {
                      _rtUrl = _bundleUrls[_bi];
                      break;
                    }
                  }
                  if (!_rtUrl) {
                    for (var _bi2 = 0; _bi2 < _bundleUrls.length; _bi2++) {
                      if (/bundle\/|static\/js/.test(_bundleUrls[_bi2])) {
                        _rtUrl = _bundleUrls[_bi2];
                        break;
                      }
                    }
                  }
                  if (!_rtUrl) return;

                  var _xhr = new XMLHttpRequest();
                  _xhr.open('GET', _rtUrl, false);
                  _xhr.send();
                  var _bundleSrc = _xhr.responseText;

                  var _uOpenMatch = _bundleSrc.match(
                    /(\w+)\['u'\]\s*=\s*function\s*\(\s*(\w+)\s*\)\s*\{/
                  );
                  if (!_uOpenMatch)
                    _uOpenMatch = _bundleSrc.match(
                      /(\w+)\.u\s*=\s*function\s*\(\s*(\w+)\s*\)\s*\{/
                    );
                  if (!_uOpenMatch) return;

                  var _uStart = _uOpenMatch.index + _uOpenMatch[0].length;
                  var _bc = 1,
                    _uEnd = _uStart;
                  while (_uEnd < _bundleSrc.length && _bc > 0) {
                    if (_bundleSrc[_uEnd] === '{') _bc++;
                    else if (_bundleSrc[_uEnd] === '}') _bc--;
                    _uEnd++;
                  }
                  var _uBody = _bundleSrc.substring(_uStart, _uEnd - 1);

                  var _ldMatch = _uBody.match(/var\s+(\w+)\s*=\s*(a\d+_0x\w+)\s*;/);
                  var _localVar = _ldMatch ? _ldMatch[1] : null;
                  var _globalDecName = _ldMatch ? _ldMatch[2] : null;
                  if (
                    !_localVar &&
                    window[_uOpenMatch[1]] &&
                    typeof window[_uOpenMatch[1]] === 'function'
                  ) {
                    _localVar = _uOpenMatch[1];
                    _globalDecName = _uOpenMatch[1];
                  }
                  if (!_localVar) return;

                  var _dec = window[_globalDecName] || window[_localVar];
                  if (!_dec || typeof _dec !== 'function') return;

                  var _maps = [],
                    _mRegex = /\{([^{}]+)\}/g,
                    _mCnt = 0,
                    _mMatch;
                  while ((_mMatch = _mRegex.exec(_uBody)) !== null && _mCnt < 2) {
                    var _hk = _mMatch[1].match(/0x[0-9a-f]+\s*:/g);
                    if (_hk && _hk.length >= 3) {
                      _maps.push(_mMatch[1]);
                      _mCnt++;
                    }
                  }
                  var _outside = _uBody.replace(/\{[^{}]+\}/g, '/*M*/');
                  var _oRegex = new RegExp(_localVar + '\\((0x[0-9a-f]+)\\)', 'g');
                  var _oIdxs = [],
                    _oM;
                  while ((_oM = _oRegex.exec(_outside)) !== null) {
                    _oIdxs.push(parseInt(_oM[1], 16));
                  }
                  var _prefix = '',
                    _suffix = '';
                  try {
                    if (_oIdxs.length >= 1) _prefix = _dec(_oIdxs[0]) || '';
                  } catch (e) {}
                  try {
                    if (_oIdxs.length >= 2) _suffix = _dec(_oIdxs[_oIdxs.length - 1]) || '';
                  } catch (e) {}

                  var _decodedChunks = {};
                  var _pr = /0x([0-9a-f]+)\s*:\s*\w+\((0x[0-9a-f]+)\)/;
                  if (_maps.length >= 2) {
                    var _mapR = new RegExp(
                      '0x([0-9a-f]+)\\s*:\\s*' + _localVar + '\\((0x[0-9a-f]+)\\)',
                      'g'
                    );
                    var _map2 = {},
                      _m2;
                    while ((_m2 = _mapR.exec(_maps[1])) !== null) {
                      var _pm = _m2[0].match(_pr);
                      if (_pm) {
                        try {
                          _map2[parseInt(_pm[1], 16)] = _dec(parseInt(_pm[2], 16));
                        } catch (e) {}
                      }
                    }
                    _mapR.lastIndex = 0;
                    var _m1;
                    while ((_m1 = _mapR.exec(_maps[0])) !== null) {
                      var _pm = _m1[0].match(_pr);
                      if (_pm) {
                        var _cid = parseInt(_pm[1], 16);
                        try {
                          var _name = _dec(parseInt(_pm[2], 16)),
                            _ext = _map2[_cid] || '';
                          if (_name && _ext)
                            _decodedChunks[String(_cid)] = _prefix + _name + '.' + _ext + _suffix;
                        } catch (e) {}
                      }
                    }
                  }
                  if (Object.keys(_decodedChunks).length === 0 && _maps.length >= 1) {
                    var _smR = new RegExp(
                      '0x([0-9a-f]+)\\s*:\\s*' + _localVar + '\\((0x[0-9a-f]+)\\)',
                      'g'
                    );
                    var _sm;
                    while ((_sm = _smR.exec(_maps[0])) !== null) {
                      var _pm = _sm[0].match(_pr);
                      if (_pm) {
                        var _cid = parseInt(_pm[1], 16);
                        try {
                          var _hash = _dec(parseInt(_pm[2], 16));
                          if (_hash)
                            _decodedChunks[String(_cid)] = _prefix + _cid + '.' + _hash + _suffix;
                        } catch (e) {}
                      }
                    }
                  }
                  if (Object.keys(_decodedChunks).length > 0) {
                    // Extract webpack public path from same object that has .u()
                    var _wpPp = '';
                    var _ppMatch = _bundleSrc.match(
                      new RegExp(_uOpenMatch[1] + '\\[\'p\'\\]\\s*=\\s*"([^"]*)"')
                    );
                    if (!_ppMatch)
                      _ppMatch = _bundleSrc.match(
                        new RegExp(_uOpenMatch[1] + '\\.p\\s*=\\s*"([^"]*)"')
                      );
                    if (_ppMatch) _wpPp = _ppMatch[1];
                    chunkInfo = { chunkFilenames: _decodedChunks, publicPath: _wpPp };
                  }
                } catch (e) {}
              })();
            }

            // Install network hooks to capture dynamically loaded scripts
            try {
              if (!window.__vulnkitScriptObserver) {
                window.__vulnkitScriptObserver = [];
                window.__vulnkitHookActive = true;

                // 1. MutationObserver: catch script nodes added to DOM
                new MutationObserver(function (mutations) {
                  mutations.forEach(function (m) {
                    m.addedNodes.forEach(function (node) {
                      if (
                        node.tagName === 'SCRIPT' &&
                        node.src &&
                        node.src.indexOf('data:') !== 0
                      ) {
                        window.__vulnkitScriptObserver.push(node.src);
                      }
                    });
                  });
                }).observe(document.documentElement, { childList: true, subtree: true });

                // 2. Hook fetch: catch JS resource requests
                var _origFetch = window.fetch.bind(window);
                window.fetch = function (input) {
                  try {
                    var url =
                      typeof input === 'string' ? input : input && input.url ? input.url : '';
                    if (
                      url &&
                      /\.js(\?|$)/.test(url) &&
                      window.__vulnkitScriptObserver.indexOf(url) === -1
                    ) {
                      window.__vulnkitScriptObserver.push(url);
                    }
                  } catch (e) {}
                  return _origFetch.apply(this, arguments);
                };

                // 3. Hook XMLHttpRequest.open: catch JS XHR requests
                var _origXhrOpen = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function (method, url) {
                  try {
                    if (
                      url &&
                      typeof url === 'string' &&
                      /\.js(\?|$)/.test(url) &&
                      window.__vulnkitScriptObserver.indexOf(url) === -1
                    ) {
                      window.__vulnkitScriptObserver.push(url);
                    }
                  } catch (e) {}
                  return _origXhrOpen.apply(this, arguments);
                };
              }
            } catch (e) {}

            // Read any already-collected script URLs
            var monitoredScripts = [];
            try {
              if (window.__vulnkitScriptObserver) {
                monitoredScripts = window.__vulnkitScriptObserver.slice();
              }
            } catch (e) {}

            var wpPublicPath = '';
            try {
              var _wpR =
                capturedWpRequire ||
                (typeof __webpack_require__ !== 'undefined' ? __webpack_require__ : null);
              if (_wpR && _wpR.p) wpPublicPath = _wpR.p;
            } catch (e) {}

            return {
              modules: modules,
              hasWebpack: hasWebpack,
              chunkInfo: chunkInfo,
              monitoredScripts: monitoredScripts,
              wpPublicPath: wpPublicPath,
            };
          },
        });
        if (wpResults && wpResults[0] && wpResults[0].result) {
          var wpData = wpResults[0].result;
          if (wpData.modules && wpData.modules.length > 0) {
            allModules = allModules.concat(wpData.modules);
          }
          // Use directly-called .u() results
          if (wpData.chunkInfo && wpData.chunkInfo.chunkFilenames) {
            chunkManifest = wpData.chunkInfo.chunkFilenames;
            // Prefer public path from Strategy 0C (extracted from bundle source),
            // fall back to __webpack_require__.p from runtime
            wpPublicPath = wpData.chunkInfo.publicPath || wpData.wpPublicPath || '';
          }
          // Store webpack public path for chunk URL resolution
          if (!wpPublicPath) wpPublicPath = wpData.wpPublicPath || '';
          // Merge DOM-monitor captured scripts
          if (wpData.monitoredScripts && wpData.monitoredScripts.length > 0) {
            wpData.monitoredScripts.forEach(function (url) {
              if (scriptUrls.indexOf(url) === -1) scriptUrls.push(url);
            });
          }
        }
      } catch (e) {
        // MAIN world may fail on some pages, continue with fallback
      }

      // Phase 2: ISOLATED world -- collect script URLs + extract source map URLs
      statusEl.textContent = 'Phase 2: 收集脚本和 Source Map...';
      smUpdateProgress(30, 2);
      try {
        var domResults = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: function () {
            var extUrls = [];
            var inlineScripts = [];
            document.querySelectorAll('script[src]').forEach(function (s) {
              extUrls.push(s.src);
            });
            document.querySelectorAll('script:not([src])').forEach(function (s) {
              var text = s.textContent || '';
              if (text.length > 10 && text.length < 500000) inlineScripts.push(text);
            });
            // Collect all loaded JS resources from Performance API (catches dynamic scripts)
            var perfUrls = [];
            try {
              performance.getEntriesByType('resource').forEach(function (e) {
                if (e.name && /\.js(\?|$)/.test(e.name)) {
                  perfUrls.push(e.name);
                }
              });
            } catch (ex) {}
            // Collect preload/modulepreload link hints
            var preloadUrls = [];
            document
              .querySelectorAll('link[rel="preload"][as="script"], link[rel="modulepreload"]')
              .forEach(function (l) {
                if (l.href) preloadUrls.push(l.href);
              });
            return {
              extUrls: extUrls,
              inlineScripts: inlineScripts,
              perfUrls: perfUrls,
              preloadUrls: preloadUrls,
            };
          },
        });
        if (domResults && domResults[0] && domResults[0].result) {
          var domData = domResults[0].result;
          scriptUrls = domData.extUrls || [];

          // Merge performance API URLs (dynamically loaded scripts)
          (domData.perfUrls || []).forEach(function (u) {
            if (scriptUrls.indexOf(u) === -1) scriptUrls.push(u);
          });
          // Merge preload hints
          (domData.preloadUrls || []).forEach(function (u) {
            if (scriptUrls.indexOf(u) === -1) scriptUrls.push(u);
          });

          // Extract source map URLs from inline scripts
          var mapRegex = /[/#][@]\s*sourceMappingURL\s*=\s*(\S+)/gi;
          (domData.inlineScripts || []).forEach(function (script) {
            mapRegex.lastIndex = 0;
            var match;
            while ((match = mapRegex.exec(script)) !== null) {
              var url = match[1];
              if (url.indexOf('data:') !== 0) {
                sourceMapUrls.push(smResolveUrl(url, tab.url));
              }
            }
          });
        }
      } catch (e) {
        // continue
      }

      // Also extract source map URLs from external script tags via link headers
      // Fetch script contents to find sourceMappingURL comments
      if (scriptUrls.length > 0 && sourceMapUrls.length < 5) {
        statusEl.textContent =
          'Phase 2: 解析脚本 Source Map URL (' + scriptUrls.length + ' 个文件)...';
        var scriptContents = await smBatchFetch(scriptUrls.slice(0, 15), false, tab.id);
        for (var si = 0; si < scriptContents.length; si++) {
          if (!scriptContents[si]) continue;
          var content = scriptContents[si];
          var lastNewline = content.lastIndexOf('\n');
          var tail =
            lastNewline >= 0
              ? content.substring(lastNewline)
              : content.substring(content.length - 200);
          var mapMatch = tail.match(/[/#][@]\s*sourceMappingURL\s*=\s*(\S+)/);
          if (mapMatch && mapMatch[1].indexOf('data:') !== 0) {
            var mapUrl = smResolveUrl(mapMatch[1], scriptUrls[si]);
            if (sourceMapUrls.indexOf(mapUrl) === -1) sourceMapUrls.push(mapUrl);
          }
        }
      }

      // Fetch and parse source map files
      if (sourceMapUrls.length > 0) {
        statusEl.textContent = 'Phase 2: 解析 ' + sourceMapUrls.length + ' 个 Source Map 文件...';
        smUpdateProgress(50, 2);
        var mapContents = await smBatchFetch(sourceMapUrls.slice(0, 20), false, tab.id);
        for (var mi = 0; mi < mapContents.length; mi++) {
          if (!mapContents[mi]) continue;
          try {
            var mapJson = JSON.parse(mapContents[mi]);
            sourcemapMapCache[sourceMapUrls[mi]] = mapJson;
            var sources = mapJson.sources || [];
            var sourcesContent = mapJson.sourcesContent || [];
            var mapBaseUrl = sourceMapUrls[mi].substring(0, sourceMapUrls[mi].lastIndexOf('/') + 1);
            for (var sIdx = 0; sIdx < sources.length; sIdx++) {
              var srcPath = sources[sIdx];
              // Normalize webpack:// prefix
              if (srcPath.indexOf('webpack://') === 0) srcPath = srcPath.replace('webpack://', '');
              var existingPath = false;
              for (var ep = 0; ep < allModules.length; ep++) {
                if (allModules[ep].path === srcPath) {
                  existingPath = true;
                  break;
                }
              }
              if (!existingPath) {
                var resolved = sourcesContent[sIdx] !== undefined && sourcesContent[sIdx] !== null;
                var mod = {
                  id: 'sm-' + sIdx,
                  path: srcPath,
                  deps: [],
                  source: 'sourcemap',
                  resolved: resolved,
                  sourceUrl: sourceMapUrls[mi],
                };
                if (resolved) sourcemapSourceCache[srcPath] = sourcesContent[sIdx];
                allModules.push(mod);
              }
            }
          } catch (parseErr) {
            // skip invalid source map
          }
        }
      }

      // Phase 2.5: Discover unloaded chunks via manifest + fetch their source maps
      var discoveredChunkUrls = [];

      // Build chunk URLs from MAIN world manifest (most reliable)
      if (chunkManifest && scriptUrls.length > 0) {
        // Infer correct base URL by cross-referencing decoded chunks with known scriptUrls.
        // Example: decoded "bundle/home.js" matches DOM "/bundle/home.js" -> base = origin root "/"
        var inferredBase = null;
        for (var si = 0; si < scriptUrls.length && !inferredBase; si++) {
          var sUrlClean = scriptUrls[si].split('?')[0];
          var sBare = sUrlClean.substring(sUrlClean.lastIndexOf('/') + 1);
          for (var cid in chunkManifest) {
            if (inferredBase) break;
            var cFname = chunkManifest[cid];
            if (!cFname) continue;
            var cBare = cFname.substring(cFname.lastIndexOf('/') + 1);
            if (cBare === sBare) {
              inferredBase = sUrlClean.substring(0, sUrlClean.length - cFname.length);
            }
          }
        }
        var baseUrl = inferredBase
          ? inferredBase
          : wpPublicPath
            ? smResolveUrl(wpPublicPath, tab.url)
            : tab.url.substring(0, tab.url.lastIndexOf('/') + 1);
        Object.keys(chunkManifest).forEach(function (chunkId) {
          var filename = chunkManifest[chunkId];
          if (!filename) return;
          var fullUrl = smResolveUrl(filename, baseUrl);
          discoveredChunkUrls.push({ chunkId: chunkId, url: fullUrl });
        });
      }

      // Fallback: deep-parse bundle JS for chunk manifest patterns
      if (discoveredChunkUrls.length === 0 && scriptUrls.length > 0) {
        statusEl.textContent = 'Phase 2.5: 深度解析 Bundle 源码发现 Chunk...';
        smUpdateProgress(40, 2);

        var runtimeUrl = null;
        for (var rb = 0; rb < scriptUrls.length; rb++) {
          if (/runtime/i.test(scriptUrls[rb]) && /\.js(\?|$)/.test(scriptUrls[rb])) {
            runtimeUrl = scriptUrls[rb];
            break;
          }
        }
        if (!runtimeUrl) {
          for (var mb = 0; mb < scriptUrls.length; mb++) {
            if (/main|app|index/i.test(scriptUrls[mb]) && /\.js(\?|$)/.test(scriptUrls[mb])) {
              runtimeUrl = scriptUrls[mb];
              break;
            }
          }
        }
        if (!runtimeUrl) {
          for (var fb = 0; fb < scriptUrls.length; fb++) {
            if (/bundle\//.test(scriptUrls[fb]) || /static\/js/.test(scriptUrls[fb])) {
              runtimeUrl = scriptUrls[fb];
              break;
            }
          }
        }

        if (runtimeUrl) {
          var runtimeContent = await smBatchFetch([runtimeUrl], false, tab.id);
          if (runtimeContent[0]) {
            var rc = runtimeContent[0];
            var rcBase = runtimeUrl.substring(0, runtimeUrl.lastIndexOf('/') + 1);

            // Strategy 1: Extract __webpack_require__.u function body
            var uFuncMatch = rc.match(
              /(__webpack_require__\s*\.\s*u\s*=\s*function\s*\([^)]*\)\s*\{[^}]*return[^}]*\})/
            );
            if (!uFuncMatch) {
              uFuncMatch = rc.match(
                /(\w+)\s*=\s*function\((\w+)\)\s*\{[^}]{10,200}?return[^}]*?\{[^}]{5,}\}[^}]*?\2[^}]*?\}/
              );
            }
            if (uFuncMatch) {
              try {
                var mappingObj = uFuncMatch[1].match(/\{[^{}]+\}/g);
                if (mappingObj) {
                  var chunkIdToHash = {};
                  mappingObj.forEach(function (obj) {
                    var pairs = obj.match(/(\d+)\s*:\s*"([a-f0-9]{4,})"/g);
                    if (pairs) {
                      pairs.forEach(function (p) {
                        var kv = p.match(/(\d+)\s*:\s*"([a-f0-9]{4,})"/);
                        if (kv) chunkIdToHash[kv[1]] = kv[2];
                      });
                    }
                  });
                  var returnMatch = uFuncMatch[1].match(/return\s+["']([^"']*\/)["']/);
                  var urlPrefix = returnMatch ? returnMatch[1] : '';
                  var ppMatch1 = rc.match(/\.p\s*=\s*"([^"]*\/)"/);
                  if (!ppMatch1) ppMatch1 = rc.match(/__webpack_require__\.p\s*=\s*"([^"]+)"/);
                  if (!ppMatch1) ppMatch1 = rc.match(/__webpack_public_path__\s*=\s*"([^"]+)"/);
                  var finalBase = ppMatch1
                    ? smResolveUrl(ppMatch1[1], tab.url)
                    : urlPrefix
                      ? smResolveUrl(urlPrefix, rcBase)
                      : rcBase;
                  var hasPublicPath = !!ppMatch1;
                  Object.keys(chunkIdToHash).forEach(function (cid) {
                    var hash = chunkIdToHash[cid];
                    var chunkUrl =
                      (hasPublicPath ? finalBase + urlPrefix : finalBase) +
                      cid +
                      '.' +
                      hash +
                      '.js';
                    if (scriptUrls.indexOf(chunkUrl) === -1) {
                      var dup = discoveredChunkUrls.some(function (cu) {
                        return cu.url === chunkUrl;
                      });
                      if (!dup) discoveredChunkUrls.push({ chunkId: cid, url: chunkUrl });
                    }
                  });
                }
              } catch (e) {}
            }

            // Strategy 2: Broad hash map scan for obfuscated code
            if (discoveredChunkUrls.length === 0) {
              var hashMaps = rc.match(/\{[^\{\}]{10,}?"?\d+"?\s*:\s*"[a-f0-9]{4,}"[^\{\}]*?\}/g);
              if (hashMaps) {
                var tempChunkMap = {};
                hashMaps.forEach(function (hm) {
                  var pairs = hm.match(/"?(\d+)"?\s*:\s*"([a-f0-9]{4,})"/g);
                  if (pairs) {
                    pairs.forEach(function (pair) {
                      var kv = pair.match(/"?(\d+)"?\s*:\s*"([a-f0-9]{4,})"/);
                      if (kv) tempChunkMap[kv[1]] = kv[2];
                    });
                  }
                });
                if (Object.keys(tempChunkMap).length > 2) {
                  var ppMatch2 = rc.match(/\.p\s*=\s*"([^"]*\/)"/);
                  if (!ppMatch2) ppMatch2 = rc.match(/__webpack_require__\.p\s*=\s*"([^"]+)"/);
                  var prefixMatch2 = rc.match(/return\s+["']([^"']*\/)["']/);
                  var urlPrefix2 = prefixMatch2 ? prefixMatch2[1] : '';
                  var hasPublicPath2 = !!ppMatch2;
                  var base2 = ppMatch2
                    ? smResolveUrl(ppMatch2[1], tab.url)
                    : urlPrefix2
                      ? smResolveUrl(urlPrefix2, rcBase)
                      : rcBase;
                  Object.keys(tempChunkMap).forEach(function (cid) {
                    var hash = tempChunkMap[cid];
                    var chunkUrl =
                      (hasPublicPath2 ? base2 + urlPrefix2 : base2) + cid + '.' + hash + '.js';
                    if (scriptUrls.indexOf(chunkUrl) === -1) {
                      var dup = discoveredChunkUrls.some(function (cu) {
                        return cu.url === chunkUrl;
                      });
                      if (!dup) discoveredChunkUrls.push({ chunkId: cid, url: chunkUrl });
                    }
                  });
                }
              }
            }

            // Strategy 3: Find explicit chunk filename references in source
            var chunkNameRefs = rc.match(/["']([\w.-]+\.[a-f0-9]{6,}\.js)["']/g);
            if (chunkNameRefs) {
              chunkNameRefs.forEach(function (ref) {
                var nameMatch = ref.match(/["']([\w.-]+\.[a-f0-9]{6,}\.js)["']/);
                if (nameMatch) {
                  var fullRef = rcBase + nameMatch[1];
                  if (scriptUrls.indexOf(fullRef) === -1) {
                    var dup = discoveredChunkUrls.some(function (cu) {
                      return cu.url === fullRef;
                    });
                    if (!dup) discoveredChunkUrls.push({ chunkId: 'ref', url: fullRef });
                  }
                }
              });
            }

            // Strategy 4: Parse vendor/main bundle for dynamic import() and .e() references
            if (discoveredChunkUrls.length === 0) {
              var otherBundles = scriptUrls.filter(function (u) {
                return (
                  u !== runtimeUrl && (/(vendor|main|app|index)/i.test(u) || /bundle\//.test(u))
                );
              });
              if (otherBundles.length > 0) {
                var bundleContents = await smBatchFetch(otherBundles.slice(0, 3), false, tab.id);
                for (var bi = 0; bi < bundleContents.length; bi++) {
                  if (!bundleContents[bi]) continue;
                  // Dynamic imports: import("./chunk-xxx.hash.js")
                  var dynamicImports = bundleContents[bi].match(
                    /["']\.\/([\w.-]+\.[a-f0-9]{6,}\.js)["']/g
                  );
                  if (dynamicImports) {
                    dynamicImports.forEach(function (imp) {
                      var nameMatch = imp.match(/["']\.\/([\w.-]+\.[a-f0-9]{6,}\.js)["']/);
                      if (nameMatch) {
                        var bundleBase = otherBundles[bi].substring(
                          0,
                          otherBundles[bi].lastIndexOf('/') + 1
                        );
                        var fullImp = bundleBase + nameMatch[1];
                        if (scriptUrls.indexOf(fullImp) === -1) {
                          var dup = discoveredChunkUrls.some(function (cu) {
                            return cu.url === fullImp;
                          });
                          if (!dup) discoveredChunkUrls.push({ chunkId: 'import', url: fullImp });
                        }
                      }
                    });
                  }
                  // .e(chunkId) references
                  var chunkERefs = bundleContents[bi].match(/\.e\s*\(\s*(\d+)\s*\)/g);
                  if (chunkERefs) {
                    chunkERefs.forEach(function (ref) {
                      var idMatch = ref.match(/\.e\s*\(\s*(\d+)\s*\)/);
                      if (idMatch) {
                        var eid = idMatch[1];
                        var dup = discoveredChunkUrls.some(function (cu) {
                          return cu.chunkId === eid;
                        });
                        if (!dup) discoveredChunkUrls.push({ chunkId: eid, url: null });
                      }
                    });
                  }
                }
              }
            }
          }
        }
      }

      if (discoveredChunkUrls.length > 0) {
        statusEl.textContent =
          'Phase 2.5: Manifest 发现 ' + discoveredChunkUrls.length + ' 个 Chunk，探测中...';
        // Deduplicate and filter out already-known URLs
        var seenChunkUrls = {};
        var chunkFetchUrls = [];
        discoveredChunkUrls.forEach(function (cu) {
          var url = cu.url;
          if (!url) return;
          // Skip if already in scriptUrls
          if (scriptUrls.indexOf(url) !== -1) return;
          // Skip if already seen
          if (seenChunkUrls[url]) return;
          seenChunkUrls[url] = true;
          chunkFetchUrls.push(url);
        });

        // Try fetching .map for every known script URL too
        scriptUrls.forEach(function (sUrl) {
          var sBase = sUrl.substring(0, sUrl.lastIndexOf('/') + 1);
          var sName = sUrl.substring(sUrl.lastIndexOf('/') + 1);
          var guessMap = smResolveUrl(sName + '.map', sBase);
          if (sourceMapUrls.indexOf(guessMap) === -1) sourceMapUrls.push(guessMap);
        });

        // Add ALL discovered chunk URLs to scriptUrls (not just fetch-confirmed ones)
        // The URLs were computed from webpack .u() decoding -- they are valid regardless of fetch success
        chunkFetchUrls.forEach(function (cUrl) {
          if (scriptUrls.indexOf(cUrl) === -1) scriptUrls.push(cUrl);
        });

        // Tail-fetch chunks (up to 50) to find sourceMappingURL
        var chunkSamples = await smBatchFetch(chunkFetchUrls.slice(0, 50), true, tab.id);
        var newSourceMapUrls = [];
        for (var ci = 0; ci < chunkSamples.length; ci++) {
          if (!chunkSamples[ci]) continue;
          var chunkContent = chunkSamples[ci];
          var chunkMapMatch = chunkContent.match(/[/#][@]\s*sourceMappingURL\s*=\s*(\S+)/);
          if (chunkMapMatch && chunkMapMatch[1].indexOf('data:') !== 0) {
            var cmUrl = smResolveUrl(chunkMapMatch[1], chunkFetchUrls[ci]);
            if (sourceMapUrls.indexOf(cmUrl) === -1) newSourceMapUrls.push(cmUrl);
          }
          var chunkMapGuess = chunkFetchUrls[ci] + '.map';
          if (sourceMapUrls.indexOf(chunkMapGuess) === -1) newSourceMapUrls.push(chunkMapGuess);
        }

        // Fetch new source maps
        var allNewMaps = newSourceMapUrls.slice(0, 50);
        if (allNewMaps.length > 0) {
          statusEl.textContent = 'Phase 2.5: 解析 ' + allNewMaps.length + ' 个新 Source Map...';
          var newMapContents = await smBatchFetch(allNewMaps, false, tab.id);
          for (var nmi = 0; nmi < newMapContents.length; nmi++) {
            if (!newMapContents[nmi]) continue;
            var nmUrl = allNewMaps[nmi];
            if (sourcemapMapCache[nmUrl]) continue;
            try {
              var nmJson = JSON.parse(newMapContents[nmi]);
              sourcemapMapCache[nmUrl] = nmJson;
              var nmSources = nmJson.sources || [];
              var nmContent = nmJson.sourcesContent || [];
              for (var nsIdx = 0; nsIdx < nmSources.length; nsIdx++) {
                var nsPath = nmSources[nsIdx];
                if (nsPath.indexOf('webpack://') === 0) nsPath = nsPath.replace('webpack://', '');
                var nsExists = false;
                for (var nse = 0; nse < allModules.length; nse++) {
                  if (allModules[nse].path === nsPath) {
                    nsExists = true;
                    break;
                  }
                }
                if (!nsExists) {
                  var nsResolved = nmContent[nsIdx] !== undefined && nmContent[nsIdx] !== null;
                  var nsMod = {
                    id: 'sm2-' + nsIdx,
                    path: nsPath,
                    deps: [],
                    source: 'sourcemap',
                    resolved: nsResolved,
                    sourceUrl: nmUrl,
                  };
                  if (nsResolved) sourcemapSourceCache[nsPath] = nmContent[nsIdx];
                  allModules.push(nsMod);
                }
              }
            } catch (e) {
              // skip invalid source map
            }
          }
        }
      }

      // Phase 3: Fallback -- parse JS files for webpack paths
      if (allModules.length === 0 && scriptUrls.length > 0) {
        statusEl.textContent = 'Phase 3: 解析 JS 文件中的模块路径...';
        smUpdateProgress(70, 3);
        var jsContents = await smBatchFetch(scriptUrls.slice(0, 10), false, tab.id);
        for (var ji = 0; ji < jsContents.length; ji++) {
          if (!jsContents[ji]) continue;
          var jsText = jsContents[ji];
          // Match webpack:// paths in module definitions
          var wpPathRegex =
            /webpack:\/\/[^\s"']+|\.[\/]?[a-zA-Z_][\w.\/-]*(?:\.vue|\.js|\.ts|\.jsx|\.tsx)/g;
          var pathMatch;
          var seen = {};
          while ((pathMatch = wpPathRegex.exec(jsText)) !== null) {
            var p = pathMatch[0].replace('webpack://', '');
            if (seen[p]) continue;
            seen[p] = true;
            allModules.push({
              id: 'ch-' + Object.keys(seen).length,
              path: p,
              deps: [],
              source: 'chunk',
            });
          }
        }
      }

      // Build reverse deps and finalize
      for (var di = 0; di < allModules.length; di++) {
        allModules[di].reverseDeps = [];
      }
      for (var di2 = 0; di2 < allModules.length; di2++) {
        var modDeps = allModules[di2].deps || [];
        for (var dd = 0; dd < modDeps.length; dd++) {
          var depId = String(modDeps[dd]);
          for (var dr = 0; dr < allModules.length; dr++) {
            if (allModules[dr].id === depId) {
              allModules[dr].reverseDeps.push(allModules[di2].id);
              break;
            }
          }
        }
      }

      // Add script URLs as chunk entries (actual loaded JS files)
      var seenScriptUrls = {};
      for (var si2 = 0; si2 < scriptUrls.length; si2++) {
        var scriptPath = scriptUrls[si2];
        if (seenScriptUrls[scriptPath]) continue;
        seenScriptUrls[scriptPath] = true;
        // Check if this path already exists from other phases
        var scriptPathExists = false;
        for (var sp = 0; sp < allModules.length; sp++) {
          if (allModules[sp].path === scriptPath) {
            scriptPathExists = true;
            break;
          }
        }
        if (!scriptPathExists) {
          allModules.push({
            id: 'script-' + si2,
            path: scriptPath,
            deps: [],
            source: 'chunk',
          });
        }
      }

      // Deduplicate by path (strip query params -- anti-crawl params cause fake duplicates)
      // Always filter out runtime modules with numeric-only paths.
      var seenPaths = {};
      var deduped = [];
      for (var ui = 0; ui < allModules.length; ui++) {
        var m = allModules[ui];
        if (!m.path) continue;
        if (m.source === 'runtime' && /^\d+$/.test(m.path)) continue;
        var baseKey = m.path.split('?')[0];
        if (seenPaths[baseKey]) continue;
        seenPaths[baseKey] = true;
        deduped.push(m);
      }

      sourcemapModules = deduped.slice(0, 2000);
      statusEl.textContent = '找到 ' + sourcemapModules.length + ' 个模块';
      smUpdateProgress(100, 3);
      renderSourcemapModules();

      // Check if network hooks are active and show hint
      try {
        var hookResults = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          world: 'MAIN',
          func: function () {
            return !!window.__vulnkitHookActive;
          },
        });
        if (hookResults && hookResults[0] && hookResults[0].result) {
          var hookHint = document.createElement('div');
          hookHint.className = 'sm-hook-hint';
          hookHint.textContent =
            'JS Hook 已激活 -- 浏览其他页面可自动捕获新 Chunk，再次扫描即可合并';
          var statusArea = document.getElementById('sourcemap-status');
          if (statusArea && statusArea.nextSibling) {
            statusArea.parentNode.insertBefore(hookHint, statusArea.nextSibling);
          }
        }
      } catch (e) {}
    } catch (err) {
      statusEl.textContent = '扫描失败: ' + (err.message || '未知错误');
    } finally {
      if (scanBtn) {
        scanBtn.disabled = false;
        scanBtn.textContent = '扫描[v2]';
        scanBtn.classList.remove('scanning');
      }
      // Hide progress bar after a brief delay
      setTimeout(function () {
        var progressEl = utils.get('sm-progress');
        var phasesEl = utils.get('sm-phases');
        if (progressEl) progressEl.classList.add('hidden');
        if (phasesEl) phasesEl.classList.add('hidden');
      }, 800);
    }
  }

  function renderSourcemapModules() {
    var container = utils.get('sourcemap-results');
    if (!container) return;

    if (sourcemapModules.length === 0) {
      container.innerHTML = utils.emptyHtml('未找到 Webpack 模块');
      return;
    }

    // Filter
    var filtered = sourcemapModules;
    if (sourcemapSearchTerm) {
      filtered = sourcemapModules.filter(function (m) {
        return m.path.toLowerCase().indexOf(sourcemapSearchTerm) !== -1;
      });
    }

    // Group by source
    var groups = { runtime: [], sourcemap: [], chunk: [] };
    for (var i = 0; i < filtered.length; i++) {
      var g = groups[filtered[i].source] || groups.chunk;
      g.push({ module: filtered[i], index: sourcemapModules.indexOf(filtered[i]) });
    }

    // Enhanced stats bar
    var allGroups = { runtime: [], sourcemap: [], chunk: [] };
    for (var ai = 0; ai < sourcemapModules.length; ai++) {
      var ag = allGroups[sourcemapModules[ai].source] || allGroups.chunk;
      ag.push(sourcemapModules[ai]);
    }
    var stats = {
      total: sourcemapModules.length,
      runtime: allGroups.runtime.length,
      sourcemap: allGroups.sourcemap.length,
      chunk: allGroups.chunk.length,
      resolved: sourcemapModules.filter(function (m) {
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
    if (filtered.length !== sourcemapModules.length) {
      html += '<span class="sm-stat-item">显示 ' + filtered.length + '</span>';
    }
    html += '</div>';

    // Extension badge helper
    var extColors = {
      '.vue': '#42B883',
      '.js': '#F7DF1E',
      '.ts': '#3178C6',
      '.tsx': '#3178C6',
      '.jsx': '#61DAFB',
      '.css': '#264DE4',
      '.scss': '#CF649A',
      '.less': '#1D365D',
      '.json': '#5B5EA6',
      '.html': '#E34F26',
      '.svg': '#FFB13B',
      '.png': '#FFB13B',
      '.jpg': '#FFB13B',
      '.gif': '#FFB13B',
      '.woff': '#888',
      '.woff2': '#888',
    };

    var groupLabels = SOURCE_TYPE_LABELS;
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
    var mod = sourcemapModules[index];
    if (!mod) return;
    sourcemapCurrentModule = index;

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
    var sourceLabels = SOURCE_TYPE_LABELS;
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
    var depsHtml = '';
    if (mod.deps && mod.deps.length > 0) {
      depsHtml +=
        '<div class="sourcemap-deps-section"><span class="sourcemap-deps-label">依赖:</span>';
      mod.deps.forEach(function (depId) {
        var depMod = null;
        for (var d = 0; d < sourcemapModules.length; d++) {
          if (sourcemapModules[d].id === String(depId)) {
            depMod = sourcemapModules[d];
            break;
          }
        }
        var label = depMod ? depMod.path : depId;
        depsHtml +=
          '<span class="sourcemap-dep-tag" title="' +
          utils.escapeHtml(label) +
          '">' +
          utils.escapeHtml(label.length > 40 ? label.substring(0, 40) + '...' : label) +
          '</span>';
      });
      depsHtml += '</div>';
    }
    if (mod.reverseDeps && mod.reverseDeps.length > 0) {
      depsHtml +=
        '<div class="sourcemap-deps-section"><span class="sourcemap-deps-label">被引用:</span>';
      mod.reverseDeps.forEach(function (rdepId) {
        var rMod = null;
        for (var r = 0; r < sourcemapModules.length; r++) {
          if (sourcemapModules[r].id === rdepId) {
            rMod = sourcemapModules[r];
            break;
          }
        }
        var label = rMod ? rMod.path : rdepId;
        depsHtml +=
          '<span class="sourcemap-dep-tag sourcemap-dep-tag-reverse" title="' +
          utils.escapeHtml(label) +
          '">' +
          utils.escapeHtml(label.length > 40 ? label.substring(0, 40) + '...' : label) +
          '</span>';
      });
      depsHtml += '</div>';
    }
    depsEl.innerHTML = depsHtml;

    // Load source code
    codeEl.value = '';
    var source = sourcemapSourceCache[mod.path];
    if (source) {
      codeEl.value = source;
    } else if (mod.sourceUrl) {
      codeEl.value = '正在加载源码...';
      try {
        var mapJson = sourcemapMapCache[mod.sourceUrl];
        if (mapJson && mapJson.sourcesContent) {
          var srcIdx = mapJson.sources.indexOf(mod.path);
          if (srcIdx === -1) srcIdx = mapJson.sources.indexOf('webpack://' + mod.path);
          if (srcIdx >= 0 && mapJson.sourcesContent[srcIdx]) {
            source = mapJson.sourcesContent[srcIdx];
            sourcemapSourceCache[mod.path] = source;
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
    sourcemapCurrentModule = null;
    var detailCard = utils.get('sourcemap-detail-card');
    var resultsEl = utils.get('sourcemap-results');
    if (detailCard) detailCard.classList.add('hidden');
    if (resultsEl) resultsEl.classList.remove('hidden');
  }

  async function analyzeSourcemaps() {
    var analysisCard = utils.get('sm-analysis-card');
    var progressEl = utils.get('sm-analysis-progress');
    var resultsEl = utils.get('sm-analysis-results');
    if (!analysisCard || !progressEl || !resultsEl) return;

    // Collect modules with available source code (sourcemap cache) + chunk JS URLs to fetch
    var resolvedModules = sourcemapModules.filter(function (m) {
      return sourcemapSourceCache[m.path] && m.source !== 'chunk';
    });
    var chunkToFetch = sourcemapModules.filter(function (m) {
      return (
        m.source === 'chunk' &&
        m.path &&
        m.path.indexOf('://') !== -1 &&
        !sourcemapSourceCache[m.path]
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
      var contents = await smBatchFetch(chunkUrls.slice(0, 50), false, sourcemapTabId);
      for (var ci = 0; ci < contents.length; ci++) {
        if (contents[ci]) {
          sourcemapSourceCache[chunkToFetch[ci].path] = contents[ci];
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

    var securityRules = [
      // === Critical ===
      {
        name: 'AWS Access Key',
        pattern: /AKIA[0-9A-Z]{16}/g,
        severity: 'critical',
      },
      {
        name: 'AWS Secret Key',
        pattern:
          /(?:aws[_-]?secret[_-]?access[_-]?key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"]/gi,
        severity: 'critical',
      },
      {
        name: 'GitHub Token',
        pattern: /gh[pousr]_[A-Za-z0-9_]{36,255}/g,
        severity: 'critical',
      },
      {
        name: 'Stripe Secret Key',
        pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
        severity: 'critical',
      },
      {
        name: 'Stripe Publishable Key',
        pattern: /pk_live_[0-9a-zA-Z]{24,}/g,
        severity: 'high',
      },
      {
        name: 'Slack Token',
        pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}/g,
        severity: 'critical',
      },
      {
        name: 'Slack Webhook',
        pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g,
        severity: 'high',
      },
      {
        name: 'Google API Key',
        pattern: /AIza[0-9A-Za-z\-_]{35}/g,
        severity: 'high',
      },
      {
        name: 'Google OAuth Token',
        pattern: /ya29\.[0-9A-Za-z\-_]+/g,
        severity: 'high',
      },
      {
        name: 'SendGrid API Key',
        pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g,
        severity: 'critical',
      },
      {
        name: 'Twilio API Key',
        pattern: /SK[0-9a-fA-F]{32}/g,
        severity: 'critical',
      },
      {
        name: '数据库连接串',
        pattern: /(?:mongodb|mysql|postgres|postgresql|redis|ftp|smtp|ssh|amqp):\/\/[^\s'"]+/gi,
        severity: 'critical',
      },
      {
        name: 'MongoDB URI',
        pattern: /mongodb(?:\+srv)?:\/\/[^\s'"]+/gi,
        severity: 'critical',
      },
      {
        name: '私钥 (RSA/EC/DSA)',
        pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
        severity: 'critical',
      },
      // === High ===
      {
        name: 'API 密钥泄露',
        pattern:
          /(?:api[_-]?key|apikey|secret[_-]?key|app[_-]?key|app[_-]?secret)\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
        severity: 'high',
      },
      {
        name: '硬编码密码',
        pattern: /(?:password|passwd|pwd|pass[_-]?word)\s*[:=]\s*['"]([^'"]{4,})['"]/gi,
        severity: 'high',
      },
      {
        name: 'JWT Secret',
        pattern: /(?:jwt[_-]?secret|token[_-]?secret|jwt[_-]?key)\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
        severity: 'high',
      },
      {
        name: 'Authorization Header',
        pattern:
          /(?:Authorization|Bearer)\s*[:=]\s*['"](?:Bearer\s+)?([A-Za-z0-9\-_.~+/]+=*)['"]/gi,
        severity: 'high',
      },
      {
        name: 'OAuth Client Secret',
        pattern: /(?:client[_-]?secret|oauth[_-]?secret)\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
        severity: 'high',
      },
      {
        name: 'Heroku API Key',
        pattern:
          /(?:heroku|HEROKU)\s*[:=]\s*['"]([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['"]/gi,
        severity: 'high',
      },
      {
        name: 'Firebase URL',
        pattern: /https:\/\/[a-z0-9-]+\.firebaseio\.com/gi,
        severity: 'high',
      },
      {
        name: 'Shopify Token',
        pattern: /shpat_[a-fA-F0-9]{32}/g,
        severity: 'high',
      },
      {
        name: 'PayPal Braintree Token',
        pattern: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g,
        severity: 'high',
      },
      {
        name: '内部IP地址',
        pattern:
          /(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/g,
        severity: 'medium',
      },
      {
        name: 'Internal Domain',
        pattern:
          /(?:https?:\/\/)?(?:[a-z0-9-]+\.)?(?:internal|intranet|staging|dev|test|local|corp)\.[a-z0-9-]+/gi,
        severity: 'high',
      },
      // === Medium ===
      {
        name: 'eval() 使用',
        pattern: /eval\s*\(/g,
        severity: 'medium',
      },
      {
        name: 'innerHTML 赋值',
        pattern: /innerHTML\s*=/g,
        severity: 'medium',
      },
      {
        name: 'document.write',
        pattern: /document\.write\s*\(/g,
        severity: 'medium',
      },
      {
        name: 'CORS 通配符',
        pattern: /Access-Control-Allow-Origin['"]\s*[:=]\s*['"]\*['"]/gi,
        severity: 'medium',
      },
      {
        name: 'CSP 禁用',
        pattern: /Content-Security-Policy['"]\s*[:=]\s*['"]unsafe/gi,
        severity: 'medium',
      },
      {
        name: '路径穿越',
        pattern: /\.\.[\/\\]/g,
        severity: 'medium',
      },
      {
        name: 'XXE 风险',
        pattern: /DOMParser|xmlHttpRequest|\.parseFromString/gi,
        severity: 'medium',
      },
      {
        name: '命令拼接风险',
        pattern: /(?:exec|execSync|spawn|child_process)\s*\(/g,
        severity: 'medium',
      },
      {
        name: 'SQL 拼接',
        pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*\+\s*(?:req|params|query|body)/gi,
        severity: 'medium',
      },
      {
        name: 'unsafe eval (CSP)',
        pattern: /unsafe-eval/gi,
        severity: 'medium',
      },
      {
        name: 'window.location 赋值',
        pattern: /(?:window\.)?location\s*=\s*[^=]/g,
        severity: 'low',
      },
      {
        name: 'postMessage 无 origin 校验',
        pattern: /postMessage\s*\([^)]*\)/g,
        severity: 'medium',
      },
      {
        name: 'localStorage 敏感数据',
        pattern:
          /localStorage\.(?:setItem|set)\s*\(\s*['"](?:token|auth|session|password|secret|key)/gi,
        severity: 'medium',
      },
      // === Low ===
      {
        name: '调试代码 (console.log)',
        pattern: /console\.(?:log|debug|info)\s*\(/g,
        severity: 'low',
      },
      {
        name: 'localStorage/sessionStorage',
        pattern: /(?:localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)/g,
        severity: 'low',
      },
      {
        name: 'document.cookie',
        pattern: /document\.cookie/g,
        severity: 'low',
      },
      {
        name: '调试断点 (debugger)',
        pattern: /debugger\s*;/g,
        severity: 'low',
      },
      // === Info ===
      {
        name: 'TODO/FIXME/HACK',
        pattern: /(?:TODO|FIXME|HACK|XXX|BUG)\s*[:\(]/gi,
        severity: 'info',
      },
      {
        name: 'Swagger/OpenAPI 端点',
        pattern: /['"]\/(?:swagger|api-docs|openapi|graphql)(?:\/)?['"]/gi,
        severity: 'info',
      },
      {
        name: 'Spring Actuator',
        pattern: /['"]\/(?:actuator|env|health|metrics|trace|beans|mappings)(?:\/)?['"]/gi,
        severity: 'info',
      },
      {
        name: '备份文件路径',
        pattern: /['"](?:backup|\.bak|\.old|\.orig|\.save|\.tar|\.zip|\.sql|\.dump)['"]/gi,
        severity: 'info',
      },
      {
        name: '.git 暴露',
        pattern: /['"]\/\.git(?:\/|['"])/g,
        severity: 'high',
      },
      {
        name: '测试文件',
        pattern: /['"](?:test|spec|mock|fixture|stub)s?['"]/gi,
        severity: 'info',
      },
      {
        name: '环境配置引用',
        pattern: /process\.env\.[A-Z_]+/g,
        severity: 'info',
      },
    ];

    var allFindings = [];

    for (var mi = 0; mi < resolvedModules.length; mi++) {
      var mod = resolvedModules[mi];
      var source = sourcemapSourceCache[mod.path];
      if (!source) continue;

      for (var ri = 0; ri < securityRules.length; ri++) {
        var rule = securityRules[ri];
        var regex = new RegExp(rule.pattern.source, rule.pattern.flags);
        var match;
        var matchCount = 0;
        while ((match = regex.exec(source)) !== null) {
          matchCount++;
          if (matchCount > 20) break;
          allFindings.push({
            severity: rule.severity,
            name: rule.name,
            match: (match[1] || match[0]).substring(0, 60),
            file: mod.path,
            moduleIndex: sourcemapModules.indexOf(mod),
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
    severityOrder.forEach(function (s) {
      if (counts[s] > 0) {
        summaryHtml +=
          ' <span class="sm-analysis-severity sm-severity-' +
          s +
          '">' +
          severityLabels[s] +
          ' ' +
          counts[s] +
          '</span>';
      }
    });
    summaryHtml += '</div>';
    resultsEl.innerHTML = summaryHtml;

    var itemsHtml = '';
    var displayFindings = allFindings.slice(0, 200);
    for (var fi = 0; fi < displayFindings.length; fi++) {
      var f = displayFindings[fi];
      itemsHtml += '<div class="sm-analysis-item" data-idx="' + f.moduleIndex + '">';
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
        if (!isNaN(idx)) showSourcemapModuleDetail(idx);
      });
    });
  }

  function copyAllSourcemapPaths() {
    if (sourcemapModules.length === 0) {
      utils.showToast('没有模块路径', 'warning');
      return;
    }
    var paths = sourcemapModules
      .map(function (m) {
        return m.path;
      })
      .filter(Boolean)
      .join('\n');
    utils.copyAndToast(paths, '已复制 ' + sourcemapModules.length + ' 个路径');
  }

  function generateSourcemapTree() {
    if (sourcemapModules.length === 0) {
      utils.showToast('没有模块路径', 'warning');
      return;
    }
    var tree = {};
    sourcemapModules.forEach(function (m) {
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
    sourcemapModules.forEach(function (m) {
      if (m.source === 'chunk' && m.path && m.path.indexOf('://') !== -1) {
        var url = m.path.split('?')[0];
        if (jsUrls.indexOf(url) === -1) jsUrls.push(url);
      }
    });
    if (jsUrls.length === 0) {
      utils.showToast('未找到可加载的 JS 文件', 'warning');
      return;
    }
    try {
      var tab = await utils.getActiveTab();
      if (!tab || !tab.id) {
        utils.showToast('无法获取当前标签页', 'warning');
        return;
      }
      var results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        world: 'MAIN',
        func: function (urls) {
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
        args: [jsUrls],
      });
      var count = results && results[0] && results[0].result ? results[0].result : 0;
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
    var resolved = sourcemapModules.filter(function (m) {
      return m.resolved || sourcemapSourceCache[m.path];
    });
    if (resolved.length === 0) {
      utils.showToast('没有可下载的源码', 'warning');
      return;
    }
    var content = '';
    resolved.forEach(function (m) {
      var src = sourcemapSourceCache[m.path] || '';
      content += '='.repeat(60) + '\n';
      content += 'FILE: ' + m.path + '\n';
      content += 'MODULE: ' + m.id + '\n';
      content += '='.repeat(60) + '\n';
      content += src + '\n\n';
    });
    var blob = new Blob([content], { type: 'text/plain' });
    var url = URL.createObjectURL(blob);
    var filename = 'webpack-sources-' + Date.now() + '.txt';
    chrome.downloads.download({ url: url, filename: filename, saveAs: true }, function () {
      URL.revokeObjectURL(url);
      if (chrome.runtime.lastError) {
        utils.showToast('下载失败: ' + chrome.runtime.lastError.message, 'error');
        return;
      }
      utils.showToast('已下载 ' + resolved.length + ' 个源文件', 'success');
    });
  }

  function downloadSingleModule(index) {
    var mod = sourcemapModules[index];
    if (!mod) return;
    var source = sourcemapSourceCache[mod.path] || '';
    if (!source) {
      utils.showToast('该模块没有可用的源码', 'warning');
      return;
    }
    var fileName = mod.path.split('/').pop() || 'module.js';
    var blob = new Blob([source], { type: 'text/javascript' });
    var url = URL.createObjectURL(blob);
    chrome.downloads.download({ url: url, filename: fileName, saveAs: true }, function () {
      URL.revokeObjectURL(url);
      if (chrome.runtime.lastError) {
        utils.showToast('下载失败: ' + chrome.runtime.lastError.message, 'error');
        return;
      }
      utils.showToast('已下载 ' + fileName, 'success');
    });
  }

  function copyModuleSource() {
    var codeEl = utils.get('sourcemap-source-code');
    if (codeEl && codeEl.value) {
      utils.copyAndToast(codeEl.value, '已复制源码');
    }
  }

  // ====== API Endpoint Extraction ======

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
    sourcemapModules.forEach(function (mod) {
      var source = sourcemapSourceCache[mod.path];
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

  // ====== Export Functions ======

  function exportModulesJSON() {
    if (sourcemapModules.length === 0) {
      utils.showToast('没有模块数据', 'warning');
      return;
    }
    var data = {
      exportedAt: new Date().toISOString(),
      moduleCount: sourcemapModules.length,
      modules: sourcemapModules.map(function (m) {
        return {
          path: m.path,
          source: m.source,
          type: SOURCE_TYPE_LABELS[m.source] || m.source,
          size: m.size || 0,
          deps: m.deps || [],
        };
      }),
    };
    utils.copyText(JSON.stringify(data, null, 2));
    utils.showToast('已导出 ' + sourcemapModules.length + ' 个模块 JSON', 'success');
  }

  function exportModulesCSV() {
    if (sourcemapModules.length === 0) {
      utils.showToast('没有模块数据', 'warning');
      return;
    }
    var lines = ['Path,Source,Size,Deps'];
    sourcemapModules.forEach(function (m) {
      lines.push(
        '"' +
          (m.path || '').replace(/"/g, '""') +
          '","' +
          (m.source || '') +
          '",' +
          (m.size || 0) +
          ',' +
          (m.deps ? m.deps.length : 0)
      );
    });
    utils.copyText(lines.join('\n'));
    utils.showToast('已导出 CSV', 'success');
  }

  // --- Public API ---
  return {
    // Functions
    scanWebpackModules: scanWebpackModules,
    copyAllSourcemapPaths: copyAllSourcemapPaths,
    generateSourcemapTree: generateSourcemapTree,
    loadSourcesToDevTools: loadSourcesToDevTools,
    downloadAllSourcemapSources: downloadAllSourcemapSources,
    backToSourcemapList: backToSourcemapList,
    copyModuleSource: copyModuleSource,
    renderSourcemapModules: renderSourcemapModules,
    analyzeSourcemaps: analyzeSourcemaps,
    downloadSingleModule: downloadSingleModule,
    showApiEndpoints: showApiEndpoints,
    exportModulesJSON: exportModulesJSON,
    exportModulesCSV: exportModulesCSV,

    // State (getter/setter)
    get sourcemapModules() {
      return sourcemapModules;
    },
    set sourcemapModules(val) {
      sourcemapModules = val;
    },
    get sourcemapSearchTerm() {
      return sourcemapSearchTerm;
    },
    set sourcemapSearchTerm(val) {
      sourcemapSearchTerm = val;
    },
    get sourcemapCurrentModule() {
      return sourcemapCurrentModule;
    },
    set sourcemapCurrentModule(val) {
      sourcemapCurrentModule = val;
    },
  };
})();
