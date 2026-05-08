// vk-sourcemap-scanner.js -- 灵眸 Chrome Extension
// scanWebpackModules: Phase 1 (MAIN world) + Phase 2 (ISOLATED) + Phase 2.5 + Phase 3
(function () {
  'use strict';

  var S = window.VulnKitSourcemapState;
  var utils = S.utils;
  var U = null; // lazy ref to S.Utils — set after registration

  // Phase 1 injected function body (executed in MAIN world via execInTabData).
  // Kept as a local constant because it's serialized and cannot reference outer scope.
  var PHASE1_MAIN_WORLD_FN = function () {
    var modules = [];
    var hasWebpack = false;
    var capturedWpRequire = null;
    function modExists(id) {
      for (var i = 0; i < modules.length; i++) {
        if (modules[i].id === id) return true;
      }
      return false;
    }

    // Strategy 0: Intercept webpackChunk* to capture webpack require
    try {
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

      for (var _wck in window) {
        if (_wck.indexOf('webpackChunk') !== 0) continue;
        if (!Array.isArray(window[_wck])) continue;
        var _arr = window[_wck];
        var _pushStr = _arr.push.toString();
        if (_pushStr.indexOf('[native code]') !== -1) {
          hookWebpackPush(_arr);
          continue;
        }
        hasWebpack = true;
        try {
          _arr.push([
            [999999],
            {},
            function (wpRequire) {
              capturedWpRequire = wpRequire;
            },
          ]);
        } catch (_fpErr) {
          hookWebpackPush(_arr);
        }
        if (capturedWpRequire) break;
      }
    } catch (e) {
      /* ignore */
    }

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
        if (!modExists(mid)) modules.push({ id: mid, path: '', deps: [], source: 'runtime' });
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
            if (!modExists(mId)) modules.push({ id: mId, path: mId, deps: [], source: 'runtime' });
          }
        }
      }
    }

    // Extract webpack chunk URL info
    var chunkInfo = null;
    try {
      var wpRequire = capturedWpRequire;
      if (!wpRequire && typeof __webpack_require__ !== 'undefined') {
        wpRequire = __webpack_require__;
      }
      if (wpRequire && typeof wpRequire.u === 'function') {
        var uBody = wpRequire.u.toString();
        var allChunkIds = [];

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

        var chunkFilenames = {};
        allChunkIds.forEach(function (id) {
          try {
            var filename = wpRequire.u(id);
            if (filename && filename.length > 0) chunkFilenames[id] = filename;
          } catch (e) {
            /* ignore */
          }
        });

        if (Object.keys(chunkFilenames).length === 0 && allChunkIds.length > 0) {
          var maxProbe = 0;
          allChunkIds.forEach(function (id) {
            var n = parseInt(id, 10);
            if (n > maxProbe) maxProbe = n;
          });
          var probeLimit = Math.min(maxProbe + 200, 100000);
          for (var pid = 1; pid <= probeLimit; pid++) {
            try {
              var pfn = wpRequire.u(pid);
              if (pfn && typeof pfn === 'string' && pfn.length > 3) {
                if (pfn.indexOf(String(pid) + '.') === -1) {
                  chunkFilenames[String(pid)] = pfn;
                } else if (pfn !== String(pid) + '.js') {
                  chunkFilenames[String(pid)] = pfn;
                }
              }
            } catch (e) {
              /* ignore */
            }
          }
        }

        if (Object.keys(chunkFilenames).length > 0) {
          chunkInfo = { chunkFilenames: chunkFilenames };
        }
      }
    } catch (e) {
      /* ignore */
    }

    // Strategy 0C: Decode obfuscated .u() via globally-accessible string decoder
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

          var _uOpenMatch = _bundleSrc.match(/(\w+)\['u'\]\s*=\s*function\s*\(\s*(\w+)\s*\)\s*\{/);
          if (!_uOpenMatch)
            _uOpenMatch = _bundleSrc.match(/(\w+)\.u\s*=\s*function\s*\(\s*(\w+)\s*\)\s*\{/);
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
          } catch (e) {
            /* ignore */
          }
          try {
            if (_oIdxs.length >= 2) _suffix = _dec(_oIdxs[_oIdxs.length - 1]) || '';
          } catch (e) {
            /* ignore */
          }

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
                } catch (e) {
                  /* ignore */
                }
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
                } catch (e) {
                  /* ignore */
                }
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
                  if (_hash) _decodedChunks[String(_cid)] = _prefix + _cid + '.' + _hash + _suffix;
                } catch (e) {
                  /* ignore */
                }
              }
            }
          }
          if (Object.keys(_decodedChunks).length > 0) {
            var _wpPp = '';
            var _ppMatch = _bundleSrc.match(
              new RegExp(_uOpenMatch[1] + '\\[\'p\'\\]\\s*=\\s*"([^"]*)"')
            );
            if (!_ppMatch)
              _ppMatch = _bundleSrc.match(new RegExp(_uOpenMatch[1] + '\\.p\\s*=\\s*"([^"]*)"'));
            if (_ppMatch) _wpPp = _ppMatch[1];
            chunkInfo = { chunkFilenames: _decodedChunks, publicPath: _wpPp };
          }
        } catch (e) {
          /* ignore */
        }
      })();
    }

    // Install network hooks to capture dynamically loaded scripts
    try {
      if (!window.__vulnkitScriptObserver) {
        window.__vulnkitScriptObserver = [];
        window.__vulnkitHookActive = true;

        new MutationObserver(function (mutations) {
          mutations.forEach(function (m) {
            m.addedNodes.forEach(function (node) {
              if (node.tagName === 'SCRIPT' && node.src && node.src.indexOf('data:') !== 0) {
                window.__vulnkitScriptObserver.push(node.src);
              }
            });
          });
        }).observe(document.documentElement, { childList: true, subtree: true });

        var _origFetch = window.fetch.bind(window);
        window.fetch = function (input) {
          try {
            var url = typeof input === 'string' ? input : input && input.url ? input.url : '';
            if (
              url &&
              /\.js(\?|$)/.test(url) &&
              window.__vulnkitScriptObserver.indexOf(url) === -1
            ) {
              window.__vulnkitScriptObserver.push(url);
            }
          } catch (e) {
            /* ignore */
          }
          return _origFetch.apply(this, arguments);
        };

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
          } catch (e) {
            /* ignore */
          }
          return _origXhrOpen.apply(this, arguments);
        };
      }
    } catch (e) {
      /* ignore */
    }

    var monitoredScripts = [];
    try {
      if (window.__vulnkitScriptObserver) {
        monitoredScripts = window.__vulnkitScriptObserver.slice();
      }
    } catch (e) {
      /* ignore */
    }

    var wpPublicPath = '';
    try {
      var _wpR =
        capturedWpRequire ||
        (typeof __webpack_require__ !== 'undefined' ? __webpack_require__ : null);
      if (_wpR && _wpR.p) wpPublicPath = _wpR.p;
    } catch (e) {
      /* ignore */
    }

    return {
      modules: modules,
      hasWebpack: hasWebpack,
      chunkInfo: chunkInfo,
      monitoredScripts: monitoredScripts,
      wpPublicPath: wpPublicPath,
    };
  };

  // --- Shared scan context ---
  function createScanContext(tab, statusEl) {
    return {
      tab: tab,
      statusEl: statusEl,
      allModules: [],
      sourceMapUrls: [],
      scriptUrls: [],
      chunkManifest: null,
      wpPublicPath: '',
      buildTool: null,
      buildFeatures: [],
      discoveredChunkUrls: [],
    };
  }

  function addSourceMapUrl(ctx, url) {
    if (ctx.sourceMapUrls.indexOf(url) === -1) ctx.sourceMapUrls.push(url);
  }

  function addScriptUrl(ctx, url) {
    if (ctx.scriptUrls.indexOf(url) === -1) ctx.scriptUrls.push(url);
  }

  // --- Phase 1: MAIN world webpack runtime detection ---
  async function runPhase1(ctx) {
    ctx.statusEl.textContent = 'Phase 1: 检测 Webpack 运行时...';
    U.smUpdateProgress(10, 1);
    try {
      var wpData = await utils.execInTabData(ctx.tab.id, PHASE1_MAIN_WORLD_FN);
      if (wpData) {
        if (wpData.modules && wpData.modules.length > 0) {
          ctx.allModules = ctx.allModules.concat(wpData.modules);
        }
        if (wpData.chunkInfo && wpData.chunkInfo.chunkFilenames) {
          ctx.chunkManifest = wpData.chunkInfo.chunkFilenames;
          ctx.wpPublicPath = wpData.chunkInfo.publicPath || wpData.wpPublicPath || '';
        }
        if (!ctx.wpPublicPath) ctx.wpPublicPath = wpData.wpPublicPath || '';
        if (wpData.monitoredScripts && wpData.monitoredScripts.length > 0) {
          wpData.monitoredScripts.forEach(function (url) {
            addScriptUrl(ctx, url);
          });
        }
      }
    } catch (e) {
      // MAIN world may fail on some pages, continue with fallback
    }
  }

  // --- Build tool detection ---
  async function detectBuildTool(ctx) {
    ctx.statusEl.textContent = '检测构建工具...';
    U.smUpdateProgress(25, 1);
    try {
      var btResult = await chrome.tabs.sendMessage(ctx.tab.id, { type: 'VK_SOURCEMAP_DETECT' });
      if (btResult && btResult.tool) {
        ctx.buildTool = btResult.tool;
        ctx.buildFeatures = btResult.features || [];
        var toolHints = (btResult.hints || []).join('; ');
        var toolLabel = ctx.buildTool.toUpperCase();
        if (btResult.version) toolLabel += ' v' + btResult.version;
        if (ctx.buildFeatures.length > 0) toolLabel += ' [' + ctx.buildFeatures.join(', ') + ']';
        ctx.statusEl.textContent = toolLabel + (toolHints ? ' (' + toolHints + ')' : '');
      }
    } catch (e) {
      // content script may not be ready, continue
    }
  }

  // --- Phase 2: ISOLATED world script collection + source map extraction ---
  async function runPhase2(ctx) {
    ctx.statusEl.textContent = 'Phase 2: 收集脚本和 Source Map...';
    U.smUpdateProgress(30, 2);

    // Collect script/preload URLs and inline scripts from ISOLATED world
    try {
      var domData = await utils.execInTabData(
        ctx.tab.id,
        function () {
          var extUrls = [];
          var inlineScripts = [];
          document.querySelectorAll('script[src]').forEach(function (s) {
            extUrls.push(s.src);
          });
          document.querySelectorAll('script:not([src])').forEach(function (s) {
            var text = s.textContent || '';
            if (text.length > 10 && text.length < 500000) inlineScripts.push(text);
          });
          var perfUrls = [];
          try {
            performance.getEntriesByType('resource').forEach(function (e) {
              if (e.name && /\.js(\?|$)/.test(e.name)) {
                perfUrls.push(e.name);
              }
            });
          } catch (ex) {}
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
        { world: 'ISOLATED' }
      );
      if (domData) {
        ctx.scriptUrls = domData.extUrls || [];
        (domData.perfUrls || []).forEach(function (u) {
          addScriptUrl(ctx, u);
        });
        (domData.preloadUrls || []).forEach(function (u) {
          addScriptUrl(ctx, u);
        });

        // Extract source map URLs from inline scripts
        var mapRegex = /[/#][@]\s*sourceMappingURL\s*=\s*(\S+)/gi;
        (domData.inlineScripts || []).forEach(function (script) {
          mapRegex.lastIndex = 0;
          var match;
          while ((match = mapRegex.exec(script)) !== null) {
            var url = match[1];
            if (url.indexOf('data:') !== 0) {
              addSourceMapUrl(ctx, U.smResolveUrl(url, ctx.tab.url));
            }
          }
        });
      }
    } catch (e) {
      // continue
    }

    // Parse script files for source map URLs
    if (ctx.scriptUrls.length > 0 && ctx.sourceMapUrls.length < 5) {
      ctx.statusEl.textContent =
        'Phase 2: 解析脚本 Source Map URL (' + ctx.scriptUrls.length + ' 个文件)...';
      var scriptContents = await U.smBatchFetch(
        ctx.scriptUrls.slice(0, S.SM_MAX_SCRIPTS_SCAN),
        false,
        ctx.tab.id
      );
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
          var mapUrl = U.smResolveUrl(mapMatch[1], ctx.scriptUrls[si]);
          addSourceMapUrl(ctx, mapUrl);
        }
      }
    }

    // Fetch and parse source map files
    if (ctx.sourceMapUrls.length > 0) {
      ctx.statusEl.textContent =
        'Phase 2: 解析 ' + ctx.sourceMapUrls.length + ' 个 Source Map 文件...';
      U.smUpdateProgress(50, 2);
      var mapContents = await U.smBatchFetch(
        ctx.sourceMapUrls.slice(0, S.SM_MAX_MAPS_PARSE),
        false,
        ctx.tab.id
      );
      for (var mi = 0; mi < mapContents.length; mi++) {
        if (!mapContents[mi]) continue;
        U.smParseMapToModules(
          mapContents[mi],
          ctx.sourceMapUrls[mi],
          'sm-',
          ctx.allModules,
          S.sourcemapSourceCache,
          S.sourcemapMapCache
        );
      }
    }
  }

  // --- Phase 2.5: Discover unloaded chunks ---
  async function runPhase25(ctx) {
    // Build-tool-specific source map guessing
    discoverToolSpecificMaps(ctx);

    // Discover chunks via webpack manifest
    discoverChunksFromManifest(ctx);

    // Fallback: deep-parse bundle JS for chunk manifest patterns
    await discoverChunksDeepParse(ctx);

    // Fetch discovered chunks and their source maps
    await fetchDiscoveredChunks(ctx);
  }

  function discoverToolSpecificMaps(ctx) {
    if (ctx.buildTool === 'vite' && ctx.scriptUrls.length > 0) {
      ctx.statusEl.textContent = 'Phase 2.5: Vite — 探测 /assets/ Source Map...';
      U.smUpdateProgress(40, 2);
      var viteAssetBase = null;
      ctx.scriptUrls.forEach(function (sUrl) {
        var m = sUrl.match(/^(https?:\/\/[^/]+\/.*)\/assets\//);
        if (m && !viteAssetBase) viteAssetBase = m[1] + '/assets/';
      });
      if (viteAssetBase) {
        ctx.scriptUrls.forEach(function (sUrl) {
          if (sUrl.indexOf(viteAssetBase) !== 0) return;
          addSourceMapUrl(ctx, sUrl + '.map');
        });
      }
    }

    if (ctx.buildTool === 'rollup' && ctx.scriptUrls.length > 0) {
      ctx.statusEl.textContent = 'Phase 2.5: Rollup — 探测 Chunk Source Map...';
      U.smUpdateProgress(40, 2);
      ctx.scriptUrls.forEach(function (sUrl) {
        addSourceMapUrl(ctx, sUrl + '.map');
      });
    }

    if (ctx.buildTool === 'esbuild' && ctx.scriptUrls.length > 0) {
      ctx.statusEl.textContent = 'Phase 2.5: esbuild — 探测 Source Map...';
      U.smUpdateProgress(40, 2);
      ctx.scriptUrls.forEach(function (sUrl) {
        addSourceMapUrl(ctx, sUrl + '.map');
      });
    }

    if (ctx.buildTool === 'turbopack' && ctx.scriptUrls.length > 0) {
      ctx.statusEl.textContent = 'Phase 2.5: Turbopack — 探测 Source Map...';
      U.smUpdateProgress(40, 2);
      ctx.scriptUrls.forEach(function (sUrl) {
        if (/_next\/static\/chunks\//.test(sUrl) || /_next\/static\/[a-z]+\//.test(sUrl)) {
          addSourceMapUrl(ctx, sUrl + '.map');
        }
      });
    }

    if (
      ctx.buildFeatures.indexOf('nuxt-payload') !== -1 ||
      ctx.buildFeatures.indexOf('nuxt-public-config') !== -1
    ) {
      ctx.statusEl.textContent = 'Phase 2.5: Nuxt — 探测 Source Map...';
      U.smUpdateProgress(40, 2);
      ctx.scriptUrls.forEach(function (sUrl) {
        if (/_nuxt\//.test(sUrl)) {
          addSourceMapUrl(ctx, sUrl + '.map');
        }
      });
    }
  }

  function discoverChunksFromManifest(ctx) {
    if (!ctx.chunkManifest || ctx.scriptUrls.length === 0) return;

    var inferredBase = null;
    for (var si = 0; si < ctx.scriptUrls.length && !inferredBase; si++) {
      var sUrlClean = ctx.scriptUrls[si].split('?')[0];
      var sBare = sUrlClean.substring(sUrlClean.lastIndexOf('/') + 1);
      for (var cid in ctx.chunkManifest) {
        if (inferredBase) break;
        var cFname = ctx.chunkManifest[cid];
        if (!cFname) continue;
        var cBare = cFname.substring(cFname.lastIndexOf('/') + 1);
        if (cBare === sBare) {
          inferredBase = sUrlClean.substring(0, sUrlClean.length - cFname.length);
        }
      }
    }
    var baseUrl = inferredBase
      ? inferredBase
      : ctx.wpPublicPath
        ? U.smResolveUrl(ctx.wpPublicPath, ctx.tab.url)
        : ctx.tab.url.substring(0, ctx.tab.url.lastIndexOf('/') + 1);
    Object.keys(ctx.chunkManifest).forEach(function (chunkId) {
      var filename = ctx.chunkManifest[chunkId];
      if (!filename) return;
      var fullUrl = U.smResolveUrl(filename, baseUrl);
      ctx.discoveredChunkUrls.push({ chunkId: chunkId, url: fullUrl });
    });
  }

  async function discoverChunksDeepParse(ctx) {
    if (ctx.discoveredChunkUrls.length > 0 || ctx.scriptUrls.length === 0) return;

    ctx.statusEl.textContent = 'Phase 2.5: 深度解析 Bundle 源码发现 Chunk...';
    U.smUpdateProgress(40, 2);

    var runtimeUrl =
      ctx.scriptUrls.find(function (u) {
        return /runtime/i.test(u) && /\.js(\?|$)/.test(u);
      }) ||
      ctx.scriptUrls.find(function (u) {
        return /main|app|index/i.test(u) && /\.js(\?|$)/.test(u);
      }) ||
      ctx.scriptUrls.find(function (u) {
        return /bundle\//.test(u) || /static\/js/.test(u);
      }) ||
      null;

    if (!runtimeUrl) return;

    var runtimeContent = await U.smBatchFetch([runtimeUrl], false, ctx.tab.id);
    if (!runtimeContent[0]) return;

    var rc = runtimeContent[0];
    var rcBase = runtimeUrl.substring(0, runtimeUrl.lastIndexOf('/') + 1);

    // Try extracting chunk ID → hash mappings from webpack require.u
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
          var chunkIdToHash = U.smMergeHashMaps(mappingObj, /(\d+)\s*:\s*"([a-f0-9]{4,})"/g);
          var baseInfo1 = U.smResolveWebpackBase(rc, rcBase, ctx.tab.url);
          U.smRegisterChunkUrls(chunkIdToHash, baseInfo1, ctx.discoveredChunkUrls, ctx.scriptUrls);
        }
      } catch (e) {
        /* ignore */
      }
    }

    // Fallback: look for hash maps in entire bundle
    if (ctx.discoveredChunkUrls.length === 0) {
      var hashMaps = rc.match(/\{[^\{\}]{10,}?"?\d+"?\s*:\s*"[a-f0-9]{4,}"[^\{\}]*?\}/g);
      if (hashMaps) {
        var tempChunkMap = U.smMergeHashMaps(hashMaps, /"?(\d+)"?\s*:\s*"([a-f0-9]{4,})"/g);
        if (Object.keys(tempChunkMap).length > 2) {
          var baseInfo2 = U.smResolveWebpackBase(rc, rcBase, ctx.tab.url);
          U.smRegisterChunkUrls(tempChunkMap, baseInfo2, ctx.discoveredChunkUrls, ctx.scriptUrls);
        }
      }
    }

    // Look for direct chunk filename references
    var chunkNameRefs = rc.match(/["']([\w.-]+\.[a-f0-9]{6,}\.js)["']/g);
    if (chunkNameRefs) {
      chunkNameRefs.forEach(function (ref) {
        var nameMatch = ref.match(/["']([\w.-]+\.[a-f0-9]{6,}\.js)["']/);
        if (nameMatch) {
          U.smAddDiscoveredChunk(
            rcBase + nameMatch[1],
            'ref',
            ctx.discoveredChunkUrls,
            ctx.scriptUrls
          );
        }
      });
    }

    // Fallback: parse other bundle files for dynamic imports and .e() calls
    if (ctx.discoveredChunkUrls.length === 0) {
      var otherBundles = ctx.scriptUrls.filter(function (u) {
        return u !== runtimeUrl && (/(vendor|main|app|index)/i.test(u) || /bundle\//.test(u));
      });
      if (otherBundles.length > 0) {
        var bundleContents = await U.smBatchFetch(
          otherBundles.slice(0, S.SM_MAX_OTHER_BUNDLES),
          false,
          ctx.tab.id
        );
        for (var bi = 0; bi < bundleContents.length; bi++) {
          if (!bundleContents[bi]) continue;
          var dynamicImports = bundleContents[bi].match(/["']\.\/([\w.-]+\.[a-f0-9]{6,}\.js)["']/g);
          if (dynamicImports) {
            dynamicImports.forEach(function (imp) {
              var nameMatch = imp.match(/["']\.\/([\w.-]+\.[a-f0-9]{6,}\.js)["']/);
              if (nameMatch) {
                var bundleBase = otherBundles[bi].substring(
                  0,
                  otherBundles[bi].lastIndexOf('/') + 1
                );
                var fullImp = bundleBase + nameMatch[1];
                U.smAddDiscoveredChunk(fullImp, 'import', ctx.discoveredChunkUrls, ctx.scriptUrls);
              }
            });
          }
          var chunkERefs = bundleContents[bi].match(/\.e\s*\(\s*(\d+)\s*\)/g);
          if (chunkERefs) {
            chunkERefs.forEach(function (ref) {
              var idMatch = ref.match(/\.e\s*\(\s*(\d+)\s*\)/);
              if (idMatch) {
                var hasEid = ctx.discoveredChunkUrls.some(function (cu) {
                  return cu.chunkId === idMatch[1];
                });
                if (!hasEid) ctx.discoveredChunkUrls.push({ chunkId: idMatch[1], url: null });
              }
            });
          }
        }
      }
    }
  }

  async function fetchDiscoveredChunks(ctx) {
    if (ctx.discoveredChunkUrls.length === 0) return;

    ctx.statusEl.textContent =
      'Phase 2.5: Manifest 发现 ' + ctx.discoveredChunkUrls.length + ' 个 Chunk，探测中...';
    var seenChunkUrls = {};
    var chunkFetchUrls = [];

    ctx.discoveredChunkUrls.forEach(function (cu) {
      var url = cu.url;
      if (!url) return;
      if (ctx.scriptUrls.indexOf(url) !== -1) return;
      if (seenChunkUrls[url]) return;
      seenChunkUrls[url] = true;
      chunkFetchUrls.push(url);
    });

    ctx.scriptUrls.forEach(function (sUrl) {
      var sBase = sUrl.substring(0, sUrl.lastIndexOf('/') + 1);
      var sName = sUrl.substring(sUrl.lastIndexOf('/') + 1);
      var guessMap = U.smResolveUrl(sName + '.map', sBase);
      addSourceMapUrl(ctx, guessMap);
    });

    chunkFetchUrls.forEach(function (cUrl) {
      if (ctx.scriptUrls.indexOf(cUrl) === -1) addScriptUrl(ctx, cUrl);
    });

    var chunkSamples = await U.smBatchFetch(
      chunkFetchUrls.slice(0, S.SM_MAX_CHUNK_SAMPLES),
      true,
      ctx.tab.id
    );
    var newSourceMapUrls = [];
    for (var ci = 0; ci < chunkSamples.length; ci++) {
      if (!chunkSamples[ci]) continue;
      var chunkContent = chunkSamples[ci];
      var chunkMapMatch = chunkContent.match(/[/#][@]\s*sourceMappingURL\s*=\s*(\S+)/);
      if (chunkMapMatch && chunkMapMatch[1].indexOf('data:') !== 0) {
        var cmUrl = U.smResolveUrl(chunkMapMatch[1], chunkFetchUrls[ci]);
        if (ctx.sourceMapUrls.indexOf(cmUrl) === -1) newSourceMapUrls.push(cmUrl);
      }
      var chunkMapGuess = chunkFetchUrls[ci] + '.map';
      if (ctx.sourceMapUrls.indexOf(chunkMapGuess) === -1) newSourceMapUrls.push(chunkMapGuess);
    }

    var allNewMaps = newSourceMapUrls.slice(0, S.SM_MAX_CHUNK_SAMPLES);
    if (allNewMaps.length > 0) {
      ctx.statusEl.textContent = 'Phase 2.5: 解析 ' + allNewMaps.length + ' 个新 Source Map...';
      var newMapContents = await U.smBatchFetch(allNewMaps, false, ctx.tab.id);
      for (var nmi = 0; nmi < newMapContents.length; nmi++) {
        if (!newMapContents[nmi]) continue;
        var nmUrl = allNewMaps[nmi];
        if (S.sourcemapMapCache[nmUrl]) continue;
        U.smParseMapToModules(
          newMapContents[nmi],
          nmUrl,
          'sm2-',
          ctx.allModules,
          S.sourcemapSourceCache,
          S.sourcemapMapCache
        );
      }
    }
  }

  // --- Phase 3: Fallback JS path parsing ---
  async function runPhase3(ctx) {
    if (ctx.allModules.length > 0 || ctx.scriptUrls.length === 0) return;

    ctx.statusEl.textContent =
      'Phase 3: 解析 JS 文件中的模块路径...' + (ctx.buildTool ? ' (' + ctx.buildTool + ')' : '');
    U.smUpdateProgress(70, 3);
    var jsContents = await U.smBatchFetch(
      ctx.scriptUrls.slice(0, S.SM_MAX_JS_FALLBACK),
      false,
      ctx.tab.id
    );
    for (var ji = 0; ji < jsContents.length; ji++) {
      if (!jsContents[ji]) continue;
      var jsText = jsContents[ji];
      var pathRegex;
      if (ctx.buildTool === 'vite') {
        pathRegex =
          /(?:\/[a-zA-Z_][\w.-]*(?:\/[a-zA-Z_][\w.-]*)*)(?:\.vue|\.jsx|\.tsx|\.ts|\.js|\.css|\.scss)/g;
      } else if (ctx.buildTool === 'rollup' || ctx.buildTool === 'esbuild') {
        pathRegex = /(?:\/src\/[^\s"'`]+)(?:\.vue|\.jsx|\.tsx|\.ts|\.js|\.css)/g;
      } else if (ctx.buildTool === 'turbopack') {
        pathRegex =
          /(?:\.\/[^\s"'`]+)(?:\.(?:tsx|ts|jsx|js|css|module\.css))|turbopack:\/\/[^\s"']+/g;
      } else {
        pathRegex =
          /webpack:\/\/[^\s"']+|\.[\/]?[a-zA-Z_][\w.\/-]*(?:\.vue|\.js|\.ts|\.jsx|\.tsx)/g;
      }
      var pathMatch;
      var seen = {};
      while ((pathMatch = pathRegex.exec(jsText)) !== null) {
        var p = ctx.buildTool ? pathMatch[0] : pathMatch[0].replace('webpack://', '');
        if (seen[p]) continue;
        seen[p] = true;
        ctx.allModules.push({
          id: 'ch-' + Object.keys(seen).length,
          path: p,
          deps: [],
          source: 'chunk',
        });
      }
    }
  }

  // --- Finalize: reverse deps, dedup, render ---
  async function finalizeResults(ctx) {
    // Build reverse deps
    for (var di = 0; di < ctx.allModules.length; di++) {
      ctx.allModules[di].reverseDeps = [];
    }
    for (var di2 = 0; di2 < ctx.allModules.length; di2++) {
      var modDeps = ctx.allModules[di2].deps || [];
      for (var dd = 0; dd < modDeps.length; dd++) {
        var depId = String(modDeps[dd]);
        for (var dr = 0; dr < ctx.allModules.length; dr++) {
          if (ctx.allModules[dr].id === depId) {
            ctx.allModules[dr].reverseDeps.push(ctx.allModules[di2].id);
            break;
          }
        }
      }
    }

    // Add script URLs as chunk entries
    var seenScriptUrls = {};
    for (var si = 0; si < ctx.scriptUrls.length; si++) {
      var scriptPath = ctx.scriptUrls[si];
      if (seenScriptUrls[scriptPath]) continue;
      seenScriptUrls[scriptPath] = true;
      var scriptPathExists = false;
      for (var sp = 0; sp < ctx.allModules.length; sp++) {
        if (ctx.allModules[sp].path === scriptPath) {
          scriptPathExists = true;
          break;
        }
      }
      if (!scriptPathExists) {
        ctx.allModules.push({
          id: 'script-' + si,
          path: scriptPath,
          deps: [],
          source: 'chunk',
        });
      }
    }

    // Deduplicate by path
    var seenPaths = {};
    var deduped = [];
    for (var ui = 0; ui < ctx.allModules.length; ui++) {
      var m = ctx.allModules[ui];
      if (!m.path) continue;
      if (m.source === 'runtime' && /^\d+$/.test(m.path)) continue;
      var baseKey = m.path.split('?')[0];
      if (seenPaths[baseKey]) continue;
      seenPaths[baseKey] = true;
      deduped.push(m);
    }

    S.sourcemapModules = deduped.slice(0, S.SM_MAX_MODULES);
    var toolLabel = ctx.buildTool ? '[' + ctx.buildTool.toUpperCase() + '] ' : '';
    ctx.statusEl.textContent = toolLabel + '找到 ' + S.sourcemapModules.length + ' 个模块';
    U.smUpdateProgress(100, 3);
    S.Render.renderSourcemapModules();

    // Check if network hooks are active and show hint
    try {
      if (
        await utils.execInTabData(ctx.tab.id, function () {
          return !!window.__vulnkitHookActive;
        })
      ) {
        var hookHint = document.createElement('div');
        hookHint.className = 'sm-hook-hint';
        hookHint.textContent = 'JS Hook 已激活 -- 浏览其他页面可自动捕获新 Chunk，再次扫描即可合并';
        var statusArea = document.getElementById('sourcemap-status');
        if (statusArea && statusArea.nextSibling) {
          statusArea.parentNode.insertBefore(hookHint, statusArea.nextSibling);
        }
      }
    } catch (e) {
      /* ignore */
    }
  }

  // --- Main entry point ---
  async function scanWebpackModules() {
    U = U || S.Utils;

    if (S.smAbortFlag === false && document.querySelector('#sourcemap-scan-btn.scanning')) {
      S.smAbortFlag = true;
      return;
    }

    var statusEl = utils.get('sourcemap-status');
    var resultsEl = utils.get('sourcemap-results');
    if (!statusEl) return;

    S.sourcemapModules = [];
    S.sourcemapSourceCache = {};
    S.sourcemapMapCache = {};
    S.sourcemapTabId = null;
    S.smAbortFlag = false;
    U.setScanState(true);
    if (resultsEl) resultsEl.innerHTML = '';

    var progressEl = utils.get('sm-progress');
    var phasesEl = utils.get('sm-phases');
    if (progressEl) progressEl.classList.remove('hidden');
    if (phasesEl) phasesEl.classList.remove('hidden');
    U.smUpdateProgress(0, 1);

    try {
      var tab = await utils.requireTabId();
      if (!tab || !tab.url || tab.url.startsWith('chrome')) {
        statusEl.textContent = '无法扫描此页面';
        U.setScanState(false);
        S.sourcemapTabId = null;
        return;
      }

      S.sourcemapTabId = tab.id;
      var ctx = createScanContext(tab, statusEl);

      await runPhase1(ctx);
      if (S.smAbortFlag) {
        statusEl.textContent = '扫描已取消';
        return;
      }

      await detectBuildTool(ctx);
      if (S.smAbortFlag) {
        statusEl.textContent = '扫描已取消';
        return;
      }

      await runPhase2(ctx);
      if (S.smAbortFlag) {
        statusEl.textContent = '扫描已取消';
        return;
      }

      await runPhase25(ctx);
      if (S.smAbortFlag) {
        statusEl.textContent = '扫描已取消';
        return;
      }

      await runPhase3(ctx);
      finalizeResults(ctx);
    } catch (err) {
      statusEl.textContent = '扫描失败: ' + (err.message || '未知错误');
    } finally {
      U.setScanState(false);
      if (S.smAbortFlag && S.sourcemapModules.length > 0) {
        S.Render.renderSourcemapModules();
      }
      setTimeout(function () {
        var progressEl = utils.get('sm-progress');
        var phasesEl = utils.get('sm-phases');
        if (progressEl) progressEl.classList.add('hidden');
        if (phasesEl) phasesEl.classList.add('hidden');
      }, 800);
    }
  }

  S.Scanner = {
    scanWebpackModules: scanWebpackModules,
  };
})();
