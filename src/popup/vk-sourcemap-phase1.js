// 灵眸 - SourceMap Phase 1: MAIN world webpack runtime detection
// Serialized function body executed in MAIN world via execInTabData.
// Cannot reference outer scope — fully self-contained.
'use strict';

const PHASE1_MAIN_WORLD_FN = function () {
  const modules = [];
  let hasWebpack = false;
  let capturedWpRequire = null;
  function modExists(id) {
    for (let i = 0; i < modules.length; i++) {
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
      const origPush = chunkArr.push.bind(chunkArr);
      chunkArr.push = function () {
        const args = Array.prototype.slice.call(arguments);
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

    for (let _wck in window) {
      if (_wck.indexOf('webpackChunk') !== 0) continue;
      if (!Array.isArray(window[_wck])) continue;
      const _arr = window[_wck];
      const _pushStr = _arr.push.toString();
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
    console.debug('Phase1 webpackChunk hook error', e);
  }

  // Webpack 4: __webpack_require__.c (module cache)
  if (typeof __webpack_require__ !== 'undefined' && __webpack_require__.c) {
    hasWebpack = true;
    const cache = __webpack_require__.c;
    for (let id in cache) {
      if (!cache.hasOwnProperty(id)) continue;
      const mod = cache[id];
      let path = '';
      if (mod.l) path = mod.l;
      let deps = [];
      if (mod.a && Array.isArray(mod.a)) deps = mod.a.slice();
      modules.push({ id: id, path: path, deps: deps, source: 'runtime' });
    }
  }

  // Webpack 4: __webpack_modules__
  if (typeof __webpack_modules__ !== 'undefined') {
    hasWebpack = true;
    for (let mid in __webpack_modules__) {
      if (!__webpack_modules__.hasOwnProperty(mid)) continue;
      if (!modExists(mid)) modules.push({ id: mid, path: '', deps: [], source: 'runtime' });
    }
  }

  // Webpack 5: webpackChunk* arrays
  for (let key in window) {
    if (key.indexOf('webpackChunk') === 0 && Array.isArray(window[key])) {
      hasWebpack = true;
      const chunk = window[key];
      for (let ci = 0; ci < chunk.length; ci++) {
        const item = chunk[ci];
        if (!item || !Array.isArray(item) || item.length < 2) continue;
        const modObj = item[1];
        if (typeof modObj !== 'object' || modObj === null) continue;
        for (let mId in modObj) {
          if (!modObj.hasOwnProperty(mId)) continue;
          if (!modExists(mId)) modules.push({ id: mId, path: mId, deps: [], source: 'runtime' });
        }
      }
    }
  }

  // Extract webpack chunk URL info
  let chunkInfo = null;
  try {
    let wpRequire = capturedWpRequire;
    if (!wpRequire && typeof __webpack_require__ !== 'undefined') {
      wpRequire = __webpack_require__;
    }
    if (wpRequire && typeof wpRequire.u === 'function') {
      let uBody = wpRequire.u.toString();
      const allChunkIds = [];

      const mapObjs = uBody.match(/\{[^}]{5,}\}/g);
      if (mapObjs) {
        mapObjs.forEach(function (obj) {
          const idPairs = obj.match(/(\d+)\s*:\s*"/g);
          if (idPairs) {
            idPairs.forEach(function (p) {
              let id = p.match(/(\d+)/);
              if (id && allChunkIds.indexOf(id[1]) === -1) allChunkIds.push(id[1]);
            });
          }
        });
      }

      if (allChunkIds.length === 0) {
        const hexPairs = uBody.match(/0x([0-9a-f]+)\s*:/g);
        if (hexPairs) {
          const seenHex = {};
          hexPairs.forEach(function (hp) {
            const hv = hp.match(/0x([0-9a-f]+)/);
            if (hv) {
              let dec = parseInt(hv[1], 16);
              if (dec > 0 && !seenHex[dec]) {
                seenHex[dec] = true;
                allChunkIds.push(String(dec));
              }
            }
          });
        }
      }

      for (let wck2 in window) {
        if (wck2.indexOf('webpackChunk') === 0 && Array.isArray(window[wck2])) {
          const wcArr = window[wck2];
          for (let wci = 0; wci < wcArr.length; wci++) {
            if (wcArr[wci] && Array.isArray(wcArr[wci]) && Array.isArray(wcArr[wci][0])) {
              wcArr[wci][0].forEach(function (cid) {
                const cidStr = String(cid);
                if (allChunkIds.indexOf(cidStr) === -1) allChunkIds.push(cidStr);
              });
            }
          }
        }
      }

      const chunkFilenames = {};
      allChunkIds.forEach(function (id) {
        try {
          const filename = wpRequire.u(id);
          if (filename && filename.length > 0) chunkFilenames[id] = filename;
        } catch (e) {
          console.debug('Phase1 chunk filename error', e);
        }
      });

      if (Object.keys(chunkFilenames).length === 0 && allChunkIds.length > 0) {
        let maxProbe = 0;
        allChunkIds.forEach(function (id) {
          let n = parseInt(id, 10);
          if (n > maxProbe) maxProbe = n;
        });
        const probeLimit = Math.min(maxProbe + 200, 100000);
        for (let pid = 1; pid <= probeLimit; pid++) {
          try {
            const pfn = wpRequire.u(pid);
            if (pfn && typeof pfn === 'string' && pfn.length > 3) {
              if (pfn.indexOf(`${String(pid)}.`) === -1) {
                chunkFilenames[String(pid)] = pfn;
              } else if (pfn !== `${String(pid)}.js`) {
                chunkFilenames[String(pid)] = pfn;
              }
            }
          } catch (e) {
            console.debug('Phase1 probe error', e);
          }
        }
      }

      if (Object.keys(chunkFilenames).length > 0) {
        chunkInfo = { chunkFilenames: chunkFilenames };
      }
    }
  } catch (e) {
    console.debug('Phase1 chunk URL extraction error', e);
  }

  // Strategy 0C: Decode obfuscated .u() via globally-accessible string decoder
  if (!chunkInfo && hasWebpack) {
    (function () {
      try {
        const _scripts = document.querySelectorAll('script[src]');
        const _bundleUrls = [];
        _scripts.forEach(function (s) {
          const _src = s.getAttribute('src') || '';
          if (_src && /\.js(\?|$)/.test(_src) && _src.indexOf('node_modules') === -1)
            _bundleUrls.push(_src);
        });
        let _rtUrl = null;
        for (let _bi = 0; _bi < _bundleUrls.length; _bi++) {
          if (/main|app|index|runtime/i.test(_bundleUrls[_bi])) {
            _rtUrl = _bundleUrls[_bi];
            break;
          }
        }
        if (!_rtUrl) {
          for (let _bi2 = 0; _bi2 < _bundleUrls.length; _bi2++) {
            if (/bundle\/|static\/js/.test(_bundleUrls[_bi2])) {
              _rtUrl = _bundleUrls[_bi2];
              break;
            }
          }
        }
        if (!_rtUrl) return;

        const _xhr = new XMLHttpRequest();
        _xhr.open('GET', _rtUrl, false);
        _xhr.send();
        const _bundleSrc = _xhr.responseText;

        let _uOpenMatch = _bundleSrc.match(/(\w+)\['u'\]\s*=\s*function\s*\(\s*(\w+)\s*\)\s*\{/);
        if (!_uOpenMatch)
          _uOpenMatch = _bundleSrc.match(/(\w+)\.u\s*=\s*function\s*\(\s*(\w+)\s*\)\s*\{/);
        if (!_uOpenMatch) return;

        const _uStart = _uOpenMatch.index + _uOpenMatch[0].length;
        let _bc = 1,
          _uEnd = _uStart;
        while (_uEnd < _bundleSrc.length && _bc > 0) {
          if (_bundleSrc[_uEnd] === '{') _bc++;
          else if (_bundleSrc[_uEnd] === '}') _bc--;
          _uEnd++;
        }
        const _uBody = _bundleSrc.substring(_uStart, _uEnd - 1);

        const _ldMatch = _uBody.match(/var\s+(\w+)\s*=\s*(a\d+_0x\w+)\s*;/);
        let _localVar = _ldMatch ? _ldMatch[1] : null;
        let _globalDecName = _ldMatch ? _ldMatch[2] : null;
        if (
          !_localVar &&
          window[_uOpenMatch[1]] &&
          typeof window[_uOpenMatch[1]] === 'function'
        ) {
          _localVar = _uOpenMatch[1];
          _globalDecName = _uOpenMatch[1];
        }
        if (!_localVar) return;

        const _dec = window[_globalDecName] || window[_localVar];
        if (!_dec || typeof _dec !== 'function') return;

        const _maps = [],
          _mRegex = /\{([^{}]+)\}/g,
          _mCnt = 0;
        let _mMatch;
        while ((_mMatch = _mRegex.exec(_uBody)) !== null && _mCnt < 2) {
          const _hk = _mMatch[1].match(/0x[0-9a-f]+\s*:/g);
          if (_hk && _hk.length >= 3) {
            _maps.push(_mMatch[1]);
            _mCnt++;
          }
        }
        const _outside = _uBody.replace(/\{[^{}]+\}/g, '/*M*/');
        const _oRegex = new RegExp(`${_localVar}\\((0x[0-9a-f]+)\\)`, 'g');
        const _oIdxs = [];
        let _oM;
        while ((_oM = _oRegex.exec(_outside)) !== null) {
          _oIdxs.push(parseInt(_oM[1], 16));
        }
        let _prefix = '',
          _suffix = '';
        try {
          if (_oIdxs.length >= 1) _prefix = _dec(_oIdxs[0]) || '';
        } catch (e) {
          console.debug('Phase1 obfuscated decode prefix error', e);
        }
        try {
          if (_oIdxs.length >= 2) _suffix = _dec(_oIdxs[_oIdxs.length - 1]) || '';
        } catch (e) {
          console.debug('Phase1 obfuscated decode suffix error', e);
        }

        const _decodedChunks = {};
        const _pr = /0x([0-9a-f]+)\s*:\s*\w+\((0x[0-9a-f]+)\)/;
        if (_maps.length >= 2) {
          const _mapR = new RegExp(`0x([0-9a-f]+)\\s*:\\s*${_localVar}\\((0x[0-9a-f]+)\\)`, 'g');
          const _map2 = {};
          let _m2;
          while ((_m2 = _mapR.exec(_maps[1])) !== null) {
            const _pm = _m2[0].match(_pr);
            if (_pm) {
              try {
                _map2[parseInt(_pm[1], 16)] = _dec(parseInt(_pm[2], 16));
              } catch (e) {
                console.debug('Phase1 map2 decode error', e);
              }
            }
          }
          _mapR.lastIndex = 0;
          let _m1;
          while ((_m1 = _mapR.exec(_maps[0])) !== null) {
            const _pm = _m1[0].match(_pr);
            if (_pm) {
              const _cid = parseInt(_pm[1], 16);
              try {
                const _name = _dec(parseInt(_pm[2], 16)),
                  _ext = _map2[_cid] || '';
                if (_name && _ext)
                  _decodedChunks[String(_cid)] = `${_prefix}${_name}.${_ext}${_suffix}`;
              } catch (e) {
                console.debug('Phase1 map1 decode error', e);
              }
            }
          }
        }
        if (Object.keys(_decodedChunks).length === 0 && _maps.length >= 1) {
          const _smR = new RegExp(`0x([0-9a-f]+)\\s*:\\s*${_localVar}\\((0x[0-9a-f]+)\\)`, 'g');
          let _sm;
          while ((_sm = _smR.exec(_maps[0])) !== null) {
            const _pm = _sm[0].match(_pr);
            if (_pm) {
              const _cid = parseInt(_pm[1], 16);
              try {
                const _hash = _dec(parseInt(_pm[2], 16));
                if (_hash) _decodedChunks[String(_cid)] = `${_prefix}${_cid}.${_hash}${_suffix}`;
              } catch (e) {
                console.debug('Phase1 single map decode error', e);
              }
            }
          }
        }
        if (Object.keys(_decodedChunks).length > 0) {
          let _wpPp = '';
          let _ppMatch = _bundleSrc.match(
            new RegExp(`${_uOpenMatch[1]}\\['p']\\s*=\\s*"([^"]*)"`)
          );
          if (!_ppMatch)
            _ppMatch = _bundleSrc.match(new RegExp(`${_uOpenMatch[1]}\\.p\\s*=\\s*"([^"]*)"`));
          if (_ppMatch) _wpPp = _ppMatch[1];
          chunkInfo = { chunkFilenames: _decodedChunks, publicPath: _wpPp };
        }
      } catch (e) {
        console.debug('Phase1 obfuscated .u() decode error', e);
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

      const _origFetch = window.fetch.bind(window);
      window.fetch = function (input) {
        try {
          const url = typeof input === 'string' ? input : input && input.url ? input.url : '';
          if (
            url &&
            /\.js(\?|$)/.test(url) &&
            window.__vulnkitScriptObserver.indexOf(url) === -1
          ) {
            window.__vulnkitScriptObserver.push(url);
          }
        } catch (e) {
          console.debug('Phase1 fetch hook error', e);
        }
        return _origFetch.apply(this, arguments);
      };

      const _origXhrOpen = XMLHttpRequest.prototype.open;
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
          console.debug('Phase1 XHR hook error', e);
        }
        return _origXhrOpen.apply(this, arguments);
      };
    }
  } catch (e) {
    console.debug('Phase1 network hooks install error', e);
  }

  let monitoredScripts = [];
  try {
    if (window.__vulnkitScriptObserver) {
      monitoredScripts = window.__vulnkitScriptObserver.slice();
    }
  } catch (e) {
    console.debug('Phase1 monitored scripts error', e);
  }

  let wpPublicPath = '';
  try {
    const _wpR =
      capturedWpRequire ||
      (typeof __webpack_require__ !== 'undefined' ? __webpack_require__ : null);
    if (_wpR && _wpR.p) wpPublicPath = _wpR.p;
  } catch (e) {
    console.debug('Phase1 public path error', e);
  }

  return {
    modules: modules,
    hasWebpack: hasWebpack,
    chunkInfo: chunkInfo,
    monitoredScripts: monitoredScripts,
    wpPublicPath: wpPublicPath,
  };
};

export { PHASE1_MAIN_WORLD_FN };
