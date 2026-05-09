// vk-sourcemap-scanner.js -- 灵眸 Chrome Extension
// scanWebpackModules: Phase 2 (ISOLATED) + Phase 2.5 + Phase 3
import { utilsProxy as utils } from './vk-namespace.js';
import { smState } from './vk-sourcemap-state.js';
import {
  smUpdateProgress,
  smBatchFetch,
  smResolveUrl,
  smParseMapToModules,
  smMergeHashMaps,
  smResolveWebpackBase,
  smRegisterChunkUrls,
  smAddDiscoveredChunk,
  setScanState,
} from './vk-sourcemap-utils.js';
import { renderSourcemapModules } from './vk-sourcemap-render.js';
import { PHASE1_MAIN_WORLD_FN } from './vk-sourcemap-phase1.js';

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
  smUpdateProgress(10, 1);
  try {
    const wpData = await utils.execInTabData(ctx.tab.id, PHASE1_MAIN_WORLD_FN);
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
  smUpdateProgress(25, 1);
  try {
    const btResult = await chrome.tabs.sendMessage(ctx.tab.id, { type: 'VK_SOURCEMAP_DETECT' });
    if (btResult && btResult.tool) {
      ctx.buildTool = btResult.tool;
      ctx.buildFeatures = btResult.features || [];
      const toolHints = (btResult.hints || []).join('; ');
      let toolLabel = ctx.buildTool.toUpperCase();
      if (btResult.version) toolLabel += ` v${btResult.version}`;
      if (ctx.buildFeatures.length > 0) toolLabel += ` [${ctx.buildFeatures.join(', ')}]`;
      ctx.statusEl.textContent = toolLabel + (toolHints ? ` (${toolHints})` : '');
    }
  } catch (e) {
    // content script may not be ready, continue
  }
}

// --- Phase 2: ISOLATED world script collection + source map extraction ---
async function runPhase2(ctx) {
  ctx.statusEl.textContent = 'Phase 2: 收集脚本和 Source Map...';
  smUpdateProgress(30, 2);

  // Collect script/preload URLs and inline scripts from ISOLATED world
  try {
    const domData = await utils.execInTabData(
      ctx.tab.id,
      function () {
        const extUrls = [];
        const inlineScripts = [];
        document.querySelectorAll('script[src]').forEach(function (s) {
          extUrls.push(s.src);
        });
        document.querySelectorAll('script:not([src])').forEach(function (s) {
          const text = s.textContent || '';
          if (text.length > 10 && text.length < 500000) inlineScripts.push(text);
        });
        const perfUrls = [];
        try {
          performance.getEntriesByType('resource').forEach(function (e) {
            if (e.name && /\.js(\?|$)/.test(e.name)) {
              perfUrls.push(e.name);
            }
          });
        } catch (ex) {}
        const preloadUrls = [];
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
      const mapRegex = /[/#][@]\s*sourceMappingURL\s*=\s*(\S+)/gi;
      (domData.inlineScripts || []).forEach(function (script) {
        mapRegex.lastIndex = 0;
        let match;
        while ((match = mapRegex.exec(script)) !== null) {
          const url = match[1];
          if (url.indexOf('data:') !== 0) {
            addSourceMapUrl(ctx, smResolveUrl(url, ctx.tab.url));
          }
        }
      });
    }
  } catch (e) {
    // continue
  }

  // Parse script files for source map URLs
  if (ctx.scriptUrls.length > 0 && ctx.sourceMapUrls.length < 5) {
    ctx.statusEl.textContent = `Phase 2: 解析脚本 Source Map URL (${ctx.scriptUrls.length} 个文件)...`;
    const scriptContents = await smBatchFetch(
      ctx.scriptUrls.slice(0, smState.SM_MAX_SCRIPTS_SCAN),
      false,
      ctx.tab.id
    );
    for (let si = 0; si < scriptContents.length; si++) {
      if (!scriptContents[si]) continue;
      const content = scriptContents[si];
      const lastNewline = content.lastIndexOf('\n');
      const tail =
        lastNewline >= 0 ? content.substring(lastNewline) : content.substring(content.length - 200);
      const mapMatch = tail.match(/[/#][@]\s*sourceMappingURL\s*=\s*(\S+)/);
      if (mapMatch && mapMatch[1].indexOf('data:') !== 0) {
        const mapUrl = smResolveUrl(mapMatch[1], ctx.scriptUrls[si]);
        addSourceMapUrl(ctx, mapUrl);
      }
    }
  }

  // Fetch and parse source map files
  if (ctx.sourceMapUrls.length > 0) {
    ctx.statusEl.textContent = `Phase 2: 解析 ${ctx.sourceMapUrls.length} 个 Source Map 文件...`;
    smUpdateProgress(50, 2);
    const mapContents = await smBatchFetch(
      ctx.sourceMapUrls.slice(0, smState.SM_MAX_MAPS_PARSE),
      false,
      ctx.tab.id
    );
    for (let mi = 0; mi < mapContents.length; mi++) {
      if (!mapContents[mi]) continue;
      smParseMapToModules(
        mapContents[mi],
        ctx.sourceMapUrls[mi],
        'sm-',
        ctx.allModules,
        smState.sourcemapSourceCache,
        smState.sourcemapMapCache
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
    smUpdateProgress(40, 2);
    let viteAssetBase = null;
    ctx.scriptUrls.forEach(function (sUrl) {
      let m = sUrl.match(/^(https?:\/\/[^/]+\/.*)\/assets\//);
      if (m && !viteAssetBase) viteAssetBase = `${m[1]}/assets/`;
    });
    if (viteAssetBase) {
      ctx.scriptUrls.forEach(function (sUrl) {
        if (sUrl.indexOf(viteAssetBase) !== 0) return;
        addSourceMapUrl(ctx, `${sUrl}.map`);
      });
    }
  }

  if (ctx.buildTool === 'rollup' && ctx.scriptUrls.length > 0) {
    ctx.statusEl.textContent = 'Phase 2.5: Rollup — 探测 Chunk Source Map...';
    smUpdateProgress(40, 2);
    ctx.scriptUrls.forEach(function (sUrl) {
      addSourceMapUrl(ctx, `${sUrl}.map`);
    });
  }

  if (ctx.buildTool === 'esbuild' && ctx.scriptUrls.length > 0) {
    ctx.statusEl.textContent = 'Phase 2.5: esbuild — 探测 Source Map...';
    smUpdateProgress(40, 2);
    ctx.scriptUrls.forEach(function (sUrl) {
      addSourceMapUrl(ctx, `${sUrl}.map`);
    });
  }

  if (ctx.buildTool === 'turbopack' && ctx.scriptUrls.length > 0) {
    ctx.statusEl.textContent = 'Phase 2.5: Turbopack — 探测 Source Map...';
    smUpdateProgress(40, 2);
    ctx.scriptUrls.forEach(function (sUrl) {
      if (/_next\/static\/chunks\//.test(sUrl) || /_next\/static\/[a-z]+\//.test(sUrl)) {
        addSourceMapUrl(ctx, `${sUrl}.map`);
      }
    });
  }

  if (
    ctx.buildFeatures.indexOf('nuxt-payload') !== -1 ||
    ctx.buildFeatures.indexOf('nuxt-public-config') !== -1
  ) {
    ctx.statusEl.textContent = 'Phase 2.5: Nuxt — 探测 Source Map...';
    smUpdateProgress(40, 2);
    ctx.scriptUrls.forEach(function (sUrl) {
      if (/_nuxt\//.test(sUrl)) {
        addSourceMapUrl(ctx, `${sUrl}.map`);
      }
    });
  }
}

function discoverChunksFromManifest(ctx) {
  if (!ctx.chunkManifest || ctx.scriptUrls.length === 0) return;

  let inferredBase = null;
  for (let si = 0; si < ctx.scriptUrls.length && !inferredBase; si++) {
    const sUrlClean = ctx.scriptUrls[si].split('?')[0];
    const sBare = sUrlClean.substring(sUrlClean.lastIndexOf('/') + 1);
    for (let cid in ctx.chunkManifest) {
      if (inferredBase) break;
      const cFname = ctx.chunkManifest[cid];
      if (!cFname) continue;
      const cBare = cFname.substring(cFname.lastIndexOf('/') + 1);
      if (cBare === sBare) {
        inferredBase = sUrlClean.substring(0, sUrlClean.length - cFname.length);
      }
    }
  }
  const baseUrl = inferredBase
    ? inferredBase
    : ctx.wpPublicPath
      ? smResolveUrl(ctx.wpPublicPath, ctx.tab.url)
      : ctx.tab.url.substring(0, ctx.tab.url.lastIndexOf('/') + 1);
  Object.keys(ctx.chunkManifest).forEach(function (chunkId) {
    const filename = ctx.chunkManifest[chunkId];
    if (!filename) return;
    const fullUrl = smResolveUrl(filename, baseUrl);
    ctx.discoveredChunkUrls.push({ chunkId: chunkId, url: fullUrl });
  });
}

async function discoverChunksDeepParse(ctx) {
  if (ctx.discoveredChunkUrls.length > 0 || ctx.scriptUrls.length === 0) return;

  ctx.statusEl.textContent = 'Phase 2.5: 深度解析 Bundle 源码发现 Chunk...';
  smUpdateProgress(40, 2);

  const runtimeUrl =
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

  const runtimeContent = await smBatchFetch([runtimeUrl], false, ctx.tab.id);
  if (!runtimeContent[0]) return;

  let rc = runtimeContent[0];
  const rcBase = runtimeUrl.substring(0, runtimeUrl.lastIndexOf('/') + 1);

  // Try extracting chunk ID → hash mappings from webpack require.u
  let uFuncMatch = rc.match(
    /(__webpack_require__\s*\.\s*u\s*=\s*function\s*\([^)]*\)\s*\{[^}]*return[^}]*\})/
  );
  if (!uFuncMatch) {
    uFuncMatch = rc.match(
      /(\w+)\s*=\s*function\((\w+)\)\s*\{[^}]{10,200}?return[^}]*?\{[^}]{5,}\}[^}]*?\2[^}]*?\}/
    );
  }
  if (uFuncMatch) {
    try {
      const mappingObj = uFuncMatch[1].match(/\{[^{}]+\}/g);
      if (mappingObj) {
        const chunkIdToHash = smMergeHashMaps(mappingObj, /(\d+)\s*:\s*"([a-f0-9]{4,})"/g);
        const baseInfo1 = smResolveWebpackBase(rc, rcBase, ctx.tab.url);
        smRegisterChunkUrls(chunkIdToHash, baseInfo1, ctx.discoveredChunkUrls, ctx.scriptUrls);
      }
    } catch (e) {
      /* ignore */
    }
  }

  // Fallback: look for hash maps in entire bundle
  if (ctx.discoveredChunkUrls.length === 0) {
    const hashMaps = rc.match(/\{[^\{\}]{10,}?"?\d+"?\s*:\s*"[a-f0-9]{4,}"[^\{\}]*?\}/g);
    if (hashMaps) {
      const tempChunkMap = smMergeHashMaps(hashMaps, /"?(\d+)"?\s*:\s*"([a-f0-9]{4,})"/g);
      if (Object.keys(tempChunkMap).length > 2) {
        const baseInfo2 = smResolveWebpackBase(rc, rcBase, ctx.tab.url);
        smRegisterChunkUrls(tempChunkMap, baseInfo2, ctx.discoveredChunkUrls, ctx.scriptUrls);
      }
    }
  }

  // Look for direct chunk filename references
  const chunkNameRefs = rc.match(/["']([\w.-]+\.[a-f0-9]{6,}\.js)["']/g);
  if (chunkNameRefs) {
    chunkNameRefs.forEach(function (ref) {
      const nameMatch = ref.match(/["']([\w.-]+\.[a-f0-9]{6,}\.js)["']/);
      if (nameMatch) {
        smAddDiscoveredChunk(rcBase + nameMatch[1], 'ref', ctx.discoveredChunkUrls, ctx.scriptUrls);
      }
    });
  }

  // Fallback: parse other bundle files for dynamic imports and .e() calls
  if (ctx.discoveredChunkUrls.length === 0) {
    const otherBundles = ctx.scriptUrls.filter(function (u) {
      return u !== runtimeUrl && (/(vendor|main|app|index)/i.test(u) || /bundle\//.test(u));
    });
    if (otherBundles.length > 0) {
      const bundleContents = await smBatchFetch(
        otherBundles.slice(0, smState.SM_MAX_OTHER_BUNDLES),
        false,
        ctx.tab.id
      );
      for (let bi = 0; bi < bundleContents.length; bi++) {
        if (!bundleContents[bi]) continue;
        const dynamicImports = bundleContents[bi].match(/["']\.\/([\w.-]+\.[a-f0-9]{6,}\.js)["']/g);
        if (dynamicImports) {
          dynamicImports.forEach(function (imp) {
            const nameMatch = imp.match(/["']\.\/([\w.-]+\.[a-f0-9]{6,}\.js)["']/);
            if (nameMatch) {
              const bundleBase = otherBundles[bi].substring(
                0,
                otherBundles[bi].lastIndexOf('/') + 1
              );
              const fullImp = bundleBase + nameMatch[1];
              smAddDiscoveredChunk(fullImp, 'import', ctx.discoveredChunkUrls, ctx.scriptUrls);
            }
          });
        }
        const chunkERefs = bundleContents[bi].match(/\.e\s*\(\s*(\d+)\s*\)/g);
        if (chunkERefs) {
          chunkERefs.forEach(function (ref) {
            const idMatch = ref.match(/\.e\s*\(\s*(\d+)\s*\)/);
            if (idMatch) {
              const hasEid = ctx.discoveredChunkUrls.some(function (cu) {
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

  ctx.statusEl.textContent = `Phase 2.5: Manifest 发现 ${ctx.discoveredChunkUrls.length} 个 Chunk，探测中...`;
  const seenChunkUrls = {};
  const chunkFetchUrls = [];

  ctx.discoveredChunkUrls.forEach(function (cu) {
    const url = cu.url;
    if (!url) return;
    if (ctx.scriptUrls.indexOf(url) !== -1) return;
    if (seenChunkUrls[url]) return;
    seenChunkUrls[url] = true;
    chunkFetchUrls.push(url);
  });

  ctx.scriptUrls.forEach(function (sUrl) {
    const sBase = sUrl.substring(0, sUrl.lastIndexOf('/') + 1);
    let sName = sUrl.substring(sUrl.lastIndexOf('/') + 1);
    const guessMap = smResolveUrl(`${sName}.map`, sBase);
    addSourceMapUrl(ctx, guessMap);
  });

  chunkFetchUrls.forEach(function (cUrl) {
    if (ctx.scriptUrls.indexOf(cUrl) === -1) addScriptUrl(ctx, cUrl);
  });

  const chunkSamples = await smBatchFetch(
    chunkFetchUrls.slice(0, smState.SM_MAX_CHUNK_SAMPLES),
    true,
    ctx.tab.id
  );
  const newSourceMapUrls = [];
  for (let ci = 0; ci < chunkSamples.length; ci++) {
    if (!chunkSamples[ci]) continue;
    const chunkContent = chunkSamples[ci];
    const chunkMapMatch = chunkContent.match(/[/#][@]\s*sourceMappingURL\s*=\s*(\S+)/);
    if (chunkMapMatch && chunkMapMatch[1].indexOf('data:') !== 0) {
      const cmUrl = smResolveUrl(chunkMapMatch[1], chunkFetchUrls[ci]);
      if (ctx.sourceMapUrls.indexOf(cmUrl) === -1) newSourceMapUrls.push(cmUrl);
    }
    const chunkMapGuess = `${chunkFetchUrls[ci]}.map`;
    if (ctx.sourceMapUrls.indexOf(chunkMapGuess) === -1) newSourceMapUrls.push(chunkMapGuess);
  }

  const allNewMaps = newSourceMapUrls.slice(0, smState.SM_MAX_CHUNK_SAMPLES);
  if (allNewMaps.length > 0) {
    ctx.statusEl.textContent = `Phase 2.5: 解析 ${allNewMaps.length} 个新 Source Map...`;
    const newMapContents = await smBatchFetch(allNewMaps, false, ctx.tab.id);
    for (let nmi = 0; nmi < newMapContents.length; nmi++) {
      if (!newMapContents[nmi]) continue;
      const nmUrl = allNewMaps[nmi];
      if (smState.sourcemapMapCache[nmUrl]) continue;
      smParseMapToModules(
        newMapContents[nmi],
        nmUrl,
        'sm2-',
        ctx.allModules,
        smState.sourcemapSourceCache,
        smState.sourcemapMapCache
      );
    }
  }
}

// --- Phase 3: Fallback JS path parsing ---
async function runPhase3(ctx) {
  if (ctx.allModules.length > 0 || ctx.scriptUrls.length === 0) return;

  ctx.statusEl.textContent = `Phase 3: 解析 JS 文件中的模块路径...${ctx.buildTool ? ` (${ctx.buildTool})` : ''}`;
  smUpdateProgress(70, 3);
  const jsContents = await smBatchFetch(
    ctx.scriptUrls.slice(0, smState.SM_MAX_JS_FALLBACK),
    false,
    ctx.tab.id
  );
  for (let ji = 0; ji < jsContents.length; ji++) {
    if (!jsContents[ji]) continue;
    const jsText = jsContents[ji];
    let pathRegex;
    if (ctx.buildTool === 'vite') {
      pathRegex =
        /(?:\/[a-zA-Z_][\w.-]*(?:\/[a-zA-Z_][\w.-]*)*)(?:\.vue|\.jsx|\.tsx|\.ts|\.js|\.css|\.scss)/g;
    } else if (ctx.buildTool === 'rollup' || ctx.buildTool === 'esbuild') {
      pathRegex = /(?:\/src\/[^\s"'`]+)(?:\.vue|\.jsx|\.tsx|\.ts|\.js|\.css)/g;
    } else if (ctx.buildTool === 'turbopack') {
      pathRegex =
        /(?:\.\/[^\s"'`]+)(?:\.(?:tsx|ts|jsx|js|css|module\.css))|turbopack:\/\/[^\s"']+/g;
    } else {
      pathRegex = /webpack:\/\/[^\s"']+|\.[\/]?[a-zA-Z_][\w.\/-]*(?:\.vue|\.js|\.ts|\.jsx|\.tsx)/g;
    }
    let pathMatch;
    const seen = {};
    while ((pathMatch = pathRegex.exec(jsText)) !== null) {
      let p = ctx.buildTool ? pathMatch[0] : pathMatch[0].replace('webpack://', '');
      if (seen[p]) continue;
      seen[p] = true;
      ctx.allModules.push({
        id: `ch-${Object.keys(seen).length}`,
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
  for (let di = 0; di < ctx.allModules.length; di++) {
    ctx.allModules[di].reverseDeps = [];
  }
  for (let di2 = 0; di2 < ctx.allModules.length; di2++) {
    const modDeps = ctx.allModules[di2].deps || [];
    for (let dd = 0; dd < modDeps.length; dd++) {
      const depId = String(modDeps[dd]);
      for (let dr = 0; dr < ctx.allModules.length; dr++) {
        if (ctx.allModules[dr].id === depId) {
          ctx.allModules[dr].reverseDeps.push(ctx.allModules[di2].id);
          break;
        }
      }
    }
  }

  // Add script URLs as chunk entries
  const seenScriptUrls = {};
  for (let si = 0; si < ctx.scriptUrls.length; si++) {
    const scriptPath = ctx.scriptUrls[si];
    if (seenScriptUrls[scriptPath]) continue;
    seenScriptUrls[scriptPath] = true;
    let scriptPathExists = false;
    for (let sp = 0; sp < ctx.allModules.length; sp++) {
      if (ctx.allModules[sp].path === scriptPath) {
        scriptPathExists = true;
        break;
      }
    }
    if (!scriptPathExists) {
      ctx.allModules.push({
        id: `script-${si}`,
        path: scriptPath,
        deps: [],
        source: 'chunk',
      });
    }
  }

  // Deduplicate by path
  const seenPaths = {};
  const deduped = [];
  for (let ui = 0; ui < ctx.allModules.length; ui++) {
    let m = ctx.allModules[ui];
    if (!m.path) continue;
    if (m.source === 'runtime' && /^\d+$/.test(m.path)) continue;
    const baseKey = m.path.split('?')[0];
    if (seenPaths[baseKey]) continue;
    seenPaths[baseKey] = true;
    deduped.push(m);
  }

  smState.sourcemapModules = deduped.slice(0, smState.SM_MAX_MODULES);
  let toolLabel = ctx.buildTool ? `[${ctx.buildTool.toUpperCase()}] ` : '';
  ctx.statusEl.textContent = `${toolLabel}找到 ${smState.sourcemapModules.length} 个模块`;
  smUpdateProgress(100, 3);
  renderSourcemapModules();

  // Check if network hooks are active and show hint
  try {
    if (
      await utils.execInTabData(ctx.tab.id, function () {
        return !!window.__vulnkitHookActive;
      })
    ) {
      const hookHint = document.createElement('div');
      hookHint.className = 'sm-hook-hint';
      hookHint.textContent = 'JS Hook 已激活 -- 浏览其他页面可自动捕获新 Chunk，再次扫描即可合并';
      const statusArea = document.getElementById('sourcemap-status');
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
  if (smState.smAbortFlag === false && document.querySelector('#sourcemap-scan-btn.scanning')) {
    smState.smAbortFlag = true;
    return;
  }

  const statusEl = utils.get('sourcemap-status');
  const resultsEl = utils.get('sourcemap-results');
  if (!statusEl) return;

  smState.sourcemapModules = [];
  smState.sourcemapSourceCache = {};
  smState.sourcemapMapCache = {};
  smState.sourcemapTabId = null;
  smState.smAbortFlag = false;
  setScanState(true);
  if (resultsEl) resultsEl.innerHTML = '';

  const progressEl = utils.get('sm-progress');
  const phasesEl = utils.get('sm-phases');
  if (progressEl) progressEl.classList.remove('hidden');
  if (phasesEl) phasesEl.classList.remove('hidden');
  smUpdateProgress(0, 1);

  try {
    const tab = await utils.requireTabId();
    if (!tab || !tab.url || tab.url.startsWith('chrome')) {
      statusEl.textContent = '无法扫描此页面';
      setScanState(false);
      smState.sourcemapTabId = null;
      return;
    }

    smState.sourcemapTabId = tab.id;
    const ctx = createScanContext(tab, statusEl);

    await runPhase1(ctx);
    if (smState.smAbortFlag) {
      statusEl.textContent = '扫描已取消';
      return;
    }

    await detectBuildTool(ctx);
    if (smState.smAbortFlag) {
      statusEl.textContent = '扫描已取消';
      return;
    }

    await runPhase2(ctx);
    if (smState.smAbortFlag) {
      statusEl.textContent = '扫描已取消';
      return;
    }

    await runPhase25(ctx);
    if (smState.smAbortFlag) {
      statusEl.textContent = '扫描已取消';
      return;
    }

    await runPhase3(ctx);
    await finalizeResults(ctx);
  } catch (err) {
    statusEl.textContent = `扫描失败: ${err.message || '未知错误'}`;
  } finally {
    setScanState(false);
    if (smState.smAbortFlag && smState.sourcemapModules.length > 0) {
      renderSourcemapModules();
    }
    setTimeout(function () {
      const progressEl = utils.get('sm-progress');
      const phasesEl = utils.get('sm-phases');
      if (progressEl) progressEl.classList.add('hidden');
      if (phasesEl) phasesEl.classList.add('hidden');
    }, 800);
  }
}

export { scanWebpackModules };
