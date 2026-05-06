// 灵眸 - Build Tool Detection (MAIN world inject)
(function () {
  'use strict';
  if (window.__vkSourcemapDetectDone) return;
  window.__vkSourcemapDetectDone = true;

  var result = { tool: null, version: null, hints: [] };

  // Webpack
  var wpKeys = Object.keys(window).filter(function (k) {
    return k.indexOf('webpackChunk') === 0;
  });
  if (wpKeys.length > 0) {
    result.tool = 'webpack';
    result.hints.push('webpackChunk keys: ' + wpKeys.join(', '));
  }
  if (typeof __webpack_require__ !== 'undefined') {
    result.tool = 'webpack';
    if (__webpack_require__.c) result.hints.push('webpack4 module cache found');
  }

  // Vite
  var scripts = document.querySelectorAll('script[type="module"]');
  var hasViteClient = false;
  scripts.forEach(function (s) {
    if (/\/@vite\/client/.test(s.src)) hasViteClient = true;
  });
  if (hasViteClient || typeof __vite_plugin_react_preamble_import__ !== 'undefined') {
    result.tool = 'vite';
    if (hasViteClient) result.hints.push('vite client script found');
  }
  // Vite env var detection
  if (!result.tool) {
    var allScripts = document.querySelectorAll('script[src]');
    allScripts.forEach(function (s) {
      if (/\/assets\/[a-zA-Z0-9_.-]+\.[a-zA-Z0-9]{8}\.js/.test(s.src) && !result.tool) {
        // Check for Vite-specific meta tag
        var viteMeta = document.querySelector('meta[name="vite-env-id"]');
        if (viteMeta) {
          result.tool = 'vite';
          result.hints.push('vite-env-id meta tag');
        }
      }
    });
  }

  // Rollup
  if (!result.tool) {
    try {
      if (window.__ROLLUP__) {
        result.tool = 'rollup';
        result.hints.push('__ROLLUP__ global found');
      }
    } catch (e) {}
    // Rollup produces modules with specific patterns
    if (!result.tool) {
      var inlineScripts = document.querySelectorAll('script:not([src])');
      var rollupPattern = /Object\.defineProperty\(exports,\s*"__esModule"/;
      var hasRollupPattern = false;
      inlineScripts.forEach(function (s) {
        if (rollupPattern.test(s.textContent)) hasRollupPattern = true;
      });
      if (hasRollupPattern) {
        result.tool = 'rollup';
        result.hints.push('Rollup __esModule pattern in inline script');
      }
    }
  }

  // esbuild
  if (!result.tool) {
    var allInline = document.querySelectorAll('script:not([src])');
    allInline.forEach(function (s) {
      if (/\/\*\s*\[esbuild\]/.test(s.textContent) && !result.tool) {
        result.tool = 'esbuild';
        result.hints.push('esbuild banner comment');
      }
    });
  }

  // Generic build hints (even if tool is unknown)
  var moduleScripts = document.querySelectorAll('script[type="module"]');
  if (moduleScripts.length > 0 && !result.tool) {
    result.hints.push('module scripts: ' + moduleScripts.length);
  }
  if (typeof __NEXT_DATA__ !== 'undefined') {
    result.hints.push('Next.js detected');
  }
  if (typeof __NUXT__ !== 'undefined') {
    result.hints.push('Nuxt.js detected');
  }

  window.postMessage(
    { __vk_sourcemap_detect: true, result: result },
    window.location.origin
  );
})();
