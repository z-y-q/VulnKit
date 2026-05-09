// 灵眸 - Build Tool Detection (MAIN world inject)
(function () {
  'use strict';
  if (window.__vkSourcemapDetectDone) return;
  window.__vkSourcemapDetectDone = true;

  const __vk_token = document.currentScript ? document.currentScript.dataset.vkToken || '' : '';

  const result = { tool: null, version: null, hints: [], features: [] };

  // Webpack
  const wpKeys = Object.keys(window).filter(function (k) {
    return k.indexOf('webpackChunk') === 0;
  });
  if (wpKeys.length > 0) {
    result.tool = 'webpack';
    result.hints.push(`webpackChunk keys: ${wpKeys.join(', ')}`);
  }
  if (typeof __webpack_require__ !== 'undefined') {
    result.tool = 'webpack';
    if (__webpack_require__.c) result.hints.push('webpack4 module cache found');
  }

  // Turbopack (Next.js 13+ bundler)
  if (!result.tool) {
    try {
      if (window.__turbopack_load__) {
        result.tool = 'turbopack';
        result.hints.push('__turbopack_load__ global found');
      }
    } catch (e) {
      /* ignore */
    }
    if (!result.tool) {
      const tpScripts = document.querySelectorAll('script[src]');
      tpScripts.forEach(function (s) {
        if (/\/_next\/static\/chunks\/[^\s]*turbopack/i.test(s.src) && !result.tool) {
          result.tool = 'turbopack';
          result.hints.push('Turbopack chunk URL pattern');
        }
      });
    }
    if (!result.tool) {
      const tpInline = document.querySelectorAll('script:not([src])');
      tpInline.forEach(function (s) {
        if (
          /self\.__turbopack_load__|__turbopack_chunk_load__|TURBOPACK/.test(s.textContent) &&
          !result.tool
        ) {
          result.tool = 'turbopack';
          result.hints.push('Turbopack runtime in inline script');
        }
      });
    }
  }

  // Vite
  const scripts = document.querySelectorAll('script[type="module"]');
  let hasViteClient = false;
  scripts.forEach(function (s) {
    if (/\/@vite\/client/.test(s.src)) hasViteClient = true;
  });
  if (hasViteClient || typeof __vite_plugin_react_preamble_import__ !== 'undefined') {
    result.tool = 'vite';
    if (hasViteClient) result.hints.push('vite client script found');
    if (typeof __vite_plugin_react_preamble_import__ !== 'undefined') {
      result.features.push('react');
    }
  }
  // import.meta checks omitted — cannot reference `import` keyword in classic script context
  if (!result.tool) {
    const allScripts = document.querySelectorAll('script[src]');
    allScripts.forEach(function (s) {
      if (/\/assets\/[a-zA-Z0-9_.-]+\.[a-zA-Z0-9]{8}\.js/.test(s.src) && !result.tool) {
        const viteMeta = document.querySelector('meta[name="vite-env-id"]');
        if (viteMeta) {
          result.tool = 'vite';
          result.hints.push('vite-env-id meta tag');
        }
      }
    });
  }
  // import.meta.env checks omitted — cannot reference `import` in classic script context

  // Rollup
  if (!result.tool) {
    try {
      if (window.__ROLLUP__) {
        result.tool = 'rollup';
        result.hints.push('__ROLLUP__ global found');
      }
    } catch (e) {
      /* ignore */
    }
    if (!result.tool) {
      const inlineScripts = document.querySelectorAll('script:not([src])');
      const rollupPattern = /Object\.defineProperty\(exports,\s*"__esModule"/;
      let hasRollupPattern = false;
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
    const allInline = document.querySelectorAll('script:not([src])');
    allInline.forEach(function (s) {
      if (/\/\*\s*\[esbuild\]/.test(s.textContent) && !result.tool) {
        result.tool = 'esbuild';
        result.hints.push('esbuild banner comment');
      }
    });
  }

  // Next.js
  if (typeof __NEXT_DATA__ !== 'undefined') {
    result.hints.push('Next.js detected');
    if (__NEXT_DATA__.buildId) result.hints.push(`buildId: ${__NEXT_DATA__.buildId}`);
    if (__NEXT_DATA__.runtimeConfig) result.features.push('runtime-config');
    const nextScript = document.querySelector('script[id="__NEXT_DATA__"]');
    if (nextScript) {
      let ver = nextScript.getAttribute('data-Next-Version') || '';
      try {
        ver = ver || (window.__NEXT_DATA__ || {}).runtimeConfig || '';
      } catch (e) {
        /* ignore */
      }
    }
    if (!result.tool && document.querySelector('meta[name="next-version"]')) {
      const nextVer =
        document.querySelector('meta[name="next-version"]').getAttribute('content') || '';
      if (nextVer) result.version = nextVer;
    }
    if (document.getElementById('__next') && result.tool === 'turbopack') {
      result.features.push('nextjs-app-router');
    }
  }

  // Nuxt.js
  if (typeof __NUXT__ !== 'undefined') {
    result.hints.push('Nuxt.js detected');
    if (__NUXT__.config) {
      if (__NUXT__.config.public) result.features.push('nuxt-public-config');
      if (
        __NUXT__.config.app &&
        __NUXT__.config.app.baseURL &&
        __NUXT__.config.app.baseURL !== '/'
      ) {
        result.hints.push(`nuxt base: ${__NUXT__.config.app.baseURL}`);
      }
    }
    try {
      const nuxtEl =
        document.getElementById('__NUXT_DATA__') ||
        document.querySelector('script[id="__NUXT_DATA__"]');
      if (nuxtEl) result.features.push('nuxt-payload');
    } catch (e) {
      /* ignore */
    }
  }

  // Generic build hints (even if tool is unknown)
  const moduleScripts = document.querySelectorAll('script[type="module"]');
  if (moduleScripts.length > 0 && !result.tool) {
    result.hints.push(`module scripts: ${moduleScripts.length}`);
  }

  window.postMessage(
    { __vk_sourcemap_detect: true, __vk_token: __vk_token, result: result },
    window.location.origin
  );
})();
