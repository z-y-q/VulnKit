// 灵眸 - Build Tool Detection (MAIN world inject)
(function () {
  'use strict';
  if ((window as any).__vkSourcemapDetectDone) return;
  (window as any).__vkSourcemapDetectDone = true;

  const __vk_token = document.currentScript
    ? (document.currentScript as HTMLScriptElement).dataset.vkToken || ''
    : '';

  const result: {
    tool: string | null;
    version: string | null;
    hints: string[];
    features: string[];
  } = { tool: null, version: null, hints: [], features: [] };

  // Webpack
  const wpKeys: string[] = Object.keys(window).filter(function (k: string) {
    return k.indexOf('webpackChunk') === 0;
  });
  if (wpKeys.length > 0) {
    result.tool = 'webpack';
    result.hints.push(`webpackChunk keys: ${wpKeys.join(', ')}`);
  }
  if (typeof (window as any).__webpack_require__ !== 'undefined') {
    result.tool = 'webpack';
    if ((window as any).__webpack_require__.c) result.hints.push('webpack4 module cache found');
  }

  // Turbopack (Next.js 13+ bundler)
  if (!result.tool) {
    try {
      if ((window as any).__turbopack_load__) {
        result.tool = 'turbopack';
        result.hints.push('__turbopack_load__ global found');
      }
    } catch (e) {
      /* ignore */
    }
    if (!result.tool) {
      const tpScripts = document.querySelectorAll('script[src]');
      tpScripts.forEach(function (s: any) {
        if (/\/_next\/static\/chunks\/[^\s]*turbopack/i.test(s.src) && !result.tool) {
          result.tool = 'turbopack';
          result.hints.push('Turbopack chunk URL pattern');
        }
      });
    }
    if (!result.tool) {
      const tpInline = document.querySelectorAll('script:not([src])');
      tpInline.forEach(function (s: any) {
        if (
          /self\.__turbopack_load__|__turbopack_chunk_load__|TURBOPACK/.test(s.textContent || '') &&
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
  scripts.forEach(function (s: any) {
    if (/\/@vite\/client/.test(s.src)) hasViteClient = true;
  });
  if (hasViteClient || typeof (window as any).__vite_plugin_react_preamble_import__ !== 'undefined') {
    result.tool = 'vite';
    if (hasViteClient) result.hints.push('vite client script found');
    if (typeof (window as any).__vite_plugin_react_preamble_import__ !== 'undefined') {
      result.features.push('react');
    }
  }
  // import.meta checks omitted — cannot reference `import` keyword in classic script context
  if (!result.tool) {
    const allScripts = document.querySelectorAll('script[src]');
    allScripts.forEach(function (s: any) {
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
      if ((window as any).__ROLLUP__) {
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
      inlineScripts.forEach(function (s: any) {
        if (rollupPattern.test(s.textContent || '')) hasRollupPattern = true;
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
    allInline.forEach(function (s: any) {
      if (/\/\*\s*\[esbuild\]/.test(s.textContent || '') && !result.tool) {
        result.tool = 'esbuild';
        result.hints.push('esbuild banner comment');
      }
    });
  }

  // Next.js
  const nextData = (window as any).__NEXT_DATA__;
  if (typeof nextData !== 'undefined') {
    result.hints.push('Next.js detected');
    if (nextData.buildId) result.hints.push(`buildId: ${nextData.buildId}`);
    if (nextData.runtimeConfig) result.features.push('runtime-config');
    const nextScript = document.querySelector('script[id="__NEXT_DATA__"]');
    if (nextScript) {
      let ver: string = nextScript.getAttribute('data-Next-Version') || '';
      try {
        ver = ver || (nextData || {}).runtimeConfig || '';
      } catch (e) {
        /* ignore */
      }
    }
    if (!result.tool && document.querySelector('meta[name="next-version"]')) {
      const nextVer =
        document.querySelector('meta[name="next-version"]')!.getAttribute('content') || '';
      if (nextVer) result.version = nextVer;
    }
    if (document.getElementById('__next') && result.tool === 'turbopack') {
      result.features.push('nextjs-app-router');
    }
  }

  // Nuxt.js
  const nuxtGlobal = (window as any).__NUXT__;
  if (typeof nuxtGlobal !== 'undefined') {
    result.hints.push('Nuxt.js detected');
    if (nuxtGlobal.config) {
      if (nuxtGlobal.config.public) result.features.push('nuxt-public-config');
      if (
        nuxtGlobal.config.app &&
        nuxtGlobal.config.app.baseURL &&
        nuxtGlobal.config.app.baseURL !== '/'
      ) {
        result.hints.push(`nuxt base: ${nuxtGlobal.config.app.baseURL}`);
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
