// 灵眸 - React Detection Inject Script
(function () {
  'use strict';
  if (window.__VK_REACT_DETECT_DONE__) return;
  window.__VK_REACT_DETECT_DONE__ = true;

  var result = { detected: false, version: '', metaframework: '', signals: [] };

  // React DevTools hook
  if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
    result.detected = true;
    result.signals.push('React DevTools Global Hook');
    var renderers = window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers;
    if (renderers) {
      var versions = [];
      renderers.forEach(function (r, id) {
        if (r && r.version) versions.push(r.version);
      });
      if (versions.length > 0) result.version = versions.join(', ');
    }
  }

  // React Fiber on root element
  var rootEl = document.getElementById('root') || document.getElementById('app') || document.getElementById('__next');
  if (rootEl) {
    var fiberKey = Object.keys(rootEl).find(function (k) { return k.startsWith('__reactFiber$') || k.startsWith('__reactInternalInstance$'); });
    if (fiberKey) {
      result.detected = true;
      result.signals.push('React Fiber (' + fiberKey + ')');
    }
    var propsKey = Object.keys(rootEl).find(function (k) { return k.startsWith('__reactProps$'); });
    if (propsKey) {
      result.detected = true;
      result.signals.push('React Props');
    }
  }

  // Legacy React attributes
  if (document.querySelector('[data-reactroot]')) {
    result.detected = true;
    result.signals.push('data-reactroot attribute');
  }
  if (document.querySelector('[data-reactid]')) {
    result.detected = true;
    result.signals.push('data-reactid attribute (React < 16)');
  }

  // Next.js
  if (window.__NEXT_DATA__) {
    result.metaframework = 'Next.js';
    result.detected = true;
    result.signals.push('__NEXT_DATA__');
    if (window.__NEXT_DATA__.buildId) result.signals.push('Next.js Build: ' + window.__NEXT_DATA__.buildId);
    if (window.__NEXT_DATA__.runtimeConfig) result.signals.push('Next.js Runtime Config');
  }
  if (document.querySelector('#__next')) {
    result.metaframework = result.metaframework || 'Next.js';
    result.detected = true;
    result.signals.push('#__next root element');
  }
  if (document.querySelector('[data-nextjs-route-announcer]')) {
    result.metaframework = result.metaframework || 'Next.js';
    result.detected = true;
    result.signals.push('data-nextjs-route-announcer');
  }

  // React Router
  var scripts = Array.from(document.querySelectorAll('script[src]'));
  var hasReactRouter = scripts.some(function (s) { return /react-router/i.test(s.src); });
  if (hasReactRouter) {
    result.signals.push('React Router detected');
  }

  // ReactDOM from script tags
  scripts.forEach(function (s) {
    if (/react-dom/i.test(s.src) && /(\d+\.\d+\.\d+)/.test(s.src)) {
      var m = s.src.match(/(\d+\.\d+\.\d+)/);
      if (m && !result.version) result.version = m[1];
    }
    if (/react\.production/i.test(s.src) || /react\.development/i.test(s.src)) {
      if (!result.version) {
        var m2 = s.src.match(/(\d+\.\d+\.\d+)/);
        if (m2) result.version = m2[1];
      }
    }
  });

  // Check for React in bundle (global)
  if (typeof React !== 'undefined' && React.version) {
    result.detected = true;
    if (!result.version) result.version = React.version;
    result.signals.push('Global React object v' + React.version);
  }
  if (typeof ReactDOM !== 'undefined' && ReactDOM.version) {
    result.detected = true;
    if (!result.version) result.version = ReactDOM.version;
  }

  window.postMessage({ __vk_react_detect: true, result: result }, location.origin);
})();
