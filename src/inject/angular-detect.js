// 灵眸 - Angular Detection Inject Script
(function () {
  'use strict';
  if (window.__VK_ANGULAR_DETECT_DONE__) return;
  window.__VK_ANGULAR_DETECT_DONE__ = true;

  var result = { detected: false, version: '', variant: '', signals: [] };

  // Angular 2+ (ng-version attribute)
  var ngApp = document.querySelector('[ng-version]');
  if (ngApp) {
    result.detected = true;
    result.version = ngApp.getAttribute('ng-version');
    result.variant = 'Angular';
    result.signals.push('ng-version="' + result.version + '"');
  }

  // Angular Material
  if (document.querySelector('[class*="mat-"], [class*="ng-"]')) {
    result.signals.push('Angular component classes detected');
  }

  // AngularJS 1.x
  if (window.angular) {
    result.detected = true;
    result.variant = result.variant || 'AngularJS';
    if (angular.version && angular.version.full) {
      result.version = angular.version.full;
      result.signals.push('window.angular v' + result.version);
    } else {
      result.signals.push('window.angular (version unknown)');
    }
  }

  // ng-app directive (AngularJS)
  var ngAppEl = document.querySelector('[ng-app], .ng-app');
  if (ngAppEl) {
    result.detected = true;
    result.variant = result.variant || 'AngularJS';
    var appName = ngAppEl.getAttribute('ng-app') || '';
    result.signals.push('ng-app directive' + (appName ? '="' + appName + '"' : ''));
  }

  // ng-controller, ng-model, ng-repeat
  var ngDirectives = document.querySelectorAll('[ng-controller], [ng-model], [ng-repeat], [ng-click], [ng-init]');
  if (ngDirectives.length > 0) {
    result.detected = true;
    result.variant = result.variant || 'AngularJS';
    result.signals.push('ng directives found (' + ngDirectives.length + ' elements)');
  }

  // Angular 2+ zone.js
  if (window.Zone && Zone.__load_patch) {
    result.detected = true;
    result.variant = result.variant || 'Angular';
    result.signals.push('Zone.js detected');
  }

  // Angular router base href
  var baseHref = document.querySelector('base[href][app-base-href]');
  if (baseHref) {
    result.detected = true;
    result.variant = result.variant || 'Angular';
    result.signals.push('app-base-href="' + baseHref.getAttribute('href') + '"');
  }

  // Angular CLI / Webpack marker
  var scripts = Array.from(document.querySelectorAll('script[src]'));
  scripts.forEach(function (s) {
    if (/angular/i.test(s.src)) {
      result.detected = true;
      result.signals.push('Angular script: ' + s.src.split('/').pop());
    }
    if (/zone\.js/i.test(s.src)) {
      result.signals.push('zone.js loaded');
    }
  });

  // Angular specific meta tags or comments
  var metas = document.querySelectorAll('meta[name]');
  metas.forEach(function (m) {
    if (m.getAttribute('name') === 'ng-version') {
      result.detected = true;
      result.variant = result.variant || 'Angular';
      if (m.getAttribute('content') && !result.version) {
        result.version = m.getAttribute('content');
      }
    }
  });

  window.postMessage({ __vk_angular_detect: true, result: result }, location.origin);
})();
