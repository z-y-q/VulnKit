// 灵眸 - Angular Detection Inject Script
(function () {
  'use strict';
  if (window.__VK_ANGULAR_DETECT_DONE__) return;
  window.__VK_ANGULAR_DETECT_DONE__ = true;

  var result = {
    detected: false,
    version: '',
    variant: '',
    mode: '',
    modules: [],
    routes: [],
    signals: [],
  };

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
  var ngDirectives = document.querySelectorAll(
    '[ng-controller], [ng-model], [ng-repeat], [ng-click], [ng-init]'
  );
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

  // Dev/Prod mode detection
  var isDev = false;
  scripts.forEach(function (s) {
    if (/angular\.development/i.test(s.src) || /zone\.js\/dist\/zone-evergreen\.js/i.test(s.src))
      isDev = true;
  });
  if (typeof ng !== 'undefined' && ng.probe) isDev = true;
  result.mode = isDev ? 'development' : 'production';
  if (isDev) result.signals.push('Development mode detected');

  // AngularJS module extraction
  if (window.angular && window.angular.module) {
    try {
      var injector = angular.element(document).injector();
      if (injector) {
        var loadedMods = [];
        if (typeof injector.modules === 'function') {
          Object.keys(injector.modules()).forEach(function (m) {
            if (m.indexOf('ng') === 0 || m === 'ngLocale') return;
            loadedMods.push(m);
          });
        }
        if (loadedMods.length === 0) {
          try {
            var _ngAppEl = document.querySelector('[ng-app]');
            if (_ngAppEl) {
              var _app = angular.element(_ngAppEl);
              if (_app.injector) {
                var _inj = _app.injector();
                if (_inj && _inj.modules) {
                  Object.keys(_inj.modules()).forEach(function (m) {
                    if (m.indexOf('ng') === 0 || m === 'ngLocale') return;
                    loadedMods.push(m);
                  });
                }
              }
            }
          } catch (e) {}
        }
        result.modules = loadedMods.slice(0, 30);
        if (loadedMods.length > 0) result.signals.push(loadedMods.length + ' modules loaded');
      }
    } catch (e) {}
  }

  // Angular 2+ component extraction from DOM
  if (result.variant === 'Angular') {
    var customElements = document.querySelectorAll('*');
    var componentSet = {};
    customElements.forEach(function (el) {
      var tag = el.tagName.toLowerCase();
      if (tag.indexOf('app-') === 0 || tag.indexOf('ngx-') === 0 || tag.indexOf('mat-') === 0) {
        componentSet[tag] = true;
      }
      if (el.hasAttribute('_ngcontent') || el.hasAttribute('_nghost')) {
        var cls = el.className || '';
        if (typeof cls === 'string') {
          cls.split(/\s+/).forEach(function (c) {
            if (
              c.length > 2 &&
              c.charAt(0) === c.charAt(0).toUpperCase() &&
              componentSet[c] === undefined
            ) {
              componentSet[c] = true;
            }
          });
        }
      }
    });
    result.modules = Object.keys(componentSet).slice(0, 30);
  }

  // Route extraction
  var routeSet = {};
  document.querySelectorAll('a[href^="/"]').forEach(function (a) {
    var href = a.getAttribute('href');
    if (href && href.charAt(0) === '/' && href.length > 1) {
      var cleanPath = href.split('?')[0].split('#')[0];
      if (cleanPath.length > 1 && !routeSet[cleanPath]) {
        routeSet[cleanPath] = true;
      }
    }
  });
  if (document.querySelector('router-outlet, [router-outlet], app-router-outlet')) {
    result.signals.push('Angular Router detected (<router-outlet>)');
  }
  result.routes = Object.keys(routeSet).slice(0, 50);
  window.postMessage({ __vk_angular_detect: true, result: result }, location.origin);
})();
