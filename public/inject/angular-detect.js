"use strict";
// 灵眸 - Angular Detection Inject Script
(function () {
    'use strict';
    // 检测为只读操作，不做一次性守卫：守卫会让二次注入早退、不回执，
    // bridge 端等到超时返回 null，面板误报「无法连接内容脚本」。
    const __vk_token = document.currentScript
        ? document.currentScript.dataset.vkToken || ''
        : '';
    const result = {
        detected: false,
        version: '',
        variant: '',
        mode: '',
        modules: [],
        routes: [],
        signals: [],
    };
    // Angular 2+ (ng-version attribute)
    const ngApp = document.querySelector('[ng-version]');
    if (ngApp) {
        result.detected = true;
        result.version = ngApp.getAttribute('ng-version') || '';
        result.variant = 'Angular';
        result.signals.push(`ng-version="${result.version}"`);
    }
    // Angular Material
    if (document.querySelector('[class*="mat-"], [class*="ng-"]')) {
        result.signals.push('Angular component classes detected');
    }
    // AngularJS 1.x
    const angularGlobal = window.angular;
    if (angularGlobal) {
        result.detected = true;
        result.variant = result.variant || 'AngularJS';
        if (angularGlobal.version && angularGlobal.version.full) {
            result.version = angularGlobal.version.full;
            result.signals.push(`window.angular v${result.version}`);
        }
        else {
            result.signals.push('window.angular (version unknown)');
        }
    }
    // ng-app directive (AngularJS)
    const ngAppEl = document.querySelector('[ng-app], .ng-app');
    if (ngAppEl) {
        result.detected = true;
        result.variant = result.variant || 'AngularJS';
        const appName = ngAppEl.getAttribute('ng-app') || '';
        result.signals.push(`ng-app directive${appName ? `="${appName}"` : ''}`);
    }
    // ng-controller, ng-model, ng-repeat
    const ngDirectives = document.querySelectorAll('[ng-controller], [ng-model], [ng-repeat], [ng-click], [ng-init]');
    if (ngDirectives.length > 0) {
        result.detected = true;
        result.variant = result.variant || 'AngularJS';
        result.signals.push(`ng directives found (${ngDirectives.length} elements)`);
    }
    // Angular 2+ zone.js
    const ZoneGlobal = window.Zone;
    if (ZoneGlobal && ZoneGlobal.__load_patch) {
        result.detected = true;
        result.variant = result.variant || 'Angular';
        result.signals.push('Zone.js detected');
    }
    // Angular router base href
    const baseHref = document.querySelector('base[href][app-base-href]');
    if (baseHref) {
        result.detected = true;
        result.variant = result.variant || 'Angular';
        result.signals.push(`app-base-href="${baseHref.getAttribute('href')}"`);
    }
    // Angular CLI / Webpack marker
    const scripts = Array.from(document.querySelectorAll('script[src]'));
    scripts.forEach(function (s) {
        if (/angular/i.test(s.src)) {
            result.detected = true;
            result.signals.push(`Angular script: ${s.src.split('/').pop()}`);
        }
        if (/zone\.js/i.test(s.src)) {
            result.signals.push('zone.js loaded');
        }
    });
    // Angular specific meta tags or comments
    const metas = document.querySelectorAll('meta[name]');
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
    let isDev = false;
    scripts.forEach(function (s) {
        if (/angular\.development/i.test(s.src) || /zone\.js\/dist\/zone-evergreen\.js/i.test(s.src))
            isDev = true;
    });
    if (typeof window.ng !== 'undefined' && window.ng.probe)
        isDev = true;
    result.mode = isDev ? 'development' : 'production';
    if (isDev)
        result.signals.push('Development mode detected');
    // AngularJS module extraction
    if (angularGlobal && angularGlobal.module) {
        try {
            const injector = angularGlobal.element(document).injector();
            if (injector) {
                const loadedMods = [];
                if (typeof injector.modules === 'function') {
                    Object.keys(injector.modules()).forEach(function (m) {
                        if (m.indexOf('ng') === 0 || m === 'ngLocale')
                            return;
                        loadedMods.push(m);
                    });
                }
                if (loadedMods.length === 0) {
                    try {
                        const _ngAppEl = document.querySelector('[ng-app]');
                        if (_ngAppEl) {
                            const _app = angularGlobal.element(_ngAppEl);
                            if (_app.injector) {
                                const _inj = _app.injector();
                                if (_inj && _inj.modules) {
                                    Object.keys(_inj.modules()).forEach(function (m) {
                                        if (m.indexOf('ng') === 0 || m === 'ngLocale')
                                            return;
                                        loadedMods.push(m);
                                    });
                                }
                            }
                        }
                    }
                    catch (e) {
                        /* ignore */
                    }
                }
                result.modules = loadedMods.slice(0, 30);
                if (loadedMods.length > 0)
                    result.signals.push(`${loadedMods.length} modules loaded`);
            }
        }
        catch (e) {
            /* ignore */
        }
    }
    // Angular 2+ component extraction from DOM
    if (result.variant === 'Angular') {
        const customElements = document.querySelectorAll('*');
        const componentSet = {};
        customElements.forEach(function (el) {
            const tag = el.tagName.toLowerCase();
            if (tag.indexOf('app-') === 0 || tag.indexOf('ngx-') === 0 || tag.indexOf('mat-') === 0) {
                componentSet[tag] = true;
            }
            if (el.hasAttribute('_ngcontent') || el.hasAttribute('_nghost')) {
                let cls = el.className || '';
                if (typeof cls === 'string') {
                    cls.split(/\s+/).forEach(function (c) {
                        if (c.length > 2 &&
                            c.charAt(0) === c.charAt(0).toUpperCase() &&
                            componentSet[c] === undefined) {
                            componentSet[c] = true;
                        }
                    });
                }
            }
        });
        result.modules = Object.keys(componentSet).slice(0, 30);
    }
    // Route extraction（含 hash 路由链接：#/xxx）
    const routeSet = {};
    document.querySelectorAll('a[href^="/"], a[href^="#/"]').forEach(function (a) {
        const href = a.getAttribute('href');
        if (!href)
            return;
        let cleanPath;
        if (href.charAt(0) === '#') {
            cleanPath = href.slice(1).split('?')[0];
        }
        else {
            cleanPath = href.split('?')[0].split('#')[0];
        }
        if (cleanPath.length > 1 && !routeSet[cleanPath]) {
            routeSet[cleanPath] = true;
        }
    });
    if (document.querySelector('router-outlet, [router-outlet], app-router-outlet')) {
        result.signals.push('Angular Router detected (<router-outlet>)');
    }
    result.routes = Object.keys(routeSet).slice(0, 50);
    window.postMessage({ __vk_angular_detect: true, __vk_token: __vk_token, result: result }, location.origin);
})();
