"use strict";
// page-inspect.ts
// MAIN world inject script for page inspection (leak-scan + fingerprint)
// 根据 dataset.vkAction 分支执行，结果通过 postMessage 回传。
(function () {
    'use strict';
    let action = '';
    let token = '';
    try {
        const cs = document.currentScript;
        if (cs) {
            action = cs.dataset.vkAction || '';
            token = cs.dataset.vkToken || '';
        }
    }
    catch {
        /* ignore */
    }
    const guardKey = '__VK_PI_' + action;
    if (window[guardKey]) {
        postResult({ error: 'Already scanned for: ' + action });
        return;
    }
    window[guardKey] = true;
    function postResult(result) {
        try {
            window.postMessage({ __vk_page_inspect: true, __vk_token: token, result: result }, location.origin);
        }
        catch {
            /* ignore */
        }
    }
    if (action === 'leak-scan') {
        const storage = [];
        const globals = [];
        // localStorage
        try {
            const lsLen = Math.min(localStorage.length || 0, 200);
            for (let i = 0; i < lsLen; i++) {
                const lsKey = localStorage.key(i);
                if (!lsKey)
                    continue;
                try {
                    const lsVal = localStorage.getItem(lsKey);
                    storage.push({ store: 'localStorage', key: lsKey, value: lsVal });
                }
                catch {
                    storage.push({ store: 'localStorage', key: lsKey, value: '[access denied]' });
                }
            }
        }
        catch {
            /* ignore */
        }
        // sessionStorage
        try {
            const ssLen = Math.min(sessionStorage.length || 0, 200);
            for (let j = 0; j < ssLen; j++) {
                const ssKey = sessionStorage.key(j);
                if (!ssKey)
                    continue;
                try {
                    const ssVal = sessionStorage.getItem(ssKey);
                    storage.push({ store: 'sessionStorage', key: ssKey, value: ssVal });
                }
                catch {
                    storage.push({ store: 'sessionStorage', key: ssKey, value: '[access denied]' });
                }
            }
        }
        catch {
            /* ignore */
        }
        // JS global variables matching sensitive patterns
        const sensitivePatterns = [
            /token/i,
            /secret/i,
            /key/i,
            /auth/i,
            /password/i,
            /credential/i,
            /api[_-]?key/i,
            /access[_-]?key/i,
            /private[_-]?key/i,
            /session/i,
            /config/i,
            /firebase/i,
            /aws/i,
            /stripe/i,
            /paypal/i,
        ];
        let scanned = 0;
        for (const prop in window) {
            if (scanned >= 100)
                break;
            if (!window.hasOwnProperty || !window.hasOwnProperty(prop))
                continue;
            if (prop.startsWith('__') || prop.startsWith('_') || prop.startsWith('webkit'))
                continue;
            if (/^(on|CSS|DOM|SVG|Math|Intl|JSON|Array|Object|String|Number|Boolean|Date|RegExp|Error|Map|Set|Promise|Proxy|Reflect|Symbol|WeakMap|WeakSet|console|document|window|navigator|location|history|screen|performance|crypto|indexedDB|caches|speechSynthesis|visualViewport|matchMedia)$/.test(prop))
                continue;
            let val;
            try {
                val = window[prop];
            }
            catch {
                continue;
            }
            if (val === null || val === undefined)
                continue;
            const matches = sensitivePatterns.some((p) => p.test(prop));
            if (matches) {
                const type = typeof val;
                let displayVal = '';
                if (type === 'string')
                    displayVal = val.length > 200 ? val.substring(0, 200) + '...' : val;
                else if (type === 'object' && val !== null)
                    displayVal = '[Object ' + (val.constructor ? val.constructor.name : 'Unknown') + ']';
                else if (type === 'function')
                    displayVal = '[Function: ' + prop + ']';
                else
                    displayVal = String(val).substring(0, 200);
                globals.push({ name: prop, type: type, value: displayVal });
                scanned++;
            }
        }
        postResult({ storage: storage, globals: globals });
        return;
    }
    if (action === 'fingerprint') {
        const detectedGlobals = [];
        const versions = {};
        // JS Framework / Library detection
        const globalChecks = [
            // Vue
            {
                name: 'Vue.js',
                prop: 'Vue',
                version: function () {
                    try {
                        return window.Vue && window.Vue.version
                            ? window.Vue.version
                            : null;
                    }
                    catch {
                        return null;
                    }
                },
            },
            { name: 'Vue (devtools)', prop: '__VUE_DEVTOOLS_GLOBAL_HOOK__' },
            { name: 'Vue Router', prop: '__VUE_ROUTER__' },
            // React
            { name: 'React', prop: 'React' },
            { name: 'ReactDOM', prop: 'ReactDOM' },
            { name: 'React DevTools', prop: '__REACT_DEVTOOLS_GLOBAL_HOOK__' },
            // Angular
            { name: 'Angular (ng)', prop: 'ng' },
            { name: 'Angular', prop: 'angular' },
            { name: 'Angular (zone)', prop: 'Zone' },
            // jQuery
            {
                name: 'jQuery',
                prop: 'jQuery',
                version: function () {
                    try {
                        const jq = window.jQuery;
                        return jq && jq.fn && jq.fn.jquery ? jq.fn.jquery : null;
                    }
                    catch {
                        return null;
                    }
                },
            },
            {
                name: 'jQuery ($)',
                prop: '$',
                version: function () {
                    try {
                        const w = window;
                        if (w.$ && w.$.fn && w.$.fn.jquery && !w.jQuery)
                            return w.$.fn.jquery;
                        return null;
                    }
                    catch {
                        return null;
                    }
                },
            },
            // Bootstrap
            { name: 'Bootstrap', prop: 'bootstrap' },
            // Lodash
            {
                name: 'Lodash',
                prop: 'lodash',
                version: function () {
                    try {
                        const l = window.lodash;
                        return l && l.VERSION ? l.VERSION : null;
                    }
                    catch {
                        return null;
                    }
                },
            },
            {
                name: 'Lodash (_)',
                prop: '_',
                version: function () {
                    try {
                        const w = window;
                        if (w._ && w._.VERSION && !w.lodash)
                            return w._.VERSION;
                        return null;
                    }
                    catch {
                        return null;
                    }
                },
            },
            // Moment
            { name: 'Moment.js', prop: 'moment' },
            // Axios
            { name: 'Axios', prop: 'axios' },
            // Webpack
            { name: 'Webpack', prop: '__webpack_require__' },
            { name: 'Webpack Modules', prop: '__webpack_modules__' },
            { name: 'Webpack Chunk', prop: '__webpack_chunk_load__' },
            // Build tools
            { name: 'Vite', prop: '__vite_plugin_react_preamble_installed__' },
            { name: 'Parcel', prop: '__parcel__' },
            // Analytics
            { name: 'Google Analytics (gtag)', prop: 'gtag' },
            { name: 'Google Analytics (ga)', prop: 'ga' },
            { name: 'Google DataLayer', prop: 'dataLayer' },
            { name: 'Baidu Tongji', prop: '_hmt' },
            { name: 'CNZZ', prop: '_czc' },
            // Maps
            { name: 'AMap (高德)', prop: 'AMap' },
            { name: 'BMap (百度)', prop: 'BMap' },
            { name: 'TMap (腾讯)', prop: 'TMap' },
            { name: 'Google Maps', prop: 'google', sub: 'maps' },
            // Rich Text Editors
            { name: 'TinyMCE', prop: 'tinymce' },
            { name: 'CKEditor', prop: 'CKEDITOR' },
            { name: 'WangEditor', prop: 'wangEditor' },
            // UI Frameworks
            { name: 'Ant Design', prop: 'antd' },
            { name: 'Element UI', prop: 'ELEMENT' },
            { name: 'Element Plus', prop: 'ElementPlus' },
            { name: 'Vuetify', prop: 'Vuetify' },
            { name: 'iView/ViewUI', prop: 'iview' },
            // Monitoring
            { name: 'Sentry', prop: 'Sentry' },
            // Chart Libraries
            { name: 'ECharts', prop: 'echarts' },
            { name: 'Chart.js', prop: 'Chart' },
            { name: 'D3.js', prop: 'd3' },
            { name: 'Highcharts', prop: 'Highcharts' },
            // Crypto
            { name: 'CryptoJS', prop: 'CryptoJS' },
            { name: 'jsencrypt', prop: 'JSEncrypt' },
            { name: 'Forge', prop: 'forge' },
            // Utils
            { name: 'Day.js', prop: 'dayjs' },
            { name: 'Numeral.js', prop: 'numeral' },
            // Social SDKs
            { name: 'WeChat JS-SDK', prop: 'wx' },
            { name: 'WeChat bridge', prop: 'WeixinJSBridge' },
            { name: 'Alipay JSAPI', prop: 'AlipayJSBridge' },
            // Mobile frameworks
            { name: 'Capacitor', prop: 'Capacitor' },
            { name: 'Cordova', prop: 'cordova' },
            // Other
            { name: 'Socket.IO', prop: 'io', sub: 'Socket' },
            { name: 'GraphQL', prop: 'graphql' },
            { name: 'NProgress', prop: 'NProgress' },
            { name: 'anime.js', prop: 'anime' },
            { name: 'Swiper', prop: 'Swiper' },
            { name: 'AOS', prop: 'AOS' },
        ];
        const w = window;
        globalChecks.forEach(function (check) {
            try {
                let target = w;
                if (check.sub) {
                    target = target[check.prop];
                    if (!target)
                        return;
                    target = target[check.sub];
                }
                else {
                    target = target[check.prop];
                }
                if (target === undefined || target === null)
                    return;
                let version = null;
                if (check.version)
                    version = check.version();
                detectedGlobals.push(check.name);
                if (version)
                    versions[check.name] = version;
            }
            catch {
                /* ignore */
            }
        });
        // Vue DOM-based detection (for production builds where window.Vue is unavailable)
        const vueDetected = detectedGlobals.indexOf('Vue.js') !== -1 ||
            detectedGlobals.indexOf('Vue (devtools)') !== -1;
        if (!vueDetected) {
            try {
                const vueSelectors = [
                    '#app',
                    '[data-v-app]',
                    '[id^="app"]',
                    '#root',
                    '#application',
                    '#main',
                ];
                let vueFound = false;
                for (let vi = 0; vi < vueSelectors.length && !vueFound; vi++) {
                    const mountEl = document.querySelector(vueSelectors[vi]);
                    if (!mountEl)
                        continue;
                    // Vue 3: __vue_app__
                    if (mountEl.__vue_app__) {
                        detectedGlobals.push('Vue.js (DOM)');
                        const v3ver = mountEl.__vue_app__.version;
                        if (v3ver) {
                            versions['Vue.js (DOM)'] = v3ver;
                            versions['Vue.js'] = v3ver;
                        }
                        vueFound = true;
                        break;
                    }
                    // Vue 2: __vue__
                    if (mountEl.__vue__) {
                        const vm = mountEl.__vue__.$root || mountEl.__vue__;
                        const v2ver = (vm && vm.$options && vm.$options.version) ||
                            (mountEl.__vue__.constructor && mountEl.__vue__.constructor.version) ||
                            null;
                        detectedGlobals.push('Vue.js (DOM)');
                        if (v2ver) {
                            versions['Vue.js (DOM)'] = v2ver;
                            versions['Vue.js'] = v2ver;
                        }
                        vueFound = true;
                        break;
                    }
                }
                // Fallback: scan any element with data-v-* (Vue SFC scoped style)
                if (!vueFound) {
                    let scopedEl = document.querySelector('[data-v-app]');
                    if (!scopedEl)
                        scopedEl = document.querySelector('[data-v-]');
                    if (!scopedEl) {
                        const allEls = document.querySelectorAll('*');
                        for (let sv = 0; sv < Math.min(allEls.length, 500); sv++) {
                            const elAttrs = allEls[sv].attributes;
                            if (!elAttrs)
                                continue;
                            for (let ai = 0; ai < elAttrs.length; ai++) {
                                if (elAttrs[ai].name.indexOf('data-v-') === 0) {
                                    scopedEl = allEls[sv];
                                    break;
                                }
                            }
                            if (scopedEl)
                                break;
                        }
                    }
                    if (scopedEl) {
                        detectedGlobals.push('Vue.js (DOM)');
                    }
                }
            }
            catch {
                /* ignore DOM access errors */
            }
        }
        // React DOM-based detection (for production builds)
        const reactDetected = detectedGlobals.indexOf('React') !== -1 || detectedGlobals.indexOf('ReactDOM') !== -1;
        if (!reactDetected) {
            try {
                let reactFound = false;
                let sampleEls = document.querySelectorAll('#root, #app, #__next, [data-reactroot], body > div');
                if (sampleEls.length === 0)
                    sampleEls = document.querySelectorAll('body > *');
                for (let ri = 0; ri < Math.min(sampleEls.length, 10) && !reactFound; ri++) {
                    const rEl = sampleEls[ri];
                    // React 16+: fiber keys
                    const rKeys = Object.keys(rEl);
                    for (let rk = 0; rk < rKeys.length; rk++) {
                        if (rKeys[rk].indexOf('__reactFiber$') === 0 ||
                            rKeys[rk].indexOf('__reactInternalInstance$') === 0) {
                            detectedGlobals.push('React (DOM)');
                            reactFound = true;
                            break;
                        }
                    }
                }
                if (!reactFound && document.querySelector('[data-reactroot]')) {
                    detectedGlobals.push('React (DOM)');
                }
                if (!reactFound && document.querySelector('[data-reactid]')) {
                    detectedGlobals.push('React (DOM)');
                }
            }
            catch {
                /* ignore */
            }
        }
        // Angular DOM-based detection
        const angularDetected = detectedGlobals.indexOf('ng') !== -1 ||
            detectedGlobals.indexOf('angular') !== -1 ||
            detectedGlobals.indexOf('Angular (zone)') !== -1;
        if (!angularDetected) {
            try {
                const ngAppEl = document.querySelector('[ng-version]');
                if (ngAppEl) {
                    detectedGlobals.push('Angular (DOM)');
                    const ngVer = ngAppEl.getAttribute('ng-version');
                    if (ngVer) {
                        versions['Angular (DOM)'] = ngVer;
                        versions['Angular'] = ngVer;
                    }
                }
                else if (document.querySelector('[_nghost]') || document.querySelector('[_ngcontent]')) {
                    detectedGlobals.push('Angular (DOM)');
                }
                else if (document.querySelector('[ng-app]') ||
                    document.querySelector('[ng-controller]')) {
                    detectedGlobals.push('Angular (DOM)');
                }
            }
            catch {
                /* ignore */
            }
        }
        // Cookies
        let cookies = '';
        try {
            cookies = document.cookie || '';
        }
        catch {
            /* ignore */
        }
        // body className
        let classNames = '';
        try {
            if (document.body)
                classNames = document.body.className || '';
        }
        catch {
            /* ignore */
        }
        // Element IDs (max 500)
        const ids = [];
        try {
            const allElements = document.querySelectorAll('[id]');
            const idSet = {};
            for (let ei = 0; ei < allElements.length && ids.length < 500; ei++) {
                const eid = allElements[ei].id;
                if (eid && !idSet[eid]) {
                    idSet[eid] = true;
                    ids.push(eid);
                }
            }
        }
        catch {
            /* ignore */
        }
        postResult({
            globals: detectedGlobals,
            versions: versions,
            cookies: cookies,
            classNames: classNames,
            ids: ids.join(','),
        });
        return;
    }
    // Unknown action — no-op
    postResult({ error: 'Unknown action: ' + action });
})();
