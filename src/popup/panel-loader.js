// panel-loader.js -- 灵眸 Chrome Extension
// Fetches panel HTML fragments in parallel and injects into #app-main
(function () {
  'use strict';

  const PANEL_DIR = 'panels/';
  const PANEL_FILES = [
    'encoding.html',
    'favicon-gather.html',
    'asset.html',
    'links-multiurl.html',
    'history.html',
    'exif.html',
    'spoof.html',
    'vue.html',
    'jsctrl.html',
    'payload.html',
    'xssscan.html',
    'sourcemap.html',
    'ruoyi.html',
    'waf.html',
    'cookie-audit.html',
    'react.html',
    'angular.html',
    'cors.html',
    'subdomain.html',
    'source-loader.html',
    'sniff.html',
    'headers.html',
    'redirect.html',
    'fuzz.html',
    'report.html',
  ];

  const appMain = document.getElementById('app-main');
  let resolve;
  window._panelsReady = new Promise(function (r) {
    resolve = r;
  });

  if (!appMain) {
    console.error('[panel-loader] #app-main not found');
    resolve();
    return;
  }

  Promise.all(
    PANEL_FILES.map(function (file) {
      return fetch(PANEL_DIR + file).then(function (resp) {
        if (!resp.ok) throw new Error('Panel load failed: ' + file);
        return resp.text();
      });
    })
  )
    .then(function (htmls) {
      htmls.forEach(function (html) {
        const doc = new DOMParser().parseFromString(html, 'text/html');
        const frag = document.createDocumentFragment();
        while (doc.body.firstChild) {
          frag.appendChild(doc.body.firstChild);
        }
        appMain.appendChild(frag);
      });
      resolve();
    })
    .catch(function (err) {
      console.error('[panel-loader]', err);
      resolve();
    });
})();
