// panel-loader.js -- 灵眸 Chrome Extension
// Fetches panel HTML fragments in parallel and injects into #app-main
(function () {
  'use strict';

  var PANEL_DIR = 'panels/';
  var PANEL_FILES = [
    'encoding.html',
    'favicon-gather.html',
    'rules-modal.html',
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
    'ruoyi.html'
  ];

  var appMain = document.getElementById('app-main');
  var resolve;
  window._panelsReady = new Promise(function (r) { resolve = r; });

  Promise.all(
    PANEL_FILES.map(function (file) {
      return fetch(PANEL_DIR + file).then(function (resp) {
        if (!resp.ok) throw new Error('Panel load failed: ' + file);
        return resp.text();
      });
    })
  ).then(function (htmls) {
    htmls.forEach(function (html) {
      var doc = new DOMParser().parseFromString(html, 'text/html');
      var frag = document.createDocumentFragment();
      while (doc.body.firstChild) {
        frag.appendChild(doc.body.firstChild);
      }
      appMain.appendChild(frag);
    });
    resolve();
  }).catch(function (err) {
    console.error('[panel-loader]', err);
    resolve();
  });
})();
