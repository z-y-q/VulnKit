// vk-init-panel-security.js - Security detector panel inits (Headers + Redirect + Fuzz)
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';

const { getActiveTab } = utils;

function initSecurityDetectors2(bindFilterSearch) {
  Promise.all([import('./vk-headers.js'), import('./vk-redirect.js'), import('./vk-fuzz.js')]).then(
    function (mods) {
      var headers = mods[0];
      var redirect = mods[1];
      var fuzz = mods[2];

      // --- Security Headers ---
      (function () {
        var urlInput = utils.get('headers-url');
        if (urlInput) {
          getActiveTab().then(function (tab) {
            if (tab && tab.url) urlInput.value = tab.url;
          });
        }

        utils.bindClick('headers-scan-btn', async function () {
          var url = (urlInput && urlInput.value) || '';
          if (!url || !/^https?:\/\//i.test(url)) {
            utils.showToast('请输入有效的 HTTP(S) URL', 'warning');
            return;
          }
          var btn = utils.get('headers-scan-btn');
          if (!btn) return;
          var origText = btn.textContent;
          btn.innerHTML = '<span class="spinner"></span> 扫描中...';
          btn.disabled = true;
          try {
            var result = await headers.scanSecurityHeaders(url);
            if (result) headers.renderHeadersResults(result);
          } finally {
            btn.textContent = origText;
            btn.disabled = false;
          }
        });

        utils.bindClick('headers-export-btn', function () {
          var format = (utils.get('headers-export-format') || {}).value || 'txt';
          headers.exportHeadersResults(format);
        });

        bindFilterSearch('#headers-filter-row .filter-btn', 'headers-search', headers);
      })();

      // --- Open Redirect ---
      (function () {
        var urlInput = utils.get('redirect-url');
        if (urlInput) {
          getActiveTab().then(function (tab) {
            if (tab && tab.url) urlInput.value = tab.url;
          });
        }

        utils.bindClick('redirect-scan-btn', async function () {
          var url = (urlInput && urlInput.value) || '';
          if (!url || !/^https?:\/\//i.test(url)) {
            utils.showToast('请输入有效的 HTTP(S) URL', 'warning');
            return;
          }
          var scanBtn = utils.get('redirect-scan-btn');
          var stopBtn = utils.get('redirect-stop-btn');
          var progressEl = utils.get('redirect-progress');
          var progressFill = utils.get('redirect-progress-fill');
          var progressText = utils.get('redirect-progress-text');
          if (scanBtn) scanBtn.style.display = 'none';
          if (stopBtn) {
            stopBtn.style.display = '';
            stopBtn.innerHTML = '<span class="spinner"></span> 扫描中...';
          }
          if (progressEl) progressEl.style.display = 'flex';

          try {
            var concurrency = parseInt((utils.get('redirect-concurrency') || {}).value, 10) || 5;
            var result = await redirect.scanRedirects(url, concurrency, function (p) {
              if (progressFill) progressFill.style.width = (p.completed / p.total) * 100 + '%';
              if (progressText) progressText.textContent = p.completed + '/' + p.total;
            });
            if (result) redirect.renderRedirectResults(result);
          } finally {
            if (scanBtn) scanBtn.style.display = '';
            if (stopBtn) {
              stopBtn.textContent = '停止';
              stopBtn.style.display = 'none';
            }
          }
        });

        utils.bindClick('redirect-stop-btn', function () {
          redirect.stopRedirectScan();
        });

        utils.bindClick('redirect-export-btn', function () {
          var format = (utils.get('redirect-export-format') || {}).value || 'txt';
          redirect.exportRedirectResults(format);
        });

        bindFilterSearch('#redirect-filter-row .filter-btn', 'redirect-search', redirect);
      })();

      // --- Directory Fuzzing ---
      (function () {
        var urlInput = utils.get('fuzz-url');
        if (urlInput) {
          getActiveTab().then(function (tab) {
            if (tab && tab.url) urlInput.value = tab.url.replace(/\/+$/, '');
          });
        }
        chrome.storage.local.get(['pentestSettings'], function (result) {
          var s = result.pentestSettings || {};
          var wl = utils.get('fuzz-wordlist');
          if (wl && s.fuzzDefaultWordlist) wl.value = s.fuzzDefaultWordlist;
          var cc = utils.get('fuzz-concurrency');
          if (cc && s.fuzzDefaultConcurrency) cc.value = s.fuzzDefaultConcurrency;
        });

        utils.bindClick('fuzz-start-btn', async function () {
          var url = (urlInput && urlInput.value) || '';
          if (!url || !/^https?:\/\//i.test(url)) {
            utils.showToast('请输入有效的 HTTP(S) URL', 'warning');
            return;
          }
          var wordlist = (utils.get('fuzz-wordlist') || {}).value || 'common';
          var concurrency = parseInt((utils.get('fuzz-concurrency') || {}).value || '5', 10);
          var startBtn = utils.get('fuzz-start-btn');
          var pauseBtn = utils.get('fuzz-pause-btn');
          var stopBtn = utils.get('fuzz-stop-btn');
          var progressEl = utils.get('fuzz-progress');
          var progressFill = utils.get('fuzz-progress-fill');
          var progressText = utils.get('fuzz-progress-text');
          if (startBtn) startBtn.style.display = 'none';
          if (pauseBtn) {
            pauseBtn.style.display = '';
            pauseBtn.innerHTML = '<span class="spinner"></span> 扫描中...';
          }
          if (stopBtn) stopBtn.style.display = '';
          if (progressEl) progressEl.style.display = 'flex';

          try {
            var result = await fuzz.runFuzzScan(
              url,
              wordlist,
              concurrency,
              function (s) {
                if (progressFill) progressFill.style.width = (s.completed / s.total) * 100 + '%';
                if (progressText)
                  progressText.textContent =
                    s.completed + '/' + s.total + ' (发现 ' + s.found + ')';
              },
              function () {
                var container = utils.get('fuzz-results');
                if (container && container.querySelector('.empty-state')) {
                  container.innerHTML = '';
                }
              }
            );
            if (result) {
              var filterRow = utils.get('fuzz-filter-row');
              if (filterRow) filterRow.style.display = 'flex';
              fuzz.renderFuzzResults(result);
            }
          } catch (e) {
            console.debug('fuzz scan error:', e);
            utils.showToast('扫描出错: ' + (e.message || e), 'error');
          } finally {
            if (startBtn) startBtn.style.display = '';
            if (pauseBtn) {
              pauseBtn.style.display = 'none';
              pauseBtn.innerHTML = '暂停';
            }
            if (stopBtn) stopBtn.style.display = 'none';
          }
        });

        utils.bindClick('fuzz-pause-btn', function () {
          var paused = fuzz.pauseFuzzScan();
          var pauseBtn = utils.get('fuzz-pause-btn');
          if (pauseBtn) pauseBtn.textContent = paused ? '继续' : '暂停';
        });

        utils.bindClick('fuzz-stop-btn', function () {
          fuzz.stopFuzzScan();
        });

        bindFilterSearch('#fuzz-filter-row .filter-btn', 'fuzz-search', fuzz, {
          defaultFilter: '',
        });

        utils.bindClick('fuzz-export-btn', function () {
          var format = (utils.get('fuzz-export-format') || {}).value || 'txt';
          fuzz.exportFuzzResults(format);
        });
      })();
    }
  );
}

export { initSecurityDetectors2 };
