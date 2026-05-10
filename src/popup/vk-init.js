// 灵眸 Init - Lightweight entry point (ES module)
// Shell UI loads eagerly; panel modules lazy-load on first tab click.
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';
import { TAB_TO_CATEGORY } from './vk-categories.js';

const { getCurrentDomain, getActiveTab } = utils;

// ====== Pagination state (moved from vk-init-panels.js) ======
let tabBtns, tabsPerPage, totalPages, currentPage;
let scrollLeftBtn, scrollRightBtn;

function showTabPage(page) {
  currentPage = page;
  tabBtns.forEach(function (btn, i) {
    if (i >= page * tabsPerPage && i < (page + 1) * tabsPerPage) {
      btn.classList.remove('hidden-tab');
    } else {
      btn.classList.add('hidden-tab');
    }
  });
  if (scrollLeftBtn) scrollLeftBtn.disabled = page === 0;
  if (scrollRightBtn) scrollRightBtn.disabled = page >= totalPages - 1;
  var pageIndicator = utils.get('tab-page-indicator');
  if (pageIndicator) pageIndicator.textContent = totalPages <= 1 ? '' : page + 1 + '/' + totalPages;
}

function getVisibleTabBtns() {
  return Array.from(
    document.querySelectorAll('.tab-btn:not(.toolbar-hidden):not(.category-filtered)')
  );
}

function recalcPagination() {
  var visible = getVisibleTabBtns();
  tabBtns = visible;
  totalPages = Math.max(1, Math.ceil(visible.length / tabsPerPage));
  if (currentPage >= totalPages) currentPage = totalPages - 1;
  var pageIndicator = utils.get('tab-page-indicator');
  if (pageIndicator) pageIndicator.style.display = totalPages <= 1 ? 'none' : '';
}

function initTabPagination() {
  tabBtns = Array.from(document.querySelectorAll('.tab-btn:not(.toolbar-hidden)'));
  tabsPerPage = 8;
  totalPages = Math.max(1, Math.ceil(tabBtns.length / tabsPerPage));
  currentPage = 0;

  tabBtns.forEach(function (btn) {
    var cat = TAB_TO_CATEGORY[btn.dataset.panel];
    if (cat) btn.style.setProperty('--cat-color', cat.color);
  });

  var pageIndicator = utils.get('tab-page-indicator');
  if (totalPages <= 1) {
    if (pageIndicator) pageIndicator.style.display = 'none';
  }

  scrollLeftBtn = utils.bindClick('tab-scroll-left', function () {
    if (currentPage > 0) showTabPage(currentPage - 1);
  });
  scrollRightBtn = utils.bindClick('tab-scroll-right', function () {
    if (currentPage < totalPages - 1) showTabPage(currentPage + 1);
  });
  showTabPage(0);
}

function initCategoryFilter() {
  var chips = document.querySelectorAll('.category-chip');
  if (chips.length === 0) return;

  chips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      chips.forEach(function (c) {
        c.classList.remove('active');
      });
      chip.classList.add('active');

      var category = chip.dataset.category;
      var allBtns = document.querySelectorAll('.tab-btn:not(.toolbar-hidden)');

      if (category === 'all') {
        allBtns.forEach(function (btn) {
          btn.classList.remove('category-filtered');
        });
      } else {
        allBtns.forEach(function (btn) {
          var tabCat = TAB_TO_CATEGORY[btn.dataset.panel];
          if (tabCat && tabCat.id === category) {
            btn.classList.remove('category-filtered');
          } else {
            btn.classList.add('category-filtered');
          }
        });
      }

      recalcPagination();
      showTabPage(0);

      var activeBtn = document.querySelector(
        '.tab-btn.active:not(.toolbar-hidden):not(.category-filtered)'
      );
      if (!activeBtn) {
        var firstVisible = document.querySelector(
          '.tab-btn:not(.toolbar-hidden):not(.category-filtered)'
        );
        if (firstVisible) firstVisible.click();
      }
    });
  });
}

function initStatusBarAndKeyboard() {
  var statusTime = utils.get('status-time');
  if (statusTime) {
    var update = function () {
      var now = new Date();
      statusTime.textContent =
        String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0');
    };
    update();
    setInterval(update, 30000);
  }

  document.addEventListener('keydown', function (e) {
    if (!e.altKey) return;
    var num = parseInt(e.key, 10);
    if (num >= 1 && num <= tabsPerPage) {
      e.preventDefault();
      var idx = currentPage * tabsPerPage + (num - 1);
      if (idx < tabBtns.length) {
        tabBtns[idx].click();
      }
      return;
    }
    if (e.key === 'ArrowLeft' && currentPage > 0) {
      e.preventDefault();
      showTabPage(currentPage - 1);
    } else if (e.key === 'ArrowRight' && currentPage < totalPages - 1) {
      e.preventDefault();
      showTabPage(currentPage + 1);
    }
  });
}

// ====== Theme (pure DOM, eager) ======
function initTheme() {
  var themes = ['light', 'dark'];
  var savedTheme = localStorage.getItem('pentest-theme');
  if (savedTheme) document.documentElement.setAttribute('data-theme', savedTheme);
  utils.bindClick('settings-btn', function () {
    chrome.runtime.openOptionsPage();
  });
  utils.bindClick('theme-toggle', function () {
    var current = document.documentElement.getAttribute('data-theme') || 'light';
    var next = themes[(themes.indexOf(current) + 1) % themes.length];
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('pentest-theme', next);
  });
}

// ====== Panel registry: maps data-panel values to lazy init functions ======
// source: 'panels' or 'detectors'
var PANEL_REGISTRY = {
  encoding: { source: 'panels', init: 'initEncodingJwtCrypto' },
  favicon: { source: 'panels', init: 'initRsaFaviconAsset' },
  gather: { source: 'panels', init: 'initGatherAndRules' },
  asset: { source: 'panels', init: 'initRsaFaviconAsset' },
  links: { source: 'panels', init: 'initLinksHistoryMultiUrl' },
  multiurl: { source: 'panels', init: 'initLinksHistoryMultiUrl' },
  history: { source: 'panels', init: 'initLinksHistoryMultiUrl' },
  exif: { source: 'panels', init: 'initExifAndSpoofing' },
  spoof: { source: 'panels', init: 'initExifAndSpoofing' },
  payload: { source: 'panels', init: 'initPayload' },
  xssscan: { source: 'panels', init: 'initXssAndSourcemap' },
  sourcemap: { source: 'panels', init: 'initXssAndSourcemap' },
  headers: { source: 'panels', init: 'initSecurityDetectors2' },
  redirect: { source: 'panels', init: 'initSecurityDetectors2' },
  fuzz: { source: 'panels', init: 'initSecurityDetectors2' },
  report: { source: 'panels', init: 'initReport' },
  vue: { source: 'detectors', init: 'initVuePermissions' },
  jsctrl: { source: 'detectors', init: 'initJsSearchAndTraverse' },
  ruoyi: { source: 'detectors', init: 'initSecurityDetectors' },
  waf: { source: 'detectors', init: 'initSecurityDetectors' },
  'cookie-audit': { source: 'detectors', init: 'initSecurityDetectors' },
  react: { source: 'detectors', init: 'initSecurityDetectors' },
  angular: { source: 'detectors', init: 'initSecurityDetectors' },
  cors: { source: 'detectors', init: 'initNetworkTools' },
  subdomain: { source: 'detectors', init: 'initNetworkTools' },
  'source-loader': { source: 'detectors', init: 'initNetworkTools' },
  sniff: { source: 'detectors', init: 'initSniff' },
};

// ====== Main tabs with lazy loading ======
function initMainTabs(savedState) {
  var loadedFns = new Set();
  var panelsModule = null;
  var detectorsModule = null;

  function ensureModule(source) {
    if (source === 'panels' && !panelsModule) {
      panelsModule = import('./vk-init-panels.js');
    }
    if (source === 'detectors' && !detectorsModule) {
      detectorsModule = import('./vk-init-detectors.js');
    }
    return source === 'panels' ? panelsModule : detectorsModule;
  }

  var onTabClick = function onTabClick() {
    var panel = this.dataset.panel;
    document.querySelectorAll('.tab-btn').forEach(function (b) {
      b.classList.remove('active');
    });
    this.classList.add('active');
    document.querySelectorAll('.panel').forEach(function (p) {
      p.classList.remove('active');
    });
    var target = utils.get('panel-' + panel);
    if (target) target.classList.add('active');
    var statusText = utils.get('status-text');
    if (statusText) statusText.textContent = this.textContent;

    // History domain auto-fill (pure DOM, no module needed)
    if (panel === 'history') {
      var historyDomainInput = utils.get('history-domain');
      if (historyDomainInput && !historyDomainInput.value.trim()) {
        getCurrentDomain().then(function (d) {
          if (d && !historyDomainInput.value.trim()) historyDomainInput.value = d;
        });
      }
    }

    // Exif lib lazy-load (no module needed)
    if (panel === 'exif' && !onTabClick._exifLoaded) {
      onTabClick._exifLoaded = true;
      utils.loadLibs(['lib/exifr.full.js']).catch(function (e) {
        console.debug('exifr load failed', e);
      });
    }

    // Lazy-load panel module on first click
    var entry = PANEL_REGISTRY[panel];
    if (entry && !loadedFns.has(entry.init)) {
      loadedFns.add(entry.init);
      ensureModule(entry.source)
        .then(function (mod) {
          return mod[entry.init](savedState);
        })
        .catch(function (err) {
          console.error('[VulnKit] Panel init failed:', panel, err);
        });
    }
  };

  document.querySelectorAll('.tab-btn').forEach(function (btn) {
    btn.addEventListener('click', onTabClick);
  });
}

// ====== Context menu (lazy encoding) ======
function initContextMenu() {
  chrome.storage.local.get(['contextSelection', 'contextAction'], function (data) {
    if (!data.contextSelection) return;
    var inputEl = utils.get('encoding-input');
    if (inputEl) inputEl.value = data.contextSelection;
    if (data.contextAction === 'decode' || data.contextAction === 'encode') {
      import('./vk-encoding.js').then(function (encoding) {
        setTimeout(function () {
          if (data.contextAction === 'decode') encoding.handleDecode();
          else encoding.handleEncode();
        }, 100);
      });
    }
    chrome.storage.local.remove(['contextSelection', 'contextAction']);
    chrome.action.setBadgeText({ text: '' });
  });
}

// ====== Settings restoration (lazy encoding/asset) ======
function initSettings(savedState) {
  if (savedState && savedState['encoding-subtab']) {
    import('./vk-encoding.js').then(function (encoding) {
      encoding.switchEncodingTab(savedState['encoding-subtab']);
    });
  }
  if (savedState && savedState['asset-source']) {
    import('./vk-asset.js').then(function (asset) {
      asset.switchAssetSource(savedState['asset-source']);
    });
  }

  var toolbarConfig = utils.getSetting('toolbarConfig', null);
  var tabGrid = utils.get('tab-grid');
  if (toolbarConfig && Array.isArray(toolbarConfig) && tabGrid) {
    var allBtns = Array.from(tabGrid.querySelectorAll('.tab-btn'));
    var btnMap = {};
    allBtns.forEach(function (btn) {
      btnMap[btn.dataset.panel] = btn;
    });
    toolbarConfig.forEach(function (cfg) {
      var btn = btnMap[cfg.id];
      if (!btn) return;
      if (cfg.visible === false) {
        btn.classList.add('toolbar-hidden');
      } else {
        btn.classList.remove('toolbar-hidden');
        tabGrid.appendChild(btn);
      }
    });
    var activeTab = tabGrid.querySelector('.tab-btn.active');
    if (activeTab && activeTab.classList.contains('toolbar-hidden')) {
      var firstVisible = tabGrid.querySelector('.tab-btn:not(.toolbar-hidden)');
      if (firstVisible) firstVisible.click();
    }
  }
}

// ====== State restoration (JS block query only; rest deferred to panel inits) ======
function initStateRestoration() {
  chrome.runtime.sendMessage({ type: 'QUERY_JS_BLOCK' }, function (resp) {
    if (chrome.runtime.lastError) {
      chrome.storage.local.remove('js_blocked_tabId');
      return;
    }
    if (resp && resp.blocked) {
      import('./vk-jsctrl.js').then(function (jsctrl) {
        jsctrl.setJsBlocked(true);
        jsctrl.updateJsToggleStatus();
      });
    } else {
      chrome.storage.local.remove('js_blocked_tabId');
    }
  });
}

// ====== Shared event delegation (copied from initSecurityDetectors2) ======
function initSharedEvents() {
  document.addEventListener('click', function (e) {
    var copyBtn = e.target.closest('.redirect-copy-btn, .fuzz-copy-btn, .headers-copy-btn');
    if (copyBtn) {
      var text = copyBtn.getAttribute('data-copy');
      if (text) {
        utils.copyText(text);
        utils.showToast('已复制到剪贴板', 'success');
      }
      return;
    }

    var headerVal = e.target.closest('.headers-header-value');
    if (headerVal) {
      headerVal.classList.toggle('expanded');
      return;
    }
  });
}

// ====== App bootstrap ======
async function initApp() {
  await utils.loadSettings();
  initTheme();
  initContextMenu();
  var savedState = await utils.restoreUIState();
  initSettings(savedState);
  initTabPagination();
  initCategoryFilter();
  initMainTabs(savedState);
  initStatusBarAndKeyboard();
  initSharedEvents();
  initStateRestoration();
  // Deferred: restore gather/links cached data (fire-and-forget, no eager module parse)
  import('./vk-init-detectors.js')
    .then(function (mod) {
      mod.initStateRestoration();
    })
    .catch(function (err) {
      console.debug('[VulnKit] State restoration deferred:', err);
    });
}

function startApp() {
  window._panelsReady.then(initApp).catch(function (err) {
    console.error('VulnKit init failed:', err);
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', startApp);
} else {
  startApp();
}
