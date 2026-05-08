// 灵眸 Init - Entry point (ES module)
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';
import * as encoding from './vk-encoding.js';
import * as asset from './vk-asset.js';
import * as gather from './vk-gather.js';
import {
  initTabPagination, initMainTabs, initEncodingJwtCrypto,
  initRsaFaviconAsset, initGatherAndRules, initLinksHistoryMultiUrl,
  initExifAndSpoofing, initVuePermissions, initJsSearchAndTraverse,
  initSecurityDetectors, initNetworkTools, initStateRestoration,
  initThemeAndPayload, initXssAndSourcemap, initStatusBarAndKeyboard,
} from './vk-init-panels.js';

function initContextMenu() {
  chrome.storage.local.get(['contextSelection', 'contextAction'], function (data) {
    if (data.contextSelection) {
      const inputEl = utils.get('encoding-input');
      if (inputEl) inputEl.value = data.contextSelection;
      if (data.contextAction === 'decode') {
        setTimeout(function () {
          encoding.handleDecode();
        }, 100);
      } else if (data.contextAction === 'encode') {
        setTimeout(function () {
          encoding.handleEncode();
        }, 100);
      }
      chrome.storage.local.remove(['contextSelection', 'contextAction']);
      chrome.action.setBadgeText({ text: '' });
    }
  });
}

function initSettings(savedState) {
  if (savedState && savedState['encoding-subtab']) {
    encoding.switchEncodingTab(savedState['encoding-subtab']);
  }
  if (savedState && savedState['asset-source']) {
    asset.switchAssetSource(savedState['asset-source']);
  }

  const toolbarConfig = utils.getSetting('toolbarConfig', null);
  const tabGrid = utils.get('tab-grid');
  if (toolbarConfig && Array.isArray(toolbarConfig) && tabGrid) {
    const allBtns = Array.from(tabGrid.querySelectorAll('.tab-btn'));
    const btnMap = {};
    allBtns.forEach(function (btn) {
      btnMap[btn.dataset.panel] = btn;
    });
    toolbarConfig.forEach(function (cfg) {
      const btn = btnMap[cfg.id];
      if (!btn) return;
      if (cfg.visible === false) {
        btn.classList.add('toolbar-hidden');
      } else {
        btn.classList.remove('toolbar-hidden');
        tabGrid.appendChild(btn);
      }
    });
    const activeTab = tabGrid.querySelector('.tab-btn.active');
    if (activeTab && activeTab.classList.contains('toolbar-hidden')) {
      const firstVisible = tabGrid.querySelector('.tab-btn:not(.toolbar-hidden)');
      if (firstVisible) firstVisible.click();
    }
  }
}

async function initApp() {
  await utils.loadSettings();
  initContextMenu();
  const savedState = await utils.restoreUIState();
  initSettings(savedState);
  initTabPagination();
  initMainTabs();
  initEncodingJwtCrypto();
  initRsaFaviconAsset();
  initGatherAndRules();
  initLinksHistoryMultiUrl();
  initExifAndSpoofing();
  initVuePermissions();
  initJsSearchAndTraverse();
  initSecurityDetectors();
  initNetworkTools();
  initStateRestoration();
  initThemeAndPayload();
  initXssAndSourcemap();
  initStatusBarAndKeyboard();
}

function startApp() {
  window._panelsReady.then(initApp);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', startApp);
} else {
  startApp();
}
