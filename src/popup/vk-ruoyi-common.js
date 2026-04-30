// VulnKit - RuoYi Common Utilities
// Shared helpers used by all RuoYi sub-modules
window.VulnKitRuoYiCommon = (function () {
  'use strict';

  function getUtils() {
    return window.VulnKitUtils || null;
  }

  var utils = {};
  ['get', 'escapeHtml', 'copyText', 'showToast'].forEach(function (method) {
    utils[method] = function () {
      var u = getUtils();
      if (!u || typeof u[method] !== 'function') return undefined;
      return u[method].apply(u, arguments);
    };
  });

  async function getActiveTab() {
    var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabs[0] || null;
  }

  function updateWorkflowStep(step) {
    var steps = document.querySelectorAll('.ruoyi-wf-step');
    for (var i = 0; i < steps.length; i++) {
      if (i < step) {
        steps[i].classList.add('done');
        steps[i].classList.remove('active');
      } else if (i === step) {
        steps[i].classList.add('active');
        steps[i].classList.remove('done');
      } else {
        steps[i].classList.remove('active', 'done');
      }
    }
  }

  return {
    getUtils: getUtils,
    utils: utils,
    getActiveTab: getActiveTab,
    updateWorkflowStep: updateWorkflowStep,
  };
})();
