// VulnKit - RuoYi Common Utilities
// Shared helpers used by all RuoYi sub-modules
window.VulnKitRuoYiCommon = (function () {
  'use strict';

  var utils = window.VulnKitUtils.utilsProxy;

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
    utils: utils,
    getActiveTab: utils.getActiveTab,
    updateWorkflowStep: updateWorkflowStep,
  };
})();
