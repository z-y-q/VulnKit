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

  function toggleSelectAll(cssSelector) {
    var checks = document.querySelectorAll(cssSelector);
    var allChecked =
      checks.length > 0 &&
      Array.from(checks).every(function (cb) {
        return cb.checked;
      });
    checks.forEach(function (cb) {
      cb.checked = !allChecked;
    });
  }

  function copyRoutePaths(routes, emptyMsg) {
    if (!routes || routes.length === 0) {
      utils.showToast(emptyMsg || '没有路由数据', 'warning');
      return;
    }
    var paths = routes
      .map(function (r) {
        return r.path || r.component;
      })
      .join('\n');
    utils.copyAndToast(paths, '已复制 ' + routes.length + ' 条路径');
  }

  return {
    utils: utils,
    getActiveTab: utils.getActiveTab,
    requireTabId: utils.requireTabId,
    updateWorkflowStep: updateWorkflowStep,
    toggleSelectAll: toggleSelectAll,
    copyRoutePaths: copyRoutePaths,
  };
})();
