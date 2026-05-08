// 灵眸 - RuoYi Common Utilities
// Shared helpers used by all RuoYi sub-modules
import { utilsProxy as utils } from './vk-namespace.js';

export { utils };

export function updateWorkflowStep(step) {
  const steps = document.querySelectorAll('.ruoyi-wf-step');
  for (let i = 0; i < steps.length; i++) {
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

export function toggleSelectAll(cssSelector) {
  const checks = document.querySelectorAll(cssSelector);
  const allChecked =
    checks.length > 0 &&
    Array.from(checks).every(function (cb) {
      return cb.checked;
    });
  checks.forEach(function (cb) {
    cb.checked = !allChecked;
  });
}

export function copyRoutePaths(routes, emptyMsg) {
  if (!routes || routes.length === 0) {
    utils.showToast(emptyMsg || '没有路由数据', 'warning');
    return;
  }
  const paths = routes
    .map(function (r) {
      return r.path || r.component;
    })
    .join('\n');
  utils.copyAndToast(paths, `已复制 ${routes.length} 条路径`);
}
