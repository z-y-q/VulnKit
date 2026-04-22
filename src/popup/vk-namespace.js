// VulnKit v5.0
(function () {
  'use strict';

  const utils = {
    cache: new Map(),
    get(id) {
      if (!this.cache.has(id)) {
        this.cache.set(id, document.getElementById(id));
      }
      return this.cache.get(id);
    },
    escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    },
    copyText(text) {
      navigator.clipboard.writeText(text).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      });
    },
    showToast: (() => {
      let current = null;
      const types = ['success', 'error', 'warning', 'info'];
      return function (message, type, duration) {
        if (current && current.parentNode) current.parentNode.removeChild(current);
        current = document.createElement('div');
        current.className = 'toast toast-' + (types.includes(type) ? type : 'info');
        current.textContent = message;
        document.body.appendChild(current);
        requestAnimationFrame(() => {
          if (current) current.classList.add('toast-show');
        });
        setTimeout(() => {
          if (current) {
            current.classList.remove('toast-show');
            setTimeout(() => {
              if (current && current.parentNode) {
                current.parentNode.removeChild(current);
                current = null;
              }
            }, 200);
          }
        }, duration || 2000);
      };
    })(),
  };

  window.VulnKitUtils = utils;
})();
