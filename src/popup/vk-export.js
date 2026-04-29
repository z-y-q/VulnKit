// VulnKit - Universal Export Utility
window.VulnKitExport = (function () {
  'use strict';

  var openDropdown = null;

  function csvEscape(val) {
    var s = String(val || '');
    if (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\t')) {
      return '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
  }

  function formatData(items, format, fields) {
    if (format === 'json') {
      return JSON.stringify(items, null, 2);
    }
    if (format === 'csv') {
      var header = fields.map(function (f) { return csvEscape(f.label); }).join(',');
      var rows = items.map(function (item) {
        return fields.map(function (f) { return csvEscape(item[f.key]); }).join(',');
      });
      return header + '\n' + rows.join('\n');
    }
    // txt - tab-separated
    var header = fields.map(function (f) { return f.label; }).join('\t');
    var rows = items.map(function (item) {
      return fields.map(function (f) { return item[f.key] || ''; }).join('\t');
    });
    return header + '\n' + rows.join('\n');
  }

  function downloadFile(content, filename, mimeType) {
    var blob = new Blob(['﻿' + content], { type: mimeType + ';charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function exportData(items, options) {
    if (!items || items.length === 0) return;
    var format = options.format || 'json';
    var fields = options.fields || [];
    var prefix = options.filename || 'export';
    var ext = format === 'json' ? 'json' : format === 'csv' ? 'csv' : 'txt';
    var mime = format === 'json' ? 'application/json' : format === 'csv' ? 'text/csv' : 'text/plain';
    var timestamp = new Date().toISOString().slice(0, 10);
    var content = formatData(items, format, fields);
    downloadFile(content, prefix + '_' + timestamp + '.' + ext, mime);
  }

  function createDropdown(btnEl, itemsGetter, fields, filename) {
    if (openDropdown) {
      openDropdown.remove();
      openDropdown = null;
      if (openDropdown === btnEl._dropdown) return;
    }

    var dd = document.createElement('div');
    dd.className = 'export-dropdown';
    var formats = [
      { key: 'json', label: 'JSON' },
      { key: 'csv', label: 'CSV' },
      { key: 'txt', label: 'TXT' },
    ];
    formats.forEach(function (f) {
      var opt = document.createElement('div');
      opt.className = 'export-dropdown-item';
      opt.textContent = f.label;
      opt.addEventListener('click', function (e) {
        e.stopPropagation();
        var items = itemsGetter();
        if (items && items.length > 0) {
          exportData(items, { format: f.key, fields: fields, filename: filename });
        }
        dd.remove();
        openDropdown = null;
      });
      dd.appendChild(opt);
    });

    btnEl._dropdown = dd;
    var rect = btnEl.getBoundingClientRect();
    dd.style.top = rect.bottom + 2 + 'px';
    dd.style.left = Math.max(0, rect.right - dd.offsetWidth) + 'px';
    document.body.appendChild(dd);
    openDropdown = dd;

    function closeIfOutside(e) {
      if (dd.contains(e.target)) return;
      dd.remove();
      openDropdown = null;
      document.removeEventListener('click', closeIfOutside);
    }
    setTimeout(function () {
      document.addEventListener('click', closeIfOutside);
    }, 0);
  }

  return {
    exportData: exportData,
    createDropdown: createDropdown,
  };
})();
