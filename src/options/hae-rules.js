// 灵眸 - HaE Rules Management (Options Page)
// Classic script — loaded before options.js

function quoteYamlString(str) {
  if (!str) return "''";
  if (/[:#{}[\],&*?|>!%@`'"\n]/.test(str) || str === '' || str === 'true' || str === 'false') {
    return '"' + str.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n') + '"';
  }
  return str;
}

function parseYamlRules(yamlText) {
  var lines = yamlText.split('\n');
  var groups = [];
  var currentGroup = null;
  var currentRule = null;
  var inMultiLine = false;
  var multiLineKey = '';
  var multiLineContent = '';

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    var trimmed = line.trim();

    if (trimmed === '' || trimmed.startsWith('#')) {
      if (inMultiLine) multiLineContent += '\n';
      continue;
    }

    if (inMultiLine) {
      if (trimmed.match(/^['"][^'"]*['"]\s*$/)) {
        multiLineContent = trimmed.replace(/^['"]|['"]$/g, '');
        if (currentRule && multiLineKey) currentRule[multiLineKey] = multiLineContent;
        inMultiLine = false;
        multiLineKey = '';
        multiLineContent = '';
      } else {
        multiLineContent += '\n' + trimmed;
      }
      continue;
    }

    var indent = line.search(/\S/);
    if (indent === -1) continue;
    if (trimmed === 'rules:') continue;

    if (indent === 2 && trimmed.startsWith('- group:')) {
      currentGroup = {
        group: trimmed.replace(/^- group:\s*/, '').replace(/^['"]|['"]$/g, ''),
        rules: [],
      };
      groups.push(currentGroup);
      currentRule = null;
      continue;
    }

    if (indent === 4 && trimmed.startsWith('- name:')) {
      currentRule = {
        name: trimmed.replace(/^- name:\s*/, '').replace(/^['"]|['"]$/g, ''),
        loaded: true,
        f_regex: '',
        s_regex: '',
        format: '{0}',
        color: 'gray',
        scope: 'response body',
        engine: 'nfa',
        sensitive: false,
      };
      if (currentGroup) currentGroup.rules.push(currentRule);
      continue;
    }

    if (indent >= 8 && currentRule) {
      var kvMatch = trimmed.match(/^(\w+)\s*:\s*(.*)$/);
      if (kvMatch) {
        var key = kvMatch[1];
        var val = (kvMatch[2] || '').trim();
        val = val.replace(/^['"]|['"]$/g, '');
        if (val === 'true') val = true;
        else if (val === 'false') val = false;
        else if (val === "''" || val === '""') val = '';
        currentRule[key] = val;
      } else if (trimmed.endsWith(':') || trimmed.endsWith('|')) {
        var rawKey = trimmed.replace(/[:|]\s*$/, '').trim();
        inMultiLine = true;
        multiLineKey = rawKey;
        multiLineContent = '';
      }
    }
  }

  return groups;
}

function rulesToYaml(rules) {
  var yaml = 'rules:\n';
  rules.forEach(function (group) {
    yaml += '  - group: ' + group.group + '\n    rules:\n';
    (group.rules || []).forEach(function (rule) {
      yaml += '      - name: ' + quoteYamlString(rule.name || '') + '\n';
      yaml += '        loaded: ' + rule.loaded + '\n';
      yaml += '        f_regex: ' + quoteYamlString(rule.f_regex || '') + '\n';
      yaml += '        s_regex: ' + quoteYamlString(rule.s_regex || '') + '\n';
      yaml += '        format: ' + quoteYamlString(rule.format || '{0}') + '\n';
      yaml += '        color: ' + quoteYamlString(rule.color || 'gray') + '\n';
      yaml += '        scope: ' + quoteYamlString(rule.scope || 'response body') + '\n';
      yaml += '        engine: ' + quoteYamlString(rule.engine || 'nfa') + '\n';
      yaml += '        sensitive: ' + (rule.sensitive || false) + '\n';
    });
  });
  return yaml;
}

var COLOR_MAP = {
  red: '#e74c3c',
  orange: '#e67e22',
  yellow: '#f1c40f',
  green: '#27ae60',
  cyan: '#00bcd4',
  blue: '#4A90E2',
  purple: '#9b59b6',
  gray: '#999',
};

function renderHaeRules() {
  chrome.storage.local.get('haeRules', function (result) {
    var rules = result.haeRules;
    if (!rules || !Array.isArray(rules)) {
      showStatus('未找到规则数据，请先使用插件收集一次数据以初始化规则', 'info');
      return;
    }

    var container = $('hae-rules-container');
    if (!container) return;
    container.innerHTML = '';

    var totalRules = 0;
    var enabledRules = 0;

    rules.forEach(function (group) {
      if (!group.rules || group.rules.length === 0) return;

      var groupDiv = document.createElement('div');
      groupDiv.className = 'hae-group';

      var groupAllLoaded = group.rules.every(function (r) {
        return r.loaded;
      });
      var groupHeader = document.createElement('div');
      groupHeader.className = 'hae-group-header';
      groupHeader.innerHTML =
        '<input type="checkbox"' +
        (groupAllLoaded ? ' checked' : '') +
        ' data-group="' +
        escapeHtml(group.group) +
        '" class="hae-group-toggle">' +
        '<span>' +
        escapeHtml(group.group) +
        '</span>' +
        '<span class="hae-rule-count">(' +
        group.rules.filter(function (r) {
          return r.loaded;
        }).length +
        '/' +
        group.rules.length +
        ')</span>';
      groupDiv.appendChild(groupHeader);

      group.rules.forEach(function (rule) {
        totalRules++;
        if (rule.loaded) enabledRules++;
        var colorStyle = COLOR_MAP[rule.color] ? 'background:' + COLOR_MAP[rule.color] : '';
        var ruleItem = document.createElement('div');
        ruleItem.className = 'hae-rule-item';
        ruleItem.innerHTML =
          '<input type="checkbox"' +
          (rule.loaded ? ' checked' : '') +
          ' data-group="' +
          escapeHtml(group.group) +
          '" data-rule="' +
          escapeHtml(rule.name) +
          '" class="hae-rule-toggle">' +
          '<span class="hae-color-dot" style="' +
          colorStyle +
          '"></span>' +
          '<span>' +
          escapeHtml(rule.name) +
          '</span>' +
          '<span class="hae-rule-scope">' +
          escapeHtml(rule.scope || '') +
          '</span>';
        groupDiv.appendChild(ruleItem);
      });

      container.appendChild(groupDiv);
    });

    container.addEventListener('change', function (e) {
      if (
        !e.target.classList.contains('hae-group-toggle') &&
        !e.target.classList.contains('hae-rule-toggle')
      )
        return;
      if (e.target.classList.contains('hae-group-toggle')) {
        toggleHaeGroup(e.target.dataset.group, e.target.checked);
      } else {
        toggleHaeRule(e.target.dataset.group, e.target.dataset.rule);
      }
    });
  });
}

function toggleHaeRule(groupName, ruleName) {
  chrome.storage.local.get('haeRules', function (result) {
    var rules = result.haeRules;
    if (!rules) return;
    var updated = rules.map(function (g) {
      if (g.group !== groupName) return g;
      return Object.assign({}, g, {
        rules: g.rules.map(function (r) {
          if (r.name !== ruleName) return r;
          return Object.assign({}, r, { loaded: !r.loaded });
        }),
      });
    });
    chrome.storage.local.set({ haeRules: updated }, function () {
      renderHaeRules();
    });
  });
}

function toggleHaeGroup(groupName, enable) {
  chrome.storage.local.get('haeRules', function (result) {
    var rules = result.haeRules;
    if (!rules) return;
    var updated = rules.map(function (g) {
      if (g.group !== groupName) return g;
      return Object.assign({}, g, {
        rules: g.rules.map(function (r) {
          return Object.assign({}, r, { loaded: enable });
        }),
      });
    });
    chrome.storage.local.set({ haeRules: updated }, function () {
      renderHaeRules();
    });
  });
}

function exportHaeYaml() {
  chrome.storage.local.get('haeRules', function (result) {
    if (!result.haeRules) {
      showStatus('没有规则数据可导出', 'error');
      return;
    }
    var yaml = rulesToYaml(result.haeRules);
    var blob = new Blob([yaml], { type: 'text/yaml' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'lingmou-hae-rules.yaml';
    a.click();
    URL.revokeObjectURL(url);
    showStatus('规则已导出为 YAML', 'success');
  });
}

function importHaeYaml() {
  var input = document.createElement('input');
  input.type = 'file';
  input.accept = '.yaml,.yml,.json';
  input.onchange = function (e) {
    var file = e.target.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function (evt) {
      try {
        var text = evt.target.result;
        var parsed = parseYamlRules(text);
        if (parsed.length === 0) {
          try {
            parsed = JSON.parse(text);
            if (!Array.isArray(parsed)) {
              showStatus('规则格式错误', 'error');
              return;
            }
          } catch (ex) {
            showStatus('无法解析规则文件', 'error');
            return;
          }
        }
        chrome.storage.local.get('haeRules', function (result) {
          var existing = result.haeRules || [];
          var existingGroupNames = {};
          existing.forEach(function (g) {
            existingGroupNames[g.group] = true;
          });

          var merged = existing.map(function (g) {
            var incoming = parsed.find(function (p) {
              return p.group === g.group;
            });
            if (!incoming || !Array.isArray(incoming.rules)) return g;
            var incomingNames = {};
            incoming.rules.forEach(function (r) {
              incomingNames[r.name] = true;
            });
            return Object.assign({}, g, {
              rules: incoming.rules.map(function (r) {
                return Object.assign({}, r, { loaded: r.loaded !== false });
              }),
            });
          });

          parsed.forEach(function (p) {
            if (!existingGroupNames[p.group]) {
              merged.push(
                Object.assign({}, p, {
                  rules: (p.rules || []).map(function (r) {
                    return Object.assign({}, r, { loaded: r.loaded !== false });
                  }),
                })
              );
            }
          });

          chrome.storage.local.set({ haeRules: merged }, function () {
            renderHaeRules();
            showStatus('规则已导入（合并 ' + merged.length + ' 组）', 'success');
          });
        });
      } catch (ex) {
        showStatus('导入失败: ' + ex.message, 'error');
      }
    };
    reader.readAsText(file);
  };
  input.click();
}

function resetHaeRules() {
  if (!confirm('确定要恢复为默认规则吗？自定义规则将被覆盖。')) return;
  fetch('../popup/vk-hae-default-rules.js')
    .then(function (r) {
      return r.text();
    })
    .then(function (src) {
      var cleaned = src.replace(/export\s+/, '');
      var fn = new Function(cleaned + '\nreturn DEFAULT_RULES;');
      var defaults = fn();
      if (!Array.isArray(defaults) || defaults.length === 0) throw new Error('No rules found');
      chrome.storage.local.set({ haeRules: JSON.parse(JSON.stringify(defaults)) }, function () {
        renderHaeRules();
        showStatus('规则已恢复为默认', 'success');
      });
    })
    .catch(function (err) {
      showStatus('恢复默认规则失败: ' + err.message, 'error');
    });
}
