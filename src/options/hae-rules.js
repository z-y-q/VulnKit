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
  pink: '#ec4899',
  magenta: '#d946ef',
};

var VALID_COLORS = Object.keys(COLOR_MAP);
var VALID_SCOPES = ['response body', 'response', 'any', 'request', 'response header', 'any header'];
var VALID_ENGINES = ['nfa', 'dfa'];

function makeDefaultRule() {
  return {
    name: '',
    loaded: true,
    f_regex: '',
    s_regex: '',
    format: '{0}',
    color: 'gray',
    scope: 'response body',
    engine: 'nfa',
    sensitive: false,
  };
}

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
        ')</span>' +
        '<span class="hae-group-actions">' +
        '<button class="hae-btn-icon hae-btn-danger" title="删除分组" data-action="delete-group"' +
        ' data-group="' +
        escapeHtml(group.group) +
        '">&#10005;</button>' +
        '</span>';
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
          '<span class="hae-rule-name-link" data-action="edit-rule"' +
          ' data-group="' +
          escapeHtml(group.group) +
          '" data-rule="' +
          escapeHtml(rule.name) +
          '">' +
          escapeHtml(rule.name) +
          '</span>' +
          '<span class="hae-rule-scope">' +
          escapeHtml(rule.scope || '') +
          '</span>' +
          '<span class="hae-rule-actions">' +
          '<button class="hae-btn-icon" title="编辑" data-action="edit-rule"' +
          ' data-group="' +
          escapeHtml(group.group) +
          '" data-rule="' +
          escapeHtml(rule.name) +
          '">&#9998;</button>' +
          '<button class="hae-btn-icon hae-btn-danger" title="删除" data-action="delete-rule"' +
          ' data-group="' +
          escapeHtml(group.group) +
          '" data-rule="' +
          escapeHtml(rule.name) +
          '">&#10005;</button>' +
          '</span>';
        groupDiv.appendChild(ruleItem);
      });

      container.appendChild(groupDiv);
    });

    container.addEventListener('change', function (e) {
      if (e.target.classList.contains('hae-group-toggle')) {
        toggleHaeGroup(e.target.dataset.group, e.target.checked);
      } else if (e.target.classList.contains('hae-rule-toggle')) {
        toggleHaeRule(e.target.dataset.group, e.target.dataset.rule);
      }
    });

    container.addEventListener('click', function (e) {
      var btn = e.target.closest('[data-action]');
      if (!btn) return;
      var action = btn.dataset.action;
      var groupName = btn.dataset.group;
      var ruleName = btn.dataset.rule;
      if (action === 'edit-rule') {
        editHaeRule(groupName, ruleName);
      } else if (action === 'delete-rule') {
        deleteHaeRule(groupName, ruleName);
      } else if (action === 'delete-group') {
        deleteHaeGroup(groupName);
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

// ====== Rule Modal ======

function openRuleModal(opts) {
  var isEdit = opts.mode === 'edit';
  var title = isEdit ? '编辑规则' : '添加规则';
  var rule = opts.rule || makeDefaultRule();

  var colorOptions = VALID_COLORS.map(function (c) {
    return (
      '<option value="' + c + '"' + (c === rule.color ? ' selected' : '') + '>' + c + '</option>'
    );
  }).join('');

  var scopeOptions = VALID_SCOPES.map(function (s) {
    return (
      '<option value="' + s + '"' + (s === rule.scope ? ' selected' : '') + '>' + s + '</option>'
    );
  }).join('');

  var engineOptions = VALID_ENGINES.map(function (e) {
    return (
      '<option value="' + e + '"' + (e === rule.engine ? ' selected' : '') + '>' + e + '</option>'
    );
  }).join('');

  var overlay = document.createElement('div');
  overlay.className = 'hae-modal-overlay';

  var modal = document.createElement('div');
  modal.className = 'hae-modal';
  modal.innerHTML =
    '<div class="hae-modal-header">' +
    '<span class="hae-modal-title">' +
    title +
    '</span>' +
    '<button class="hae-modal-close" id="hae-modal-close-btn">&times;</button>' +
    '</div>' +
    '<div class="hae-modal-body">' +
    '<div class="hae-modal-section">' +
    '<div class="hae-modal-section-title">基本信息</div>' +
    '<div class="hae-form-grid">' +
    '<div class="hae-form-group">' +
    '<label class="hae-form-label" for="hae-modal-group">所属分组</label>' +
    '<select id="hae-modal-group"></select>' +
    '<input type="text" id="hae-modal-new-group" class="hae-new-group-input" placeholder="新分组名称">' +
    '</div>' +
    '<div class="hae-form-group">' +
    '<label class="hae-form-label" for="hae-modal-name">规则名称</label>' +
    '<input type="text" id="hae-modal-name" value="' +
    escapeHtml(rule.name) +
    '" placeholder="输入规则名称">' +
    '</div>' +
    '</div>' +
    '</div>' +
    '<div class="hae-modal-section">' +
    '<div class="hae-modal-section-title">正则表达式</div>' +
    '<div class="hae-form-vertical">' +
    '<div class="hae-form-group">' +
    '<label class="hae-form-label" for="hae-modal-fregex">主正则 <span class="hae-form-hint">f_regex — 必填</span></label>' +
    '<textarea id="hae-modal-fregex" rows="3" placeholder="输入正则表达式" spellcheck="false">' +
    escapeHtml(rule.f_regex) +
    '</textarea>' +
    '</div>' +
    '<div class="hae-form-group">' +
    '<label class="hae-form-label" for="hae-modal-sregex">次正则 <span class="hae-form-hint">s_regex — 可选</span></label>' +
    '<textarea id="hae-modal-sregex" rows="2" placeholder="留空表示不使用" spellcheck="false">' +
    escapeHtml(rule.s_regex) +
    '</textarea>' +
    '</div>' +
    '</div>' +
    '</div>' +
    '<div class="hae-modal-section">' +
    '<div class="hae-modal-section-title">匹配设置</div>' +
    '<div class="hae-form-grid hae-form-grid-3">' +
    '<div class="hae-form-group">' +
    '<label class="hae-form-label" for="hae-modal-color">颜色</label>' +
    '<div class="hae-color-select">' +
    '<span class="hae-color-preview" id="hae-modal-color-preview"></span>' +
    '<select id="hae-modal-color">' +
    colorOptions +
    '</select>' +
    '</div>' +
    '</div>' +
    '<div class="hae-form-group">' +
    '<label class="hae-form-label" for="hae-modal-scope">匹配范围</label>' +
    '<select id="hae-modal-scope">' +
    scopeOptions +
    '</select>' +
    '</div>' +
    '<div class="hae-form-group">' +
    '<label class="hae-form-label" for="hae-modal-engine">引擎</label>' +
    '<select id="hae-modal-engine">' +
    engineOptions +
    '</select>' +
    '</div>' +
    '</div>' +
    '<div class="hae-form-grid hae-form-grid-3" style="margin-top:10px">' +
    '<div class="hae-form-group">' +
    '<label class="hae-form-label" for="hae-modal-format">输出格式</label>' +
    '<input type="text" id="hae-modal-format" value="' +
    escapeHtml(rule.format) +
    '" placeholder="{0}">' +
    '</div>' +
    '<div class="hae-form-group hae-form-group-check">' +
    '<label class="hae-form-check-label">' +
    '<input type="checkbox" id="hae-modal-loaded"' +
    (rule.loaded ? ' checked' : '') +
    '> 启用规则' +
    '</label>' +
    '</div>' +
    '<div class="hae-form-group hae-form-group-check">' +
    '<label class="hae-form-check-label">' +
    '<input type="checkbox" id="hae-modal-sensitive"' +
    (rule.sensitive ? ' checked' : '') +
    '> 区分大小写' +
    '</label>' +
    '</div>' +
    '</div>' +
    '</div>' +
    '</div>' +
    '<div class="hae-modal-footer">' +
    '<div class="hae-modal-footer-left">' +
    '<button class="btn btn-secondary btn-sm" id="hae-modal-compile">编译验证</button>' +
    '<span class="hae-modal-status" id="hae-modal-status"></span>' +
    '</div>' +
    '<div class="hae-modal-footer-right">' +
    '<button class="btn btn-outline btn-sm" id="hae-modal-cancel">取消</button>' +
    '<button class="btn btn-primary btn-sm" id="hae-modal-save">保存</button>' +
    '</div>' +
    '</div>';

  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  chrome.storage.local.get('haeRules', function (result) {
    var groups = result.haeRules || [];
    var html = groups
      .map(function (g) {
        return (
          '<option value="' +
          escapeHtml(g.group) +
          '"' +
          (g.group === opts.groupName ? ' selected' : '') +
          '>' +
          escapeHtml(g.group) +
          '</option>'
        );
      })
      .join('');
    html += '<option value="__new__">+ 新建分组</option>';
    var groupSelect = modal.querySelector('#hae-modal-group');
    groupSelect.innerHTML = html;
  });

  var groupSelect = modal.querySelector('#hae-modal-group');
  var newGroupInput = modal.querySelector('#hae-modal-new-group');
  groupSelect.addEventListener('change', function () {
    newGroupInput.classList.toggle('visible', this.value === '__new__');
  });

  var colorPreview = modal.querySelector('#hae-modal-color-preview');
  var colorSelect = modal.querySelector('#hae-modal-color');
  function updateColorPreview() {
    colorPreview.style.backgroundColor = COLOR_MAP[colorSelect.value] || '#999';
  }
  colorSelect.addEventListener('change', updateColorPreview);
  updateColorPreview();

  modal.querySelector('#hae-modal-compile').addEventListener('click', function () {
    compileRuleInModal(modal);
  });

  function closeModal() {
    if (overlay.parentNode) document.body.removeChild(overlay);
  }

  modal.querySelector('#hae-modal-close-btn').addEventListener('click', closeModal);
  modal.querySelector('#hae-modal-cancel').addEventListener('click', closeModal);
  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) closeModal();
  });
  document.addEventListener('keydown', function escHandler(e) {
    if (e.key === 'Escape') {
      closeModal();
      document.removeEventListener('keydown', escHandler);
    }
  });

  modal.querySelector('#hae-modal-save').addEventListener('click', function () {
    var name = modal.querySelector('#hae-modal-name').value.trim();
    if (!name) {
      setModalStatus(modal, '规则名称不能为空', 'error');
      return;
    }
    var fRegex = modal.querySelector('#hae-modal-fregex').value;
    if (!fRegex) {
      setModalStatus(modal, '主正则不能为空', 'error');
      return;
    }

    var selectedGroup = groupSelect.value;
    var targetGroup = selectedGroup === '__new__' ? newGroupInput.value.trim() : selectedGroup;
    if (!targetGroup) {
      setModalStatus(modal, '请输入或选择分组名称', 'error');
      return;
    }

    var ruleData = {
      name: name,
      loaded: modal.querySelector('#hae-modal-loaded').checked,
      f_regex: fRegex,
      s_regex: modal.querySelector('#hae-modal-sregex').value,
      format: modal.querySelector('#hae-modal-format').value || '{0}',
      color: modal.querySelector('#hae-modal-color').value,
      scope: modal.querySelector('#hae-modal-scope').value,
      engine: modal.querySelector('#hae-modal-engine').value,
      sensitive: modal.querySelector('#hae-modal-sensitive').checked,
    };

    closeModal();
    opts.onSave(targetGroup, ruleData);
  });
}

function setModalStatus(modal, text, type) {
  var el = modal.querySelector('#hae-modal-status');
  if (!el) return;
  el.textContent = text;
  el.className = 'hae-modal-status ' + (type || '');
}

function compileRuleInModal(modal) {
  var fRegex = modal.querySelector('#hae-modal-fregex').value;
  var sRegex = modal.querySelector('#hae-modal-sregex').value;

  if (!fRegex) {
    setModalStatus(modal, '主正则为空', 'error');
    return;
  }
  try {
    new RegExp(fRegex);
  } catch (e) {
    setModalStatus(modal, '主正则无效: ' + e.message, 'error');
    return;
  }

  if (sRegex) {
    try {
      new RegExp(sRegex);
    } catch (e) {
      setModalStatus(modal, '次正则无效: ' + e.message, 'error');
      return;
    }
  }

  setModalStatus(modal, '正则验证通过', 'success');
}

function editHaeRule(groupName, ruleName) {
  chrome.storage.local.get('haeRules', function (result) {
    var rules = result.haeRules;
    if (!rules) return;
    var group = rules.find(function (g) {
      return g.group === groupName;
    });
    if (!group) return;
    var rule = (group.rules || []).find(function (r) {
      return r.name === ruleName;
    });
    if (!rule) return;

    openRuleModal({
      mode: 'edit',
      groupName: groupName,
      ruleName: ruleName,
      rule: Object.assign({}, rule),
      onSave: function (targetGroup, ruleData) {
        chrome.storage.local.get('haeRules', function (result2) {
          var rules2 = result2.haeRules || [];

          if (targetGroup !== groupName) {
            var oldGroup = rules2.find(function (g) {
              return g.group === groupName;
            });
            if (oldGroup) {
              oldGroup.rules = (oldGroup.rules || []).filter(function (r) {
                return r.name !== ruleName;
              });
            }
            var newGroup = rules2.find(function (g) {
              return g.group === targetGroup;
            });
            if (!newGroup) {
              newGroup = { group: targetGroup, rules: [] };
              rules2 = rules2.concat([newGroup]);
            }
            newGroup.rules = newGroup.rules.concat([ruleData]);
          } else {
            rules2 = rules2.map(function (g) {
              if (g.group !== targetGroup) return g;
              return Object.assign({}, g, {
                rules: g.rules.map(function (r) {
                  return r.name === ruleName ? ruleData : r;
                }),
              });
            });
          }

          rules2 = rules2.filter(function (g) {
            return g.rules && g.rules.length > 0;
          });

          chrome.storage.local.set({ haeRules: rules2 }, function () {
            renderHaeRules();
            showStatus('规则已更新', 'success');
          });
        });
      },
    });
  });
}

function addHaeRule() {
  chrome.storage.local.get('haeRules', function (result) {
    var rules = result.haeRules || [];
    if (rules.length === 0) {
      showStatus('请先导入或重置默认规则', 'error');
      return;
    }

    openRuleModal({
      mode: 'add',
      groupName: rules[0].group,
      rule: makeDefaultRule(),
      onSave: function (targetGroup, ruleData) {
        chrome.storage.local.get('haeRules', function (result2) {
          var rules2 = result2.haeRules || [];
          var group = rules2.find(function (g) {
            return g.group === targetGroup;
          });
          if (!group) {
            group = { group: targetGroup, rules: [] };
            rules2 = rules2.concat([group]);
          }

          var dupName = (group.rules || []).some(function (r) {
            return r.name === ruleData.name;
          });
          if (dupName) {
            renderHaeRules();
            showStatus(
              '规则 "' + ruleData.name + '" 在分组 "' + targetGroup + '" 中已存在',
              'error'
            );
            return;
          }

          group.rules = group.rules.concat([ruleData]);
          chrome.storage.local.set({ haeRules: rules2 }, function () {
            renderHaeRules();
            showStatus('规则已添加到 ' + targetGroup, 'success');
          });
        });
      },
    });
  });
}

function deleteHaeRule(groupName, ruleName) {
  if (!confirm('确定删除规则 "' + ruleName + '" 吗？')) return;

  chrome.storage.local.get('haeRules', function (result) {
    var rules = result.haeRules || [];
    var updated = rules
      .map(function (g) {
        if (g.group !== groupName) return g;
        return Object.assign({}, g, {
          rules: g.rules.filter(function (r) {
            return r.name !== ruleName;
          }),
        });
      })
      .filter(function (g) {
        return g.rules && g.rules.length > 0;
      });

    chrome.storage.local.set({ haeRules: updated }, function () {
      renderHaeRules();
      showStatus('规则已删除', 'success');
    });
  });
}

function deleteHaeGroup(groupName) {
  chrome.storage.local.get('haeRules', function (result) {
    var rules = result.haeRules || [];
    var group = rules.find(function (g) {
      return g.group === groupName;
    });
    var ruleCount = group && group.rules ? group.rules.length : 0;

    if (!confirm('确定删除分组 "' + groupName + '" 及其 ' + ruleCount + ' 条规则吗？')) return;

    var updated = rules.filter(function (g) {
      return g.group !== groupName;
    });
    chrome.storage.local.set({ haeRules: updated }, function () {
      renderHaeRules();
      showStatus('分组 "' + groupName + '" 已删除', 'success');
    });
  });
}

function addHaeGroup() {
  var groupName = prompt('输入新分组名称:');
  if (!groupName || !groupName.trim()) return;
  groupName = groupName.trim();

  chrome.storage.local.get('haeRules', function (result) {
    var rules = result.haeRules || [];
    var exists = rules.some(function (g) {
      return g.group === groupName;
    });
    if (exists) {
      showStatus('分组 "' + groupName + '" 已存在', 'error');
      return;
    }

    rules = rules.concat([{ group: groupName, rules: [] }]);
    chrome.storage.local.set({ haeRules: rules }, function () {
      renderHaeRules();
      showStatus('分组 "' + groupName + '" 已创建', 'success');
    });
  });
}

function validateAllHaeRules() {
  chrome.storage.local.get('haeRules', function (result) {
    var rules = result.haeRules;
    if (!rules || !Array.isArray(rules)) {
      showStatus('未找到规则数据', 'error');
      return;
    }

    var existingResults = document.querySelector('.hae-validate-results');
    if (existingResults) existingResults.remove();

    var totalRules = 0;
    var validCount = 0;
    var invalidList = [];

    rules.forEach(function (group) {
      if (!group.rules) return;
      group.rules.forEach(function (rule) {
        totalRules++;
        if (!rule.f_regex) {
          invalidList.push({ group: group.group, name: rule.name, error: '主正则为空' });
          return;
        }
        try {
          new RegExp(rule.f_regex);
        } catch (e) {
          invalidList.push({ group: group.group, name: rule.name, error: 'f_regex: ' + e.message });
          return;
        }
        if (rule.s_regex) {
          try {
            new RegExp(rule.s_regex);
          } catch (e) {
            invalidList.push({
              group: group.group,
              name: rule.name,
              error: 's_regex: ' + e.message,
            });
            return;
          }
        }
        validCount++;
      });
    });

    var container = $('hae-rules-container');
    if (!container) return;

    var resultsDiv = document.createElement('div');
    resultsDiv.className = 'hae-validate-results';

    var summaryHtml =
      '<div style="margin-bottom:6px;font-weight:600;color:var(--opt-text)">' +
      '验证完成: ' +
      validCount +
      '/' +
      totalRules +
      ' 条规则有效';
    summaryHtml +=
      invalidList.length === 0 ? ' -- 全部通过</div>' : ', ' + invalidList.length + ' 条无效</div>';
    resultsDiv.innerHTML = summaryHtml;

    if (invalidList.length > 0) {
      invalidList.forEach(function (item) {
        var row = document.createElement('div');
        row.className = 'hae-validate-item invalid';
        row.innerHTML =
          '<span>' +
          escapeHtml(item.group) +
          ' / ' +
          escapeHtml(item.name) +
          '</span>' +
          '<span class="hae-validate-error">' +
          escapeHtml(item.error) +
          '</span>';
        resultsDiv.appendChild(row);
      });
    }

    container.parentNode.insertBefore(resultsDiv, container);

    if (invalidList.length === 0) {
      showStatus('所有 ' + totalRules + ' 条规则验证通过', 'success');
    } else {
      showStatus(invalidList.length + ' 条规则验证失败', 'error');
    }
  });
}
