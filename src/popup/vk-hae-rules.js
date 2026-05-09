// 灵眸 - HaE Rules Engine
'use strict';

import { DEFAULT_RULES } from './vk-hae-default-rules.js';

const STORAGE_KEY = 'haeRules';
const PAGE_SCOPE = ['response body', 'response', 'any', 'request', 'response header', 'any header'];
function isPageScope(scope) {
  return PAGE_SCOPE.indexOf(scope) !== -1;
}

function applyFormat(format, captures) {
  let result = format;
  for (let i = 0; i < captures.length; i++) {
    const placeholder = `{${i}}`;
    while (result.indexOf(placeholder) !== -1) {
      result = result.replace(placeholder, captures[i] || '');
    }
  }
  return result;
}

function matchSingleRule(text, rule) {
  if (!rule.loaded || !rule.f_regex) return [];

  if (!isPageScope(rule.scope)) return [];

  try {
    const flags = rule.sensitive ? 'g' : 'gi';
    const regex = new RegExp(rule.f_regex, flags);
    const results = [];
    let match;
    const seen = {};

    while ((match = regex.exec(text)) !== null) {
      const captures = [];
      for (let i = 1; i < match.length; i++) {
        captures.push(match[i] || '');
      }

      const value = applyFormat(rule.format || '{0}', captures);
      if (!value || value.trim() === '') continue;

      if (rule.s_regex && rule.s_regex.trim() !== '') {
        try {
          const sFlags = rule.sensitive ? '' : 'i';
          const sRegex = new RegExp(rule.s_regex, sFlags);
          if (!sRegex.test(match[0])) continue;
        } catch (e) {
          // invalid s_regex, skip filter
        }
      }

      let key = `${rule.name}::${value}`;
      if (seen[key]) continue;
      seen[key] = true;

      results.push({
        name: rule.name,
        value: value,
        color: rule.color || 'gray',
      });
    }

    return results;
  } catch (e) {
    return [];
  }
}

function matchRules(text, rules) {
  const grouped = {};
  rules.forEach(function (group) {
    let groupResults = [];
    (group.rules || []).forEach(function (rule) {
      const matches = matchSingleRule(text, rule);
      groupResults = groupResults.concat(matches);
    });
    if (groupResults.length > 0) {
      grouped[group.group] = groupResults;
    }
  });
  return grouped;
}

function getGroups(rules) {
  return rules.map(function (g) {
    return g.group;
  });
}

function getDefaultRules() {
  return JSON.parse(JSON.stringify(DEFAULT_RULES));
}

function parseYaml(yamlText) {
  const lines = yamlText.split('\n');
  const groups = [];
  let currentGroup = null;
  let currentRule = null;
  let inMultiLine = false;
  let multiLineKey = '';
  let multiLineContent = '';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let trimmed = line.trim();

    if (trimmed === '' || trimmed.startsWith('#')) {
      if (inMultiLine) {
        multiLineContent += '\n';
      }
      continue;
    }

    if (inMultiLine) {
      if (trimmed.match(/^['"][^'"]*['"]\s*$/)) {
        multiLineContent = trimmed.replace(/^['"]|['"]$/g, '');
        if (currentRule && multiLineKey) {
          currentRule[multiLineKey] = multiLineContent;
        }
        inMultiLine = false;
        multiLineKey = '';
        multiLineContent = '';
      } else {
        multiLineContent += `\n${trimmed}`;
      }
      continue;
    }

    let indent = line.search(/\S/);
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
      const kvMatch = trimmed.match(/^(\w+)\s*:\s*(.*)$/);
      if (kvMatch) {
        const key = kvMatch[1];
        let val = (kvMatch[2] || '').trim();
        val = val.replace(/^['"]|['"]$/g, '');
        if (val === 'true') val = true;
        else if (val === 'false') val = false;
        else if (val === "''" || val === '""') val = '';
        currentRule[key] = val;
      } else if (trimmed.endsWith(':') || trimmed.endsWith('|')) {
        const rawKey = trimmed.replace(/[:|]\s*$/, '').trim();
        inMultiLine = true;
        multiLineKey = rawKey;
        multiLineContent = '';
      }
    }
  }

  return groups;
}

function rulesToYaml(rules) {
  let yaml = 'rules:\n';
  rules.forEach(function (group) {
    yaml += `  - group: ${group.group}\n    rules:\n`;
    (group.rules || []).forEach(function (rule) {
      yaml += `      - name: ${quoteYamlString(rule.name || '')}\n        loaded: ${rule.loaded}\n        f_regex: ${quoteYamlString(rule.f_regex || '')}\n        s_regex: ${quoteYamlString(rule.s_regex || '')}\n        format: ${quoteYamlString(rule.format || '{0}')}\n        color: ${quoteYamlString(rule.color || 'gray')}\n        scope: ${quoteYamlString(rule.scope || 'response body')}\n        engine: ${quoteYamlString(rule.engine || 'nfa')}\n        sensitive: ${rule.sensitive || false}\n`;
    });
  });
  return yaml;
}

function quoteYamlString(str) {
  if (!str) return "''";
  if (/[:#{}[\],&*?|>!%@`'"\n]/.test(str) || str === '' || str === 'true' || str === 'false') {
    return `"${str.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}"`;
  }
  return str;
}

function loadRules(callback) {
  chrome.storage.local.get(STORAGE_KEY, function (result) {
    if (result[STORAGE_KEY]) {
      try {
        callback(JSON.parse(JSON.stringify(result[STORAGE_KEY])));
        return;
      } catch (e) {
        // corrupted, use default
      }
    }
    const defaults = getDefaultRules();
    saveRules(defaults);
    callback(defaults);
  });
}

function saveRules(rules) {
  chrome.storage.local.set({ haeRules: JSON.parse(JSON.stringify(rules)) });
}

function toggleRule(rules, groupName, ruleName) {
  return rules.map(function (g) {
    if (g.group !== groupName) return g;
    return {
      group: g.group,
      rules: g.rules.map(function (r) {
        if (r.name !== ruleName) return r;
        return Object.assign({}, r, { loaded: !r.loaded });
      }),
    };
  });
}

function importRules(yamlText) {
  let parsed = parseYaml(yamlText);
  if (parsed.length === 0) {
    try {
      parsed = JSON.parse(yamlText);
      if (!Array.isArray(parsed)) return null;
    } catch (e) {
      return null;
    }
  }
  return parsed;
}

export {
  getDefaultRules,
  matchRules,
  getGroups,
  parseYaml,
  rulesToYaml,
  loadRules,
  saveRules,
  toggleRule,
  importRules,
  isPageScope,
};
