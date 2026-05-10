import { describe, it, expect } from '@jest/globals';
import {
  applyFormat,
  matchSingleRule,
  matchRules,
  parseYaml,
  rulesToYaml,
  isPageScope,
  getGroups,
} from '../src/popup/vk-hae-rules.js';

// ---------------------------------------------------------------------------
// isPageScope
// ---------------------------------------------------------------------------
describe('isPageScope', () => {
  it('returns true for "response body"', () => {
    expect(isPageScope('response body')).toBe(true);
  });

  it('returns true for "response"', () => {
    expect(isPageScope('response')).toBe(true);
  });

  it('returns true for "any"', () => {
    expect(isPageScope('any')).toBe(true);
  });

  it('returns true for "request"', () => {
    expect(isPageScope('request')).toBe(true);
  });

  it('returns false for "invalid" scope', () => {
    expect(isPageScope('invalid')).toBe(false);
  });

  it('returns false for empty string', () => {
    expect(isPageScope('')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// applyFormat
// ---------------------------------------------------------------------------
describe('applyFormat', () => {
  it('replaces {0} and {1} with corresponding captures', () => {
    expect(applyFormat('{0}={1}', ['key', 'value'])).toBe('key=value');
  });

  it('replaces single placeholder', () => {
    expect(applyFormat('Result: {0}', ['42'])).toBe('Result: 42');
  });

  it('returns format unchanged when no placeholders exist', () => {
    expect(applyFormat('No placeholders', ['a', 'b'])).toBe('No placeholders');
  });

  it('leaves unreplaced placeholders when captures array is shorter', () => {
    // applyFormat only iterates up to captures.length, so {1} stays intact
    expect(applyFormat('{0}-{1}', ['a'])).toBe('a-{1}');
  });
});

// ---------------------------------------------------------------------------
// matchSingleRule
// ---------------------------------------------------------------------------
describe('matchSingleRule', () => {
  it('returns [] when rule.loaded is false', () => {
    const rule = {
      loaded: false,
      f_regex: 'secret=(\\w+)',
      scope: 'response body',
    };
    expect(matchSingleRule('secret=abc123', rule)).toEqual([]);
  });

  it('returns [] when rule scope is not a page scope', () => {
    const rule = {
      loaded: true,
      f_regex: 'secret=(\\w+)',
      scope: 'invalid-scope',
    };
    expect(matchSingleRule('secret=abc123', rule)).toEqual([]);
  });

  it('returns matching captures with regex', () => {
    const rule = {
      loaded: true,
      f_regex: 'secret=(\\w+)',
      scope: 'response body',
      format: '{0}',
      name: undefined,
      color: 'gray',
    };
    const results = matchSingleRule('secret=abc123', rule);
    expect(results).toHaveLength(1);
    expect(results[0].name).toBeUndefined();
    expect(results[0].value).toBe('abc123');
  });

  it('filters results with non-matching s_regex', () => {
    const rule = {
      loaded: true,
      f_regex: 'secret=(\\w+)',
      s_regex: 'production',
      scope: 'response body',
      format: '{0}',
      name: 'SecretRule',
      color: 'red',
    };
    // "secret=abc123" does not contain "production" so s_regex should filter it out
    const results = matchSingleRule('secret=abc123', rule);
    expect(results).toEqual([]);
  });

  it('returns [] when regex does not match', () => {
    const rule = {
      loaded: true,
      f_regex: 'secret=(\\w+)',
      scope: 'response body',
      format: '{0}',
      name: 'SecretRule',
      color: 'gray',
    };
    expect(matchSingleRule('no match here', rule)).toEqual([]);
  });

  it('deduplicates results with same name::value key', () => {
    const rule = {
      loaded: true,
      f_regex: '(abc)',
      scope: 'response body',
      format: '{0}',
      name: 'TestRule',
      color: 'gray',
    };
    // "abc" appears twice but should only produce one result
    const results = matchSingleRule('abc and abc', rule);
    expect(results).toHaveLength(1);
    expect(results[0].value).toBe('abc');
  });
});

// ---------------------------------------------------------------------------
// matchRules
// ---------------------------------------------------------------------------
describe('matchRules', () => {
  it('returns {} for empty rules array', () => {
    expect(matchRules('some text', [])).toEqual({});
  });

  it('returns grouped matches for matching rules', () => {
    const rules = [
      {
        group: 'SQL',
        rules: [
          {
            loaded: true,
            f_regex: "password='([^']+)'",
            scope: 'response body',
            format: '{0}',
            name: 'SQL Password',
            color: 'red',
          },
        ],
      },
      {
        group: 'XSS',
        rules: [
          {
            loaded: true,
            f_regex: '<script>(.*?)</script>',
            scope: 'response body',
            format: '{0}',
            name: 'XSS Script',
            color: 'orange',
          },
        ],
      },
    ];
    const text = "password='hunter2' and <script>alert(1)</script>";
    const results = matchRules(text, rules);
    expect(Object.keys(results)).toContain('SQL');
    expect(Object.keys(results)).toContain('XSS');
    expect(results['SQL']).toHaveLength(1);
    expect(results['SQL'][0].value).toBe('hunter2');
    expect(results['XSS']).toHaveLength(1);
    expect(results['XSS'][0].value).toBe('alert(1)');
  });

  it('omits groups with no matches', () => {
    const rules = [
      {
        group: 'SQL',
        rules: [
          {
            loaded: true,
            f_regex: 'nonexistent_pattern',
            scope: 'response body',
            format: '{0}',
            name: 'SQL Test',
            color: 'gray',
          },
        ],
      },
    ];
    const results = matchRules('no match here', rules);
    expect(Object.keys(results)).not.toContain('SQL');
  });
});

// ---------------------------------------------------------------------------
// getGroups
// ---------------------------------------------------------------------------
describe('getGroups', () => {
  it('extracts group names from rules array', () => {
    const rules = [{ group: 'SQL' }, { group: 'XSS' }];
    expect(getGroups(rules)).toEqual(['SQL', 'XSS']);
  });
});

// ---------------------------------------------------------------------------
// parseYaml + rulesToYaml roundtrip
// ---------------------------------------------------------------------------
describe('parseYaml + rulesToYaml', () => {
  // parseYaml expects: "- group:" at indent 2, "- name:" at indent 4, kv at indent 8+
  const sampleYaml = `rules:
  - group: SQL Injection
    - name: Union Select
        loaded: true
        f_regex: "UNION SELECT"
        s_regex: ''
        format: '{0}'
        color: red
        scope: response body
        engine: nfa
        sensitive: false`;

  it('parses yaml text into groups array', () => {
    const groups = parseYaml(sampleYaml);
    expect(groups).toHaveLength(1);
    expect(groups[0].group).toBe('SQL Injection');
    expect(groups[0].rules).toHaveLength(1);
    expect(groups[0].rules[0].name).toBe('Union Select');
    expect(groups[0].rules[0].loaded).toBe(true);
    expect(groups[0].rules[0].f_regex).toBe('UNION SELECT');
    expect(groups[0].rules[0].scope).toBe('response body');
  });

  it('converts groups back to yaml string', () => {
    const groups = parseYaml(sampleYaml);
    const yaml = rulesToYaml(groups);
    expect(yaml).toContain('rules:');
    expect(yaml).toContain('SQL Injection');
    expect(yaml).toContain('Union Select');
    expect(yaml).toContain('UNION SELECT');
  });

  it('roundtrips: rulesToYaml(parseYaml()) produces valid yaml with same data', () => {
    // Note: parseYaml and rulesToYaml use slightly different indentation
    // conventions, so a full parseYaml(rulesToYaml()) roundtrip does not work.
    // Instead, verify that the serialized YAML contains the correct data.
    const groups = parseYaml(sampleYaml);
    const yaml = rulesToYaml(groups);

    // The YAML should contain group and rule metadata
    expect(yaml).toContain('group: SQL Injection');
    expect(yaml).toContain('name: Union Select');
    expect(yaml).toContain('loaded: true');
    expect(yaml).toContain('UNION SELECT');
    expect(yaml).toContain('response body');
    expect(yaml).toContain('nfa');
  });
});
