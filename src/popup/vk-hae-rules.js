// 灵眸 - HaE Rules Engine
window.VulnKitHaeRules = (function () {
  'use strict';

  var STORAGE_KEY = 'haeRules';
  var PAGE_SCOPE = ['response body', 'response', 'any', 'request', 'response header', 'any header'];

  var DEFAULT_RULES = [
    {
      group: 'Fingerprint',
      rules: [
        {
          name: 'Shiro',
          loaded: true,
          f_regex: '(=deleteMe|rememberMe=)',
          s_regex: '',
          format: '{0}',
          color: 'green',
          scope: 'any header',
          engine: 'dfa',
          sensitive: true,
        },
        {
          name: 'JSON Web Token',
          loaded: true,
          f_regex:
            '(eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9._-]{10,}|eyJ[A-Za-z0-9_/+-]{10,}\\.[A-Za-z0-9._/+-]{10,})',
          s_regex: '',
          format: '{0}',
          color: 'green',
          scope: 'any',
          engine: 'nfa',
          sensitive: true,
        },
        {
          name: 'Swagger UI',
          loaded: true,
          f_regex: '((swagger-ui.html)|(\\"swagger\\":)|(Swagger UI)|(swaggerUi)|(swaggerVersion))',
          s_regex: '',
          format: '{0}',
          color: 'red',
          scope: 'response body',
          engine: 'dfa',
          sensitive: false,
        },
        {
          name: 'Ueditor',
          loaded: true,
          f_regex: '(ueditor\\.(config|all)\\.js)',
          s_regex: '',
          format: '{0}',
          color: 'green',
          scope: 'response body',
          engine: 'dfa',
          sensitive: false,
        },
        {
          name: 'Druid',
          loaded: true,
          f_regex: '(Druid Stat Index)',
          s_regex: '',
          format: '{0}',
          color: 'orange',
          scope: 'response body',
          engine: 'dfa',
          sensitive: false,
        },
        {
          name: 'PDF.js Viewer',
          loaded: true,
          f_regex: '(pdf\\.worker)',
          s_regex: '',
          format: '{0}',
          color: 'green',
          scope: 'response body',
          engine: 'dfa',
          sensitive: false,
        },
        {
          name: 'Vite DevMode',
          loaded: true,
          f_regex: '(/\\@vite/client)',
          s_regex: '',
          format: '{0}',
          color: 'red',
          scope: 'response body',
          engine: 'dfa',
          sensitive: true,
        },
      ],
    },
    {
      group: 'Maybe Vulnerability',
      rules: [
        {
          name: 'Java Deserialization',
          loaded: true,
          f_regex: '(javax\\.faces\\.ViewState)',
          s_regex: '',
          format: '{0}',
          color: 'yellow',
          scope: 'response body',
          engine: 'dfa',
          sensitive: false,
        },
        {
          name: 'Debug Logic Parameters',
          loaded: true,
          f_regex:
            '((access=)|(adm=)|(admin=)|(alter=)|(cfg=)|(clone=)|(config=)|(create=)|(dbg=)|(debug=)|(delete=)|(disable=)|(edit=)|(enable=)|(exec=)|(execute=)|(grant=)|(load=)|(make=)|(modify=)|(rename=)|(reset=)|(root=)|(shell=)|(test=)|(toggl=))',
          s_regex: '',
          format: '{0}',
          color: 'cyan',
          scope: 'request',
          engine: 'dfa',
          sensitive: false,
        },
        {
          name: 'URL As A Value',
          loaded: true,
          f_regex: '(=(https?)(://|%3a%2f%2f))',
          s_regex: '',
          format: '{0}',
          color: 'cyan',
          scope: 'any',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'Upload Form',
          loaded: true,
          f_regex: '(type=\\"file\\")',
          s_regex: '',
          format: '{0}',
          color: 'yellow',
          scope: 'response body',
          engine: 'dfa',
          sensitive: false,
        },
        {
          name: 'DoS Parameters',
          loaded: true,
          f_regex: '((size=)|(page=)|(num=)|(limit=)|(start=)|(end=)|(count=))',
          s_regex: '',
          format: '{0}',
          color: 'cyan',
          scope: 'request',
          engine: 'dfa',
          sensitive: false,
        },
        {
          name: 'Passwd File',
          loaded: true,
          f_regex: '(/root:/bin/bash)',
          s_regex: '',
          format: '{0}',
          color: 'red',
          scope: 'response body',
          engine: 'dfa',
          sensitive: true,
        },
        {
          name: 'Win.ini File',
          loaded: true,
          f_regex: '(for 16-bit app)',
          s_regex: '',
          format: '{0}',
          color: 'red',
          scope: 'response body',
          engine: 'dfa',
          sensitive: true,
        },
      ],
    },
    {
      group: 'Basic Information',
      rules: [
        {
          name: 'Email',
          loaded: true,
          f_regex: '(\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,5}\\b)',
          s_regex: '',
          format: '{0}',
          color: 'yellow',
          scope: 'response',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'Chinese IDCard',
          loaded: true,
          f_regex:
            '[^0-9]((\\d{8}(0\\d|10|11|12)([0-2]\\d|30|31)\\d{3}$)|(\\d{6}(18|19|20)\\d{2}(0[1-9]|10|11|12)([0-2]\\d|30|31)\\d{3}(\\d|X|x)))[^0-9]',
          s_regex: '',
          format: '{0}',
          color: 'orange',
          scope: 'response body',
          engine: 'nfa',
          sensitive: true,
        },
        {
          name: 'Chinese Mobile Number',
          loaded: true,
          f_regex:
            '[^\\w]((?:(?:\\+|0{0,2})86)?1(?:(?:3[\\d])|(?:4[5-79])|(?:5[0-35-9])|(?:6[5-7])|(?:7[0-8])|(?:8[\\d])|(?:9[189]))\\d{8})[^\\w]',
          s_regex: '',
          format: '{0}',
          color: 'orange',
          scope: 'response body',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'Internal IP Address',
          loaded: true,
          f_regex:
            '[^0-9]((127\\.0\\.0\\.1)|(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|(172\\.((1[6-9])|(2\\d)|(3[01]))\\.\\d{1,3}\\.\\d{1,3})|(192\\.168\\.\\d{1,3}\\.\\d{1,3}))',
          s_regex: '',
          format: '{0}',
          color: 'cyan',
          scope: 'response',
          engine: 'nfa',
          sensitive: true,
        },
        {
          name: 'MAC Address',
          loaded: true,
          f_regex:
            '(^([a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5})|[^a-zA-Z0-9]([a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5}))',
          s_regex: '',
          format: '{0}',
          color: 'green',
          scope: 'response',
          engine: 'nfa',
          sensitive: true,
        },
      ],
    },
    {
      group: 'Sensitive Information',
      rules: [
        {
          name: 'Cloud Key',
          loaded: true,
          f_regex: '(((access)(|-|_)(key)(|-|_)(id|secret))|(LTAI[a-z0-9]{12,20}))',
          s_regex: '',
          format: '{0}',
          color: 'yellow',
          scope: 'any',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'Windows File/Dir Path',
          loaded: true,
          f_regex:
            '[^\\w]([a-zA-Z]:\\\\?(?:[^<>:/\\\\|?*]+\\\\?)*)([^<>:/\\\\|?*]+(?:\\.[^<>:/\\\\|?*]+)?)',
          s_regex: '',
          format: '{0}',
          color: 'green',
          scope: 'response',
          engine: 'nfa',
          sensitive: true,
        },
        {
          name: 'Password Field',
          loaded: true,
          f_regex:
            '(((|\\\\)(|\'|")(|[\\.\\w]{1,32})([p](ass|wd|asswd|assword))(|[\\.\\w]{1,32})(|\\\\)(|\'|")(\\s*)(:|[=]{1,3}|![=]{1,2}|[\\)]{0,1}\\.val\\()(\\s*)(|\\\\)(\'|")([^\'"]+?)(|\\\\)(\'|")(|,|\\)))|((|\\\\)(\'|")([^\'"]+?)(|\\\\)(\'|")(|\\\\)(|\'|")(\\s*)(:|[=]{1,3}|![=]{1,2})(\\s*)(|[\\.\\w]{1,32})([p](ass|wd|asswd|assword))(|[\\.\\w]{1,32})(|\\\\)(|\'|"))',
          s_regex: '',
          format: '{0}',
          color: 'yellow',
          scope: 'response body',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'Username Field',
          loaded: true,
          f_regex:
            '(((|\\\\)(|\'|")(|[\\.\\w]{1,32})(([u](ser|name|sername))|(account)|((((create|update)((d|r)|(by|on|at)))|(creator))))(|[\\.\\w]{1,32})(|\\\\)(|\'|")(\\s*)(:|[=]{1,3}|![=]{1,2}|[\\)]{0,1}\\.val\\()(\\s*)(|\\\\)(\'|")([^\'"]+?)(|\\\\)(\'|")(|,|\\)))|((|\\\\)(\'|")([^\'"]+?)(|\\\\)(\'|")(|\\\\)(|\'|")(\\s*)(:|[=]{1,3}|![=]{1,2})(\\s*)(|[\\.\\w]{1,32})(([u](ser|name|sername))|(account)|((((create|update)((d|r)|(by|on|at)))|(creator))))(|[\\.\\w]{1,32})(|\\\\)(|\'|"))',
          s_regex: '',
          format: '{0}',
          color: 'green',
          scope: 'response body',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'WeCom Key',
          loaded: true,
          f_regex: '((corp)(id|secret))',
          s_regex: '',
          format: '{0}',
          color: 'green',
          scope: 'response body',
          engine: 'dfa',
          sensitive: false,
        },
        {
          name: 'JDBC Connection',
          loaded: true,
          f_regex: '(jdbc:[a-z:]+://[a-z0-9\\.\\-_:;=/@?,&]+)',
          s_regex: '',
          format: '{0}',
          color: 'yellow',
          scope: 'any',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'Authorization Header',
          loaded: true,
          f_regex: '((basic [a-z0-9=:_+/\\-]{5,100})|(bearer [a-z0-9_.=:_+/\\-]{5,100}))',
          s_regex: '',
          format: '{0}',
          color: 'yellow',
          scope: 'response body',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'Sensitive Field',
          loaded: true,
          f_regex:
            '(((|\\\\)(|\'|")(|[\\.\\w]{1,32})(key|secret|token|config|auth|access|admin|ticket)(|[\\.\\w]{1,32})(|\\\\)(|\'|")(\\s*)(:|[=]{1,3}|![=]{1,2}|[\\)]{0,1}\\.val\\()(\\s*)(|\\\\)(\'|")([^\'"]+?)(|\\\\)(\'|")(|,|\\)))|((|\\\\)(\'|")([^\'"]+?)(|\\\\)(\'|")(|\\\\)(|\'|")(\\s*)(:|[=]{1,3}|![=]{1,2})(\\s*)(|[\\.\\w]{1,32})(key|secret|token|config|auth|access|admin|ticket)(|[\\.\\w]{1,32})(|\\\\)(|\'|"))',
          s_regex: '',
          format: '{0}',
          color: 'yellow',
          scope: 'response',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'Mobile Number Field',
          loaded: true,
          f_regex:
            '(((|\\\\)(|\'|")(|[\\.\\w]{1,32})(mobile|phone|sjh|shoujihao|concat)(|[\\.\\w]{1,32})(|\\\\)(|\'|")(\\s*)(:|[=]{1,3}|![=]{1,2}|[\\)]{0,1}\\.val\\()(\\s*)(|\\\\)(\'|")([^\'"]+?)(|\\\\)(\'|")(|,|\\)))|((|\\\\)(\'|")([^\'"]+?)(|\\\\)(\'|")(|\\\\)(|\'|")(\\s*)(:|[=]{1,3}|![=]{1,2})(\\s*)(|[\\.\\w]{1,32})(mobile|phone|sjh|shoujihao|concat)(|[\\.\\w]{1,32})(|\\\\)(|\'|"))',
          s_regex: '',
          format: '{0}',
          color: 'green',
          scope: 'response body',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'User Identity',
          loaded: true,
          f_regex:
            '(\\b(?:(localStorage|sessionStorage)\\.(setItem|getItem)|setCookie|Cookies\\.set)\\s*\\(\\s*[\'"](.+?)[\'"].*?)',
          s_regex: '',
          format: '{0}',
          color: 'green',
          scope: 'response body',
          engine: 'nfa',
          sensitive: false,
        },
      ],
    },
    {
      group: 'JS Sensitive Info',
      rules: [
        {
          name: 'AWS Access Key',
          loaded: true,
          f_regex: '(AKIA[0-9A-Z]{16})',
          s_regex: '',
          format: '{0}',
          color: 'red',
          scope: 'response body',
          engine: 'dfa',
          sensitive: true,
        },
        {
          name: 'Private Key',
          loaded: true,
          f_regex: '(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)',
          s_regex: '',
          format: '{0}',
          color: 'red',
          scope: 'response body',
          engine: 'dfa',
          sensitive: true,
        },
        {
          name: 'JWT Token (Full)',
          loaded: true,
          f_regex: '(eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,})',
          s_regex: '',
          format: '{0}',
          color: 'yellow',
          scope: 'response body',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'Public IP Address',
          loaded: true,
          f_regex:
            '(\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b)',
          s_regex: '',
          format: '{0}',
          color: 'cyan',
          scope: 'response body',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'Database Connection',
          loaded: true,
          f_regex: '((?:mongodb|mysql|postgres|redis)://[^\\s\'"]+)',
          s_regex: '',
          format: '{0}',
          color: 'red',
          scope: 'response body',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'Hardcoded Password',
          loaded: true,
          f_regex: '((?:password|passwd|pwd)\\s*[:=]\\s*[\'"][^\'"]{4,}[\'"])',
          s_regex: '',
          format: '{0}',
          color: 'red',
          scope: 'response body',
          engine: 'nfa',
          sensitive: true,
        },
        {
          name: 'API Key (Generic)',
          loaded: true,
          f_regex:
            '(["\'](?:api[_-]?key|apikey|api[_-]?secret)["\']\\s*[:=]\\s*["\']([^"\']{8,})["\'])',
          s_regex: '',
          format: '{1}',
          color: 'yellow',
          scope: 'response body',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'Google API Key',
          loaded: true,
          f_regex: '(AIza[0-9A-Za-z_-]{35})',
          s_regex: '',
          format: '{0}',
          color: 'yellow',
          scope: 'response body',
          engine: 'dfa',
          sensitive: true,
        },
        {
          name: 'Slack Token',
          loaded: true,
          f_regex: '(xox[baprs]-[0-9a-zA-Z-]{10,})',
          s_regex: '',
          format: '{0}',
          color: 'red',
          scope: 'response body',
          engine: 'nfa',
          sensitive: true,
        },
        {
          name: 'GitHub Token',
          loaded: true,
          f_regex: '((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,})',
          s_regex: '',
          format: '{0}',
          color: 'red',
          scope: 'response body',
          engine: 'nfa',
          sensitive: true,
        },
        {
          name: 'Stripe API Key',
          loaded: true,
          f_regex: '((?:sk|pk|rk)_(?:test|live)_[A-Za-z0-9]{24,})',
          s_regex: '',
          format: '{0}',
          color: 'red',
          scope: 'response body',
          engine: 'nfa',
          sensitive: true,
        },
        {
          name: 'SendGrid API Key',
          loaded: true,
          f_regex: '(SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43})',
          s_regex: '',
          format: '{0}',
          color: 'red',
          scope: 'response body',
          engine: 'nfa',
          sensitive: true,
        },
        {
          name: 'Twilio API Key',
          loaded: true,
          f_regex: '(SK[0-9a-fA-F]{32})',
          s_regex: '',
          format: '{0}',
          color: 'yellow',
          scope: 'response body',
          engine: 'dfa',
          sensitive: true,
        },
        {
          name: 'Azure Key Vault Secret',
          loaded: true,
          f_regex: '(https://[a-zA-Z0-9-]+\\.vault\\.azure\\.net/secrets/[a-zA-Z0-9-]+)',
          s_regex: '',
          format: '{0}',
          color: 'red',
          scope: 'response body',
          engine: 'nfa',
          sensitive: true,
        },
        {
          name: 'Generic Base64 Key',
          loaded: true,
          f_regex:
            '(["\'](?:secret|token|key|auth|credential)["\']\\s*[:=]\\s*["\'](?:[A-Za-z0-9+/]{40,}={0,2})["\'])',
          s_regex: '',
          format: '{0}',
          color: 'yellow',
          scope: 'response body',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'Email Address',
          loaded: true,
          f_regex: '([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})',
          s_regex: '',
          format: '{0}',
          color: 'cyan',
          scope: 'response body',
          engine: 'nfa',
          sensitive: false,
        },
      ],
    },
    {
      group: 'Other',
      rules: [
        {
          name: 'Linkfinder',
          loaded: true,
          f_regex:
            '(?:"|\'|`)(((?:[a-zA-Z]{1,10}://|//)[^"\'/]{1,}\\.[a-zA-Z]{2,}[^"\']{0,})|((?:/|\\.\\./|\\./)[^"\'><,;|*()#%%\\$^/\\\\\\\\[\\]][^"\'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|#][^"|\\\']{0,}|))|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{3,}(?:[\\?|#][^"|\\\']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:\\w)(?:[\\?|#][^"|\\\']{0,}|)))(?:"|\'|`)',
          s_regex: '',
          format: '{0}',
          color: 'gray',
          scope: 'response body',
          engine: 'nfa',
          sensitive: true,
        },
        {
          name: 'Source Map',
          loaded: true,
          f_regex: '(\\.js\\.map)',
          s_regex: '',
          format: '{0}',
          color: 'pink',
          scope: 'response body',
          engine: 'dfa',
          sensitive: false,
        },
        {
          name: 'Create Script',
          loaded: true,
          f_regex: '(\\{[^{}]*\\}\\s*\\[[^\\s]*\\]\\s*\\+\s*"[^\\s]*\\.js")',
          s_regex: '"?([\\w].*?)"?:"(.*?)"',
          format: '{0}.{1}',
          color: 'green',
          scope: 'response body',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'URL Schemes',
          loaded: true,
          f_regex:
            '(\\b(?![\\w]{0,10}?https?://)(([A-Za-z0-9-\\.]{1,20})://([-\\w+&@#/%?=~_|!:,.;]*[-\\w+&@#/%=~_|])?))',
          s_regex: '',
          format: '{0}',
          color: 'yellow',
          scope: 'response body',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'Router Push',
          loaded: true,
          f_regex: '(\\$router\\.push)',
          s_regex: '',
          format: '{0}',
          color: 'magenta',
          scope: 'response body',
          engine: 'dfa',
          sensitive: false,
        },
        {
          name: 'All URL',
          loaded: true,
          f_regex: '(https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;\\u4E00-\\u9FFF]+[-A-Za-z0-9+&@#/%=~_|])',
          s_regex: '',
          format: '{0}',
          color: 'gray',
          scope: 'response body',
          engine: 'nfa',
          sensitive: true,
        },
        {
          name: '302 Location',
          loaded: true,
          f_regex: 'Location: ([^\\r\\n]*)',
          s_regex: '',
          format: '{0}',
          color: 'gray',
          scope: 'response header',
          engine: 'nfa',
          sensitive: false,
        },
        {
          name: 'OSKeys',
          loaded: true,
          f_regex: '<Key>(.*?)</Key>',
          s_regex: '',
          format: '{0}',
          color: 'gray',
          scope: 'response body',
          engine: 'nfa',
          sensitive: true,
        },
      ],
    },
  ];

  function isPageScope(scope) {
    return PAGE_SCOPE.indexOf(scope) !== -1;
  }

  function applyFormat(format, captures) {
    var result = format;
    for (var i = 0; i < captures.length; i++) {
      var placeholder = '{' + i + '}';
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
      var flags = rule.sensitive ? 'g' : 'gi';
      var regex = new RegExp(rule.f_regex, flags);
      var results = [];
      var match;
      var seen = {};

      while ((match = regex.exec(text)) !== null) {
        var captures = [];
        for (var i = 1; i < match.length; i++) {
          captures.push(match[i] || '');
        }

        var value = applyFormat(rule.format || '{0}', captures);
        if (!value || value.trim() === '') continue;

        if (rule.s_regex && rule.s_regex.trim() !== '') {
          try {
            var sFlags = rule.sensitive ? '' : 'i';
            var sRegex = new RegExp(rule.s_regex, sFlags);
            if (!sRegex.test(match[0])) continue;
          } catch (e) {
            // invalid s_regex, skip filter
          }
        }

        var key = rule.name + '::' + value;
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
    var grouped = {};
    rules.forEach(function (group) {
      var groupResults = [];
      (group.rules || []).forEach(function (rule) {
        var matches = matchSingleRule(text, rule);
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
      yaml += '  - group: ' + group.group + '\n';
      yaml += '    rules:\n';
      (group.rules || []).forEach(function (rule) {
        yaml += '      - name: ' + rule.name + '\n';
        yaml += '        loaded: ' + rule.loaded + '\n';
        yaml += '        f_regex: ' + quoteYamlString(rule.f_regex || '') + '\n';
        yaml += '        s_regex: ' + quoteYamlString(rule.s_regex || '') + '\n';
        yaml += '        format: ' + quoteYamlString(rule.format || '{0}') + '\n';
        yaml += '        color: ' + (rule.color || 'gray') + '\n';
        yaml += '        scope: ' + (rule.scope || 'response body') + '\n';
        yaml += '        engine: ' + (rule.engine || 'nfa') + '\n';
        yaml += '        sensitive: ' + (rule.sensitive || false) + '\n';
      });
    });
    return yaml;
  }

  function quoteYamlString(str) {
    if (!str) return "''";
    if (/[:#{}[\],&*?|>!%@`'"\n]/.test(str) || str === '' || str === 'true' || str === 'false') {
      return '"' + str.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n') + '"';
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
      var defaults = getDefaultRules();
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
    var parsed = parseYaml(yamlText);
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

  return {
    getDefaultRules: getDefaultRules,
    matchRules: matchRules,
    getGroups: getGroups,
    parseYaml: parseYaml,
    rulesToYaml: rulesToYaml,
    loadRules: loadRules,
    saveRules: saveRules,
    toggleRule: toggleRule,
    importRules: importRules,
    isPageScope: isPageScope,
  };
})();
