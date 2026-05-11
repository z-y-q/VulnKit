// 灵眸 - Extended Rule Manager (Generic CRUD Engine)
// Classic script — loaded before options.js

// ====== Serialization Utilities ======

function serializeValue(val) {
  if (val instanceof RegExp) return val.toString();
  if (Array.isArray(val)) return val.map(serializeValue);
  if (val && typeof val === 'object') {
    var out = {};
    for (var k in val) {
      if (!val.hasOwnProperty(k)) continue;
      out[k] = serializeValue(val[k]);
    }
    return out;
  }
  return val;
}

function deserializeValue(val, type) {
  if (type === 'regex' && typeof val === 'string') {
    try {
      return new RegExp(val);
    } catch (e) {
      return val;
    }
  }
  if (type === 'regex-array' && Array.isArray(val)) {
    return val.map(function (v) {
      if (typeof v === 'string') {
        try {
          return new RegExp(v);
        } catch (e) {
          return v;
        }
      }
      return v;
    });
  }
  return val;
}

function deserializeItem(item, fields) {
  if (!fields || fields.length === 0) return item;
  var out = {};
  var fieldMap = {};
  fields.forEach(function (f) {
    fieldMap[f.key] = f;
  });
  for (var k in item) {
    if (!item.hasOwnProperty(k)) continue;
    var f = fieldMap[k];
    out[k] = f ? deserializeValue(item[k], f.type) : item[k];
  }
  return out;
}

function serializeData(data, config) {
  if (config.structure === 'grouped-strings' || config.structure === 'flat-strings') {
    return data;
  }
  if (!Array.isArray(data)) return data;
  return data.map(function (item) {
    return serializeValue(item);
  });
}

function generateId(prefix) {
  return prefix + '_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 5);
}

function getIdentityValue(item, config) {
  if (config.identityKey === '_self') return item;
  return item[config.identityKey];
}

function countItems(data, config) {
  if (config.structure === 'grouped-strings') {
    var total = 0;
    for (var g in data) {
      if (data.hasOwnProperty(g)) total += data[g].length;
    }
    return total;
  }
  if (config.structure === 'flat-strings') return data.length;
  return data.length;
}

// ====== Default Value Loading (CSP-safe, no eval) ======

var _defaultCache = {};

// Minimal JS literal parser — handles objects, arrays, strings, numbers, booleans, null, regex
function parseJSLiteral(src) {
  var pos = 0;

  function skipWS() {
    while (pos < src.length) {
      if (/\s/.test(src[pos])) {
        pos++;
        continue;
      }
      if (src[pos] === '/' && pos + 1 < src.length && src[pos + 1] === '/') {
        pos += 2;
        while (pos < src.length && src[pos] !== '\n') pos++;
        continue;
      }
      if (src[pos] === '/' && pos + 1 < src.length && src[pos + 1] === '*') {
        pos += 2;
        while (pos + 1 < src.length && !(src[pos] === '*' && src[pos + 1] === '/')) pos++;
        pos += 2;
        continue;
      }
      break;
    }
  }

  function parseValue() {
    skipWS();
    if (pos >= src.length) throw new Error('Unexpected end of input');
    var ch = src[pos];
    if (ch === '{') return parseObject();
    if (ch === '[') return parseArray();
    if (ch === '"' || ch === "'" || ch === '`') return parseString();
    if (ch === '/' && isRegexStart()) return parseRegex();
    if (ch === 't') return expectKeyword('true', true);
    if (ch === 'f') return expectKeyword('false', false);
    if (ch === 'n') return expectKeyword('null', null);
    if (ch === '-' || (ch >= '0' && ch <= '9')) return parseNumber();
    throw new Error('Unexpected char ' + JSON.stringify(ch) + ' at pos ' + pos);
  }

  function isRegexStart() {
    if (pos === 0) return true;
    var j = pos - 1;
    while (j >= 0 && /\s/.test(src[j])) j--;
    if (j < 0) return true;
    return /[\[\{,;:=!&|?+\-~^%*\n\r(]/.test(src[j]);
  }

  function parseObject() {
    pos++;
    var obj = {};
    skipWS();
    if (pos < src.length && src[pos] === '}') {
      pos++;
      return obj;
    }
    while (pos < src.length) {
      skipWS();
      if (src[pos] === '}') {
        pos++;
        break;
      }
      var key;
      if (src[pos] === '"' || src[pos] === "'") {
        key = parseString();
      } else {
        var start = pos;
        while (pos < src.length && /[\w$一-鿿㐀-䶿]/.test(src[pos])) pos++;
        key = src.substring(start, pos);
      }
      skipWS();
      if (src[pos] !== ':') throw new Error('Expected : at pos ' + pos);
      pos++;
      var val = parseValue();
      obj[key] = val;
      skipWS();
      if (src[pos] === ',') {
        pos++;
        continue;
      }
      if (src[pos] === '}') {
        pos++;
        break;
      }
      throw new Error('Expected , or } at pos ' + pos);
    }
    return obj;
  }

  function parseArray() {
    pos++;
    var arr = [];
    skipWS();
    if (pos < src.length && src[pos] === ']') {
      pos++;
      return arr;
    }
    while (pos < src.length) {
      skipWS();
      if (src[pos] === ']') {
        pos++;
        break;
      }
      arr.push(parseValue());
      skipWS();
      if (src[pos] === ',') {
        pos++;
        continue;
      }
      if (src[pos] === ']') {
        pos++;
        break;
      }
      throw new Error('Expected , or ] at pos ' + pos);
    }
    return arr;
  }

  function parseString() {
    var parts = [parseSingleString()];
    while (true) {
      var saved = pos;
      skipWS();
      if (pos < src.length && src[pos] === '+') {
        pos++;
        skipWS();
        if (pos < src.length && (src[pos] === '"' || src[pos] === "'" || src[pos] === '`')) {
          parts.push(parseSingleString());
          continue;
        }
      }
      pos = saved;
      break;
    }
    return parts.length === 1 ? parts[0] : parts.join('');
  }

  function parseSingleString() {
    var quote = src[pos];
    pos++;
    var result = '';
    while (pos < src.length && src[pos] !== quote) {
      if (src[pos] === '\\' && pos + 1 < src.length) {
        pos++;
        var esc = src[pos];
        if (esc === 'n') result += '\n';
        else if (esc === 't') result += '\t';
        else if (esc === 'r') result += '\r';
        else if (esc === 'b') result += '\b';
        else if (esc === 'f') result += '\f';
        else if (esc === 'v') result += '\v';
        else if (esc === '0') result += '\0';
        else result += esc;
        pos++;
      } else if (
        quote === '`' &&
        src[pos] === '$' &&
        pos + 1 < src.length &&
        src[pos + 1] === '{'
      ) {
        result += '${';
        pos += 2;
        var depth = 1;
        while (pos < src.length && depth > 0) {
          if (src[pos] === '{') depth++;
          else if (src[pos] === '}') depth--;
          if (depth > 0) result += src[pos];
          pos++;
        }
        result += '}';
      } else {
        result += src[pos];
        pos++;
      }
    }
    if (pos < src.length) pos++;
    return result;
  }

  function parseRegex() {
    pos++;
    var pattern = '';
    while (pos < src.length) {
      if (src[pos] === '\\') {
        pattern += src[pos] + (src[pos + 1] || '');
        pos += 2;
        continue;
      }
      if (src[pos] === '[') {
        pattern += src[pos];
        pos++;
        while (pos < src.length && src[pos] !== ']') {
          if (src[pos] === '\\') {
            pattern += src[pos] + (src[pos + 1] || '');
            pos += 2;
            continue;
          }
          pattern += src[pos];
          pos++;
        }
        if (pos < src.length) {
          pattern += src[pos];
          pos++;
        }
        continue;
      }
      if (src[pos] === '/') {
        pos++;
        break;
      }
      pattern += src[pos];
      pos++;
    }
    var flags = '';
    while (pos < src.length && /[gimsuy]/.test(src[pos])) {
      flags += src[pos];
      pos++;
    }
    try {
      return new RegExp(pattern, flags);
    } catch (e) {
      return pattern;
    }
  }

  function expectKeyword(kw, val) {
    if (src.substring(pos, pos + kw.length) === kw) {
      pos += kw.length;
      return val;
    }
    throw new Error('Expected ' + kw + ' at pos ' + pos);
  }

  function parseNumber() {
    var start = pos;
    if (src[pos] === '-') pos++;
    if (src.substring(pos, pos + 2) === '0x' || src.substring(pos, pos + 2) === '0X') {
      pos += 2;
      while (pos < src.length && /[0-9a-fA-F]/.test(src[pos])) pos++;
      return parseInt(src.substring(start, pos), 16);
    }
    while (pos < src.length && /\d/.test(src[pos])) pos++;
    if (pos < src.length && src[pos] === '.') {
      pos++;
      while (pos < src.length && /\d/.test(src[pos])) pos++;
    }
    if (pos < src.length && (src[pos] === 'e' || src[pos] === 'E')) {
      pos++;
      if (pos < src.length && (src[pos] === '+' || src[pos] === '-')) pos++;
      while (pos < src.length && /\d/.test(src[pos])) pos++;
    }
    return Number(src.substring(start, pos));
  }

  return parseValue();
}

// Preprocess extracted JS literal: replace function expressions with null
// so the literal parser can handle data objects that contain validate: function(ctx) {...}
function stripFunctions(literal) {
  var result = '';
  var i = 0;
  while (i < literal.length) {
    // Skip regex literals — must come before string check so that
    // quote chars inside regex patterns aren't misidentified as string delimiters
    if (literal[i] === '/') {
      var prev = i - 1;
      while (prev >= 0 && /\s/.test(literal[prev])) prev--;
      var isRe = prev < 0 || /[\[\{,;:=!&|?+\-~^%*\n\r(]/.test(literal[prev]);
      if (isRe && i + 1 < literal.length && literal[i + 1] !== '/' && literal[i + 1] !== '*') {
        result += literal[i];
        i++;
        while (i < literal.length && literal[i] !== '/') {
          if (literal[i] === '\\') {
            result += literal[i] + (literal[i + 1] || '');
            i += 2;
            continue;
          }
          if (literal[i] === '[') {
            result += literal[i];
            i++;
            while (i < literal.length && literal[i] !== ']') {
              if (literal[i] === '\\') {
                result += literal[i] + (literal[i + 1] || '');
                i += 2;
                continue;
              }
              result += literal[i];
              i++;
            }
            if (i < literal.length) {
              result += literal[i];
              i++;
            }
            continue;
          }
          result += literal[i];
          i++;
        }
        if (i < literal.length) {
          result += literal[i];
          i++;
        }
        while (i < literal.length && /[gimsuy]/.test(literal[i])) {
          result += literal[i];
          i++;
        }
        continue;
      }
    }
    // Skip strings (single/double/backtick)
    if (literal[i] === '"' || literal[i] === "'" || literal[i] === '`') {
      var q = literal[i];
      result += literal[i];
      i++;
      while (i < literal.length && literal[i] !== q) {
        if (literal[i] === '\\' && i + 1 < literal.length) {
          result += literal[i] + literal[i + 1];
          i += 2;
          continue;
        }
        result += literal[i];
        i++;
      }
      if (i < literal.length) {
        result += literal[i];
        i++;
      }
      continue;
    }
    // Skip line comments
    if (literal[i] === '/' && i + 1 < literal.length && literal[i + 1] === '/') {
      while (i < literal.length && literal[i] !== '\n') i++;
      continue;
    }
    // Skip block comments
    if (literal[i] === '/' && i + 1 < literal.length && literal[i + 1] === '*') {
      i += 2;
      while (i + 1 < literal.length && !(literal[i] === '*' && literal[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    // Detect "function" keyword as a value (preceded by : or =)
    if (
      literal.substring(i, i + 8) === 'function' &&
      (i + 8 >= literal.length || !/[\w$]/.test(literal[i + 8]))
    ) {
      // Look back to confirm this is a value context (after : or =)
      var j = i - 1;
      while (j >= 0 && /\s/.test(literal[j])) j--;
      if (j >= 0 && (literal[j] === ':' || literal[j] === '=')) {
        // Skip the function keyword
        i += 8;
        // Skip whitespace
        while (i < literal.length && /\s/.test(literal[i])) i++;
        // Skip optional function name
        if (i < literal.length && /[\w$]/.test(literal[i])) {
          while (i < literal.length && /[\w$]/.test(literal[i])) i++;
          while (i < literal.length && /\s/.test(literal[i])) i++;
        }
        // Skip parameter list (...)
        if (i < literal.length && literal[i] === '(') {
          var depth = 1;
          i++;
          while (i < literal.length && depth > 0) {
            if (literal[i] === '(') depth++;
            else if (literal[i] === ')') depth--;
            else if (literal[i] === '"' || literal[i] === "'" || literal[i] === '`') {
              var q2 = literal[i];
              i++;
              while (i < literal.length && literal[i] !== q2) {
                if (literal[i] === '\\') i++;
                i++;
              }
            }
            i++;
          }
          i++; // skip closing )
        }
        // Skip whitespace before body
        while (i < literal.length && /\s/.test(literal[i])) i++;
        // Skip function body {...}
        if (i < literal.length && literal[i] === '{') {
          var bdepth = 1;
          i++;
          while (i < literal.length && bdepth > 0) {
            var c = literal[i];
            if (c === '{') bdepth++;
            else if (c === '}') bdepth--;
            else if (c === '"' || c === "'" || c === '`') {
              var q3 = c;
              i++;
              while (i < literal.length && literal[i] !== q3) {
                if (literal[i] === '\\') i++;
                i++;
              }
            } else if (c === '/') {
              // Regex detection inside function body
              var p2 = i - 1;
              while (p2 >= 0 && /\s/.test(literal[p2])) p2--;
              var isRe2 = p2 < 0 || /[\[\{,;:=!&|?+\-~^%*\n\r(]/.test(literal[p2]);
              if (
                isRe2 &&
                i + 1 < literal.length &&
                literal[i + 1] !== '/' &&
                literal[i + 1] !== '*'
              ) {
                i++;
                while (i < literal.length && literal[i] !== '/') {
                  if (literal[i] === '\\') {
                    i += 2;
                    continue;
                  }
                  if (i < literal.length && literal[i] === '[') {
                    i++;
                    while (i < literal.length && literal[i] !== ']') {
                      if (literal[i] === '\\') i++;
                      i++;
                    }
                  }
                  i++;
                }
                if (i < literal.length) i++;
                while (i < literal.length && /[gimsuy]/.test(literal[i])) i++;
                continue;
              }
              if (i + 1 < literal.length && literal[i + 1] === '/') {
                while (i < literal.length && literal[i] !== '\n') i++;
                continue;
              }
              if (i + 1 < literal.length && literal[i + 1] === '*') {
                i += 2;
                while (i + 1 < literal.length && !(literal[i] === '*' && literal[i + 1] === '/'))
                  i++;
                i += 2;
                continue;
              }
            }
            i++;
          }
          i++; // skip closing }
          result += 'null';
          continue;
        }
        // Arrow function without braces: (params) => expression
        // Just output null and continue
        result += 'null';
        continue;
      }
    }
    result += literal[i];
    i++;
  }
  return result;
}

// Extract a variable's literal value from source code (bracket-matching)
function extractVarLiteral(src, varName) {
  var escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  var re = new RegExp('(?:var|let|const)\\s+' + escaped + '\\s*=\\s*');
  var m = re.exec(src);
  if (!m) throw new Error('Variable ' + varName + ' not found');

  var start = m.index + m[0].length;
  while (start < src.length && /\s/.test(src[start])) start++;

  var ch = src[start];
  if (ch !== '[' && ch !== '{') {
    throw new Error('Expected [ or { for ' + varName + ' at pos ' + start);
  }

  var openChar = ch;
  var closeChar = openChar === '[' ? ']' : '}';
  var depth = 0;
  var i = start;
  while (i < src.length) {
    var c = src[i];
    // Handle / first: could be comment or regex — must skip before string check
    // so that quote chars inside regex aren't misidentified as string delimiters
    if (c === '/') {
      if (i + 1 < src.length && src[i + 1] === '/') {
        while (i < src.length && src[i] !== '\n') i++;
        continue;
      }
      if (i + 1 < src.length && src[i + 1] === '*') {
        i += 2;
        while (i + 1 < src.length && !(src[i] === '*' && src[i + 1] === '/')) i++;
        i += 2;
        continue;
      }
      // Look back past whitespace to determine context
      var prev = i - 1;
      while (prev >= start && /\s/.test(src[prev])) prev--;
      var isAfterValueOp = prev < start || /[\[\{,;:=!&|?+\-~^%*\n\r(]/.test(src[prev]);
      if (isAfterValueOp && i + 1 < src.length && src[i + 1] !== '/' && src[i + 1] !== '*') {
        i++;
        while (i < src.length && src[i] !== '/') {
          if (src[i] === '\\') {
            i += 2;
            continue;
          }
          if (i < src.length && src[i] === '[') {
            i++;
            while (i < src.length && src[i] !== ']') {
              if (src[i] === '\\') i++;
              i++;
            }
          }
          i++;
        }
        i++; // skip closing /
        while (i < src.length && /[gimsuy]/.test(src[i])) i++;
        continue;
      }
      // Division operator — just skip
      i++;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      var q = c;
      i++;
      while (i < src.length && src[i] !== q) {
        if (src[i] === '\\') i++;
        if (q === '`' && src[i] === '$' && i + 1 < src.length && src[i + 1] === '{') {
          var tDepth = 1;
          i += 2;
          while (i < src.length && tDepth > 0) {
            if (src[i] === '{') tDepth++;
            else if (src[i] === '}') tDepth--;
            else if (src[i] === '"' || src[i] === "'" || src[i] === '`') {
              var tq = src[i];
              i++;
              while (i < src.length && src[i] !== tq) {
                if (src[i] === '\\') i++;
                i++;
              }
            }
            i++;
          }
          continue;
        }
        i++;
      }
      i++;
      continue;
    }
    if (c === openChar) depth++;
    if (c === closeChar) depth--;
    if (depth === 0) break;
    i++;
  }

  return src.substring(start, i + 1);
}

function loadDefaultFromPopup(filePath, varName) {
  var cacheKey = filePath + '::' + varName;
  if (_defaultCache[cacheKey] !== undefined) {
    return Promise.resolve(_defaultCache[cacheKey]);
  }
  return fetch(filePath)
    .then(function (r) {
      if (!r.ok) throw new Error('fetch status ' + r.status);
      return r.text();
    })
    .then(function (src) {
      console.log('[rule-manager] fetch OK:', src.length, 'chars');
      try {
        var literal = extractVarLiteral(src, varName);
        console.log('[rule-manager] extracted literal:', literal.length, 'chars');
        var cleaned = stripFunctions(literal);
        if (cleaned !== literal) {
          console.log(
            '[rule-manager] stripped functions:',
            literal.length,
            '->',
            cleaned.length,
            'chars'
          );
        }
        var collapsed = cleaned;
        var result = parseJSLiteral(collapsed);
        console.log(
          '[rule-manager] parsed:',
          Array.isArray(result) ? result.length + ' items' : typeof result
        );
        _defaultCache[cacheKey] = result;
        return result;
      } catch (err) {
        console.error('[rule-manager] parse error:', err.message);
        throw err;
      }
    })
    .catch(function (err) {
      console.error('[rule-manager] loadDefault failed:', filePath, varName, err);
      return null;
    });
}

function loadDefaultForConfig(config) {
  return loadDefaultFromPopup(config.defaultSource.file, config.defaultSource.varName);
}

// ====== Storage Layer ======

function makeEmptyDelta() {
  return { customItems: [], modifiedDefaults: {}, deletedDefaults: [] };
}

function mergeWithDefaults(delta, defaults, config) {
  if (delta === null) delta = makeEmptyDelta();
  var customItems = delta.customItems || [];
  var modifiedDefaults = delta.modifiedDefaults || {};
  var deletedDefaults = delta.deletedDefaults || [];

  if (config.structure === 'flat-strings') {
    var base = (defaults || []).slice();
    var filtered = base.filter(function (s) {
      return deletedDefaults.indexOf(s) === -1;
    });
    var merged = filtered.concat(customItems);
    return merged;
  }

  if (config.structure === 'grouped-strings') {
    var result = {};
    var src = defaults || {};
    for (var g in src) {
      if (!src.hasOwnProperty(g)) continue;
      result[g] = src[g].filter(function (s) {
        return deletedDefaults.indexOf(s) === -1;
      });
    }
    if (modifiedDefaults) {
      for (var mk in modifiedDefaults) {
        if (!modifiedDefaults.hasOwnProperty(mk)) continue;
        if (result.hasOwnProperty(mk)) {
          result[mk] = modifiedDefaults[mk];
        }
      }
    }
    if (customItems) {
      customItems.forEach(function (ci) {
        var group = ci._group;
        if (!group) return;
        if (!result[group]) result[group] = [];
        if (ci._strings && Array.isArray(ci._strings)) {
          result[group] = result[group].concat(ci._strings);
        }
      });
    }
    return result;
  }

  // flat-objects
  var baseItems = Array.isArray(defaults) ? defaults.slice() : [];
  var mergedItems = baseItems
    .filter(function (item) {
      var id = getIdentityValue(item, config);
      return deletedDefaults.indexOf(id) === -1;
    })
    .map(function (item) {
      var id = getIdentityValue(item, config);
      if (modifiedDefaults && modifiedDefaults.hasOwnProperty(id)) {
        return deserializeItem(modifiedDefaults[id], config.fields);
      }
      return item;
    });
  if (customItems) {
    customItems.forEach(function (ci) {
      mergedItems.push(deserializeItem(ci, config.fields));
    });
  }
  return mergedItems;
}

function computeDelta(merged, defaults, config) {
  if (config.structure === 'flat-strings') {
    var base = (defaults || []).slice();
    var baseSet = {};
    base.forEach(function (s) {
      baseSet[s] = true;
    });
    var mergedSet = {};
    (merged || []).forEach(function (s) {
      mergedSet[s] = true;
    });

    var deletedDefaults = base.filter(function (s) {
      return !mergedSet[s];
    });
    var customItems = (merged || []).filter(function (s) {
      return !baseSet[s];
    });
    return { customItems: customItems, modifiedDefaults: {}, deletedDefaults: deletedDefaults };
  }

  if (config.structure === 'grouped-strings') {
    var delta = { customItems: [], modifiedDefaults: {}, deletedDefaults: [] };
    var src = defaults || {};
    var allSrcStrings = {};
    for (var g in src) {
      if (!src.hasOwnProperty(g)) continue;
      allSrcStrings[g] = {};
      src[g].forEach(function (s) {
        allSrcStrings[g][s] = true;
      });
    }
    // For grouped-strings: deleted are those in defaults but not in merged
    for (var g2 in src) {
      if (!src.hasOwnProperty(g2)) continue;
      var mergedGroup = (merged && merged[g2]) || [];
      var mergedGroupSet = {};
      mergedGroup.forEach(function (s) {
        mergedGroupSet[s] = true;
      });
      (src[g2] || []).forEach(function (s) {
        if (!mergedGroupSet[s]) delta.deletedDefaults.push(s);
      });
    }
    // Custom items: strings in merged that aren't in any default group
    if (merged) {
      for (var mg in merged) {
        if (!merged.hasOwnProperty(mg)) continue;
        (merged[mg] || []).forEach(function (s) {
          var inSrc = allSrcStrings[mg] && allSrcStrings[mg][s];
          if (!inSrc) {
            delta.customItems.push({ _group: mg, _strings: [s] });
          }
        });
      }
    }
    return delta;
  }

  // flat-objects
  var baseMap = {};
  (defaults || []).forEach(function (item) {
    baseMap[getIdentityValue(item, config)] = item;
  });
  var mergedMap = {};
  (merged || []).forEach(function (item) {
    mergedMap[getIdentityValue(item, config)] = item;
  });

  var deletedDefaults = [];
  var modifiedDefaults = {};
  var customItems = [];

  for (var bk in baseMap) {
    if (!baseMap.hasOwnProperty(bk)) continue;
    if (!mergedMap.hasOwnProperty(bk)) {
      deletedDefaults.push(bk);
    } else {
      var baseItem = baseMap[bk];
      var mergedItem = mergedMap[bk];
      var isModified = false;
      for (var fk in baseItem) {
        if (!baseItem.hasOwnProperty(fk)) continue;
        var bv = baseItem[fk];
        var mv = mergedItem[fk];
        if (bv instanceof RegExp) bv = bv.toString();
        if (mv instanceof RegExp) mv = mv.toString();
        if (bv !== mv && JSON.stringify(bv) !== JSON.stringify(mv)) {
          isModified = true;
          break;
        }
      }
      if (isModified) {
        modifiedDefaults[bk] = serializeValue(mergedItem);
      }
    }
  }
  (merged || []).forEach(function (item) {
    var id = getIdentityValue(item, config);
    if (!baseMap.hasOwnProperty(id)) {
      customItems.push(serializeValue(item));
    }
  });

  return {
    customItems: customItems,
    modifiedDefaults: modifiedDefaults,
    deletedDefaults: deletedDefaults,
  };
}

function loadRuleData(config) {
  return new Promise(function (resolve) {
    chrome.storage.local.get(config.storageKey, function (result) {
      var delta = result[config.storageKey] || null;
      loadDefaultForConfig(config)
        .then(function (defaults) {
          var merged = mergeWithDefaults(delta, defaults, config);
          resolve(merged);
        })
        .catch(function (err) {
          console.error('[rule-manager] loadDefault error:', config.id, err);
          resolve(delta ? delta.customItems || [] : []);
        });
    });
  });
}

function saveRuleData(config, mergedData) {
  return new Promise(function (resolve) {
    loadDefaultForConfig(config).then(function (defaults) {
      var delta = computeDelta(mergedData, defaults, config);
      var obj = {};
      obj[config.storageKey] = delta;
      chrome.storage.local.set(obj, function () {
        resolve();
      });
    });
  });
}

// ====== Rendering Engine ======

var _currentRuleConfig = null;
var _currentRuleData = null;

function escapeAttr(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function getRuleConfigById(id) {
  for (var i = 0; i < RULE_CONFIGS.length; i++) {
    if (RULE_CONFIGS[i].id === id) return RULE_CONFIGS[i];
  }
  return null;
}

function initAllRuleSections() {
  var selectEl = $('rule-type-select');
  if (!selectEl) return;
  selectEl.innerHTML = '';

  RULE_CATEGORIES.forEach(function (cat) {
    var group = document.createElement('optgroup');
    group.label = cat.label;
    RULE_CONFIGS.filter(function (c) {
      return c.category === cat.id;
    }).forEach(function (cfg) {
      var opt = document.createElement('option');
      opt.value = cfg.id;
      opt.textContent = cfg.label;
      group.appendChild(opt);
    });
    selectEl.appendChild(group);
  });

  selectEl.addEventListener('change', function () {
    renderCurrentSection();
  });

  if (RULE_CONFIGS.length > 0) {
    renderCurrentSection();
  }
}

function renderCurrentSection() {
  var selectEl = $('rule-type-select');
  var actionsEl = $('extended-rules-actions');
  var containerEl = $('extended-rules-container');
  if (!selectEl || !actionsEl || !containerEl) return;

  var config = getRuleConfigById(selectEl.value);
  _currentRuleConfig = config;
  _currentRuleData = null;
  if (!config) {
    containerEl.innerHTML = '<div class="rule-empty">请选择规则类型</div>';
    actionsEl.innerHTML = '';
    return;
  }

  loadRuleData(config).then(function (data) {
    _currentRuleData = data;
    renderActionButtons(config, actionsEl);
    renderRuleList(containerEl, data, config);
    updateSelectCounts(data, config);
  });
}

function updateSelectCounts(data, config) {
  var selectEl = $('rule-type-select');
  if (!selectEl) return;
  var total = countItems(data, config);
  var opt = selectEl.querySelector('option[value="' + config.id + '"]');
  if (opt) opt.textContent = config.label + ' (' + total + ')';
}

function renderActionButtons(config, container) {
  var html = '';
  if (config.structure === 'grouped-strings' || config.structure === 'flat-strings') {
    html += '<button class="btn btn-primary btn-sm" id="rule-add-btn">批量添加</button>';
  } else {
    html += '<button class="btn btn-primary btn-sm" id="rule-add-btn">添加</button>';
  }
  html += '<button class="btn btn-secondary btn-sm" id="rule-validate-btn">验证全部</button>';
  html += '<button class="btn btn-primary btn-sm" id="rule-export-btn">导出 JSON</button>';
  html += '<button class="btn btn-primary btn-sm" id="rule-import-btn">导入 JSON</button>';
  html += '<button class="btn btn-danger btn-sm" id="rule-reset-btn">恢复默认</button>';
  container.innerHTML = html;

  container.querySelector('#rule-add-btn').addEventListener('click', function () {
    handleAdd(config);
  });
  container.querySelector('#rule-validate-btn').addEventListener('click', function () {
    validateAllRules(config);
  });
  container.querySelector('#rule-export-btn').addEventListener('click', function () {
    exportRulesJSON(config);
  });
  container.querySelector('#rule-import-btn').addEventListener('click', function () {
    importRulesJSON(config);
  });
  container.querySelector('#rule-reset-btn').addEventListener('click', function () {
    resetToDefaults(config);
  });
}

function renderRuleList(container, data, config) {
  container.innerHTML = '';

  var existingResults = container.parentNode.querySelector('.hae-validate-results');
  if (existingResults) existingResults.remove();

  if (config.structure === 'grouped-strings') return renderGroupedStrings(container, data, config);
  if (config.structure === 'flat-strings') return renderFlatStrings(container, data, config);
  if (config.groupBy) return renderGroupedObjects(container, data, config);
  return renderFlatObjects(container, data, config);
}

function renderGroupedObjects(container, data, config) {
  if (!Array.isArray(data) || data.length === 0) {
    container.innerHTML = '<div class="rule-empty">暂无数据</div>';
    return;
  }
  var groups = {};
  var groupOrder = [];
  data.forEach(function (item) {
    var g = item[config.groupBy] || '未分类';
    if (!groups[g]) {
      groups[g] = [];
      groupOrder.push(g);
    }
    groups[g].push(item);
  });

  groupOrder.forEach(function (gName) {
    var items = groups[gName];
    var groupDiv = document.createElement('div');
    groupDiv.className = 'rule-group';

    var header = document.createElement('div');
    header.className = 'rule-group-header';
    header.innerHTML =
      '<span class="rule-group-name">' +
      escapeHtml(gName) +
      '</span>' +
      '<span class="rule-group-count">' +
      items.length +
      ' 项</span>' +
      '<button class="hae-btn-icon" title="折叠/展开" data-action="toggle-group">&#9660;</button>';
    groupDiv.appendChild(header);

    var itemsDiv = document.createElement('div');
    itemsDiv.className = 'rule-group-items';
    items.forEach(function (item) {
      itemsDiv.appendChild(createObjectItem(item, config));
    });
    groupDiv.appendChild(itemsDiv);
    container.appendChild(groupDiv);
  });

  attachContainerEvents(container, config);
}

function renderFlatObjects(container, data, config) {
  if (!Array.isArray(data) || data.length === 0) {
    container.innerHTML = '<div class="rule-empty">暂无数据</div>';
    return;
  }
  data.forEach(function (item) {
    container.appendChild(createObjectItem(item, config));
  });
  attachContainerEvents(container, config);
}

function createObjectItem(item, config) {
  var id = getIdentityValue(item, config);
  var row = document.createElement('div');
  row.className = 'rule-item';
  row.dataset.identity = typeof id === 'object' ? JSON.stringify(serializeValue(id)) : String(id);

  var labelVal = config.listLabel ? item[config.listLabel] : '';
  var labelSpan = '<span class="rule-item-label">' + escapeHtml(String(labelVal || '')) + '</span>';

  var badges = '';
  (config.listFields || []).forEach(function (fk) {
    if (fk === config.listLabel) return;
    var val = item[fk];
    if (val === undefined || val === null) return;
    var displayVal = val instanceof RegExp ? val.toString() : String(val);
    badges += '<span class="rule-item-badge">' + escapeHtml(displayVal) + '</span>';
  });

  row.innerHTML =
    labelSpan +
    '<span class="rule-item-badges">' +
    badges +
    '</span>' +
    '<span class="rule-actions">' +
    '<button class="hae-btn-icon" title="编辑" data-action="edit">&#9998;</button>' +
    '<button class="hae-btn-icon hae-btn-danger" title="删除" data-action="delete">&#10005;</button>' +
    '</span>';
  return row;
}

function renderGroupedStrings(container, data, config) {
  var groups = data || {};
  var groupKeys = Object.keys(groups);
  if (groupKeys.length === 0) {
    container.innerHTML = '<div class="rule-empty">暂无数据</div>';
    return;
  }

  var totalCount = 0;
  groupKeys.forEach(function (gk) {
    totalCount += (groups[gk] || []).length;
  });
  if (totalCount === 0) {
    container.innerHTML = '<div class="rule-empty">暂无数据</div>';
    return;
  }

  groupKeys.forEach(function (gk) {
    var strings = groups[gk] || [];
    var groupDiv = document.createElement('div');
    groupDiv.className = 'rule-group';

    var header = document.createElement('div');
    header.className = 'rule-group-header';
    header.innerHTML =
      '<span class="rule-group-name">' +
      escapeHtml(gk) +
      '</span>' +
      '<span class="rule-group-count">' +
      strings.length +
      ' 项</span>' +
      '<button class="hae-btn-icon" title="折叠/展开" data-action="toggle-group">&#9660;</button>' +
      '<span class="rule-actions" style="opacity:0.4">' +
      '<button class="hae-btn-icon" title="添加到此分组" data-action="add-to-group" data-group="' +
      escapeAttr(gk) +
      '">+</button>' +
      '</span>';
    groupDiv.appendChild(header);

    var itemsDiv = document.createElement('div');
    itemsDiv.className = 'rule-group-items';
    strings.forEach(function (s) {
      itemsDiv.appendChild(createStringItem(s, config));
    });
    groupDiv.appendChild(itemsDiv);
    container.appendChild(groupDiv);
  });

  attachContainerEvents(container, config);
}

function renderFlatStrings(container, data, config) {
  if (!Array.isArray(data) || data.length === 0) {
    container.innerHTML = '<div class="rule-empty">暂无数据</div>';
    return;
  }
  data.forEach(function (s) {
    container.appendChild(createStringItem(s, config));
  });
  attachContainerEvents(container, config);
}

function createStringItem(str, config) {
  var row = document.createElement('div');
  row.className = 'rule-item rule-item-string';
  row.dataset.identity = escapeAttr(str);

  var span = document.createElement('span');
  span.className = 'rule-item-label';
  span.textContent = str;
  span.title = '双击编辑';

  var actions = document.createElement('span');
  actions.className = 'rule-actions';
  actions.innerHTML =
    '<button class="hae-btn-icon hae-btn-danger" title="删除" data-action="delete">&#10005;</button>';

  row.appendChild(span);
  row.appendChild(actions);
  return row;
}

function attachContainerEvents(container, config) {
  container.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-action]');
    if (!btn) return;
    var action = btn.dataset.action;
    var row = btn.closest('.rule-item');
    var identity = row ? row.dataset.identity : null;

    if (action === 'toggle-group') {
      var group = btn.closest('.rule-group');
      var items = group.querySelector('.rule-group-items');
      if (items) {
        var hidden = items.style.display === 'none';
        items.style.display = hidden ? '' : 'none';
        btn.innerHTML = hidden ? '&#9660;' : '&#9654;';
      }
    } else if (action === 'edit' && identity) {
      handleEdit(config, identity);
    } else if (action === 'delete' && identity) {
      handleDelete(config, identity);
    } else if (action === 'add-to-group') {
      var group = btn.dataset.group;
      promptAddToStrings(config, group);
    }
  });

  container.addEventListener('dblclick', function (e) {
    var row = e.target.closest('.rule-item-string');
    if (!row) return;
    startInlineEdit(row, config);
  });
}

function startInlineEdit(row, config) {
  var span = row.querySelector('.rule-item-label');
  if (!span) return;
  var oldVal = span.textContent;

  var input = document.createElement('input');
  input.type = 'text';
  input.className = 'rule-inline-input';
  input.value = oldVal;

  span.style.display = 'none';
  row.insertBefore(input, span.nextSibling);
  input.focus();
  input.select();

  function finish(newVal) {
    input.remove();
    span.style.display = '';
    if (newVal && newVal !== oldVal) {
      handleStringEdit(config, oldVal, newVal);
    }
  }

  input.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      finish(input.value.trim());
    }
    if (e.key === 'Escape') {
      finish(null);
    }
  });
  input.addEventListener('blur', function () {
    finish(input.value.trim());
  });
}

// ====== CRUD Operations ======

function handleAdd(config) {
  if (config.structure === 'grouped-strings' || config.structure === 'flat-strings') {
    promptAddToStrings(config, null);
    return;
  }
  openItemModal(config, { mode: 'add' });
}

function promptAddToStrings(config, group) {
  if (!group && config.structure === 'grouped-strings') {
    if (!_currentRuleData) return;
    var groups = Object.keys(_currentRuleData);
    if (groups.length === 0) {
      group = prompt('输入新分组名称:');
      if (!group || !group.trim()) return;
      group = group.trim();
    } else {
      var options = groups
        .map(function (g, i) {
          return i + 1 + '. ' + g + ' (' + (_currentRuleData[g] || []).length + ')';
        })
        .join('\n');
      var choice = prompt('选择分组序号（或输入新分组名称）:\n' + options);
      if (!choice || !choice.trim()) return;
      choice = choice.trim();
      var num = parseInt(choice, 10);
      if (!isNaN(num) && num >= 1 && num <= groups.length) {
        group = groups[num - 1];
      } else {
        group = choice;
      }
    }
  }

  var input = prompt('输入要添加的内容（每行一个）:');
  if (!input || !input.trim()) return;
  var lines = input
    .trim()
    .split('\n')
    .map(function (l) {
      return l.trim();
    })
    .filter(function (l) {
      return l.length > 0;
    });
  if (lines.length === 0) return;

  if (config.structure === 'flat-strings') {
    loadRuleData(config).then(function (data) {
      var existing = new Set(data);
      var newItems = lines.filter(function (l) {
        return !existing.has(l);
      });
      if (newItems.length === 0) {
        showStatus('所有内容已存在', 'info');
        return;
      }
      var merged = data.concat(newItems);
      saveRuleData(config, merged).then(function () {
        renderCurrentSection();
        showStatus('已添加 ' + newItems.length + ' 项', 'success');
      });
    });
    return;
  }

  // grouped-strings
  loadRuleData(config).then(function (data) {
    if (!data[group]) data[group] = [];
    var existing = new Set(data[group]);
    var newItems = lines.filter(function (l) {
      return !existing.has(l);
    });
    if (newItems.length === 0) {
      showStatus('所有内容已存在', 'info');
      return;
    }
    var newData = Object.assign({}, data);
    newData[group] = data[group].concat(newItems);
    saveRuleData(config, newData).then(function () {
      renderCurrentSection();
      showStatus('已添加 ' + newItems.length + ' 项到 ' + group, 'success');
    });
  });
}

function handleStringEdit(config, oldVal, newVal) {
  if (config.structure === 'flat-strings') {
    loadRuleData(config).then(function (data) {
      var merged = data.map(function (s) {
        return s === oldVal ? newVal : s;
      });
      saveRuleData(config, merged).then(function () {
        renderCurrentSection();
        showStatus('已更新', 'success');
      });
    });
    return;
  }
  // grouped-strings: find and replace in all groups
  loadRuleData(config).then(function (data) {
    var found = false;
    var newData = {};
    for (var g in data) {
      if (!data.hasOwnProperty(g)) continue;
      newData[g] = data[g].map(function (s) {
        if (s === oldVal) {
          found = true;
          return newVal;
        }
        return s;
      });
    }
    if (!found) {
      showStatus('未找到原始内容', 'error');
      return;
    }
    saveRuleData(config, newData).then(function () {
      renderCurrentSection();
      showStatus('已更新', 'success');
    });
  });
}

function handleEdit(config, identityStr) {
  if (config.structure === 'grouped-strings' || config.structure === 'flat-strings') {
    startInlineEdit(
      document.querySelector('.rule-item[data-identity="' + escapeAttr(identityStr) + '"]'),
      config
    );
    return;
  }
  // flat-objects: find item by identity
  var data = _currentRuleData;
  if (!data) return;
  var item = data.find(function (it) {
    var id = getIdentityValue(it, config);
    return String(id) === identityStr;
  });
  if (!item) return;
  openItemModal(config, { mode: 'edit', item: Object.assign({}, item) });
}

function handleDelete(config, identityStr) {
  if (!confirm('确定删除此项吗？')) return;

  loadRuleData(config).then(function (data) {
    var merged;
    if (config.structure === 'flat-strings') {
      merged = data.filter(function (s) {
        return String(s) !== identityStr;
      });
    } else if (config.structure === 'grouped-strings') {
      merged = {};
      for (var g in data) {
        if (!data.hasOwnProperty(g)) continue;
        merged[g] = data[g].filter(function (s) {
          return String(s) !== identityStr;
        });
        if (merged[g].length === 0) delete merged[g];
      }
    } else {
      merged = data.filter(function (item) {
        return String(getIdentityValue(item, config)) !== identityStr;
      });
    }
    saveRuleData(config, merged).then(function () {
      renderCurrentSection();
      showStatus('已删除', 'success');
    });
  });
}

function resetToDefaults(config) {
  if (!confirm('确定恢复为默认数据吗？自定义修改将被清除。')) return;
  var obj = {};
  obj[config.storageKey] = null;
  chrome.storage.local.remove(config.storageKey, function () {
    delete _defaultCache[config.defaultSource.file + '::' + config.defaultSource.varName];
    renderCurrentSection();
    showStatus('已恢复为默认数据', 'success');
  });
}

// ====== Generic Modal ======

function openItemModal(config, opts) {
  var isEdit = opts.mode === 'edit';
  var item = opts.item || {};
  var title = isEdit ? '编辑 - ' + config.label : '添加 - ' + config.label;

  var overlay = document.createElement('div');
  overlay.className = 'hae-modal-overlay';

  var modal = document.createElement('div');
  modal.className = 'hae-modal';

  var bodyHtml = '';
  config.fields.forEach(function (field) {
    if (field.key === 'matchers') {
      bodyHtml += renderSubObjectArrayField(field, isEdit ? item[field.key] || [] : [{}], config);
      return;
    }
    bodyHtml +=
      '<div class="hae-form-group">' +
      '<label class="hae-form-label" for="rule-field-' +
      field.key +
      '">' +
      field.label +
      (field.required ? ' <span class="hae-form-hint">*</span>' : '') +
      '</label>';
    bodyHtml += createFormFieldHTML(field, item[field.key]);
    bodyHtml += '</div>';
  });

  modal.innerHTML =
    '<div class="hae-modal-header">' +
    '<span class="hae-modal-title">' +
    escapeHtml(title) +
    '</span>' +
    '<button class="hae-modal-close">&times;</button>' +
    '</div>' +
    '<div class="hae-modal-body">' +
    '<div class="hae-form-grid">' +
    bodyHtml +
    '</div>' +
    '</div>' +
    '<div class="hae-modal-footer">' +
    '<div class="hae-modal-footer-left">' +
    '<button class="btn btn-secondary btn-sm" id="rule-modal-compile">编译验证</button>' +
    '<span class="hae-modal-status" id="rule-modal-status"></span>' +
    '</div>' +
    '<div class="hae-modal-footer-right">' +
    '<button class="btn btn-outline btn-sm" id="rule-modal-cancel">取消</button>' +
    '<button class="btn btn-primary btn-sm" id="rule-modal-save">保存</button>' +
    '</div>';

  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  // Auto-generate ID for new items
  if (
    !isEdit &&
    config.fields.some(function (f) {
      return f.autoGenerate;
    })
  ) {
    var idField = config.fields.find(function (f) {
      return f.autoGenerate;
    });
    if (idField) {
      var idInput = modal.querySelector('#rule-field-' + idField.key);
      if (idInput && !idInput.value) {
        idInput.value = generateId(idField.autoGenerate);
      }
    }
  }

  // Sub-object-array add/remove buttons
  var subContainers = modal.querySelectorAll('.rule-sub-form-container');
  subContainers.forEach(function (container) {
    var fieldKey = container.dataset.fieldKey;
    var field = config.fields.find(function (f) {
      return f.key === fieldKey;
    });
    var addBtn = container.querySelector('.rule-sub-form-add');
    if (addBtn && field) {
      addBtn.addEventListener('click', function () {
        var emptyRow = {};
        (field.subFields || []).forEach(function (sf) {
          emptyRow[sf.key] = '';
        });
        container.appendChild(createSubFormRow(emptyRow, field));
      });
    }
    container.addEventListener('click', function (e) {
      if (e.target.classList.contains('rule-sub-form-remove')) {
        var row = e.target.closest('.rule-sub-form-row');
        if (row) row.remove();
      }
    });
  });

  // Color preview for select with type 'color'
  var colorSelects = modal.querySelectorAll('.rule-color-select');
  colorSelects.forEach(function (wrap) {
    var sel = wrap.querySelector('select');
    var preview = wrap.querySelector('.rule-color-preview');
    function updatePreview() {
      preview.style.backgroundColor = (COLOR_MAP || {})[sel.value] || sel.value || '#999';
    }
    sel.addEventListener('change', updatePreview);
    updatePreview();
  });

  // Compile
  modal.querySelector('#rule-modal-compile').addEventListener('click', function () {
    compileModalFields(modal, config);
  });

  function closeModal() {
    if (overlay.parentNode) overlay.remove();
  }
  modal.querySelector('.hae-modal-close').addEventListener('click', closeModal);
  modal.querySelector('#rule-modal-cancel').addEventListener('click', closeModal);
  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) closeModal();
  });
  document.addEventListener('keydown', function escHandler(e) {
    if (e.key === 'Escape') {
      closeModal();
      document.removeEventListener('keydown', escHandler);
    }
  });

  // Save
  modal.querySelector('#rule-modal-save').addEventListener('click', function () {
    var newItem = collectModalData(modal, config);
    if (newItem === null) return;

    if (isEdit) {
      var oldIdentity = getIdentityValue(opts.item, config);
      loadRuleData(config).then(function (data) {
        var merged = data.map(function (it) {
          return String(getIdentityValue(it, config)) === String(oldIdentity) ? newItem : it;
        });
        saveRuleData(config, merged).then(function () {
          closeModal();
          renderCurrentSection();
          showStatus('已更新', 'success');
        });
      });
    } else {
      loadRuleData(config).then(function (data) {
        var dup = data.some(function (it) {
          return String(getIdentityValue(it, config)) === String(getIdentityValue(newItem, config));
        });
        if (dup) {
          setModalStatus(modal, 'ID 重复，请修改', 'error');
          return;
        }
        data = data.concat([newItem]);
        saveRuleData(config, data).then(function () {
          closeModal();
          renderCurrentSection();
          showStatus('已添加', 'success');
        });
      });
    }
  });
}

function createFormFieldHTML(field, value) {
  switch (field.type) {
    case 'text':
      return (
        '<input type="text" id="rule-field-' +
        field.key +
        '" value="' +
        escapeAttr(String(value || '')) +
        '">'
      );
    case 'textarea':
      return (
        '<textarea id="rule-field-' +
        field.key +
        '" rows="3">' +
        escapeHtml(String(value || '')) +
        '</textarea>'
      );
    case 'regex':
      var display =
        value instanceof RegExp
          ? value.toString().replace(/^\/|\/[gimsuy]*$/g, '')
          : String(value || '');
      return (
        '<textarea id="rule-field-' +
        field.key +
        '" rows="3" placeholder="输入正则表达式" spellcheck="false">' +
        escapeHtml(display) +
        '</textarea>'
      );
    case 'select':
      var opts = (field.options || [])
        .map(function (o) {
          return (
            '<option value="' +
            escapeAttr(o) +
            '"' +
            (o === value ? ' selected' : '') +
            '>' +
            escapeHtml(o) +
            '</option>'
          );
        })
        .join('');
      if (field.key === 'color') {
        return (
          '<div class="rule-color-select"><span class="rule-color-preview" style="display:inline-block;width:14px;height:14px;border-radius:3px;margin-right:6px;vertical-align:middle"></span><select id="rule-field-' +
          field.key +
          '">' +
          opts +
          '</select></div>'
        );
      }
      return '<select id="rule-field-' + field.key + '">' + opts + '</select>';
    case 'checkbox':
      return (
        '<input type="checkbox" id="rule-field-' + field.key + '"' + (value ? ' checked' : '') + '>'
      );
    case 'number':
      return (
        '<input type="number" id="rule-field-' +
        field.key +
        '" value="' +
        (value !== undefined && value !== null ? value : '') +
        '">'
      );
    case 'regex-array':
      var arr = Array.isArray(value) ? value : [];
      var lines = arr.map(function (r) {
        return r instanceof RegExp ? r.toString().replace(/^\/|\/[gimsuy]*$/g, '') : String(r);
      });
      return (
        '<textarea id="rule-field-' +
        field.key +
        '" rows="4" placeholder="每行一个正则表达式" spellcheck="false">' +
        escapeHtml(lines.join('\n')) +
        '</textarea>'
      );
    default:
      return (
        '<input type="text" id="rule-field-' +
        field.key +
        '" value="' +
        escapeAttr(String(value || '')) +
        '">'
      );
  }
}

function renderSubObjectArrayField(field, items, config) {
  var html =
    '<div class="hae-form-group" style="grid-column:1/-1">' +
    '<label class="hae-form-label">' +
    field.label +
    '</label>' +
    '<div class="rule-sub-form-container" data-field-key="' +
    field.key +
    '">';
  items.forEach(function (item) {
    html += createSubFormRowHTML(item, field);
  });
  html +=
    '<button type="button" class="btn btn-outline btn-sm rule-sub-form-add">+ 添加规则</button>';
  html += '</div></div>';
  return html;
}

function createSubFormRowHTML(item, field) {
  var html = '<div class="rule-sub-form-row">';
  (field.subFields || []).forEach(function (sf) {
    var val = item[sf.key] || '';
    if (val instanceof RegExp) val = val.toString();
    var displayVal =
      sf.type === 'select'
        ? (sf.options || [])
            .map(function (o) {
              return (
                '<option value="' +
                escapeAttr(o) +
                '"' +
                (o === val ? ' selected' : '') +
                '>' +
                escapeHtml(o) +
                '</option>'
              );
            })
            .join('')
        : ' value="' + escapeAttr(String(val)) + '"';
    var inputTag = sf.type === 'select' ? 'select' : 'input type="text"';
    html +=
      '<' +
      inputTag +
      ' class="rule-sub-input" data-sub-key="' +
      sf.key +
      '"' +
      displayTag(inputTag, displayVal) +
      '>';
  });
  html +=
    '<button type="button" class="hae-btn-icon hae-btn-danger rule-sub-form-remove" title="删除">&#10005;</button>';
  html += '</div>';
  return html;
}

function displayTag(inputTag, displayVal) {
  return inputTag === 'select' ? '>' + displayVal + '</select>' : displayVal;
}

function createSubFormRow(item, field) {
  var row = document.createElement('div');
  row.className = 'rule-sub-form-row';
  (field.subFields || []).forEach(function (sf) {
    var val = item[sf.key] || '';
    if (sf.type === 'select') {
      var sel = document.createElement('select');
      sel.className = 'rule-sub-input';
      sel.dataset.subKey = sf.key;
      (sf.options || []).forEach(function (o) {
        var opt = document.createElement('option');
        opt.value = o;
        opt.textContent = o;
        if (o === val) opt.selected = true;
        sel.appendChild(opt);
      });
      row.appendChild(sel);
    } else {
      var input = document.createElement('input');
      input.type = 'text';
      input.className = 'rule-sub-input';
      input.dataset.subKey = sf.key;
      input.value = String(val);
      row.appendChild(input);
    }
  });
  var removeBtn = document.createElement('button');
  removeBtn.type = 'button';
  removeBtn.className = 'hae-btn-icon hae-btn-danger rule-sub-form-remove';
  removeBtn.title = '删除';
  removeBtn.innerHTML = '&#10005;';
  row.appendChild(removeBtn);
  return row;
}

function setModalStatus(modal, text, type) {
  var el = modal.querySelector('#rule-modal-status');
  if (!el) return;
  el.textContent = text;
  el.className = 'hae-modal-status ' + (type || '');
}

function collectModalData(modal, config) {
  var item = {};
  var hasError = false;

  config.fields.forEach(function (field) {
    if (field.key === 'matchers') {
      var rows = modal.querySelectorAll(
        '.rule-sub-form-container[data-field-key="matchers"] .rule-sub-form-row'
      );
      var matchers = [];
      rows.forEach(function (row) {
        var m = {};
        row.querySelectorAll('.rule-sub-input').forEach(function (input) {
          var key = input.dataset.subKey;
          m[key] = input.value;
        });
        if (m.source && m.value) matchers.push(m);
      });
      item[field.key] = matchers;
      return;
    }

    var el = modal.querySelector('#rule-field-' + field.key);
    if (!el) return;

    if (field.type === 'regex') {
      var val = el.value.trim();
      if (field.required && !val) {
        setModalStatus(modal, field.label + ' 不能为空', 'error');
        hasError = true;
        return;
      }
      if (val) {
        try {
          item[field.key] = new RegExp(val);
        } catch (e) {
          setModalStatus(modal, field.label + ' 正则无效: ' + e.message, 'error');
          hasError = true;
          return;
        }
      }
    } else if (field.type === 'regex-array') {
      var lines = el.value
        .split('\n')
        .map(function (l) {
          return l.trim();
        })
        .filter(function (l) {
          return l.length > 0;
        });
      var regexes = [];
      lines.forEach(function (line) {
        try {
          regexes.push(new RegExp(line));
        } catch (e) {
          setModalStatus(modal, field.label + ' 正则无效 (' + line + '): ' + e.message, 'error');
          hasError = true;
        }
      });
      item[field.key] = regexes;
    } else if (field.type === 'checkbox') {
      item[field.key] = el.checked;
    } else if (field.type === 'number') {
      item[field.key] = parseInt(el.value, 10) || 0;
    } else if (field.type === 'select') {
      item[field.key] = el.value;
    } else {
      item[field.key] = el.value.trim();
      if (field.required && !item[field.key]) {
        setModalStatus(modal, field.label + ' 不能为空', 'error');
        hasError = true;
      }
    }
  });

  return hasError ? null : item;
}

function compileModalFields(modal, config) {
  var errors = [];
  config.fields.forEach(function (field) {
    if (field.type === 'regex') {
      var el = modal.querySelector('#rule-field-' + field.key);
      if (!el) return;
      var val = el.value.trim();
      if (!val) {
        errors.push(field.label + ': 空');
        return;
      }
      try {
        new RegExp(val);
      } catch (e) {
        errors.push(field.label + ': ' + e.message);
      }
    } else if (field.type === 'regex-array') {
      var el2 = modal.querySelector('#rule-field-' + field.key);
      if (!el2) return;
      el2.value.split('\n').forEach(function (line, i) {
        line = line.trim();
        if (!line) return;
        try {
          new RegExp(line);
        } catch (e) {
          errors.push(field.label + ' #' + (i + 1) + ': ' + e.message);
        }
      });
    }
  });

  if (errors.length === 0) {
    setModalStatus(modal, '验证通过', 'success');
  } else {
    setModalStatus(modal, errors[0], 'error');
  }
}

// ====== Import / Export / Validate ======

function exportRulesJSON(config) {
  loadRuleData(config).then(function (data) {
    var serialized = serializeData(data, config);
    var json = JSON.stringify(serialized, null, 2);
    var blob = new Blob([json], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'lingmou-' + config.id + '.json';
    a.click();
    URL.revokeObjectURL(url);
    showStatus('已导出 ' + config.label, 'success');
  });
}

function importRulesJSON(config) {
  var input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  input.onchange = function (e) {
    var file = e.target.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function (evt) {
      try {
        var parsed = JSON.parse(evt.target.result);
        if (config.structure === 'flat-strings') {
          if (!Array.isArray(parsed)) {
            showStatus('格式错误：需要字符串数组', 'error');
            return;
          }
          var valid = parsed.filter(function (s) {
            return typeof s === 'string';
          });
          saveRuleData(config, valid).then(function () {
            renderCurrentSection();
            showStatus('已导入 ' + valid.length + ' 项', 'success');
          });
          return;
        }
        if (config.structure === 'grouped-strings') {
          if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
            showStatus('格式错误：需要分组对象', 'error');
            return;
          }
          saveRuleData(config, parsed).then(function () {
            renderCurrentSection();
            showStatus('已导入', 'success');
          });
          return;
        }
        // flat-objects
        if (!Array.isArray(parsed)) {
          showStatus('格式错误：需要对象数组', 'error');
          return;
        }
        saveRuleData(config, parsed).then(function () {
          renderCurrentSection();
          showStatus('已导入 ' + parsed.length + ' 项', 'success');
        });
      } catch (ex) {
        showStatus('导入失败: ' + ex.message, 'error');
      }
    };
    reader.readAsText(file);
  };
  input.click();
}

function validateAllRules(config) {
  var data = _currentRuleData;
  if (!data) return;

  var container = $('extended-rules-container');
  if (!container) return;

  var existingResults = container.parentNode.querySelector('.hae-validate-results');
  if (existingResults) existingResults.remove();

  var total = 0;
  var valid = 0;
  var invalidList = [];

  if (config.structure === 'grouped-strings' || config.structure === 'flat-strings') {
    showStatus('字符串类型无需正则验证', 'info');
    return;
  }

  data.forEach(function (item) {
    total++;
    var itemLabel = config.listLabel ? item[config.listLabel] : '?';
    config.fields.forEach(function (field) {
      if (field.type !== 'regex' && field.type !== 'regex-array') return;
      if (field.type === 'regex') {
        var val = item[field.key];
        if (!val) {
          invalidList.push({ label: itemLabel, error: field.label + ' 为空' });
          return;
        }
        if (!(val instanceof RegExp)) {
          invalidList.push({ label: itemLabel, error: field.label + ' 非正则' });
          return;
        }
        valid++;
      } else if (field.type === 'regex-array') {
        var arr = item[field.key];
        if (!Array.isArray(arr)) return;
        arr.forEach(function (r, i) {
          total++;
          if (!(r instanceof RegExp)) {
            invalidList.push({ label: itemLabel, error: field.label + ' #' + (i + 1) + ' 非正则' });
          } else {
            valid++;
          }
        });
      }
    });
  });

  var resultsDiv = document.createElement('div');
  resultsDiv.className = 'hae-validate-results';
  var summary = '验证完成: ' + valid + '/' + total + ' 项有效';
  summary += invalidList.length === 0 ? ' -- 全部通过' : ', ' + invalidList.length + ' 项无效';
  resultsDiv.innerHTML =
    '<div style="margin-bottom:6px;font-weight:600;color:var(--opt-text)">' +
    escapeHtml(summary) +
    '</div>';

  invalidList.forEach(function (item) {
    var row = document.createElement('div');
    row.className = 'hae-validate-item invalid';
    row.innerHTML =
      '<span>' +
      escapeHtml(item.label) +
      '</span><span class="hae-validate-error">' +
      escapeHtml(item.error) +
      '</span>';
    resultsDiv.appendChild(row);
  });

  container.parentNode.insertBefore(resultsDiv, container);

  if (invalidList.length === 0) {
    showStatus('全部 ' + valid + ' 项验证通过', 'success');
  } else {
    showStatus(invalidList.length + ' 项验证失败', 'error');
  }
}
