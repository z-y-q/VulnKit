// 灵眸 - XSS DOM Sink Analysis
'use strict';

import { utilsProxy as utils } from './vk-namespace.js';
import {
  CONTEXT_PAYLOADS,
  SINK_PATTERNS,
  SANITIZER_PATTERNS,
  SEVERITY_CONFIG,
} from './vk-xss-data.js';

let domSinks = [];

function analyzeSingleSink(sink) {
  let code = sink.code || '';
  let matchedPatterns = [];
  SINK_PATTERNS.forEach(function (sp) {
    let regex = new RegExp(sp.regex.source, sp.regex.flags);
    let matches = code.match(regex);
    if (matches && matches.length > 0) {
      matchedPatterns.push({ context: sp.context, severity: sp.severity, count: matches.length });
    }
  });
  if (matchedPatterns.length === 0) {
    return Object.assign({}, sink, { matched: false });
  }
  let sanitizers = [];
  let totalReduction = 0;
  SANITIZER_PATTERNS.forEach(function (sp) {
    let regex = new RegExp(sp.regex.source, sp.regex.flags);
    if (regex.test(code)) {
      sanitizers.push(sp.name);
      totalReduction += sp.reduction;
    }
  });
  let baseScore = 8;
  let hasCritical = matchedPatterns.some(function (m) {
    return m.severity === 'critical';
  });
  let hasHigh = matchedPatterns.some(function (m) {
    return m.severity === 'high';
  });
  if (hasCritical) baseScore = 9;
  else if (hasHigh) baseScore = 7;
  else baseScore = 5;
  baseScore -= totalReduction;
  baseScore += matchedPatterns.length > 2 ? 1 : 0;
  if (sink.source === 'event-attr') baseScore += 1;
  if (sink.source === 'js-href') baseScore += 2;
  baseScore = Math.max(1, Math.min(10, baseScore));
  let severity;
  if (baseScore >= 8) severity = 'critical';
  else if (baseScore >= 6) severity = 'high';
  else if (baseScore >= 4) severity = 'medium';
  else severity = 'low';
  let contexts = matchedPatterns.map(function (m) {
    return m.context;
  });
  let uniqueContexts = contexts.filter(function (v, i, a) {
    return a.indexOf(v) === i;
  });
  return Object.assign({}, sink, {
    matched: true,
    contexts: uniqueContexts,
    severity: severity,
    score: baseScore,
    sanitizers: sanitizers,
    sinkCount: matchedPatterns.reduce(function (sum, m) {
      return sum + m.count;
    }, 0),
  });
}

function getContextPayloads(sink) {
  let payloads = [];
  (sink.contexts || []).forEach(function (ctx) {
    let ctxPayloads = CONTEXT_PAYLOADS[ctx];
    if (ctxPayloads) {
      payloads = payloads.concat(ctxPayloads);
    }
  });
  let seen = {};
  return payloads.filter(function (p) {
    if (seen[p]) return false;
    seen[p] = true;
    return true;
  });
}

function renderDomSinks() {
  let container = utils.get('xssscan-sink-results');
  if (!container) return;
  if (domSinks.length === 0) {
    utils.setEmpty('xssscan-sink-results', '未发现 DOM XSS 汇点');
    return;
  }
  let html = '<div class="xssscan-sink-list">';
  domSinks.forEach(function (sink, i) {
    let sevConf = SEVERITY_CONFIG[sink.severity] || SEVERITY_CONFIG.info;
    let shortCode = sink.code.length > 80 ? `${sink.code.substring(0, 77)}...` : sink.code;
    let sanitizerTag =
      sink.sanitizers.length > 0
        ? `<span class="xssscan-sanitizer-tag">${sink.sanitizers.join(', ')}</span>`
        : '';
    let sourceLabels = {
      inline: '内联JS',
      external: '外部脚本',
      'event-attr': '事件属性',
      'js-href': 'JS链接',
    };
    let contextTags = (sink.contexts || [])
      .map(function (c) {
        return `<span class="xssscan-ctx-tag">${utils.escapeHtml(c)}</span>`;
      })
      .join('');
    html += `<div class="xssscan-sink-item">
<div class="xssscan-sink-header">
<span class="xssscan-severity-badge" style="background:${sevConf.color}">${sevConf.label}</span>
<span class="xssscan-score-badge">评分: ${sink.score}/10</span>
<span class="xssscan-source-label">${sourceLabels[sink.source] || sink.source}</span>`;
    if (sink.sinkCount > 1) {
      html += `<span class="xssscan-count-tag">x${sink.sinkCount}</span>`;
    }
    html += sanitizerTag;
    html += '</div>';
    html += `<div class="xssscan-sink-code" title="${utils.escapeHtml(sink.code)}">${utils.escapeHtml(shortCode)}</div>`;
    if (contextTags) {
      html += `<div class="xssscan-sink-contexts">${contextTags}</div>`;
    }
    let ctxPayloads = getContextPayloads(sink);
    if (ctxPayloads.length > 0) {
      html += '<div class="xssscan-sink-payloads">';
      ctxPayloads.slice(0, 3).forEach(function (p) {
        html += `<code class="xssscan-sink-payload" title="${utils.escapeHtml(p)}">${utils.escapeHtml(p.length > 50 ? `${p.substring(0, 47)}...` : p)}</code>`;
      });
      if (ctxPayloads.length > 3) {
        html += `<span class="xssscan-sink-more">+${ctxPayloads.length - 3}</span>`;
      }
      html += '</div>';
    }
    html += '</div>';
  });
  html += '</div>';
  container.innerHTML = html;
  container.querySelectorAll('.xssscan-sink-payload').forEach(function (el) {
    el.style.cursor = 'pointer';
    el.title = '点击复制';
    el.addEventListener('click', function () {
      utils.copyText(el.getAttribute('title'));
      utils.showToast('已复制 Payload', 'success');
    });
  });
}

async function analyzeDomSinks() {
  const tab = await utils.requireTabId();
  if (!tab) return [];
  const statusEl = utils.get('xssscan-sink-status');
  if (statusEl) {
    statusEl.textContent = '正在分析 DOM XSS 汇点...';
    statusEl.style.color = '#4A90E2';
  }
  try {
    let rawSinks = await utils.execInTabData(
      tab.id,
      function () {
        let sinks = [];
        let scripts = document.querySelectorAll('script:not([src])');
        scripts.forEach(function (s) {
          let text = s.textContent || '';
          let lines = text.split('\n');
          lines.forEach(function (line, idx) {
            let trimmed = line.trim();
            if (!trimmed || trimmed.length < 5) return;
            if (trimmed.indexOf('return ') === 0 && trimmed.length < 30) return;
            sinks.push({ code: trimmed, line: idx + 1, source: 'inline' });
          });
        });
        document.querySelectorAll('script[src]').forEach(function (s) {
          sinks.push({ code: s.src || '', line: 0, source: 'external', isUrl: true });
        });
        let allEls = document.querySelectorAll('*');
        let scanned = 0;
        for (let i = 0; i < allEls.length && scanned < 2000; i++) {
          let el = allEls[i];
          let hasOn = false;
          el.getAttributeNames().forEach(function (n) {
            if (n.indexOf('on') === 0 && el.getAttribute(n)) {
              hasOn = true;
            }
          });
          if (hasOn) {
            scanned++;
            let attrs = [];
            el.getAttributeNames().forEach(function (n) {
              if (n.indexOf('on') === 0 && el.getAttribute(n)) {
                attrs.push({ attr: n, value: el.getAttribute(n) });
              }
            });
            if (attrs.length > 0) {
              sinks.push({
                code: attrs
                  .map(function (a) {
                    return `${a.attr}="${a.value}"`;
                  })
                  .join(' '),
                line: 0,
                source: 'event-attr',
                tag: el.tagName.toLowerCase(),
              });
            }
          }
        }
        let hrefs = document.querySelectorAll('a[href^="javascript:"]');
        hrefs.forEach(function (a) {
          sinks.push({
            code: `href="${a.getAttribute('href') || ''}"`,
            line: 0,
            source: 'js-href',
            tag: 'a',
          });
        });
        return sinks;
      },
      { world: 'ISOLATED' }
    );
    rawSinks = rawSinks || [];
    let analyzed = rawSinks.map(function (s) {
      return analyzeSingleSink(s);
    });
    analyzed = analyzed.filter(function (s) {
      return s.matched;
    });
    analyzed.sort(function (a, b) {
      return b.score - a.score;
    });
    domSinks = analyzed;
    renderDomSinks();
    if (statusEl) {
      statusEl.textContent = `分析完成，发现 ${analyzed.length} 个潜在 DOM XSS 汇点`;
      statusEl.style.color = analyzed.length > 0 ? '#e67e22' : '#27ae60';
    }
    if (analyzed.length > 0) {
      utils.showToast(`发现 ${analyzed.length} 个 DOM XSS 汇点`, 'warning');
    } else {
      utils.showToast('未发现 DOM XSS 汇点', 'info');
    }
    return analyzed;
  } catch (e) {
    if (statusEl) {
      statusEl.textContent = `分析失败: ${e.message}`;
      statusEl.style.color = '#e74c3c';
    }
    utils.showToast('DOM 分析失败', 'error');
    return [];
  }
}

export { analyzeDomSinks, domSinks };
