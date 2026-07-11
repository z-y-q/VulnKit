import { describe, it, expect } from 'vitest';
import {
  detectContext,
  findReflection,
  isSanitized,
  buildPayloadsForContext,
  assessSeverity,
  severityLabel,
  SEVERITY_ORDER,
  XSS_SORT_FNS,
  XSS_MARKERS,
  REFLECTION_PROBE,
  analyzeSinkLine,
  type XssContext,
} from '@/lib/scanners/xss-engine';

// ====== 测试 ======

describe('xss-engine: 常量', () => {
  it('XSS_MARKERS 非空，含特殊字符', () => {
    expect(XSS_MARKERS.length).toBeGreaterThan(0);
    expect(XSS_MARKERS[0]).toContain('vkxssprobe');
    expect(XSS_MARKERS[1]).toContain('"');
    expect(XSS_MARKERS[2]).toContain('/');
  });

  it('REFLECTION_PROBE 非空', () => {
    expect(REFLECTION_PROBE.length).toBeGreaterThan(0);
    expect(REFLECTION_PROBE).toContain("vkxss'");
  });

  it('SEVERITY_ORDER critical < high < medium < low < info', () => {
    expect(SEVERITY_ORDER.critical).toBeLessThan(SEVERITY_ORDER.high);
    expect(SEVERITY_ORDER.high).toBeLessThan(SEVERITY_ORDER.medium);
    expect(SEVERITY_ORDER.medium).toBeLessThan(SEVERITY_ORDER.low);
    expect(SEVERITY_ORDER.low).toBeLessThan(SEVERITY_ORDER.info);
  });
});

describe('xss-engine: detectContext', () => {
  // detectContext uses before = surrounding.slice(-60) and after = surrounding.slice(0, 60)
  // So the LAST 60 chars must contain the injection context pattern

  it('script 标签内 → script', () => {
    // before (last 60) ends with <script...>, after (first 60) starts with </script>
    const surrounding = '</script>  <script type="text/javascript">var x = "PAYLOAD';
    expect(detectContext(surrounding)).toBe('script');
  });

  it('href 属性值 → url', () => {
    // before (last 60) ends with href="
    const surrounding = '<div>some content</div><a href="PAYLOAD';
    expect(detectContext(surrounding)).toBe('url');
  });

  it('src 属性值 → url', () => {
    const surrounding = '<div>content</div><img src="PAYLOAD';
    expect(detectContext(surrounding)).toBe('url');
  });

  it('style 属性值 → style', () => {
    const surrounding = '<div>text</div><div style="PAYLOAD';
    expect(detectContext(surrounding)).toBe('style');
  });

  it('引号未闭合属性值 → attr', () => {
    const surrounding = '<div>text</div><input value="PAYLOAD';
    expect(detectContext(surrounding)).toBe('attr');
  });

  it('HTML 标签属性区 → attr', () => {
    const surrounding = '<div>text</div><div class="x" PAYLOAD';
    expect(detectContext(surrounding)).toBe('attr');
  });

  it('普通 HTML 文本 → html', () => {
    const surrounding = '<p>Hello PAYLOAD</p>';
    expect(detectContext(surrounding)).toBe('html');
  });

  it('空字符串 → html', () => {
    expect(detectContext('')).toBe('html');
  });

  it('action 属性值 → url', () => {
    const surrounding = '<div>content</div><form action="PAYLOAD';
    expect(detectContext(surrounding)).toBe('url');
  });
});

describe('xss-engine: findReflection', () => {
  it('精确匹配 — 返回 found=true，含 surrounding', () => {
    const body = '<div class="test">vkxssprobe1<></div>';
    const result = findReflection(body, 'vkxssprobe1<>');
    expect(result.found).toBe(true);
    expect(result.surrounding).toBeDefined();
    expect(result.context).toBe('html');
  });

  it('不匹配 — 返回 found=false', () => {
    const body = '<div>Nothing here</div>';
    const result = findReflection(body, 'vkxssprobe1<>');
    expect(result.found).toBe(false);
  });

  it('空 body — 返回 found=false', () => {
    const result = findReflection('', 'vkxssprobe1<>');
    expect(result.found).toBe(false);
  });

  it('空 marker — 返回 found=false', () => {
    const result = findReflection('<div>test</div>', '');
    expect(result.found).toBe(false);
  });

  it('HTML 实体编码后匹配 — &lt; 被解码', () => {
    const body = '<div>vkxssprobe1&lt;&gt;</div>';
    const result = findReflection(body, 'vkxssprobe1<>');
    expect(result.found).toBe(true);
  });

  it('URI 编码后匹配', () => {
    const encoded = encodeURIComponent('vkxssprobe1<>');
    const body = '<div>' + encoded + '</div>';
    const result = findReflection(body, 'vkxssprobe1<>');
    expect(result.found).toBe(true);
  });

  it('反射在 script 标签内 → context=script', () => {
    const body = '<script>var x = "vkxssprobe1<>";</script>';
    const result = findReflection(body, 'vkxssprobe1<>');
    expect(result.found).toBe(true);
    expect(result.context).toBe('script');
  });

  it('反射在 href 属性 → context=url', () => {
    const body = '<div>some padding to ensure before slice has enough</div><a href="vkxssprobe1<>">link</a>';
    const result = findReflection(body, 'vkxssprobe1<>');
    expect(result.found).toBe(true);
    expect(result.context).toBe('url');
  });

  it('去空白后匹配也能找到', () => {
    const body = '<div>vkxss probe1<></div>';
    const result = findReflection(body, 'vkxssprobe1<>');
    // marker stripped = "vkxssprobe1<>" 与 body stripped "vkxssprobe1<>" 匹配
    expect(result.found).toBe(true);
  });
});

describe('xss-engine: isSanitized', () => {
  it('空 body 返回 false', () => {
    expect(isSanitized('', '<script>alert(1)</script>')).toBe(false);
  });

  it('payload 仍完整反射，无 sanitizer → false', () => {
    const body = '<div><script>alert(1)</script></div>';
    expect(isSanitized(body, '<script>alert(1)</script>')).toBe(false);
  });

  it('DOMPurify 存在 → true（reduction >= 5）', () => {
    const body = 'const clean = DOMPurify.sanitize(input); element.innerHTML = clean;';
    expect(isSanitized(body, '<script>alert(1)</script>')).toBe(true);
  });

  it('Trusted Types 存在 → true（reduction >= 5）', () => {
    const body = 'policy = trustedTypes.createPolicy("default", { createHTML: (s) => s });';
    expect(isSanitized(body, '<script>alert(1)</script>')).toBe(true);
  });

  it('escapeHtml 存在且 payload 被移除 → true', () => {
    // escapeHtml reduction=3，且 payload 不再出现
    const body = 'const safe = escapeHtml(userInput); div.textContent = safe;';
    expect(isSanitized(body, '<img src=x onerror=alert(1)>')).toBe(true);
  });
});

describe('xss-engine: buildPayloadsForContext', () => {
  it('返回数组，且长度大于 0', () => {
    for (const ctx of ['html', 'attr', 'script', 'url', 'style'] as XssContext[]) {
      const payloads = buildPayloadsForContext(ctx);
      expect(Array.isArray(payloads)).toBe(true);
      expect(payloads.length).toBeGreaterThan(0);
    }
  });

  it('html 上下文包含通用 payload', () => {
    const payloads = buildPayloadsForContext('html');
    // 至少有 XSS_SCAN_PAYLOADS 中的数量
    expect(payloads.length).toBeGreaterThanOrEqual(20);
  });

  it('attr 上下文包含 attribute payload', () => {
    const payloads = buildPayloadsForContext('attr');
    // 应含 onerror/onfocus 等 attribute payloads
    const hasAttrPayload = payloads.some(p => p.includes('onerror=') || p.includes('onfocus='));
    expect(hasAttrPayload).toBe(true);
  });

  it('script 上下文包含 eval payload', () => {
    const payloads = buildPayloadsForContext('script');
    const hasEval = payloads.some(p => p.includes('console.log') || p.includes('constructor'));
    expect(hasEval).toBe(true);
  });

  it('url 上下文包含 javascript: payload', () => {
    const payloads = buildPayloadsForContext('url');
    const hasJs = payloads.some(p => p.includes('javascript:'));
    expect(hasJs).toBe(true);
  });

  it('所有上下文共享通用 payload（去重）', () => {
    const htmlPayloads = buildPayloadsForContext('html');
    const attrPayloads = buildPayloadsForContext('attr');
    // 通用 payload 应出现在所有上下文
    const common = htmlPayloads[0]; // 第一个来自 XSS_SCAN_PAYLOADS
    expect(attrPayloads).toContain(common);
  });
});

describe('xss-engine: assessSeverity', () => {
  it('未反射 → info', () => {
    expect(assessSeverity('html', false, false)).toBe('info');
    expect(assessSeverity('script', false, false)).toBe('info');
  });

  it('已净化 → low', () => {
    expect(assessSeverity('html', true, true)).toBe('low');
    expect(assessSeverity('script', true, true)).toBe('low');
  });

  it('script 上下文反射且未净化 → critical', () => {
    expect(assessSeverity('script', true, false)).toBe('critical');
  });

  it('html 上下文反射且未净化 → high', () => {
    expect(assessSeverity('html', true, false)).toBe('high');
  });

  it('attr 上下文反射且未净化 → high', () => {
    expect(assessSeverity('attr', true, false)).toBe('high');
  });

  it('url 上下文反射且未净化 → medium', () => {
    expect(assessSeverity('url', true, false)).toBe('medium');
  });

  it('style 上下文反射且未净化 → medium', () => {
    expect(assessSeverity('style', true, false)).toBe('medium');
  });
});

describe('xss-engine: severityLabel', () => {
  it('中文映射正确', () => {
    expect(severityLabel('critical')).toBe('严重');
    expect(severityLabel('high')).toBe('高危');
    expect(severityLabel('medium')).toBe('中危');
    expect(severityLabel('low')).toBe('低危');
    expect(severityLabel('info')).toBe('信息');
  });
});

describe('xss-engine: analyzeSinkLine', () => {
  it('innerHtml sink 匹配，返回结果', () => {
    const result = analyzeSinkLine('document.getElementById("x").innerHTML = userInput;');
    expect(result).not.toBeNull();
    expect(result!.contexts).toContain('innerHTML');
    expect(result!.severity).toBeDefined();
    expect(result!.score).toBeGreaterThanOrEqual(1);
    expect(result!.score).toBeLessThanOrEqual(10);
  });

  it('eval sink 为 critical 级别', () => {
    const result = analyzeSinkLine('eval(userInput);');
    expect(result).not.toBeNull();
    expect(result!.severity).toBe('critical');
  });

  it('document.write sink 匹配', () => {
    const result = analyzeSinkLine('document.write("<div>" + userInput + "</div>");');
    expect(result).not.toBeNull();
    expect(result!.contexts).toContain('documentWrite');
  });

  it('setTimeout 字符串参数匹配', () => {
    const result = analyzeSinkLine("setTimeout('userInput', 100);");
    expect(result).not.toBeNull();
    expect(result!.contexts).toContain('setTimeout');
  });

  it('普通代码不匹配 → 返回 null', () => {
    const result = analyzeSinkLine('const x = 42;');
    expect(result).toBeNull();
  });

  it('DOMPurify sanitizer 降低分数', () => {
    const without = analyzeSinkLine('element.innerHTML = userInput;');
    const withSanitizer = analyzeSinkLine('element.innerHTML = DOMPurify.sanitize(userInput);');
    expect(without).not.toBeNull();
    expect(withSanitizer).not.toBeNull();
    expect(withSanitizer!.score).toBeLessThanOrEqual(without!.score);
    expect(withSanitizer!.sanitizers).toContain('DOMPurify');
  });

  it('source=event-attr 增加分数', () => {
    const normal = analyzeSinkLine('element.innerHTML = data;');
    const eventAttr = analyzeSinkLine('element.innerHTML = data;', 'event-attr');
    expect(eventAttr).not.toBeNull();
    expect(normal).not.toBeNull();
    expect(eventAttr!.score).toBeGreaterThan(normal!.score);
  });

  it('source=js-href 增加更多分数', () => {
    const normal = analyzeSinkLine('element.innerHTML = data;');
    const jsHref = analyzeSinkLine('element.innerHTML = data;', 'js-href');
    expect(jsHref).not.toBeNull();
    expect(normal).not.toBeNull();
    expect(jsHref!.score).toBeGreaterThan(normal!.score);
  });

  it('Trusted Types sanitizer 大幅降低分数', () => {
    const result = analyzeSinkLine('const p = trustedTypes.createPolicy("d", {}); element.innerHTML = input;');
    expect(result).not.toBeNull();
    expect(result!.sanitizers).toContain('Trusted Types');
    expect(result!.score).toBeLessThanOrEqual(4); // 严重 reduction
  });

  it('分数 clamp 在 1-10', () => {
    // 非常多的 sanitizer 应不会降到 0
    const result = analyzeSinkLine(
      'const p = trustedTypes.createPolicy("d", {});' +
      'const c = DOMPurify.sanitize(d);' +
      'element.innerHTML = c;',
    );
    expect(result).not.toBeNull();
    expect(result!.score).toBeGreaterThanOrEqual(1);
    expect(result!.score).toBeLessThanOrEqual(10);
  });

  it('多 pattern 匹配时 contexts 去重', () => {
    // innerHTML + insertAdjacentHTML 都命中
    const result = analyzeSinkLine(
      'div.innerHTML = data; div.insertAdjacentHTML("beforeend", data);',
    );
    expect(result).not.toBeNull();
    const uniqueContexts = new Set(result!.contexts);
    expect(result!.contexts.length).toBe(uniqueContexts.size);
  });
});

describe('xss-engine: XSS_SORT_FNS', () => {
  it('按 severity 排序', () => {
    const findings = [
      { param: 'a', payload: '', context: 'html' as XssContext, reflected: true, sanitized: false, severity: 'info' as const },
      { param: 'b', payload: '', context: 'html' as XssContext, reflected: true, sanitized: false, severity: 'critical' as const },
      { param: 'c', payload: '', context: 'html' as XssContext, reflected: true, sanitized: false, severity: 'medium' as const },
    ];
    const sorted = [...findings].sort(XSS_SORT_FNS.severity);
    expect(sorted[0].severity).toBe('critical');
    expect(sorted[2].severity).toBe('info');
  });

  it('按 param 名称排序', () => {
    const findings = [
      { param: 'zebra', payload: '', context: 'html' as XssContext, reflected: true, sanitized: false, severity: 'info' as const },
      { param: 'alpha', payload: '', context: 'html' as XssContext, reflected: true, sanitized: false, severity: 'info' as const },
    ];
    const sorted = [...findings].sort(XSS_SORT_FNS.param);
    expect(sorted[0].param).toBe('alpha');
  });

  it('按 context 排序', () => {
    const findings = [
      { param: 'a', payload: '', context: 'script' as XssContext, reflected: true, sanitized: false, severity: 'info' as const },
      { param: 'b', payload: '', context: 'attr' as XssContext, reflected: true, sanitized: false, severity: 'info' as const },
    ];
    const sorted = [...findings].sort(XSS_SORT_FNS.context);
    expect(sorted[0].context).toBe('attr');
  });
});
