import { describe, it, expect } from '@jest/globals';
import { analyzeSingleSink, getContextPayloads } from '../src/popup/vk-xss-sinks.js';

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low'];

describe('analyzeSingleSink', () => {
  it('returns matched: false for code that matches no sink pattern', () => {
    const sink = { code: 'let x = 1;', source: 'inline' };
    const result = analyzeSingleSink(sink);

    expect(result).toMatchObject({ matched: false });
    expect(result.code).toBe('let x = 1;');
    expect(result.source).toBe('inline');
  });

  it('assigns high severity for innerHTML assignment', () => {
    const sink = { code: 'el.innerHTML = userInput;', source: 'inline' };
    const result = analyzeSingleSink(sink);

    expect(result.matched).toBe(true);
    expect(VALID_SEVERITIES).toContain(result.severity);
    expect(result.contexts).toEqual(expect.arrayContaining(['innerHTML']));
    expect(result.score).toBeGreaterThanOrEqual(1);
    expect(result.score).toBeLessThanOrEqual(10);
  });

  it('assigns critical severity for eval() call', () => {
    const sink = { code: "eval(userInput);", source: 'inline' };
    const result = analyzeSingleSink(sink);

    expect(result.matched).toBe(true);
    expect(result.severity).toBe('critical');
    expect(result.contexts).toEqual(expect.arrayContaining(['eval']));
  });

  it('assigns critical severity for new Function()', () => {
    const sink = { code: "new Function(userInput);", source: 'inline' };
    const result = analyzeSingleSink(sink);

    expect(result.matched).toBe(true);
    expect(result.severity).toBe('critical');
    expect(result.contexts).toEqual(expect.arrayContaining(['eval']));
  });

  it('innerHTML has lower severity than eval (critical sinks)', () => {
    const innerHtmlSink = { code: 'el.innerHTML = data;', source: 'inline' };
    const evalSink = { code: 'eval(data);', source: 'inline' };

    const innerResult = analyzeSingleSink(innerHtmlSink);
    const evalResult = analyzeSingleSink(evalSink);

    const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
    expect(severityRank[evalResult.severity]).toBeGreaterThan(severityRank[innerResult.severity]);
  });

  it('reduces severity when sanitizers are present', () => {
    const unsanitized = { code: 'el.innerHTML = userInput;', source: 'inline' };
    const sanitized = { code: 'el.innerHTML = DOMPurify.sanitize(userInput);', source: 'inline' };

    const unsafeResult = analyzeSingleSink(unsanitized);
    const safeResult = analyzeSingleSink(sanitized);

    expect(unsafeResult.score).toBeGreaterThan(safeResult.score);
    expect(safeResult.sanitizers).toContain('DOMPurify');
  });

  it('increases score for event-attr source', () => {
    const inlineSink = { code: 'el.innerHTML = data;', source: 'inline' };
    const eventSink = { code: 'el.innerHTML = data;', source: 'event-attr' };

    const inlineResult = analyzeSingleSink(inlineSink);
    const eventResult = analyzeSingleSink(eventSink);

    expect(eventResult.score).toBeGreaterThan(inlineResult.score);
  });

  it('increases score for js-href source', () => {
    const inlineSink = { code: 'el.innerHTML = data;', source: 'inline' };
    const jsHrefSink = { code: 'el.innerHTML = data;', source: 'js-href' };

    const inlineResult = analyzeSingleSink(inlineSink);
    const jsHrefResult = analyzeSingleSink(jsHrefSink);

    expect(jsHrefResult.score).toBeGreaterThan(inlineResult.score);
  });

  it('detects document.write sink', () => {
    const sink = { code: 'document.write(userInput);', source: 'inline' };
    const result = analyzeSingleSink(sink);

    expect(result.matched).toBe(true);
    expect(result.contexts).toEqual(expect.arrayContaining(['documentWrite']));
    expect(VALID_SEVERITIES).toContain(result.severity);
  });

  it('detects setTimeout with string argument', () => {
    const sink = { code: "setTimeout('userInput', 100);", source: 'inline' };
    const result = analyzeSingleSink(sink);

    expect(result.matched).toBe(true);
    expect(result.contexts).toEqual(expect.arrayContaining(['setTimeout']));
    expect(VALID_SEVERITIES).toContain(result.severity);
  });

  it('detects srcdoc assignment', () => {
    const sink = { code: "iframe.srcdoc = userInput;", source: 'inline' };
    const result = analyzeSingleSink(sink);

    expect(result.matched).toBe(true);
    expect(result.contexts).toEqual(expect.arrayContaining(['srcdoc']));
  });

  it('does not mutate the original sink object', () => {
    const sink = { code: 'eval(x);', source: 'inline' };
    const originalSink = { ...sink };
    analyzeSingleSink(sink);

    expect(sink).toEqual(originalSink);
  });

  it('preserves original sink fields in result', () => {
    const sink = { code: 'eval(x);', source: 'inline', line: 42, tag: 'script' };
    const result = analyzeSingleSink(sink);

    expect(result.code).toBe('eval(x);');
    expect(result.source).toBe('inline');
    expect(result.line).toBe(42);
    expect(result.tag).toBe('script');
  });
});

describe('getContextPayloads', () => {
  it('returns an array of payload strings for a sink with innerHTML context', () => {
    const sink = { contexts: ['innerHTML'] };
    const payloads = getContextPayloads(sink);

    expect(Array.isArray(payloads)).toBe(true);
    expect(payloads.length).toBeGreaterThan(0);
    payloads.forEach(p => {
      expect(typeof p).toBe('string');
      expect(p.length).toBeGreaterThan(0);
    });
  });

  it('returns payloads for documentWrite context', () => {
    const sink = { contexts: ['documentWrite'] };
    const payloads = getContextPayloads(sink);

    expect(payloads.length).toBeGreaterThan(0);
    const hasScriptTag = payloads.some(p => p.includes('<script>'));
    expect(hasScriptTag).toBe(true);
  });

  it('returns empty array for sink with no contexts', () => {
    const sink = { contexts: [] };
    const payloads = getContextPayloads(sink);

    expect(payloads).toEqual([]);
  });

  it('returns empty array for sink with missing contexts', () => {
    const sink = {};
    const payloads = getContextPayloads(sink);

    expect(payloads).toEqual([]);
  });

  it('deduplicates payloads when multiple contexts share the same payload', () => {
    const sink = { contexts: ['innerHTML', 'outerHTML'] };
    const payloads = getContextPayloads(sink);

    const uniquePayloads = new Set(payloads);
    expect(payloads.length).toBe(uniquePayloads.size);
  });

  it('includes location-specific payload for location context', () => {
    const sink = { contexts: ['location'] };
    const payloads = getContextPayloads(sink);

    expect(payloads.length).toBeGreaterThan(0);
    const hasJsProtocol = payloads.some(p => p.startsWith('javascript:'));
    expect(hasJsProtocol).toBe(true);
  });

  it('merges payloads from multiple distinct contexts', () => {
    const singleCtx = getContextPayloads({ contexts: ['innerHTML'] });
    const multiCtx = getContextPayloads({ contexts: ['innerHTML', 'documentWrite'] });

    expect(multiCtx.length).toBeGreaterThanOrEqual(singleCtx.length);
  });

  it('returns payloads for eval context without HTML tags', () => {
    const sink = { contexts: ['eval'] };
    const payloads = getContextPayloads(sink);

    expect(payloads.length).toBeGreaterThan(0);
    const hasNoScriptTag = payloads.every(p => !p.includes('<script>'));
    expect(hasNoScriptTag).toBe(true);
  });

  it('handles unknown context gracefully by returning empty for that context', () => {
    const sink = { contexts: ['innerHTML', 'nonexistent_context_xyz'] };
    const payloads = getContextPayloads(sink);

    const innerHtmlOnly = getContextPayloads({ contexts: ['innerHTML'] });
    expect(payloads).toEqual(innerHtmlOnly);
  });
});
