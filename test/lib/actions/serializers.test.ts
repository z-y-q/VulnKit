import { describe, it, expect } from 'vitest';
import { toCsv, toJson, toMarkdownTable } from '@/lib/actions/serializers';

describe('serializers（§6.1）', () => {
  it('toCsv 简单行', () => {
    expect(toCsv([['a', 'b'], ['1', '2']])).toBe('a,b\n1,2');
  });

  it('toCsv 转义含逗号/引号/换行（RFC 4180）', () => {
    expect(toCsv([['a,b', 'c"d', 'e\nf']])).toBe('"a,b","c""d","e\nf"');
  });

  it('toCsv null/undefined/boolean 处理', () => {
    expect(toCsv([[null, undefined, true, false]])).toBe(',,true,false');
  });

  it('toCsv 数字', () => {
    expect(toCsv([[1, 2.5, 0]])).toBe('1,2.5,0');
  });

  it('toJson 美化（2 空格）', () => {
    expect(toJson({ a: 1 })).toBe('{\n  "a": 1\n}');
  });

  it('toJson 循环引用降级为字符串', () => {
    const o: any = { a: 1 };
    o.self = o;
    const s = toJson(o);
    expect(typeof s).toBe('string');
    expect(s.length).toBeGreaterThan(0);
  });

  it('toMarkdownTable 表头 + 分隔 + 数据行，| 转义', () => {
    const md = toMarkdownTable(['A', 'B'], [['1', '2'], ['x|y', 'z']]);
    expect(md).toContain('| A | B |');
    expect(md).toContain('| --- | --- |');
    expect(md).toContain('x\\|y');
    expect(md.split('\n').length).toBe(4);
  });
});
