import { describe, it, expect } from 'vitest';
import { classifyRuntimeSinks, type RuntimeSinkEvent } from '@/lib/scanners/xss-engine';

function ev(sink: string, value: string, time = 1000): RuntimeSinkEvent {
  return { sink, value, time };
}

describe('xss-engine: classifyRuntimeSinks', () => {
  const sources = ['search%20keyword', '/admin/dashboard', 'ref-token-123'];

  it('sink 值包含来源值 → confirmed 且带 sourceHit', () => {
    const rows = classifyRuntimeSinks(
      [ev('innerHTML', '<div>/admin/dashboard</div>')],
      sources,
    );
    expect(rows[0].confirmed).toBe(true);
    expect(rows[0].sourceHit).toBe('/admin/dashboard');
  });

  it('与来源无关的 sink 调用 → 未确认', () => {
    const rows = classifyRuntimeSinks([ev('eval', '1+1')], sources);
    expect(rows[0].confirmed).toBe(false);
    expect(rows[0].sourceHit).toBeUndefined();
  });

  it('confirmed 排在前，同级按时间倒序', () => {
    const rows = classifyRuntimeSinks(
      [
        ev('eval', 'plain', 1000),
        ev('innerHTML', 'xx /admin/dashboard yy', 1001),
        ev('setTimeout', 'ref-token-123+x', 1002),
        ev('document.write', 'other', 1003),
      ],
      sources,
    );
    expect(rows[0].confirmed).toBe(true);
    expect(rows[0].time).toBe(1002);
    expect(rows[1].time).toBe(1001);
    expect(rows[2].confirmed).toBe(false);
  });

  it('短来源值（<4 字符）忽略，防误报', () => {
    const rows = classifyRuntimeSinks([ev('innerHTML', '<b>ab</b>xxx')], ['ab']);
    expect(rows[0].confirmed).toBe(false);
  });

  it('空输入返回空数组', () => {
    expect(classifyRuntimeSinks([], sources)).toHaveLength(0);
    expect(classifyRuntimeSinks([ev('eval', 'x')], [])).toHaveLength(1);
  });
});
