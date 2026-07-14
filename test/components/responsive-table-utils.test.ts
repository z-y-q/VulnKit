import { describe, it, expect } from 'vitest';
import {
  visibleColumns,
  pickPrimary,
  cardColumns,
  shouldUseCardMode,
  type Col,
} from '@/components/results/responsive-table-utils';

const COLS: Col[] = [
  { key: 'ip', header: 'IP', primary: true },
  { key: 'port', header: '端口', hideUnder: 480 },
  { key: 'service', header: '服务', hideUnder: 600 },
  { key: 'hostname', header: '主机名', hideUnder: 720 },
];

describe('responsive-table-utils', () => {
  it('visibleColumns: 宽屏显示全部', () => {
    expect(visibleColumns(COLS, 1024).map((c) => c.key)).toEqual(['ip', 'port', 'service', 'hostname']);
  });

  it('visibleColumns: 按 hideUnder 逐级隐藏', () => {
    expect(visibleColumns(COLS, 700).map((c) => c.key)).toEqual(['ip', 'port', 'service']);
    expect(visibleColumns(COLS, 500).map((c) => c.key)).toEqual(['ip', 'port']);
    expect(visibleColumns(COLS, 400).map((c) => c.key)).toEqual(['ip']);
  });

  it('visibleColumns: 无 hideUnder 的列恒显示', () => {
    const cols: Col[] = [{ key: 'a', header: 'A' }, { key: 'b', header: 'B', hideUnder: 600 }];
    expect(visibleColumns(cols, 0).map((c) => c.key)).toEqual(['a']);
    expect(visibleColumns(cols, 600).map((c) => c.key)).toEqual(['a', 'b']);
  });

  it('pickPrimary: 优先 primary 列', () => {
    expect(pickPrimary(COLS)?.key).toBe('ip');
  });

  it('pickPrimary: 无 primary 回退首列', () => {
    const cols: Col[] = [{ key: 'x', header: 'X' }, { key: 'y', header: 'Y' }];
    expect(pickPrimary(cols)?.key).toBe('x');
  });

  it('pickPrimary: 空数组返回 undefined', () => {
    expect(pickPrimary([])).toBeUndefined();
  });

  it('cardColumns: 排除标题列', () => {
    const primary = pickPrimary(COLS)!;
    expect(cardColumns(COLS, primary).map((c) => c.key)).toEqual(['port', 'service', 'hostname']);
  });

  it('cardColumns: primary 为 undefined 时返回空', () => {
    expect(cardColumns(COLS, undefined)).toEqual([]);
  });

  it('shouldUseCardMode: 默认断点 480', () => {
    expect(shouldUseCardMode(479)).toBe(true);
    expect(shouldUseCardMode(480)).toBe(false);
    expect(shouldUseCardMode(720)).toBe(false);
  });

  it('shouldUseCardMode: 自定义断点', () => {
    expect(shouldUseCardMode(600, 720)).toBe(true);
    expect(shouldUseCardMode(800, 720)).toBe(false);
  });
});
