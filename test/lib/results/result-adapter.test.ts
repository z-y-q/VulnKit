import { describe, it, expect } from 'vitest';
import { EMPTY_QUERY, hasActiveQuery, cloneQuery } from '@/lib/results/result-adapter';

describe('result-adapter（§10.3）', () => {
  it('EMPTY_QUERY 无任何筛选', () => {
    expect(hasActiveQuery(EMPTY_QUERY)).toBe(false);
  });

  it('hasActiveQuery 识别 search', () => {
    expect(hasActiveQuery({ ...EMPTY_QUERY, search: 'x' })).toBe(true);
    expect(hasActiveQuery({ ...EMPTY_QUERY, search: '   ' })).toBe(false);
  });

  it('hasActiveQuery 识别 filters（空数组不算）', () => {
    expect(hasActiveQuery({ ...EMPTY_QUERY, filters: { sev: ['high'] } })).toBe(true);
    expect(hasActiveQuery({ ...EMPTY_QUERY, filters: { sev: [] } })).toBe(false);
  });

  it('cloneQuery 深拷贝 filters/sort（互不影响）', () => {
    const q = { search: '', filters: { sev: ['high'] }, sort: { key: 'a', direction: 'asc' as const } };
    const c = cloneQuery(q);
    c.filters.sev.push('low');
    c.sort.key = 'b';
    expect(q.filters.sev).toEqual(['high']);
    expect(q.sort.key).toBe('a');
  });
});
