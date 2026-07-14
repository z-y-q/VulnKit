import { describe, it, expect } from 'vitest';
import { panelMeta, panelMatches, type PanelMeta } from '@/panels/registry';

function find(id: string): PanelMeta {
  const m = panelMeta.find((p) => p.id === id);
  if (!m) throw new Error(`missing panel ${id}`);
  return m;
}

describe('panelMatches', () => {
  it('空 query 一律返回 true', () => {
    expect(panelMatches(find('cors'), '')).toBe(true);
    expect(panelMatches(find('cors'), '   ')).toBe(true);
  });

  it('命中 label（中文）', () => {
    expect(panelMatches(find('subdomain'), '子域名')).toBe(true);
  });

  it('命中英文别名 alias（核心场景：跨域 → CORS）', () => {
    expect(panelMatches(find('cors'), '跨域')).toBe(true);
    expect(panelMatches(find('cors'), 'cors')).toBe(true);
  });

  it('命中 keyword（cookie → Cookie 审计）', () => {
    expect(panelMatches(find('cookie-audit'), 'cookie')).toBe(true);
    expect(panelMatches(find('cookie-audit'), 'httponly')).toBe(true);
  });

  it('命中 id（sniff）', () => {
    expect(panelMatches(find('sniff'), 'sniff')).toBe(true);
  });

  it('命中嗅探别名（sniff 面板）', () => {
    expect(panelMatches(find('sniff'), '嗅探')).toBe(true);
  });

  it('大小写无关', () => {
    expect(panelMatches(find('graphql'), 'GQL')).toBe(true);
    expect(panelMatches(find('vue'), 'VUE')).toBe(true);
  });

  it('子串匹配', () => {
    expect(panelMatches(find('sourcemap'), 'source')).toBe(true);
    expect(panelMatches(find('xssscan'), 'xss')).toBe(true);
  });

  it('不匹配时返回 false', () => {
    expect(panelMatches(find('cors'), 'zzz-not-a-term')).toBe(false);
  });

  it('不同面板的词不串匹配', () => {
    // "waf" 不应命中 cors 面板
    expect(panelMatches(find('cors'), 'waf')).toBe(false);
  });

  it('panelMeta 至少 35 项且每项有 aliases/keywords', () => {
    expect(panelMeta.length).toBeGreaterThanOrEqual(35);
    for (const m of panelMeta) {
      expect(m.aliases?.length, `${m.id} 缺 aliases`).toBeGreaterThan(0);
      expect(m.keywords?.length, `${m.id} 缺 keywords`).toBeGreaterThan(0);
    }
  });

  it('id 唯一', () => {
    const ids = panelMeta.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
