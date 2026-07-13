import { describe, it, expect } from 'vitest';
import {
  isJsLike,
  isArchiveableScript,
  isExplicitlyNonJs,
  urlToZipPath,
  dedupePaths,
  buildManifest,
} from '@/lib/scanners/js-archive';

describe('isJsLike (严格 .js/.mjs)', () => {
  it('接受 .js / .mjs（含 query/hash）', () => {
    expect(isJsLike('https://cdn.x.com/a/app.js')).toBe(true);
    expect(isJsLike('https://cdn.x.com/a/app.mjs')).toBe(true);
    expect(isJsLike('https://cdn.x.com/a/app.js?v=1')).toBe(true);
    expect(isJsLike('https://cdn.x.com/a/app.js#x')).toBe(true);
  });
  it('拒绝非 http(s) 与无后缀', () => {
    expect(isJsLike('file:///a/app.js')).toBe(false);
    expect(isJsLike('https://cdn.x.com/chunk?id=1')).toBe(false);
  });
});

describe('isExplicitlyNonJs', () => {
  it('识别图片/字体/CSS/JSON/HTML', () => {
    expect(isExplicitlyNonJs('https://x.com/a.png')).toBe(true);
    expect(isExplicitlyNonJs('https://x.com/a.css?v=2')).toBe(true);
    expect(isExplicitlyNonJs('https://x.com/font.woff2')).toBe(true);
    expect(isExplicitlyNonJs('https://x.com/data.json')).toBe(true);
    expect(isExplicitlyNonJs('https://x.com/index.html')).toBe(true);
  });
  it('不误伤 .js 与无后缀', () => {
    expect(isExplicitlyNonJs('https://x.com/a.js')).toBe(false);
    expect(isExplicitlyNonJs('https://x.com/chunk?id=1')).toBe(false);
  });
});

describe('isArchiveableScript (来源置信度放宽版)', () => {
  it('接受 .js 与 extensionless/query-only chunk', () => {
    expect(isArchiveableScript('https://x.com/a.js')).toBe(true);
    expect(isArchiveableScript('https://x.com/static/chunk?id=123')).toBe(true);
    expect(isArchiveableScript('https://x.com/_next/static/bundle')).toBe(true);
  });
  it('排除明显非 JS 资源', () => {
    expect(isArchiveableScript('https://x.com/a.png')).toBe(false);
    expect(isArchiveableScript('https://x.com/a.css')).toBe(false);
    expect(isArchiveableScript('https://x.com/a.json')).toBe(false);
    expect(isArchiveableScript('https://x.com/a.wasm')).toBe(false);
  });
  it('拒绝非 http(s)', () => {
    expect(isArchiveableScript('data:text/plain,hi')).toBe(false);
    expect(isArchiveableScript('ftp://x.com/a.js')).toBe(false);
  });
});

describe('urlToZipPath', () => {
  it('host + pathname，去 query/hash', () => {
    expect(urlToZipPath('https://cdn.x.com/a/b/app.js?v=1#x')).toBe('cdn.x.com/a/b/app.js');
  });
  it('目录补 index.js，无扩展名补 .js', () => {
    expect(urlToZipPath('https://cdn.x.com/a/b/')).toBe('cdn.x.com/a/b/index.js');
    expect(urlToZipPath('https://cdn.x.com/chunk?id=1')).toBe('cdn.x.com/chunk.js');
  });
  it('拒绝非 http(s)', () => {
    expect(urlToZipPath('data:application/javascript,x')).toBeNull();
  });
});

describe('dedupePaths', () => {
  it('相同路径追加 __2、__3', () => {
    const m = dedupePaths([
      { key: 'a', path: 'x.com/app.js' },
      { key: 'b', path: 'x.com/app.js' },
      { key: 'c', path: 'x.com/app.js' },
    ]);
    expect(m.get('a')).toBe('x.com/app.js');
    expect(m.get('b')).toBe('x.com/app__2.js');
    expect(m.get('c')).toBe('x.com/app__3.js');
  });
});

describe('buildManifest', () => {
  it('包含 source 列与统计行', () => {
    const out = buildManifest(
      [
        { url: 'https://x.com/a.js', path: 'x.com/a.js', size: 10, status: 'ok', kind: 'http', source: 'dom' },
        { url: 'https://x.com/b.js', path: 'x.com/b.js', size: 0, status: 'fail', kind: 'http', source: 'performance', note: '超时' },
        { url: '', path: '_inline/inline-001.js', size: 5, status: 'ok', kind: 'inline', source: 'inline' },
      ],
      'https://x.com/',
      0,
    );
    expect(out).toContain('成功 2 / 失败 1 / 跳过 0');
    expect(out).toContain('[status]\tsize\tsource\tpath');
    expect(out).toContain('OK\t10\tdom\tx.com/a.js');
    expect(out).toContain('FAIL\t0\tperformance\tx.com/b.js');
    expect(out).toContain('OK\t5\tinline\t_inline/inline-001.js');
  });
});
