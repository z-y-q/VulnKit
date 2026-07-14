import { describe, it, expect } from 'vitest';
import {
  extractSourceMapUrl,
  extractInlineSourceMap,
  parseSourceMap,
  hasSourceContent,
  classifySources,
  assessRisk,
  severityLabel,
  SEV_COLOR,
  extractScriptUrls,
  extractInlineSourceMapHints,
  type SourceMapResult,
} from '@/lib/analyzers/sourcemap-analyzer';

describe('sourcemap-analyzer: extractSourceMapUrl', () => {
  it('从 JS 尾部提取 sourceMappingURL 并解析为绝对 URL', () => {
    const body = 'var a = 1;\n//# sourceMappingURL=app.js.map';
    const result = extractSourceMapUrl(body, 'https://example.com/assets/');
    expect(result).toBe('https://example.com/assets/app.js.map');
  });

  it('使用 //@ 格式', () => {
    const body = '//@ sourceMappingURL=main.js.map';
    const result = extractSourceMapUrl(body, 'https://cdn.example.com/js/');
    expect(result).toBe('https://cdn.example.com/js/main.js.map');
  });

  it('无 sourceMappingURL 返回 null', () => {
    const body = 'var a = 1; var b = 2;';
    expect(extractSourceMapUrl(body, 'https://example.com/')).toBeNull();
  });

  it('data: URL 返回 null', () => {
    const body = '//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==';
    expect(extractSourceMapUrl(body, 'https://example.com/')).toBeNull();
  });
});

describe('sourcemap-analyzer: parseSourceMap', () => {
  it('解析有效的 SourceMap JSON', () => {
    const json = JSON.stringify({
      version: 3,
      file: 'app.js',
      sources: ['src/index.ts', 'src/utils.ts'],
      sourcesContent: ['export default {}', 'export const x = 1'],
      mappings: 'AAAA',
    });
    const info = parseSourceMap(json);
    expect(info).not.toBeNull();
    expect(info!.version).toBe(3);
    expect(info!.file).toBe('app.js');
    expect(info!.sources).toEqual(['src/index.ts', 'src/utils.ts']);
    expect(info!.sourcesContent).toEqual(['export default {}', 'export const x = 1']);
    expect(info!.mappings).toBe('AAAA');
  });

  it('缺少 sourcesContent 时为 null', () => {
    const json = JSON.stringify({ version: 3, file: 'a.js', sources: ['a.ts'] });
    const info = parseSourceMap(json);
    expect(info).not.toBeNull();
    expect(info!.sourcesContent).toBeNull();
  });

  it('无效 JSON 返回 null', () => {
    expect(parseSourceMap('not json')).toBeNull();
    expect(parseSourceMap('{}')).toBeNull(); // 缺少 version
  });

  it('非对象 JSON 返回 null', () => {
    expect(parseSourceMap('"string"')).toBeNull();
    expect(parseSourceMap('123')).toBeNull();
  });
});

describe('sourcemap-analyzer: hasSourceContent', () => {
  it('有内容返回 true', () => {
    const info = parseSourceMap(JSON.stringify({
      version: 3,
      sources: ['a.ts'],
      sourcesContent: ['const x = 1'],
    }));
    expect(hasSourceContent(info!)).toBe(true);
  });

  it('sourcesContent 为空数组返回 false', () => {
    const info = parseSourceMap(JSON.stringify({
      version: 3,
      sources: ['a.ts'],
      sourcesContent: [],
    }));
    expect(hasSourceContent(info!)).toBe(false);
  });

  it('sourcesContent 为 null 返回 false', () => {
    const info = parseSourceMap(JSON.stringify({
      version: 3,
      sources: ['a.ts'],
    }));
    expect(hasSourceContent(info!)).toBe(false);
  });
});

describe('sourcemap-analyzer: classifySources', () => {
  it('标记敏感路径', () => {
    const sources = [
      'webpack:///src/.env',
      'webpack:///src/config/database.ts',
      'webpack:///src/api/secret.ts',
      'webpack:///src/README.md',
      'webpack:///src/utils/helper.ts',
    ];
    const result = classifySources(sources);
    expect(result.all.length).toBe(5);
    // .env, config, api/secret, api 应被标记为敏感
    expect(result.sensitive.length).toBeGreaterThanOrEqual(3);
    // README 不应标记为敏感
    expect(result.sensitive).not.toContain('src/README.md');
  });

  it('空数组返回空', () => {
    const result = classifySources([]);
    expect(result.all).toEqual([]);
    expect(result.sensitive).toEqual([]);
  });

  it('去除 webpack:// 前缀', () => {
    const result = classifySources(['webpack:///src/index.ts']);
    // webpack:/// 去除后变为 /src/index.ts
    expect(result.all).toContain('/src/index.ts');
  });
});

describe('sourcemap-analyzer: assessRisk', () => {
  const makeResult = (partial: Partial<SourceMapResult>): SourceMapResult => ({
    bundleUrl: 'https://example.com/app.js',
    mapUrl: null,
    info: null,
    sourceCount: 0,
    sensitiveFiles: [],
    hasContentLeak: false,
    ...partial,
  });

  it('contentLeak + 敏感文件 = critical', () => {
    const result = makeResult({
      info: { file: '', version: 3, sources: ['a.ts'], sourcesContent: ['secret'], mappings: '' },
      sourceCount: 1,
      sensitiveFiles: ['.env'],
      hasContentLeak: true,
    });
    expect(assessRisk(result)).toBe('critical');
  });

  it('contentLeak 无敏感文件 = high', () => {
    const result = makeResult({
      info: { file: '', version: 3, sources: ['a.ts'], sourcesContent: ['code'], mappings: '' },
      sourceCount: 1,
      sensitiveFiles: [],
      hasContentLeak: true,
    });
    expect(assessRisk(result)).toBe('high');
  });

  it('无 contentLeak 有敏感文件 = medium', () => {
    const result = makeResult({
      info: { file: '', version: 3, sources: ['.env'], sourcesContent: null, mappings: '' },
      sourceCount: 1,
      sensitiveFiles: ['.env'],
      hasContentLeak: false,
    });
    expect(assessRisk(result)).toBe('medium');
  });

  it('无 info = info', () => {
    expect(assessRisk(makeResult({ info: null }))).toBe('info');
  });
});

describe('sourcemap-analyzer: severityLabel / SEV_COLOR', () => {
  it('severityLabel 中文映射', () => {
    expect(severityLabel('critical')).toBe('严重');
    expect(severityLabel('high')).toBe('高危');
    expect(severityLabel('medium')).toBe('中危');
    expect(severityLabel('info')).toBe('信息');
  });

  it('SEV_COLOR 包含所有级别', () => {
    expect(SEV_COLOR.critical).toContain('bg-red');
    expect(SEV_COLOR.high).toContain('bg-red');
    expect(SEV_COLOR.medium).toContain('bg-yellow');
    expect(SEV_COLOR.info).toContain('bg-blue');
  });
});

describe('sourcemap-analyzer: extractScriptUrls', () => {
  it('从 HTML 提取 script src', () => {
    const html = '<script src="/assets/app.js"></script><script src="/assets/vendor.js"></script>';
    const urls = extractScriptUrls(html, 'https://example.com');
    expect(urls).toEqual([
      'https://example.com/assets/app.js',
      'https://example.com/assets/vendor.js',
    ]);
  });

  it('去重', () => {
    const html = '<script src="/a.js"></script><script src="/a.js"></script>';
    const urls = extractScriptUrls(html, 'https://example.com');
    expect(urls).toEqual(['https://example.com/a.js']);
  });
});

describe('sourcemap-analyzer: extractInlineSourceMapHints', () => {
  it('从内联 script 提取 sourceMappingURL', () => {
    const html = '<script>var x=1;\n//# sourceMappingURL=inline.map</script>';
    const urls = extractInlineSourceMapHints(html, 'https://example.com/js/');
    expect(urls).toEqual(['https://example.com/js/inline.map']);
  });

  it('忽略带 src 的 script', () => {
    const html = '<script src="/app.js"></script>';
    const urls = extractInlineSourceMapHints(html, 'https://example.com');
    expect(urls).toEqual([]);
  });
});

describe('sourcemap-analyzer: extractInlineSourceMap', () => {
  // 拆分字面量构造 sourceMappingURL 注释，避免 Vite 误把字面量当真实注释解析（§3.3 警告根因）
  const sm = (url: string) => `//# sourceMapping${'URL='}${url}`;

  it('解析内联 base64 source map', () => {
    const body = sm(`data:application/json;base64,${btoa(JSON.stringify({ version: 3, sources: ['a.ts'] }))}`);
    const info = extractInlineSourceMap(body);
    expect(info).not.toBeNull();
    expect(info!.version).toBe(3);
    expect(info!.sources).toEqual(['a.ts']);
  });

  it('解析 URL encoded JSON', () => {
    const json = JSON.stringify({ version: 3, file: 'b.js' });
    const body = sm(`data:application/json,${encodeURIComponent(json)}`);
    const info = extractInlineSourceMap(body);
    expect(info).not.toBeNull();
    expect(info!.file).toBe('b.js');
  });

  it('MIME 参数顺序不影响 base64 识别', () => {
    const json = JSON.stringify({ version: 3 });
    const body = sm(`data:application/json;charset=utf-8;base64,${btoa(json)}`);
    const info = extractInlineSourceMap(body);
    expect(info).not.toBeNull();
    expect(info!.version).toBe(3);
  });

  it('非法 base64 返回 null（不抛文件系统错误）', () => {
    const body = sm('data:application/json;base64,!!!invalid-base64!!!');
    expect(extractInlineSourceMap(body)).toBeNull();
  });

  it('空 payload 返回 null', () => {
    const body = sm('data:application/json;base64,');
    expect(extractInlineSourceMap(body)).toBeNull();
  });

  it('非 data: URL（外部相对路径）返回 null', () => {
    const body = sm('app.js.map');
    expect(extractInlineSourceMap(body)).toBeNull();
  });

  it('无 sourceMappingURL 返回 null', () => {
    expect(extractInlineSourceMap('var a = 1;')).toBeNull();
  });
});
