import { describe, it, expect } from 'vitest';
import {
  hydrateMatcher,
  scan,
  getCompiledSignatures,
  CATEGORY_LABELS,
  CATEGORY_ORDER,
  type SniffInput,
} from '@/lib/scanners/sniff-engine';

describe('sniff-engine: hydrateMatcher', () => {
  it('普通字符串直接返回', () => {
    const result = hydrateMatcher('hello');
    expect(result).toBe('hello');
    expect(typeof result).toBe('string');
  });

  it('__regexp__ 对象转换为 RegExp', () => {
    const result = hydrateMatcher({
      __regexp__: true,
      source: 'wordpress',
      flags: 'i',
    });
    expect(result).toBeInstanceOf(RegExp);
    expect((result as RegExp).source).toBe('wordpress');
    expect((result as RegExp).flags).toBe('i');
  });

  it('转换后的 RegExp 可以正常匹配', () => {
    const re = hydrateMatcher({
      __regexp__: true,
      source: 'X-Pingback',
      flags: 'i',
    }) as RegExp;
    expect(re.test('x-pingback: https://example.com')).toBe(true);
    expect(re.test('some-other-header')).toBe(false);
  });

  it('无 flags 时也能正确转换', () => {
    const result = hydrateMatcher({
      __regexp__: true,
      source: '^server:',
      flags: '',
    });
    expect(result).toBeInstanceOf(RegExp);
    const re = result as RegExp;
    expect(re.test('server: nginx')).toBe(true);
    expect(re.test('x-server: nginx')).toBe(false);
  });

  it('非 __regexp__ 对象回退为字符串', () => {
    const result = hydrateMatcher({ foo: 'bar' } as any);
    expect(typeof result).toBe('string');
  });
});

describe('sniff-engine: scan', () => {
  it('WordPress 站点能匹配到 WordPress', () => {
    const input: SniffInput = {
      html: '<html><head></head><body><script src="/wp-content/themes/twentytwenty/style.css"></script><link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css"></body></html>',
      headers: {
        'X-Pingback': 'https://example.com/xmlrpc.php',
        'Server': 'nginx',
      },
      scriptSrcs: [
        'https://example.com/wp-content/plugins/contact-form-7/js/scripts.js',
      ],
      cookies: {},
      meta: [
        { name: 'generator', content: 'WordPress 6.4.2' },
      ],
    };

    const matches = scan(input);
    const wpMatch = matches.find(m => m.name === 'WordPress');
    expect(wpMatch).toBeDefined();
    expect(wpMatch!.category).toBe('CMS');
    expect(wpMatch!.matchedCount).toBeGreaterThanOrEqual(1);
    expect(wpMatch!.evidences.length).toBeGreaterThanOrEqual(1);
  });

  it('匹配结果包含 name 和 category 字段', () => {
    const input: SniffInput = {
      html: '<html></html>',
      headers: {
        'X-Powered-By': 'Express',
      },
      scriptSrcs: [],
      cookies: {},
      meta: [],
    };

    const matches = scan(input);
    for (const m of matches) {
      expect(m).toHaveProperty('name');
      expect(m).toHaveProperty('category');
      expect(typeof m.name).toBe('string');
      expect(typeof m.category).toBe('string');
      expect(m.name.length).toBeGreaterThan(0);
      expect(m.category.length).toBeGreaterThan(0);
    }
  });

  it('匹配结果的 evidences 非空', () => {
    const input: SniffInput = {
      html: '<html></html>',
      headers: {
        'Server': 'Apache/2.4.41',
      },
      scriptSrcs: [],
      cookies: {},
      meta: [],
    };

    const matches = scan(input);
    for (const m of matches) {
      expect(m.evidences.length).toBeGreaterThanOrEqual(1);
      for (const e of m.evidences) {
        expect(e).toHaveProperty('source');
        expect(e).toHaveProperty('evidence');
      }
    }
  });

  it('空输入返回空数组', () => {
    const input: SniffInput = {
      html: '',
      headers: {},
      scriptSrcs: [],
      cookies: {},
      meta: [],
    };

    const matches = scan(input);
    expect(matches).toEqual([]);
  });

  it('纯文本无特征内容返回空', () => {
    const input: SniffInput = {
      html: '<html><body><p>Hello World</p></body></html>',
      headers: { 'Content-Type': 'text/html' },
      scriptSrcs: [],
      cookies: {},
      meta: [],
    };

    const matches = scan(input);
    expect(matches.length).toBe(0);
  });

  it('匹配数量降序排列', () => {
    const input: SniffInput = {
      html: `
        <html>
        <body>
          <script src="https://cdn.shopify.com/s/files/1/assets/theme.js"></script>
          <link rel="dns-prefetch" href="//cdn.shopify.com">
          Whitelabel Error Page
        </body>
        </html>
      `,
      headers: {
        'X-ShopId': '12345',
        'X-Application-Context': 'app:8080',
        'cf-ray': 'abc123',
      },
      scriptSrcs: [
        'https://cdn.shopify.com/s/assets/shopify.js',
      ],
      cookies: {
        __cfduid: 'abc123',
      },
      meta: [],
    };

    const matches = scan(input);
    for (let i = 1; i < matches.length; i++) {
      expect(matches[i - 1].matchedCount).toBeGreaterThanOrEqual(matches[i].matchedCount);
    }
  });

  it('Nginx 通过 Server 头匹配', () => {
    const input: SniffInput = {
      html: '<html></html>',
      headers: {
        'Server': 'nginx/1.18.0',
      },
      scriptSrcs: [],
      cookies: {},
      meta: [],
    };

    const matches = scan(input);
    const nginx = matches.find(m => m.name === 'Nginx');
    expect(nginx).toBeDefined();
    expect(nginx!.category).toBe('Web 服务器');
  });
});

describe('sniff-engine: CATEGORY_LABELS 完整性', () => {
  it('CATEGORY_LABELS 为非空 Record', () => {
    expect(typeof CATEGORY_LABELS).toBe('object');
    expect(Object.keys(CATEGORY_LABELS).length).toBeGreaterThan(0);
  });

  it('包含 CMS 分类标签', () => {
    expect(CATEGORY_LABELS).toHaveProperty('CMS');
  });

  it('包含框架分类标签', () => {
    expect(CATEGORY_LABELS).toHaveProperty('框架');
  });

  it('包含 Web 服务器分类标签', () => {
    expect(CATEGORY_LABELS).toHaveProperty('Web 服务器');
  });

  it('包含 CDN 分类标签', () => {
    expect(CATEGORY_LABELS).toHaveProperty('CDN');
  });
});

describe('sniff-engine: CATEGORY_ORDER 完整性', () => {
  it('CATEGORY_ORDER 为非空数组', () => {
    expect(Array.isArray(CATEGORY_ORDER)).toBe(true);
    expect(CATEGORY_ORDER.length).toBeGreaterThan(0);
  });

  it('第一个是 CMS', () => {
    expect(CATEGORY_ORDER[0]).toBe('CMS');
  });

  it('所有值都在 CATEGORY_LABELS 中', () => {
    for (const cat of CATEGORY_ORDER) {
      expect(CATEGORY_LABELS).toHaveProperty(cat);
    }
  });
});

describe('sniff-engine: 签名预编译', () => {
  it('编译缓存为模块级单例（多次获取同一引用）', () => {
    const a = getCompiledSignatures();
    const b = getCompiledSignatures();
    expect(a).toBe(b); // 同一数组引用 → 不随 scan 重建
  });

  it('所有 regex matcher 已预编译为 RegExp 实例', () => {
    const sigs = getCompiledSignatures();
    expect(sigs.length).toBeGreaterThan(100); // 134 条
    let regexCount = 0;
    for (const sig of sigs) {
      for (const m of sig.matchers) {
        if (m.type === 'regex') {
          expect(m.pattern).toBeInstanceOf(RegExp);
          regexCount++;
        }
      }
    }
    expect(regexCount).toBeGreaterThan(50); // 大量正则均已预编译
  });

  it('多次 scan 复用同一编译缓存（regex 引用不变）', () => {
    const before = getCompiledSignatures();
    const firstRegex = before[0].matchers.find(m => m.pattern instanceof RegExp)?.pattern;
    scan({ html: '<html></html>', headers: {}, scriptSrcs: [], cookies: {}, meta: [] });
    scan({ html: '<script src="jquery.js"></script>', headers: { server: 'nginx' }, scriptSrcs: ['jquery.js'], cookies: {}, meta: [] });
    const after = getCompiledSignatures();
    const afterRegex = after[0].matchers.find(m => m.pattern instanceof RegExp)?.pattern;
    expect(after).toBe(before);
    expect(afterRegex).toBe(firstRegex); // 同一 RegExp 对象，未重建
  });
});
