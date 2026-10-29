import { describe, it, expect } from 'vitest';
import {
  detectSqlError,
  isNewSqlError,
  assessSqliSeverity,
  sqlSeverityLabel,
  dbLabel,
  SQLI_ERROR_PAYLOADS,
  SQLI_SORT_FNS,
  buildBooleanBlindPair,
  analyzeBooleanBlind,
  type SqlDb,
  type SqliFinding,
} from '@/lib/scanners/sqli-engine';

describe('sqli-engine', () => {
  describe('detectSqlError — 各 DB 真实报错样本', () => {
    const cases: Array<{ name: string; db: SqlDb; body: string }> = [
      {
        name: 'MySQL 语法错误',
        db: 'mysql',
        body: "<b>Fatal error</b>: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1",
      },
      {
        name: 'MySQL mysqli 警告',
        db: 'mysql',
        body: 'Warning: mysqli_query(): (42000/1064): You have an error in your SQL syntax',
      },
      {
        name: 'MariaDB',
        db: 'mysql',
        body: 'check the manual that corresponds to your MariaDB server version',
      },
      {
        name: 'MSSQL 未闭合引号',
        db: 'mssql',
        body: "Microsoft OLE DB Provider for SQL Server error '80040e14' Unclosed quotation mark after the character string '''",
      },
      {
        name: 'MSSQL 语法错误',
        db: 'mssql',
        body: "System.Data.SqlClient.SqlException: Incorrect syntax near the keyword 'AND'",
      },
      {
        name: 'PostgreSQL 语法错误',
        db: 'postgresql',
        body: 'ERROR: syntax error at or near "\'" LINE 1: SELECT * FROM users',
      },
      {
        name: 'PostgreSQL PSQLException',
        db: 'postgresql',
        body: 'org.postgresql.util.PSQLException: ERROR: syntax error at end of input',
      },
      {
        name: 'Oracle ORA 错误码',
        db: 'oracle',
        body: 'ORA-00936: missing expression',
      },
      {
        name: 'Oracle 未终止字符串',
        db: 'oracle',
        body: 'ORA-01756: quoted string not properly terminated',
      },
      {
        name: 'SQLite 语法错误',
        db: 'sqlite',
        body: 'near "abc": syntax error',
      },
      {
        name: 'SQLite OperationalError',
        db: 'sqlite',
        body: 'sqlite3.OperationalError: near "1": syntax error',
      },
    ];

    for (const c of cases) {
      it(`${c.name} → 命中且 db=${c.db}`, () => {
        const r = detectSqlError(c.body);
        expect(r.found).toBe(true);
        expect(r.db).toBe(c.db);
        expect(r.evidence.length).toBeGreaterThan(0);
      });
    }

    it('仅通用 "SQL syntax" 命中 → db=unknown', () => {
      const r = detectSqlError('something SQL syntax something else');
      expect(r.found).toBe(true);
      expect(r.db).toBe('unknown');
    });

    it('具体 DB 优先于通用兜底(MySQL 错误不归为 unknown)', () => {
      const r = detectSqlError('You have an error in your SQL syntax; check the manual that corresponds to your MySQL server');
      // 命中 MySQL 具体特征（通用 SQL syntax 在其后），应为 mysql 而非 unknown
      expect(r.db).toBe('mysql');
    });
  });

  describe('detectSqlError — 不应误命中', () => {
    it('正常 HTML 页面', () => {
      expect(detectSqlError('<html><body><h1>Welcome</h1><p>Hello World</p></body></html>').found).toBe(false);
    });
    it('普通 JSON 响应', () => {
      expect(detectSqlError('{"code":0,"msg":"ok","data":[1,2,3]}').found).toBe(false);
    });
    it('空 body', () => {
      const r = detectSqlError('');
      expect(r.found).toBe(false);
      expect(r.db).toBe('unknown');
    });
    it('空字符串', () => {
      expect(detectSqlError('').found).toBe(false);
    });
    it('不含 SQL 关键词的报错(如 JS 报错)', () => {
      expect(detectSqlError('Uncaught TypeError: Cannot read properties of undefined').found).toBe(false);
    });
  });

  describe('detectSqlError — evidence 提取', () => {
    it('返回错误周围片段且压缩空白', () => {
      const body = 'x'.repeat(100) + 'You have an error in your SQL syntax' + 'y'.repeat(100);
      const r = detectSqlError(body);
      expect(r.found).toBe(true);
      expect(r.evidence).toContain('SQL syntax');
      // 多个连续空白应被压成单空格
      expect(r.evidence).not.toMatch(/\s{2,}/);
    });
  });

  describe('detectSqlError — 性能', () => {
    it('100KB body 在末尾命中 < 50ms', () => {
      const body = 'a'.repeat(100_000) + 'ORA-00936: missing expression';
      const t0 = performance.now();
      const r = detectSqlError(body);
      const dt = performance.now() - t0;
      expect(r.found).toBe(true);
      expect(dt).toBeLessThan(50);
    });
  });

  describe('isNewSqlError — 基线对比防误报', () => {
    it('基线无错 + payload 触发 MySQL 错误 → 确认 mysql', () => {
      const baseline = '<html><body>normal page</body></html>';
      const payload = 'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server';
      const r = isNewSqlError(payload, baseline);
      expect(r.found).toBe(true);
      expect(r.db).toBe('mysql');
    });

    it('基线含同 DB 报错(页面静态报错) → 不确认(防误报)', () => {
      // 技术博客讨论 SQL，页面本身就含 MySQL 报错文字
      const baseline = 'Today we talk about: You have an error in your SQL syntax; MySQL';
      const payload = 'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server';
      const r = isNewSqlError(payload, baseline);
      expect(r.found).toBe(false); // 基线已有同 DB 错误，不归为注入触发
    });

    it('基线 unknown(通用) + payload 具体 DB → 确认(错误形态改变)', () => {
      const baseline = 'some SQL syntax discussion'; // 命中通用 → unknown
      const payload = 'check the manual that corresponds to your MySQL server version'; // 具体 mysql
      const r = isNewSqlError(payload, baseline);
      expect(r.found).toBe(true);
      expect(r.db).toBe('mysql');
    });

    it('两者都无错 → 不确认', () => {
      expect(isNewSqlError('normal response', 'normal baseline').found).toBe(false);
    });

    it('payload 无错(被参数化查询挡住) → 不确认', () => {
      expect(isNewSqlError('{"code":0,"msg":"ok"}', '<html>ok</html>').found).toBe(false);
    });
  });

  describe('SQLI_ERROR_PAYLOADS', () => {
    it('非空', () => {
      expect(SQLI_ERROR_PAYLOADS.length).toBeGreaterThan(0);
    });
    it('含单引号 payload(最基础的报错触发)', () => {
      expect(SQLI_ERROR_PAYLOADS.some((p) => p.payload === `'`)).toBe(true);
    });
    it('每条都有 payload 与 desc', () => {
      for (const p of SQLI_ERROR_PAYLOADS) {
        expect(typeof p.payload).toBe('string');
        expect(p.payload.length).toBeGreaterThan(0);
        expect(typeof p.desc).toBe('string');
        expect(p.desc.length).toBeGreaterThan(0);
      }
    });
    it('payload 去重', () => {
      const vals = SQLI_ERROR_PAYLOADS.map((p) => p.payload);
      expect(new Set(vals).size).toBe(vals.length);
    });
  });

  describe('严重度与标签', () => {
    it('具体 DB → high', () => {
      expect(assessSqliSeverity('mysql')).toBe('high');
      expect(assessSqliSeverity('mssql')).toBe('high');
      expect(assessSqliSeverity('postgresql')).toBe('high');
      expect(assessSqliSeverity('oracle')).toBe('high');
      expect(assessSqliSeverity('sqlite')).toBe('high');
    });
    it('unknown → medium(疑似，需人工确认)', () => {
      expect(assessSqliSeverity('unknown')).toBe('medium');
    });
    it('sqlSeverityLabel 中文', () => {
      expect(sqlSeverityLabel('high')).toBe('高危');
      expect(sqlSeverityLabel('medium')).toBe('中危');
    });
    it('dbLabel 中文', () => {
      expect(dbLabel('mysql')).toBe('MySQL');
      expect(dbLabel('postgresql')).toBe('PostgreSQL');
      expect(dbLabel('unknown')).toBe('未知');
    });
  });

  describe('排序', () => {
    const findings: SqliFinding[] = [
      { param: 'b', payload: "'", db: 'unknown', evidence: '', url: '', method: 'GET' as const, source: 'url', severity: 'medium' as const },
      { param: 'a', payload: "'", db: 'mysql', evidence: '', url: '', method: 'GET' as const, source: 'url', severity: 'high' as const },
    ];
    it('severity 升序(high 在前)', () => {
      const sorted = [...findings].sort(SQLI_SORT_FNS.severity);
      expect(sorted[0].severity).toBe('high');
    });
    it('param 字母序', () => {
      const sorted = [...findings].sort(SQLI_SORT_FNS.param);
      expect(sorted[0].param).toBe('a');
    });
  });

  describe('buildBooleanBlindPair', () => {
    it('纯数字参数走数字型变体', () => {
      const p = buildBooleanBlindPair('42');
      expect(p.truthy).toBe('42 AND 1=1');
      expect(p.falsy).toBe('42 AND 1=2');
    });
    it('字符串参数走引号闭合变体', () => {
      const p = buildBooleanBlindPair('news');
      expect(p.truthy).toBe("news' AND '1'='1");
      expect(p.falsy).toBe("news' AND '1'='2");
    });
    it('空值按字符串型处理', () => {
      const p = buildBooleanBlindPair('');
      expect(p.truthy).toBe("' AND '1'='1");
    });
  });

  describe('analyzeBooleanBlind', () => {
    it('恒真/恒假长度差显著 → 疑似', () => {
      const r = analyzeBooleanBlind(5000, 5200, 4620);
      expect(r.suspected).toBe(true);
      expect(r.lengthDiff).toBe(580);
    });
    it('长度差在动态渲染抖动范围内 → 不报', () => {
      const r = analyzeBooleanBlind(5000, 5020, 4990);
      expect(r.suspected).toBe(false);
    });
    it('长度差占比过小 → 不报', () => {
      const r = analyzeBooleanBlind(30000, 30080, 30000);
      expect(r.suspected).toBe(false);
    });
    it('空响应（探测失败）不误判', () => {
      const r = analyzeBooleanBlind(0, 0, 0);
      expect(r.suspected).toBe(false);
    });
    it('truthyBaselineDiff 记录恒真与基线的接近程度', () => {
      const r = analyzeBooleanBlind(5000, 5005, 4600);
      expect(r.truthyBaselineDiff).toBe(5);
      expect(r.suspected).toBe(true);
    });
  });
});
