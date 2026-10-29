/**
 * SQLi 报错注入检测引擎（纯分析逻辑）
 *
 * 不含 browser / fetch / DOM 操作；网络探测由调用方（SqliPanel）提供。
 * 与 xss-engine 同款组织：类型 + 常量 + 纯函数，便于单测。
 *
 * 检测策略 —— 基线对比防误报：
 *   报错注入的"证据"是响应体里的 SQL 错误特征。但有些页面本身就会含
 *   "SQL syntax" 之类的文字（如技术博客、调试页）。因此确认逻辑是：
 *   1. 先发基线请求（原参数正常值）→ 记录基线是否已有 SQL 错误
 *   2. 再发报错 payload → 检测响应
 *   3. 仅当 payload 触发了【基线没有的】SQL 错误（不同 DB 或基线无错误）才确认
 *   见 isNewSqlError()。
 *
 * 特征库参考 OWASP / SQLmap 公开的 DB 报错签名，按 DB 分组，覆盖主流数据库。
 */

// ====== 类型 ======

export type SqlDb = 'mysql' | 'mssql' | 'postgresql' | 'oracle' | 'sqlite' | 'unknown';

export type SqlSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SqliFinding {
  param: string;
  payload: string;
  db: SqlDb;
  evidence: string;
  url: string;
  method: 'GET' | 'POST';
  /** 注入点来源（'url' | 'form'） */
  source: string;
  severity: SqlSeverity;
}

// ====== 错误特征库（多 DB）======

interface SqlErrorSig {
  db: SqlDb;
  /** 模块加载时预编译（对齐 sniff-engine / xss-engine 策略） */
  pattern: RegExp;
}

const SQL_ERROR_SIGNATURES: SqlErrorSig[] = [
  // MySQL / MariaDB
  { db: 'mysql', pattern: /SQL syntax[\s\S]{0,120}?MySQL|check the manual that corresponds to your (?:MySQL|MariaDB) server version/i },
  { db: 'mysql', pattern: /Warning.*\bmysqli?_[a-z_]+\(|\bMySQLSyntaxErrorException\b|com\.mysql\.jdbc|valid MySQL result/i },
  { db: 'mysql', pattern: /You have an error in your SQL syntax/i },

  // Microsoft SQL Server
  { db: 'mssql', pattern: /Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server/i },
  { db: 'mssql', pattern: /Microsoft SQL Native Client|SQLServer JDBC Driver|ODBC SQL Server Driver|\[SQL Server\]|\bSqlException\b/i },
  { db: 'mssql', pattern: /Incorrect syntax near (?:the|')/i },

  // PostgreSQL
  { db: 'postgresql', pattern: /PostgreSQL[\s\S]{0,60}?ERROR|PSQLException|org\.postgresql\.util\.PSQLException|\bNpgsql\b/i },
  { db: 'postgresql', pattern: /Warning.*\bpg_[a-z_]+|valid PostgreSQL result|pg_query\(\)/i },
  { db: 'postgresql', pattern: /syntax error at or near "|unterminated quoted identifier/i },

  // Oracle
  { db: 'oracle', pattern: /ORA-\d{4,5}\b|Oracle error|OracleException/i },
  { db: 'oracle', pattern: /quoted string not properly terminated|Oracle[\s\S]{0,30}?(?:Driver|ODBC)/i },

  // SQLite
  { db: 'sqlite', pattern: /SQLite\/JDBCDriver|SQLite3?::SQLException|sqlite3?\.OperationalError|SQLITE_ERROR|sqlite_query\(\)/i },
  { db: 'sqlite', pattern: /near "[^"]{0,40}": syntax error/i },

  // 通用兜底（仅命中通用特征时 db=unknown，严重度降为 medium）
  { db: 'unknown', pattern: /SQL syntax/i },
];

// ====== 报错触发 payload ======

export interface SqliErrorPayload {
  payload: string;
  desc: string;
}

/**
 * 报错注入 payload 集 —— 目的是触发后端 SQL 解析错误。
 * 保持精简：覆盖引号 / 括号 / 注释闭合等常见断点；布尔恒真作辅助。
 * 不含时间盲注（SLEEP）与报错外带数据的高级 payload —— 那些在后续阶段，且涉及合规风险。
 */
export const SQLI_ERROR_PAYLOADS: SqliErrorPayload[] = [
  { payload: `'`, desc: '单引号（通用）' },
  { payload: `"`, desc: '双引号（通用）' },
  { payload: `')`, desc: '单引号 + 括号' },
  { payload: `'))`, desc: '单引号 + 双括号' },
  { payload: `'#"`, desc: '引号 + 注释' },
  { payload: '`', desc: '反引号（MySQL 标识符）' },
  { payload: `';`, desc: '引号 + 分号' },
  { payload: `' AND '1'='1`, desc: '布尔恒真（辅助）' },
];

// ====== 检测 ======

export interface SqlErrorMatch {
  found: boolean;
  db: SqlDb;
  evidence: string;
}

const EVIDENCE_RADIUS = 80;

/**
 * 在响应体里检测 SQL 错误特征，返回 DB 类型与证据片段。
 * 纯函数，无副作用。按特征库顺序匹配（具体 DB 在前，通用兜底在后）。
 */
export function detectSqlError(body: string): SqlErrorMatch {
  if (!body) return { found: false, db: 'unknown', evidence: '' };
  for (const sig of SQL_ERROR_SIGNATURES) {
    const m = sig.pattern.exec(body);
    if (m) {
      const idx = m.index;
      const len = m[0]?.length ?? 0;
      const start = Math.max(0, idx - EVIDENCE_RADIUS);
      const end = Math.min(body.length, idx + len + EVIDENCE_RADIUS);
      const evidence = body.substring(start, end).replace(/\s+/g, ' ').trim();
      return { found: true, db: sig.db, evidence };
    }
  }
  return { found: false, db: 'unknown', evidence: '' };
}

/**
 * 基线对比 —— 判定是否为注入触发的"新"错误。
 *
 * payload 响应命中错误，但基线响应也命中【相同 DB】的错误时，
 * 视为页面本来就有的报错（非本次注入触发），降级为未确认，避免误报。
 * 基线无错误、或基线错误 DB 不同（注入改变了错误形态）时才确认。
 */
export function isNewSqlError(payloadBody: string, baselineBody: string): SqlErrorMatch {
  const hit = detectSqlError(payloadBody);
  if (!hit.found) return hit;
  const base = detectSqlError(baselineBody);
  if (base.found && base.db === hit.db) {
    return { found: false, db: 'unknown', evidence: '' };
  }
  return hit;
}

// ====== 严重度 ======

/**
 * 报错注入严重度：能触发 SQL 解析错误说明参数已进入 SQL 语句，即可注入。
 *  - 识别出具体 DB（mysql/mssql/...）：high（明确可利用，且暴露 DB 类型/版本线索）
 *  - 仅命中通用特征（db=unknown）：medium（疑似，需人工确认）
 */
export function assessSqliSeverity(db: SqlDb): SqlSeverity {
  return db !== 'unknown' ? 'high' : 'medium';
}

export const SQL_SEVERITY_ORDER: Record<SqlSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SQL_SEVERITY_LABELS: Record<SqlSeverity, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
};

export function sqlSeverityLabel(sev: SqlSeverity): string {
  return SQL_SEVERITY_LABELS[sev] ?? sev;
}

const DB_LABELS: Record<SqlDb, string> = {
  mysql: 'MySQL',
  mssql: 'MSSQL',
  postgresql: 'PostgreSQL',
  oracle: 'Oracle',
  sqlite: 'SQLite',
  unknown: '未知',
};

export function dbLabel(db: SqlDb): string {
  return DB_LABELS[db] ?? db;
}

// ====== 布尔盲注 ======

/**
 * 布尔盲注 payload 对 —— 基于原始参数值构造恒真/恒假变体。
 * 只追加到原值之后，保持请求语义正常（风险与普通访问相当）。
 */
export interface BooleanBlindPair {
  truthy: string;
  falsy: string;
  desc: string;
}

export function buildBooleanBlindPair(originalValue: string): BooleanBlindPair {
  if (/^\d+$/.test(originalValue)) {
    return {
      truthy: `${originalValue} AND 1=1`,
      falsy: `${originalValue} AND 1=2`,
      desc: '数字型布尔盲注',
    };
  }
  return {
    truthy: `${originalValue}' AND '1'='1`,
    falsy: `${originalValue}' AND '1'='2`,
    desc: '字符型布尔盲注',
  };
}

export interface BooleanBlindAssessment {
  suspected: boolean;
  /** 恒真/恒假响应长度差（字节） */
  lengthDiff: number;
  /** 长度差相对较大响应的占比 */
  ratio: number;
  /** 原始值响应与恒真响应的长度差（越小说明恒真回到正常语义） */
  truthyBaselineDiff: number;
}

/**
 * 布尔盲注判定 —— 恒真与恒假响应长度差异显著、且恒真响应接近基线时疑似注入。
 * 阈值：长度差 ≥ minDiff 且占比 ≥ minRatio（动态页面每次渲染有几十字节抖动，双阈值过滤）。
 * 纯函数，无副作用。
 */
export function analyzeBooleanBlind(
  baselineLen: number,
  truthyLen: number,
  falsyLen: number,
  opts?: { minDiff?: number; minRatio?: number },
): BooleanBlindAssessment {
  const minDiff = opts?.minDiff ?? 60;
  const minRatio = opts?.minRatio ?? 0.05;
  const lengthDiff = Math.abs(truthyLen - falsyLen);
  const maxLen = Math.max(truthyLen, falsyLen, 1);
  const ratio = lengthDiff / maxLen;
  const truthyBaselineDiff = Math.abs(truthyLen - baselineLen);
  const suspected = lengthDiff >= minDiff && ratio >= minRatio;
  return { suspected, lengthDiff, ratio, truthyBaselineDiff };
}

// ====== 排序 ======

export const SQLI_SORT_FNS: Record<string, (a: SqliFinding, b: SqliFinding) => number> = {
  severity: (a, b) => (SQL_SEVERITY_ORDER[a.severity] ?? 4) - (SQL_SEVERITY_ORDER[b.severity] ?? 4),
  param: (a, b) => a.param.localeCompare(b.param),
  db: (a, b) => a.db.localeCompare(b.db),
};
