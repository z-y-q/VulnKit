// 存储检查分类引擎
// 敏感键/值模式匹配、分类、熵检测

// ---------- 类型 ----------

export interface SensitivityResult {
  isSensitive: boolean;
  patterns: string[];
  severity: 'high' | 'medium' | 'low';
}

export interface StorageItem {
  key: string;
  value: string;
  isSensitive: boolean;
  matchedPatterns: string[];
  severity: 'high' | 'medium' | 'low';
  storageType: 'local' | 'session' | 'cookie' | 'window' | 'indexeddb';
}

export interface IndexedDBInfo {
  databases: { name: string; version: number; stores: IDBStoreInfo[] }[];
  error?: string;
}

export interface IDBStoreInfo {
  name: string;
  count: number;
  records: string[];
}

// ---------- 敏感键模式 ----------

const KEY_PATTERNS = [
  'token', 'auth', 'session', 'password', 'passwd', 'secret',
  'api_key', 'apikey', 'bearer', 'access_token', 'refresh_token',
  'private_key', 'credential', 'jwt', 'id_token',
  'stripe', 'twilio', 'sendgrid', 'mailgun', 'nexmo',
  'api_secret', 'apisecret', 'secret_key', 'secretkey',
  'privatekey', 'auth_token', 'db_password', 'db_host', 'db_port',
  'connection_string', 'conn_str', 'firebase', 'supabase',
  'csrf', 'xsrf', 'xsrf-token', 'csrf-token',
];

// ---------- 敏感值模式 ----------

const VALUE_PATTERNS: { regex: RegExp; label: string; severity: 'high' | 'medium' | 'low' }[] = [
  { regex: /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, label: 'JWT Token', severity: 'high' },
  { regex: /^Bearer\s+/i, label: 'Bearer Token', severity: 'high' },
  { regex: /^sk-[A-Za-z0-9]{20,}$/, label: 'OpenAI API Key', severity: 'high' },
  { regex: /^AKIA[A-Z0-9]{16}$/, label: 'AWS Access Key', severity: 'high' },
  { regex: /-----BEGIN.*PRIVATE KEY-----/, label: 'PEM Private Key', severity: 'high' },
  { regex: /^(pk|sk|rk)_live_[A-Za-z0-9]{24,}$/, label: 'Stripe API Key', severity: 'high' },
  { regex: /^(pk|sk|rk)_test_[A-Za-z0-9]{24,}$/, label: 'Stripe Test Key', severity: 'medium' },
  { regex: /^ghp_[A-Za-z0-9]{36,}$/, label: 'GitHub PAT', severity: 'high' },
  { regex: /^gho_[A-Za-z0-9]{36,}$/, label: 'GitHub OAuth Token', severity: 'high' },
  { regex: /^ghs_[A-Za-z0-9]{36,}$/, label: 'GitHub App Token', severity: 'high' },
  { regex: /^ghu_[A-Za-z0-9]{36,}$/, label: 'GitHub User Token', severity: 'high' },
  { regex: /^xox[bpas]-[A-Za-z0-9-]{10,}$/, label: 'Slack Token', severity: 'high' },
  { regex: /^AIza[A-Za-z0-9_-]{35}$/, label: 'Google API Key', severity: 'high' },
  { regex: /^wif-[a-f0-9-]{36,}$/, label: 'GCP Service Account Key', severity: 'high' },
  { regex: /^AC[a-f0-9]{32}$/, label: 'Twilio Account SID', severity: 'medium' },
  { regex: /^SK[a-f0-9]{32}$/, label: 'Twilio Auth Token', severity: 'medium' },
  { regex: /^NDA[0-9A-Z]{24,}$/, label: 'Nexmo API Key', severity: 'medium' },
  { regex: /-----BEGIN CERTIFICATE-----/, label: 'PEM Certificate', severity: 'low' },
  { regex: /-----BEGIN RSA PRIVATE KEY-----/, label: 'RSA Private Key', severity: 'high' },
  { regex: /-----BEGIN EC PRIVATE KEY-----/, label: 'EC Private Key', severity: 'high' },
  { regex: /-----BEGIN OPENSSH PRIVATE KEY-----/, label: 'OpenSSH Private Key', severity: 'high' },
  { regex: /^mysql:\/\/[^\s]+/, label: 'MySQL Connection String', severity: 'high' },
  { regex: /^postgres(?:ql)?:\/\/[^\s]+/, label: 'PostgreSQL Connection String', severity: 'high' },
  { regex: /^mongodb(?:\+srv)?:\/\/[^\s]+/, label: 'MongoDB Connection String', severity: 'high' },
  { regex: /^redis:\/\/[^\s]+/, label: 'Redis Connection String', severity: 'high' },
  { regex: /^amqp(?:s)?:\/\/[^\s]+/, label: 'RabbitMQ Connection String', severity: 'medium' },
  { regex: /^[a-f0-9]{64}$/, label: 'SHA-256 Hash', severity: 'low' },
  { regex: /^[A-F0-9]{8}-[A-F0-9]{4}-4[A-F0-9]{3}-[89AB][A-F0-9]{3}-[A-F0-9]{12}$/i, label: 'UUID Token', severity: 'low' },
  { regex: /^[a-zA-Z0-9+/]{200,}={0,2}$/, label: 'Long Base64 (Possible Secret)', severity: 'medium' },
  { regex: /^(?:MII[A-Za-z0-9+/]{4,})/, label: 'X.509 Certificate', severity: 'low' },
];

// ---------- 公共函数 ----------

/** 检查存储键值对的敏感性 */
export function classifyStorageValue(key: string, value: unknown): SensitivityResult {
  const keyLower = (key || '').toLowerCase();
  const valStr = typeof value === 'string' ? value : String(value ?? '');
  const matched: { pattern: string; severity: 'high' | 'medium' | 'low' }[] = [];

  // 键匹配
  for (const kp of KEY_PATTERNS) {
    if (keyLower.includes(kp)) {
      matched.push({ pattern: kp, severity: 'medium' });
    }
  }

  // 值匹配
  for (const vp of VALUE_PATTERNS) {
    if (vp.regex.test(valStr)) {
      matched.push({ pattern: vp.label, severity: vp.severity });
    }
  }

  // 去重
  const seen = new Set<string>();
  const unique: string[] = [];
  let maxSev: 'high' | 'medium' | 'low' = 'low';
  for (const m of matched) {
    if (!seen.has(m.pattern)) {
      seen.add(m.pattern);
      unique.push(m.pattern);
      if (m.severity === 'high') maxSev = 'high';
      else if (m.severity === 'medium' && maxSev !== 'high') maxSev = 'medium';
    }
  }

  return { isSensitive: unique.length > 0, patterns: unique, severity: maxSev };
}

/** 快速检查键名是否可能敏感 */
export function isSensitiveStorageKey(key: string): boolean {
  const keyLower = key.toLowerCase();
  for (const kp of KEY_PATTERNS) {
    if (keyLower.includes(kp)) return true;
  }
  return false;
}

/** 裁剪长值 */
export function truncate(val: string, max: number): string {
  if (val.length <= max) return val;
  return val.substring(0, max) + '...';
}

/** HTML 转义 */
export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
