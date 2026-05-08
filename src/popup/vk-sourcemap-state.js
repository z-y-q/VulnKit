// vk-sourcemap-state.js -- 灵眸 Chrome Extension
// Sourcemap shared state, constants, registration slots
import { utilsProxy as utils } from './vk-namespace.js';

const SM_SECURITY_RULES = [
  ['AWS Access Key', /AKIA[0-9A-Z]{16}/g, 'critical'],
  [
    'AWS Secret Key',
    /(?:aws[_-]?secret[_-]?access[_-]?key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"]/gi,
    'critical',
  ],
  ['GitHub Token', /gh[pousr]_[A-Za-z0-9_]{36,255}/g, 'critical'],
  ['Stripe Secret Key', /sk_live_[0-9a-zA-Z]{24,}/g, 'critical'],
  ['Stripe Publishable Key', /pk_live_[0-9a-zA-Z]{24,}/g, 'high'],
  ['Slack Token', /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}/g, 'critical'],
  [
    'Slack Webhook',
    /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g,
    'high',
  ],
  ['Google API Key', /AIza[0-9A-Za-z\-_]{35}/g, 'high'],
  ['Google OAuth Token', /ya29\.[0-9A-Za-z\-_]+/g, 'high'],
  ['SendGrid API Key', /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g, 'critical'],
  ['Twilio API Key', /SK[0-9a-fA-F]{32}/g, 'critical'],
  [
    '数据库连接串',
    /(?:mongodb|mysql|postgres|postgresql|redis|ftp|smtp|ssh|amqp):\/\/[^\s'"]+/gi,
    'critical',
  ],
  ['MongoDB URI', /mongodb(?:\+srv)?:\/\/[^\s'"]+/gi, 'critical'],
  ['私钥 (RSA/EC/DSA)', /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g, 'critical'],
  [
    'API 密钥泄露',
    /(?:api[_-]?key|apikey|secret[_-]?key|app[_-]?key|app[_-]?secret)\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
    'high',
  ],
  ['硬编码密码', /(?:password|passwd|pwd|pass[_-]?word)\s*[:=]\s*['"]([^'"]{4,})['"]/gi, 'high'],
  [
    'JWT Secret',
    /(?:jwt[_-]?secret|token[_-]?secret|jwt[_-]?key)\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
    'high',
  ],
  [
    'Authorization Header',
    /(?:Authorization|Bearer)\s*[:=]\s*['"](?:Bearer\s+)?([A-Za-z0-9\-_.~+/]+=*)['"]/gi,
    'high',
  ],
  [
    'OAuth Client Secret',
    /(?:client[_-]?secret|oauth[_-]?secret)\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
    'high',
  ],
  [
    'Heroku API Key',
    /(?:heroku|HEROKU)\s*[:=]\s*['"]([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['"]/gi,
    'high',
  ],
  ['Firebase URL', /https:\/\/[a-z0-9-]+\.firebaseio\.com/gi, 'high'],
  ['Shopify Token', /shpat_[a-fA-F0-9]{32}/g, 'high'],
  ['PayPal Braintree Token', /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g, 'high'],
  [
    '内部IP地址',
    /(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/g,
    'medium',
  ],
  [
    'Internal Domain',
    /(?:https?:\/\/)?(?:[a-z0-9-]+\.)?(?:internal|intranet|staging|dev|test|local|corp)\.[a-z0-9-]+/gi,
    'high',
  ],
  ['eval() 使用', /eval\s*\(/g, 'medium'],
  ['innerHTML 赋值', /innerHTML\s*=/g, 'medium'],
  ['document.write', /document\.write\s*\(/g, 'medium'],
  ['CORS 通配符', /Access-Control-Allow-Origin['"]\s*[:=]\s*['"]\*['"]/gi, 'medium'],
  ['CSP 禁用', /Content-Security-Policy['"]\s*[:=]\s*['"]unsafe/gi, 'medium'],
  ['路径穿越', /\.\.[\/\\]/g, 'medium'],
  ['XXE 风险', /DOMParser|xmlHttpRequest|\.parseFromString/gi, 'medium'],
  ['命令拼接风险', /(?:exec|execSync|spawn|child_process)\s*\(/g, 'medium'],
  [
    'SQL 拼接',
    /(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*\+\s*(?:req|params|query|body)/gi,
    'medium',
  ],
  ['unsafe eval (CSP)', /unsafe-eval/gi, 'medium'],
  ['window.location 赋值', /(?:window\.)?location\s*=\s*[^=]/g, 'low'],
  ['postMessage 无 origin 校验', /postMessage\s*\([^)]*\)/g, 'medium'],
  [
    'localStorage 敏感数据',
    /localStorage\.(?:setItem|set)\s*\(\s*['"](?:token|auth|session|password|secret|key)/gi,
    'medium',
  ],
  ['调试代码 (console.log)', /console\.(?:log|debug|info)\s*\(/g, 'low'],
  [
    'localStorage/sessionStorage',
    /(?:localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)/g,
    'low',
  ],
  ['document.cookie', /document\.cookie/g, 'low'],
  ['调试断点 (debugger)', /debugger\s*;/g, 'low'],
  ['TODO/FIXME/HACK', /(?:TODO|FIXME|HACK|XXX|BUG)\s*[:\(]/gi, 'info'],
  ['Swagger/OpenAPI 端点', /['"]\/(?:swagger|api-docs|openapi|graphql)(?:\/)?['"]/gi, 'info'],
  [
    'Spring Actuator',
    /['"]\/(?:actuator|env|health|metrics|trace|beans|mappings)(?:\/)?['"]/gi,
    'info',
  ],
  [
    '备份文件路径',
    /['"](?:backup|\.bak|\.old|\.orig|\.save|\.tar|\.zip|\.sql|\.dump)['"]/gi,
    'info',
  ],
  ['.git 暴露', /['"]\/\.git(?:\/|['"])/g, 'high'],
  ['测试文件', /['"](?:test|spec|mock|fixture|stub)s?['"]/gi, 'info'],
  ['环境配置引用', /process\.env\.[A-Z_]+/g, 'info'],
];

const SOURCE_TYPE_LABELS = {
  runtime: 'Webpack 运行时',
  sourcemap: 'Source Map',
  chunk: 'JS 文件解析',
};

const SM_MAX_SCRIPTS_SCAN = 15;
const SM_MAX_MAPS_PARSE = 20;
const SM_MAX_CHUNK_SAMPLES = 50;
const SM_MAX_JS_FALLBACK = 10;
const SM_MAX_OTHER_BUNDLES = 3;
const SM_MAX_MODULES = 2000;
const SM_MAX_FINDINGS = 200;
const SM_MAX_LABEL_LEN = 40;
const SM_MAX_MATCH_LEN = 60;
const SM_MAX_INLINE_SCRIPT = 500000;

let sourcemapModules = [];
let sourcemapSearchTerm = '';
let sourcemapCurrentModule = null;
let sourcemapSourceCache = {};
let sourcemapTabId = null;
let sourcemapMapCache = {};
let smAbortFlag = false;
let smTimerInterval = null;
let smStartTime = 0;

export const smState = {
  utils: utils,
  SM_SECURITY_RULES: SM_SECURITY_RULES,
  SOURCE_TYPE_LABELS: SOURCE_TYPE_LABELS,
  SM_MAX_SCRIPTS_SCAN: SM_MAX_SCRIPTS_SCAN,
  SM_MAX_MAPS_PARSE: SM_MAX_MAPS_PARSE,
  SM_MAX_CHUNK_SAMPLES: SM_MAX_CHUNK_SAMPLES,
  SM_MAX_JS_FALLBACK: SM_MAX_JS_FALLBACK,
  SM_MAX_OTHER_BUNDLES: SM_MAX_OTHER_BUNDLES,
  SM_MAX_MODULES: SM_MAX_MODULES,
  SM_MAX_FINDINGS: SM_MAX_FINDINGS,
  SM_MAX_LABEL_LEN: SM_MAX_LABEL_LEN,
  SM_MAX_MATCH_LEN: SM_MAX_MATCH_LEN,
  SM_MAX_INLINE_SCRIPT: SM_MAX_INLINE_SCRIPT,
  get sourcemapModules() { return sourcemapModules; },
  set sourcemapModules(v) { sourcemapModules = v; },
  get sourcemapSearchTerm() { return sourcemapSearchTerm; },
  set sourcemapSearchTerm(v) { sourcemapSearchTerm = v; },
  get sourcemapCurrentModule() { return sourcemapCurrentModule; },
  set sourcemapCurrentModule(v) { sourcemapCurrentModule = v; },
  get sourcemapSourceCache() { return sourcemapSourceCache; },
  set sourcemapSourceCache(v) { sourcemapSourceCache = v; },
  get sourcemapTabId() { return sourcemapTabId; },
  set sourcemapTabId(v) { sourcemapTabId = v; },
  get sourcemapMapCache() { return sourcemapMapCache; },
  set sourcemapMapCache(v) { sourcemapMapCache = v; },
  get smAbortFlag() { return smAbortFlag; },
  set smAbortFlag(v) { smAbortFlag = v; },
  get smTimerInterval() { return smTimerInterval; },
  set smTimerInterval(v) { smTimerInterval = v; },
  get smStartTime() { return smStartTime; },
  set smStartTime(v) { smStartTime = v; },
  Utils: null,
  Scanner: null,
  Render: null,
  Analysis: null,
  Actions: null,
};
