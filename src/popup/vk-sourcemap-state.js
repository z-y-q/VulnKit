// vk-sourcemap-state.js -- 灵眸 Chrome Extension
// Sourcemap shared state, constants, registration slots
import { utilsProxy as utils } from './vk-namespace.js';
import { LEAK_RULES_LEGACY } from './vk-leak-rules.js';

const SM_SECURITY_RULES = LEAK_RULES_LEGACY;

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
  get sourcemapModules() {
    return sourcemapModules;
  },
  set sourcemapModules(v) {
    sourcemapModules = v;
  },
  get sourcemapSearchTerm() {
    return sourcemapSearchTerm;
  },
  set sourcemapSearchTerm(v) {
    sourcemapSearchTerm = v;
  },
  get sourcemapCurrentModule() {
    return sourcemapCurrentModule;
  },
  set sourcemapCurrentModule(v) {
    sourcemapCurrentModule = v;
  },
  get sourcemapSourceCache() {
    return sourcemapSourceCache;
  },
  set sourcemapSourceCache(v) {
    sourcemapSourceCache = v;
  },
  get sourcemapTabId() {
    return sourcemapTabId;
  },
  set sourcemapTabId(v) {
    sourcemapTabId = v;
  },
  get sourcemapMapCache() {
    return sourcemapMapCache;
  },
  set sourcemapMapCache(v) {
    sourcemapMapCache = v;
  },
  get smAbortFlag() {
    return smAbortFlag;
  },
  set smAbortFlag(v) {
    smAbortFlag = v;
  },
  get smTimerInterval() {
    return smTimerInterval;
  },
  set smTimerInterval(v) {
    smTimerInterval = v;
  },
  get smStartTime() {
    return smStartTime;
  },
  set smStartTime(v) {
    smStartTime = v;
  },
  Utils: null,
  Scanner: null,
  Render: null,
  Analysis: null,
  Actions: null,
};
