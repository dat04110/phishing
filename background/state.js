
// ── STATE ─────────────────────────────────────────────────────
let S = {
  stats: {
    total: 0, phishing: 0, suspicious: 0, safe: 0,
    links: 0, reported: 0, geminiCalls: 0, vtCalls: 0, deleted: 0,
    quarantined: 0, falsePositives: 0, avgRiskScore: 0,
    byCategory: {}, bySource: {}, byHour: new Array(24).fill(0),
    riskScoreSum: 0, startDate: new Date().toISOString(),
    urlsScanned: 0, urlsMalicious: 0, urlsSuspicious: 0,
    mediaScanned: 0, mediaMalicious: 0, qrCodesFound: 0,
    // ── New API stats v7.2 ────────────────────────────────────
    urlhausCalls: 0, urlhausHits: 0,
    abuseipdbCalls: 0, abuseipdbHits: 0,
    ipqsCalls: 0, ipqsHits: 0
  },
  history: [],
  whitelist: [],
  blacklist: [],
  quarantine: [],
  threatFeed: [],
  logs: [],
  settings: {
    autoScan: true,
    notifications: true,
    toolbar: true,
    aiServer: true,
    useGemini: true,
    useGeminiPro: false,
    useGemini2: true,
    safeBrowsing: true,
    virusTotal: false,
    aggressiveMode: false,
    passwordAlert: true,
    autoQuarantine: false,
    notifyLevel: 'suspicious',
    hybridWeight: 0.65,        // AI weight vs local (0-1)
    confidenceThreshold: 40,   // Min AI confidence to use result
    geminiKey: '',
    sbKey: '',
    vtKey: '',
    backendUrl: 'http://localhost:5001',
    logLevel: 'info',          // 'debug' | 'info' | 'warn' | 'error'
    // ── New API settings v7.2 ─────────────────────────────────
    urlhausEnabled: true,      // URLHaus — không cần key, bật mặc định
    abuseipdbEnabled: false,   // AbuseIPDB — cần key
    abuseipdbKey: '',
    ipqsEnabled: false,        // IPQualityScore Email Validation — cần key
    ipqsKey: ''
  },
  aiCache: {},
  performanceMetrics: {
    avgAnalysisTime: 0, totalAnalysisTime: 0, analysisCounts: 0,
    geminiAvgTime: 0, localAvgTime: 0, cacheHits: 0
  }
};

chrome.storage.local.get(['pgS'], r => {
  if (r.pgS) {
    S = deepMerge(S, r.pgS);
    S.aiCache = {};
  }
  if (!Array.isArray(S.whitelist)) S.whitelist = [];
  if (!Array.isArray(S.blacklist)) S.blacklist = [];
  if (!Array.isArray(S.quarantine)) S.quarantine = [];
  if (!Array.isArray(S.logs)) S.logs = [];
  if (!Array.isArray(S.threatFeed)) S.threatFeed = [];

  // ── Đảm bảo các settings v7.2 mới luôn có giá trị mặc định ──
  // Nếu storage cũ chưa có trường này → deepMerge sẽ không set nó
  // → phải tự gán default để tránh undefined gây lúc bật lúc tắt
  if (S.settings.urlhausEnabled === undefined) S.settings.urlhausEnabled = true;
  if (S.settings.abuseipdbEnabled === undefined) S.settings.abuseipdbEnabled = false;
  if (S.settings.abuseipdbKey === undefined) S.settings.abuseipdbKey = '';
  if (S.settings.ipqsEnabled === undefined) S.settings.ipqsEnabled = false;
  if (S.settings.ipqsKey === undefined) S.settings.ipqsKey = '';

  // ── Đảm bảo stats v7.2 mới luôn có giá trị ──
  if (S.stats.urlhausCalls === undefined) S.stats.urlhausCalls = 0;
  if (S.stats.urlhausHits === undefined) S.stats.urlhausHits = 0;
  if (S.stats.abuseipdbCalls === undefined) S.stats.abuseipdbCalls = 0;
  if (S.stats.abuseipdbHits === undefined) S.stats.abuseipdbHits = 0;
  if (S.stats.ipqsCalls === undefined) S.stats.ipqsCalls = 0;
  if (S.stats.ipqsHits === undefined) S.stats.ipqsHits = 0;
});

function save() {
  if (S.history.length > 3000) S.history = S.history.slice(-3000);
  if (S.logs.length > 5000) S.logs = S.logs.slice(-5000);
  if (S.quarantine.length > 500) S.quarantine = S.quarantine.slice(-500);
  chrome.storage.local.set({ pgS: S });
}

// ── LOGGING SYSTEM ────────────────────────────────────────────
function log(level, event, data = {}) {
  const levels = { debug: 0, info: 1, warn: 2, error: 3 };
  const current = levels[S.settings.logLevel || 'info'] || 1;
  if (levels[level] < current) return;

  const entry = {
    id: `log_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    ts: new Date().toISOString(),
    level, event,
    data: typeof data === 'object' ? { ...data } : { value: data }
  };
  S.logs.push(entry);
  if (S.settings.logLevel === 'debug') console.log(`[PhishGuard][${level.toUpperCase()}]`, event, data);
  return entry;
}
