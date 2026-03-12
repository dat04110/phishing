// Entry point for PhishGuard Service Worker
try {
  importScripts(
    'background/config.js',
    'background/state.js',
    'background/engine.js'
  );
} catch (e) {
  console.error('Failed to import scripts:', e);
}

// ── CONTEXT MENU ──────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: 'pg-check-link', title: '🛡 PhishGuard: Kiểm tra link', contexts: ['link'] });
  chrome.contextMenus.create({ id: 'pg-report-page', title: '🚨 PhishGuard: Báo cáo trang này', contexts: ['page'] });
  log('info', 'extension_installed', { version: VERSION });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'pg-check-link') {
    checkUrl(info.linkUrl).then(result => {
      log('info', 'context_menu_url_check', { url: info.linkUrl, result: result.status });
      chrome.notifications.create(`pg_url_${Date.now()}`, {
        type: 'basic', iconUrl: 'icons/icon48.png',
        title: result.status === 'malicious' ? '⛔ Link Độc Hại!' : result.status === 'suspicious' ? '⚠️ Link Đáng Ngờ' : '✅ Link An Toàn',
        message: `${info.linkUrl.substring(0, 80)}\n→ ${result.reason || result.status}`,
        priority: result.status === 'malicious' ? 2 : 1
      });
    });
  }
  if (info.menuItemId === 'pg-report-page') {
    doReport({ url: tab.url, title: tab.title, reportedAt: now() });
  }
});

// ── MESSAGE ROUTER ────────────────────────────────────────────
chrome.runtime.onMessage.addListener((req, _s, reply) => {
  const handlers = {
    analyzeEmail: () => analyzeEmail(req.data).then(reply),
    analyzeEmailList: () => analyzeBatch(req.data).then(reply),
    checkUrl: () => checkUrl(req.url).then(reply),
    analyzeUrlBatch: () => analyzeUrlBatch(req.urls || [], req.emailContext || '').then(reply),
    analyzeUrlDeep: () => analyzeUrlDeep(req.url).then(reply),
    scanMedia: () => scanMediaItem(req.mediaItem).then(reply),
    scanMediaBatch: () => scanMediaBatch(req.items || []).then(reply),
    getStats: () => reply(S.stats),
    getHistory: () => reply([...S.history].reverse()),
    getSettings: () => reply(S.settings),
    getMetrics: () => reply(S.performanceMetrics),
    getQuarantine: () => reply([...S.quarantine].reverse()),
    getLogs: () => reply({ logs: [...S.logs].reverse().slice(0, req.limit || 200), total: S.logs.length }),
    getThreatFeed: () => reply(S.threatFeed),
    getExportData: () => reply(buildExport(req.format)),
    saveSettings: () => { Object.assign(S.settings, req.settings); save(); reply({ ok: true }); log('info', 'settings_saved'); },
    addWhitelist: () => { addToList('whitelist', req.email); save(); reply({ ok: true }); },
    removeWhitelist: () => { S.whitelist = S.whitelist.filter(x => x !== req.email); save(); reply({ ok: true }); },
    addBlacklist: () => { addToList('blacklist', req.email); save(); reply({ ok: true }); },
    removeBlacklist: () => { S.blacklist = S.blacklist.filter(x => x !== req.email); save(); reply({ ok: true }); },
    getLists: () => reply({ whitelist: S.whitelist, blacklist: S.blacklist }),
    reportPhishing: () => doReport(req.data).then(reply),
    markDeleted: () => { markEmailDeleted(req.emailData); save(); reply({ ok: true }); },
    markFalsePositive: () => { markFalsePositive(req.emailId); save(); reply({ ok: true }); },
    releaseQuarantine: () => { releaseFromQuarantine(req.id); save(); reply({ ok: true }); },
    saveDeletedCount: () => { S.stats.deleted = (S.stats.deleted || 0) + (req.count || 1); save(); reply({ ok: true }); },
    clearHistory: () => { S.history = []; save(); reply({ ok: true }); },
    clearPhishingHistory: () => { S.history = S.history.filter(h => h.riskLevel !== 'PHISHING'); save(); reply({ ok: true }); },
    clearLogs: () => { S.logs = []; save(); reply({ ok: true }); },
    resetStats: () => { resetStats(); save(); reply({ ok: true }); },
    clearAll: () => { chrome.storage.local.clear(() => reply({ ok: true })); }
  };
  (handlers[req.action] || (() => reply(null)))();
  return true;
});

function addToList(list, email) {
  if (email && !S[list].includes(email)) S[list].push(email);
}

function markEmailDeleted(emailData) {
  if (!emailData) return;
  const entry = S.history.find(h => h.sender === emailData.sender && h.subject === emailData.subject);
  if (entry) entry.deleted = true;
  S.stats.deleted = (S.stats.deleted || 0) + 1;
  log('info', 'email_deleted', { sender: emailData.sender, subject: emailData.subject });
}

function markFalsePositive(emailId) {
  const entry = S.history.find(h => h.id === emailId);
  if (entry) { entry.falsePositive = true; S.stats.falsePositives++; }
  log('warn', 'false_positive_marked', { emailId });
}

function releaseFromQuarantine(id) {
  S.quarantine = S.quarantine.filter(q => q.id !== id);
  log('info', 'quarantine_released', { id });
}

function resetStats() {
  S.stats = {
    total: 0, phishing: 0, suspicious: 0, safe: 0,
    links: 0, reported: 0, geminiCalls: 0, vtCalls: 0, deleted: 0,
    quarantined: 0, falsePositives: 0, avgRiskScore: 0,
    byCategory: {}, bySource: {}, byHour: new Array(24).fill(0),
    riskScoreSum: 0, startDate: new Date().toISOString(),
    urlsScanned: 0, urlsMalicious: 0, urlsSuspicious: 0,
    mediaScanned: 0, mediaMalicious: 0, qrCodesFound: 0
  };
  log('info', 'stats_reset');
}