// PhishGuard Enterprise v7.0 — Popup Controller
'use strict';

let allHistory = [];
let histFilter = 'all';
let histSort = 'desc'; // desc = mới nhất

const CAT_COLORS = {
  credential: '#a855f7', financial: '#ef4444', spoofing: '#f97316',
  urgency: '#f59e0b', link: '#3b82f6', domain: '#06b6d4', malware: '#ef4444',
  scam: '#ec4899', social_engineering: '#8b5cf6', style: '#6b7280', spam: '#9ca3af'
};

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('ft').textContent = new Date().toLocaleTimeString('vi-VN');
  wireNav();
  wireHistory();
  wireLists();
  wireSettings();
  wireAnalytics();
  wireQuarantine();
  wireLogs();
  wireLinks();
  loadDashboard();
  loadSettings();
  loadLists();
});

// ── NAV ──────────────────────────────────────────────────────
function wireNav() {
  document.getElementById('nav').addEventListener('click', e => {
    const btn = e.target.closest('.ntab'); if (!btn) return;
    const name = btn.dataset.tab;
    document.querySelectorAll('.ntab').forEach(b => b.classList.remove('on'));
    document.querySelectorAll('.pg').forEach(p => p.classList.remove('on'));
    btn.classList.add('on');
    document.getElementById('pg-' + name).classList.add('on');
    if (name === 'dash') loadDashboard();
    if (name === 'analytics') loadAnalytics();
    if (name === 'hist') loadHistory();
    if (name === 'quarantine') loadQuarantine();
    if (name === 'lists') loadLists();
    if (name === 'logs') loadLogs();
  });
}

// ── DASHBOARD ────────────────────────────────────────────────
function loadDashboard() {
  send('getStats', {}, s => {
    if (!s) return;
    const { total = 0, phishing = 0, suspicious = 0, safe = 0, links = 0, reported = 0, geminiCalls = 0, deleted = 0,
      byCategory = {} } = s;
    anim('nt', total);
    anim('np', phishing);
    anim('ns', suspicious);
    anim('nok', safe);
    anim('nlinks', links);
    anim('nrep', reported);
    anim('ngem', geminiCalls);
    anim('ndel', deleted || 0);

    const p = (v, t) => t > 0 ? Math.round(v / t * 100) : 0;
    const credCount = (byCategory.credential || 0) + (byCategory.financial || 0);
    setTimeout(() => {
      setBar('bp', 'vp', p(phishing, total), phishing);
      setBar('bs', 'vs', p(suspicious, total), suspicious);
      setBar('bk', 'vk', p(credCount, total), credCount);
      setBar('bok', 'vok', p(safe, total), safe);
    }, 100);
    updateScore(total, phishing, suspicious);
  });

  // ── Sync AI cards & badges (chỉ cập nhật display, không fill inputs) ──
  send('getSettings', {}, s => { if (s) { updateBadges(s); updateAiCards(s); } });
}

function setBar(bid, vid, pct, val) {
  const b = document.getElementById(bid);
  const v = document.getElementById(vid);
  if (b) b.style.width = pct + '%';
  if (v) v.textContent = val;
}

function updateScore(total, p, s) {
  const arc = document.getElementById('sc-arc');
  const n = document.getElementById('sc-n');
  const h = document.getElementById('sc-h');
  const sub = document.getElementById('sc-s');
  if (!arc) return;
  if (!total) {
    n.textContent = '—'; h.textContent = 'Awaiting data';
    sub.textContent = 'Quét email để tạo điểm bảo mật'; return;
  }
  const score = Math.max(0, Math.round(100 - ((p + s) / total * 80)));
  const circ = 2 * Math.PI * 22;
  const dash = (score / 100) * circ;
  const col = score >= 80 ? '#10b981' : score >= 50 ? '#f59e0b' : '#ef4444';

  arc.setAttribute('stroke-dasharray', `${dash} ${circ}`);
  arc.setAttribute('stroke', col);
  n.textContent = score;
  n.style.color = col;

  if (score >= 80) { h.textContent = '✅ Môi trường An toàn'; sub.textContent = `${total} email đã quét — rủi ro thấp`; }
  else if (score >= 50) { h.textContent = '⚠️ Rủi ro Trung bình'; sub.textContent = 'Một số hoạt động đáng ngờ'; }
  else { h.textContent = '🚨 Nguy hiểm Cao'; sub.textContent = 'Nhiều mối đe dọa trong hộp thư!'; }
}

function updateBadges(s) {
  const set = (id, lbl, on) => {
    const el = document.getElementById(id); if (!el) return;
    el.textContent = lbl; el.className = 'badge ' + (on ? 'b-on' : 'b-off');
  };
  const modelName = s.useGemini2 ? '2.0 Flash' : s.useGeminiPro ? '1.5 Pro' : '1.5 Flash';
  set('ab-gemini', `Gemini ${s.useGemini && s.geminiKey ? modelName : 'OFF'}`, s.useGemini && s.geminiKey);
  set('ab-sb', `SafeBrowse: ${s.safeBrowsing && s.sbKey ? 'ON' : 'OFF'}`, s.safeBrowsing && s.sbKey);
  set('ab-vt', `VirusTotal: ${s.virusTotal && s.vtKey ? 'ON' : 'OFF'}`, s.virusTotal && s.vtKey);
  set('ab-be', `Backend: ${s.aiServer ? 'ON' : 'OFF'}`, s.aiServer);
  set('ab-urlhaus', `URLHaus: ${s.urlhausEnabled ? 'ON' : 'OFF'}`, s.urlhausEnabled);
  set('ab-abuseipdb', `AbuseIPDB: ${s.abuseipdbEnabled && s.abuseipdbKey ? 'ON' : 'OFF'}`, s.abuseipdbEnabled && s.abuseipdbKey);
  set('ab-ipqs', `IPQS: ${s.ipqsEnabled && s.ipqsKey ? 'ON' : 'OFF'}`, s.ipqsEnabled && s.ipqsKey);
  const modeEl = document.getElementById('ab-mode');
  if (modeEl) {
    modeEl.textContent = s.aggressiveMode ? '⚡ Aggressive' : 'Normal';
    modeEl.className = 'badge ' + (s.aggressiveMode ? 'b-on' : 'b-acc');
  }
}

function updateAiCards(s) {
  const upd = (cid, sid, cls, txt) => {
    const c = document.getElementById(cid);
    const st = document.getElementById(sid);
    if (c) c.className = 'ai-card' + (cls ? ' ' + cls : '');
    if (st) st.textContent = txt;
  };
  const modelName = s.useGemini2 ? 'Gemini 2.0 Flash' : s.useGeminiPro ? 'Gemini 1.5 Pro' : 'Gemini 1.5 Flash';
  upd('ai-gemini', 'ai-gemini-s', s.useGemini && s.geminiKey ? 'on-purple' : '',
    s.useGemini && s.geminiKey ? `✓ Active — ${modelName}` : s.geminiKey ? 'Disabled' : 'No key');
  upd('ai-sb', 'ai-sb-s', s.safeBrowsing && s.sbKey ? 'on-blue' : '',
    s.safeBrowsing && s.sbKey ? '✓ Active' : 'No key');
  upd('ai-vt', 'ai-vt-s', s.virusTotal && s.vtKey ? 'on-orange' : '',
    s.virusTotal && s.vtKey ? '✓ Active — 70+ engines' : 'No key');
  upd('ai-be', 'ai-be-s', s.aiServer ? 'on-green' : '',
    s.aiServer ? `✓ ${s.backendUrl || 'localhost:5001'}` : 'Disabled');
  // New APIs v7.2
  upd('ai-urlhaus', 'ai-urlhaus-s', s.urlhausEnabled ? 'on-red' : '',
    s.urlhausEnabled ? '✓ Active — No key required' : 'Disabled');
  upd('ai-abuseipdb', 'ai-abuseipdb-s', s.abuseipdbEnabled && s.abuseipdbKey ? 'on-orange' : '',
    s.abuseipdbEnabled && s.abuseipdbKey ? '✓ Active — IP Reputation' : s.abuseipdbKey ? 'Disabled' : 'No key');
  upd('ai-ipqs', 'ai-ipqs-s', s.ipqsEnabled && s.ipqsKey ? 'on-purple' : '',
    s.ipqsEnabled && s.ipqsKey ? '✓ Active — Email Fraud Score' : s.ipqsKey ? 'Disabled' : 'No key');
}

// ── ANALYTICS ────────────────────────────────────────────────
function wireAnalytics() {
  document.getElementById('btn-export-json')?.addEventListener('click', () => exportData('json'));
  document.getElementById('btn-export-csv')?.addEventListener('click', () => exportData('csv'));
}

function loadAnalytics() {
  // Performance metrics
  send('getMetrics', {}, pm => {
    if (!pm) return;
    setText('m-avg', pm.avgAnalysisTime ? pm.avgAnalysisTime + 'ms' : '—');
    setText('m-gem', pm.geminiAvgTime ? pm.geminiAvgTime + 'ms' : '—');
    setText('m-cache', pm.cacheHits || 0);
  });

  send('getStats', {}, s => {
    if (!s) return;
    setText('m-fp', s.falsePositives || 0);
    setText('m-quar', s.quarantined || 0);
    setText('m-avg-risk', (s.avgRiskScore || 0) + '%');

    // Hourly chart
    renderHourlyChart(s.byHour || new Array(24).fill(0));

    // Threat categories
    renderCategoryGrid(s.byCategory || {});

    // Source breakdown
    renderSourceBreakdown(s.bySource || {});
  });
}

function renderHourlyChart(byHour) {
  const el = document.getElementById('hourly-chart'); if (!el) return;
  const max = Math.max(1, ...byHour);
  el.innerHTML = byHour.map((v, i) => {
    const pct = Math.max(4, (v / max) * 100);
    return `<div class="hb" style="height:${pct}%;${v > 0 ? 'background:rgba(59,130,246,.5)' : ''}">
      <span class="hb-tooltip">${i}h: ${v}</span>
    </div>`;
  }).join('');
}

function renderCategoryGrid(byCategory) {
  const el = document.getElementById('cat-grid'); if (!el) return;
  const entries = Object.entries(byCategory).sort((a, b) => b[1] - a[1]);
  if (!entries.length) { el.innerHTML = '<div class="empty" style="grid-column:1/-1">Chưa có dữ liệu</div>'; return; }
  el.innerHTML = entries.slice(0, 10).map(([cat, count]) => {
    const color = CAT_COLORS[cat] || '#6b7280';
    return `<div class="cat-item">
      <div class="cat-dot" style="background:${color}"></div>
      <span class="cat-n" style="color:${color}">${cat}</span>
      <span class="cat-v">${count}</span>
    </div>`;
  }).join('');
}

function renderSourceBreakdown(bySource) {
  const el = document.getElementById('src-breakdown'); if (!el) return;
  const entries = Object.entries(bySource).sort((a, b) => b[1] - a[1]);
  if (!entries.length) { el.innerHTML = '<div class="empty">Chưa có dữ liệu</div>'; return; }
  const total = entries.reduce((s, [, v]) => s + v, 0);
  el.innerHTML = entries.map(([src, count]) => {
    const pct = Math.round(count / total * 100);
    return `<div style="display:flex;align-items:center;gap:7px;margin-bottom:4px;font-size:9px">
      <span style="width:90px;color:var(--mu);font-family:var(--m);text-overflow:ellipsis;overflow:hidden;white-space:nowrap">${src}</span>
      <div style="flex:1;height:4px;background:rgba(255,255,255,.05);border-radius:2px;overflow:hidden">
        <div style="height:100%;width:${pct}%;background:linear-gradient(90deg,#3b82f6,#60a5fa);border-radius:2px;transition:width .8s ease"></div>
      </div>
      <span style="font-family:var(--m);color:var(--mu);width:22px;text-align:right">${count}</span>
    </div>`;
  }).join('');
}

function exportData(format) {
  send('getExportData', { format }, data => {
    if (!data) return;
    const blob = format === 'csv'
      ? new Blob([data], { type: 'text/csv;charset=utf-8;' })
      : new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-export-${new Date().toISOString().slice(0, 10)}.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  });
}

// ── HISTORY ──────────────────────────────────────────────────
function wireHistory() {
  document.getElementById('hfilt').addEventListener('click', e => {
    const btn = e.target.closest('.hfb'); if (!btn) return;
    histFilter = btn.dataset.filter;
    document.querySelectorAll('.hfb').forEach(b => b.classList.remove('on'));
    btn.classList.add('on');
    renderHistory();
  });
  document.getElementById('hist-search')?.addEventListener('input', () => renderHistory());
  document.getElementById('btn-sort-hist')?.addEventListener('click', () => {
    histSort = histSort === 'desc' ? 'asc' : 'desc';
    const btn = document.getElementById('btn-sort-hist');
    if (btn) btn.textContent = histSort === 'desc' ? 'Mới nhất' : 'Cũ nhất';
    renderHistory();
  });
  document.getElementById('btn-clear-hist')?.addEventListener('click', () => {
    if (!confirm('Xóa tất cả lịch sử?')) return;
    send('clearHistory', {}, () => { allHistory = []; renderHistory(); });
  });
  document.getElementById('btn-clear-phish')?.addEventListener('click', () => {
    const count = allHistory.filter(h => h.riskLevel === 'PHISHING').length;
    if (!count) { alert('Không có phishing để xóa'); return; }
    if (!confirm(`Xóa ${count} bản ghi phishing?`)) return;
    send('clearPhishingHistory', {}, () => { allHistory = allHistory.filter(h => h.riskLevel !== 'PHISHING'); renderHistory(); });
  });
}

function loadHistory() {
  send('getHistory', {}, h => { allHistory = h || []; renderHistory(); });
}

function renderHistory() {
  const el = document.getElementById('hlist'); if (!el) return;
  const search = document.getElementById('hist-search')?.value?.toLowerCase() || '';

  let items = histFilter === 'all' ? allHistory : allHistory.filter(h => h.riskLevel === histFilter);
  if (search) items = items.filter(h => (h.subject || '').toLowerCase().includes(search) || (h.sender || '').toLowerCase().includes(search));
  if (histSort === 'asc') items = [...items].reverse();

  if (!items.length) { el.innerHTML = '<div class="empty">Không có dữ liệu</div>'; return; }

  const dc = { SAFE: 'var(--safe)', SUSPICIOUS: 'var(--warn)', PHISHING: 'var(--crit)' };
  const tc = { SAFE: 'tok', SUSPICIOUS: 'ts', PHISHING: 'tp' };
  const tl = { SAFE: 'CLEAN', SUSPICIOUS: 'WARN', PHISHING: 'PHISH' };

  el.innerHTML = items.slice(0, 150).map(h => {
    const confBadge = h.confidence ? `<span style="font-size:7px;padding:1px 3px;border-radius:2px;background:rgba(255,255,255,.05);color:var(--dim)">${h.confidence}%</span>` : '';
    const fpBadge = h.falsePositive ? `<span style="font-size:7px;color:var(--warn);margin-left:3px">[FP]</span>` : '';
    const delBadge = h.deleted ? `<span style="font-size:7px;color:var(--dim);margin-left:3px">[del]</span>` : '';
    const hybBadge = h.hybridUsed ? `<span style="font-size:7px;color:#60a5fa;margin-left:3px">H</span>` : '';
    return `<div class="hrow" style="${h.deleted || h.falsePositive ? 'opacity:0.45' : ''}" data-id="${esc(h.id || '')}">
      <div class="hd2" style="background:${dc[h.riskLevel] || 'var(--safe)'}"></div>
      <div class="hb2">
        <div class="hs2">${esc((h.subject || 'No subject').substring(0, 50))}${fpBadge}${delBadge}${hybBadge}</div>
        <div class="hm">${esc(h.sender || '')} · ${h.riskPercent}% · ${fmt(h.timestamp)}${confBadge}</div>
      </div>
      <span class="htag ${tc[h.riskLevel] || 'tok'}">${tl[h.riskLevel] || 'OK'}</span>
    </div>`;
  }).join('');

  // FP marking on click
  el.querySelectorAll('.hrow').forEach(row => {
    row.addEventListener('dblclick', () => {
      const id = row.dataset.id;
      if (id) send('markFalsePositive', { emailId: id }, () => loadHistory());
    });
  });
}

// ── QUARANTINE ───────────────────────────────────────────────
function wireQuarantine() {
  document.getElementById('btn-clear-quar')?.addEventListener('click', () => {
    if (!confirm('Xóa toàn bộ quarantine?')) return;
    send('clearHistory', {}, () => loadQuarantine());
  });
}

function loadQuarantine() {
  send('getQuarantine', {}, q => {
    const items = q || [];
    const el = document.getElementById('quarantine-list');
    if (!el) return;
    if (!items.length) { el.innerHTML = '<div class="empty">Không có email trong quarantine</div>'; return; }
    el.innerHTML = items.map(item => `
      <div class="qrow">
        <div class="qb">
          <div class="qt">${esc((item.subject || '').substring(0, 50))}</div>
          <div class="qs">${esc(item.sender || '')} · ${item.riskPercent}% · ${fmt(item.quarantinedAt)}</div>
          <div class="qs" style="color:#f87171;margin-top:2px">${esc(item.mainThreat || '')}</div>
        </div>
        <button class="q-rel" data-qid="${esc(item.id)}">✓ Release</button>
      </div>`).join('');
    el.querySelectorAll('.q-rel').forEach(btn => {
      btn.addEventListener('click', () => {
        send('releaseQuarantine', { id: btn.dataset.qid }, () => loadQuarantine());
      });
    });
  });
}

// ── LOGS ─────────────────────────────────────────────────────
function wireLogs() {
  document.getElementById('btn-refresh-logs')?.addEventListener('click', loadLogs);
  document.getElementById('btn-clear-logs')?.addEventListener('click', () => {
    if (!confirm('Xóa tất cả logs?')) return;
    send('clearLogs', {}, () => loadLogs());
  });
  document.getElementById('log-filter')?.addEventListener('change', loadLogs);
}

function loadLogs() {
  send('getLogs', { limit: 300 }, data => {
    if (!data) return;
    const filterVal = document.getElementById('log-filter')?.value || 'all';
    let logs = data.logs || [];
    if (filterVal !== 'all') logs = logs.filter(l => l.level === filterVal);

    const statsEl = document.getElementById('log-stats');
    if (statsEl) statsEl.textContent = `${data.total} total · Hiển thị ${logs.length}`;

    const el = document.getElementById('log-list');
    if (!el) return;
    if (!logs.length) { el.innerHTML = '<div class="empty">Không có log</div>'; return; }

    el.innerHTML = logs.slice(0, 200).map(entry => {
      const lcls = { info: 'log-i', warn: 'log-w', error: 'log-e', debug: 'log-d' }[entry.level] || 'log-d';
      const ts = entry.ts ? new Date(entry.ts).toLocaleTimeString('vi-VN') : '';
      const dataStr = entry.data && Object.keys(entry.data).length
        ? ` | ${JSON.stringify(entry.data).substring(0, 60)}` : '';
      return `<div class="log-row ${lcls}">
        <span class="log-lvl">${(entry.level || '').toUpperCase()}</span>
        <span class="log-ev">${esc(entry.event || '')}${esc(dataStr)}</span>
        <span class="log-ts">${ts}</span>
      </div>`;
    }).join('');
  });
}

// ── LISTS ─────────────────────────────────────────────────────
function wireLists() {
  document.getElementById('btn-wl-add')?.addEventListener('click', () => addList('white'));
  document.getElementById('btn-bl-add')?.addEventListener('click', () => addList('black'));
  document.getElementById('wl-in')?.addEventListener('keydown', e => { if (e.key === 'Enter') addList('white'); });
  document.getElementById('bl-in')?.addEventListener('keydown', e => { if (e.key === 'Enter') addList('black'); });
  document.getElementById('wl-el')?.addEventListener('click', e => { const b = e.target.closest('.li-del'); if (b) send('removeWhitelist', { email: b.dataset.email }, loadLists); });
  document.getElementById('bl-el')?.addEventListener('click', e => { const b = e.target.closest('.li-del'); if (b) send('removeBlacklist', { email: b.dataset.email }, loadLists); });
}
function addList(type) {
  const inp = document.getElementById(type === 'white' ? 'wl-in' : 'bl-in');
  const val = inp?.value?.trim(); if (!val) return;
  send(type === 'white' ? 'addWhitelist' : 'addBlacklist', { email: val }, () => { if (inp) inp.value = ''; loadLists(); });
}
function loadLists() {
  send('getLists', {}, d => { if (!d) return; renderList('wl-el', d.whitelist || []); renderList('bl-el', d.blacklist || []); });
}
function renderList(elId, items) {
  const el = document.getElementById(elId); if (!el) return;
  if (!items.length) { el.innerHTML = '<div class="empty">Không có</div>'; return; }
  el.innerHTML = items.map(item => `
    <div class="li-item">
      <span class="li-txt">${esc(item)}</span>
      <button class="li-del" data-email="${esc(item)}">✕</button>
    </div>`).join('');
}

// ── SETTINGS ─────────────────────────────────────────────────
function wireSettings() {
  document.getElementById('pg-settings').addEventListener('click', e => {
    const t = e.target.closest('.tgl'); if (t) t.classList.toggle('on');
  });
  document.getElementById('btn-save')?.addEventListener('click', saveSettings);
  document.getElementById('btn-clear-all')?.addEventListener('click', () => {
    if (!confirm('Xóa TẤT CẢ dữ liệu? Không thể hoàn tác!')) return;
    send('clearAll', {}, () => { alert('Đã xóa.'); window.close(); });
  });
  document.getElementById('btn-reset-stats')?.addEventListener('click', () => {
    if (!confirm('Reset toàn bộ thống kê?')) return;
    send('resetStats', {}, () => { loadDashboard(); alert('Đã reset stats'); });
  });
  document.getElementById('btn-test-backend')?.addEventListener('click', testBackend);

  // Range sliders
  const hwSlider = document.getElementById('hybrid-weight');
  const hwVal = document.getElementById('hw-val');
  hwSlider?.addEventListener('input', () => { if (hwVal) hwVal.textContent = hwSlider.value + '%'; });

  const ctSlider = document.getElementById('confidence-thresh');
  const ctVal = document.getElementById('ct-val');
  ctSlider?.addEventListener('input', () => { if (ctVal) ctVal.textContent = ctSlider.value + '%'; });
}

async function testBackend() {
  const btn = document.getElementById('btn-test-backend');
  const url = document.getElementById('be-url')?.value?.trim() || 'http://localhost:5001';
  if (btn) { btn.textContent = '⏳ Testing...'; btn.disabled = true; }
  try {
    const res = await fetch(`${url}/api/health`, { signal: AbortSignal.timeout(3000) });
    const data = await res.json();
    if (btn) { btn.textContent = `✓ Online (${data.analyzed || 0} analyzed)`; btn.style.color = '#10b981'; }
  } catch {
    if (btn) { btn.textContent = '✕ Offline'; btn.style.color = '#ef4444'; }
  }
  setTimeout(() => { if (btn) { btn.textContent = '🔌 Test Connection'; btn.style.color = ''; btn.disabled = false; } }, 3000);
}

function loadSettings() {
  send('getSettings', {}, s => {
    if (!s) return;
    // ── Toggle buttons ──
    document.querySelectorAll('[data-k]').forEach(t => {
      if (s[t.dataset.k] === true) t.classList.add('on');
      if (s[t.dataset.k] === false) t.classList.remove('on');
    });
    // ── Text inputs — cách viết đúng để tránh lúc có lúc không ──
    const setVal = (id, val) => { const el = document.getElementById(id); if (el && val) el.value = val; };
    setVal('gemini-key', s.geminiKey);
    setVal('sb-key', s.sbKey);
    setVal('vt-key', s.vtKey);
    setVal('abuseipdb-key', s.abuseipdbKey);
    setVal('ipqs-key', s.ipqsKey);
    setVal('be-url', s.backendUrl || 'http://localhost:5001');

    const hw = document.getElementById('hybrid-weight');
    const hv = document.getElementById('hw-val');
    if (hw && s.hybridWeight !== undefined) {
      hw.value = Math.round(s.hybridWeight * 100);
      if (hv) hv.textContent = hw.value + '%';
    }
    const ct = document.getElementById('confidence-thresh');
    const cv = document.getElementById('ct-val');
    if (ct && s.confidenceThreshold !== undefined) {
      ct.value = s.confidenceThreshold;
      if (cv) cv.textContent = ct.value + '%';
    }
    const ll = document.getElementById('log-level');
    if (ll && s.logLevel) ll.value = s.logLevel;

    // ── Sync badges & AI cards ngay sau khi load — tránh race condition ──
    updateBadges(s);
    updateAiCards(s);
  });
}


function saveSettings() {
  const settings = {};
  document.querySelectorAll('[data-k]').forEach(b => { settings[b.dataset.k] = b.classList.contains('on'); });
  settings.geminiKey = document.getElementById('gemini-key')?.value?.trim() || '';
  settings.sbKey = document.getElementById('sb-key')?.value?.trim() || '';
  settings.vtKey = document.getElementById('vt-key')?.value?.trim() || '';
  settings.abuseipdbKey = document.getElementById('abuseipdb-key')?.value?.trim() || '';
  settings.ipqsKey = document.getElementById('ipqs-key')?.value?.trim() || '';
  settings.backendUrl = document.getElementById('be-url')?.value?.trim() || 'http://localhost:5001';
  settings.hybridWeight = (parseInt(document.getElementById('hybrid-weight')?.value || 65)) / 100;
  settings.confidenceThreshold = parseInt(document.getElementById('confidence-thresh')?.value || 40);
  settings.logLevel = document.getElementById('log-level')?.value || 'info';

  send('saveSettings', { settings }, () => { });
  updateBadges(settings);
  const btn = document.getElementById('btn-save');
  if (btn) { btn.textContent = '✓ Đã lưu!'; setTimeout(() => { btn.textContent = '💾 Lưu Cài Đặt'; }, 2000); }
}

// ── EXTERNAL LINKS ───────────────────────────────────────────
function wireLinks() {
  const map = {
    'link-gemini': 'https://aistudio.google.com/app/apikey',
    'link-gcloud': 'https://console.cloud.google.com',
    'link-vt': 'https://www.virustotal.com'
  };
  Object.entries(map).forEach(([id, url]) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('click', e => { e.preventDefault(); chrome.tabs.create({ url }); });
  });
}

// ── UTILS ─────────────────────────────────────────────────────
function send(action, extra, cb) { chrome.runtime.sendMessage({ action, ...extra }, r => cb && cb(r)); }
function setText(id, v) { const e = document.getElementById(id); if (e) e.textContent = v; }
function anim(id, target) {
  const el = document.getElementById(id); if (!el) return;
  let c = 0;
  const inc = Math.max(1, Math.ceil(target / 25));
  const t = setInterval(() => { c = Math.min(c + inc, target); el.textContent = c; if (c >= target) clearInterval(t); }, 35);
}
function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function fmt(ts) {
  if (!ts) return '';
  const d = (Date.now() - new Date(ts)) / 1000;
  if (d < 60) return 'vừa xong';
  if (d < 3600) return `${~~(d / 60)}p`;
  if (d < 86400) return `${~~(d / 3600)}h`;
  return new Date(ts).toLocaleDateString('vi-VN');
}
