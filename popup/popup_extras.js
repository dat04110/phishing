// PhishGuard Enterprise v7.1 — Extra Features JS
// Simulator + Threat Map + AI Chatbot
// Tách ra file riêng để tuân thủ CSP MV3 (không dùng inline script)
'use strict';

// ═══════════════════════════════════════════════════════════════
// SIMULATOR ENGINE
// ═══════════════════════════════════════════════════════════════
const PHISH_SAMPLES = [
    {
        sender: 'security-alert@vietcombank-verify.tk',
        subject: '[KHẨN CẤP] Tài khoản của bạn đã bị đình chỉ!!!',
        body: 'Kính gửi quý khách,\n\nTài khoản ngân hàng của bạn đã bị tạm khóa do hoạt động bất thường.\nVui lòng xác minh danh tính NGAY TRONG 24 GIỜ bằng cách nhập:\n- Số thẻ ngân hàng\n- Mã CVV\n- Mã PIN\n- Mã OTP gửi về điện thoại\n\nClick vào: http://192.168.1.1/verify-account\n\nNếu không xác minh, tài khoản sẽ bị xóa vĩnh viễn.\n\nTrân trọng,\nVietcombank Security Team'
    },
    {
        sender: 'admin@google-account-verify.xyz',
        subject: 'URGENT: Your Google account will be suspended!!!',
        body: 'Dear user,\n\nUnusual activity detected on your account.\nYour account has been compromised. You must verify immediately.\n\nClick here to verify: http://bit.ly/3xK9mVp\n\nProvide your:\n- Password\n- OTP code\n- Recovery email\n\nFail to do so will result in permanent account deletion.\n\nGoogle Security Team'
    }
];

const SAFE_SAMPLE = {
    sender: 'noreply@google.com',
    subject: 'Security alert for your Google Account',
    body: 'Hi,\n\nA new sign-in to your Google Account was detected from Chrome on Windows.\n\nIf this was you, you can ignore this message.\nIf you did not sign in, go to your Google Account to take action.\n\nYou received this email to let you know about important changes to your Google Account and services.\n\n© Google LLC, 1600 Amphitheatre Pkwy, Mountain View, CA 94043'
};

let simRunning = false;

function initSimulator() {
    const loadPhishBtn = document.getElementById('sim-load-phish');
    const loadSafeBtn = document.getElementById('sim-load-safe');
    const runBtn = document.getElementById('sim-run');

    if (!loadPhishBtn) return; // page not present

    loadPhishBtn.addEventListener('click', () => {
        const s = PHISH_SAMPLES[0];
        document.getElementById('sim-sender').value = s.sender;
        document.getElementById('sim-subject').value = s.subject;
        document.getElementById('sim-body').value = s.body;
    });

    loadSafeBtn.addEventListener('click', () => {
        document.getElementById('sim-sender').value = SAFE_SAMPLE.sender;
        document.getElementById('sim-subject').value = SAFE_SAMPLE.subject;
        document.getElementById('sim-body').value = SAFE_SAMPLE.body;
    });

    runBtn.addEventListener('click', runSimulator);

    // Enter key triggers analysis
    ['sim-sender', 'sim-subject'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('keydown', e => { if (e.key === 'Enter') runBtn.click(); });
    });
}

async function runSimulator() {
    if (simRunning) return;
    const sender = document.getElementById('sim-sender').value.trim();
    const subject = document.getElementById('sim-subject').value.trim();
    const body = document.getElementById('sim-body').value.trim();
    if (!sender && !subject && !body) {
        showSimError('Vui lòng nhập ít nhất một trường thông tin email.');
        return;
    }

    simRunning = true;
    const btn = document.getElementById('sim-run');
    btn.textContent = '⏳ Đang phân tích...';
    btn.disabled = true;

    const resultDiv = document.getElementById('sim-result');
    resultDiv.style.display = 'block';
    resultDiv.innerHTML = `
    <div style="display:flex;align-items:center;gap:8px;padding:14px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:8px">
      <div class="sim-spinner"></div>
      <div>
        <div style="font-size:11px;color:rgba(255,255,255,.8)">Đang phân tích với Hybrid AI Engine...</div>
        <div style="font-size:9px;color:rgba(255,255,255,.35);margin-top:2px">Local heuristics + Trusted sender check + Gemini AI</div>
      </div>
    </div>
  `;

    try {
        const result = await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => reject(new Error('Timeout 15s')), 15000);
            chrome.runtime.sendMessage(
                { action: 'analyzeEmail', data: { sender, subject, body } },
                r => {
                    clearTimeout(timeout);
                    if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
                    else resolve(r);
                }
            );
        });
        renderSimResult(result);
    } catch (e) {
        showSimError('Lỗi: ' + e.message);
    }

    btn.textContent = '⚡ Phân Tích Ngay';
    btn.disabled = false;
    simRunning = false;
}

function showSimError(msg) {
    const d = document.getElementById('sim-result');
    if (d) {
        d.style.display = 'block';
        d.innerHTML = `<div style="color:#f87171;font-size:11px;padding:10px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:8px">❌ ${escHtml(msg)}</div>`;
    }
}

function renderSimResult(r) {
    if (!r) { showSimError('Không có kết quả — kiểm tra extension đang chạy và API key đã cấu hình.'); return; }

    const isPhish = r.riskLevel === 'PHISHING';
    const isSusp = r.riskLevel === 'SUSPICIOUS';
    const color = isPhish ? '#ef4444' : isSusp ? '#f59e0b' : '#10b981';
    const colorBg = isPhish ? 'rgba(239,68,68,.08)' : isSusp ? 'rgba(245,158,11,.08)' : 'rgba(16,185,129,.08)';
    const colorBd = isPhish ? 'rgba(239,68,68,.25)' : isSusp ? 'rgba(245,158,11,.25)' : 'rgba(16,185,129,.25)';
    const icon = isPhish ? '⛔' : isSusp ? '⚠️' : '✅';
    const label = isPhish ? 'PHISHING' : isSusp ? 'SUSPICIOUS' : 'SAFE';
    const trusted = r.source === 'trusted-sender' || r.trustedDomain;

    const threats = (r.threats || []).slice(0, 6);
    const threatHtml = threats.length
        ? threats.map(t => {
            const tc = t.severity === 'critical' ? '#ef4444' : t.severity === 'high' ? '#f59e0b' : '#64748b';
            return `<div style="display:flex;gap:6px;align-items:flex-start;padding:5px 8px;background:rgba(255,255,255,.02);border-radius:5px;border-left:2px solid ${tc}44">
          <span style="color:${tc};font-size:9px;margin-top:2px">▶</span>
          <span style="font-size:9px;color:rgba(255,255,255,.65);line-height:1.5;flex:1">${escHtml(t.text || '')}</span>
          <span style="font-size:9px;font-family:monospace;color:${tc};white-space:nowrap">+${t.score || 0}pts</span>
        </div>`;
        }).join('')
        : `<div style="font-size:9px;color:rgba(255,255,255,.4);padding:5px 8px">Không phát hiện mối đe dọa cụ thể</div>`;

    const hybridHtml = r.hybridUsed
        ? `<div style="display:flex;gap:4px;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.06)">
        <div style="flex:1;padding:5px 8px;background:rgba(59,130,246,.08);border-radius:5px;text-align:center">
          <div style="font-size:12px;font-weight:700;font-family:monospace;color:#60a5fa">${r.aiScore !== undefined ? r.aiScore + '%' : '—'}</div>
          <div style="font-size:8px;color:rgba(255,255,255,.35)">Gemini AI</div>
        </div>
        <div style="flex:1;padding:5px 8px;background:rgba(168,85,247,.08);border-radius:5px;text-align:center">
          <div style="font-size:12px;font-weight:700;font-family:monospace;color:#c084fc">${r.localScore || 0}%</div>
          <div style="font-size:8px;color:rgba(255,255,255,.35)">Local Rules</div>
        </div>
        <div style="flex:1;padding:5px 8px;background:rgba(16,185,129,.08);border-radius:5px;text-align:center">
          <div style="font-size:12px;font-weight:700;font-family:monospace;color:#34d399">${r.confidence || 0}%</div>
          <div style="font-size:8px;color:rgba(255,255,255,.35)">Confidence</div>
        </div>
      </div>`
        : '';

    const trustedBadge = trusted
        ? `<div style="font-size:8px;background:rgba(16,185,129,.12);border:1px solid rgba(16,185,129,.25);color:#34d399;padding:3px 8px;border-radius:4px;margin-top:4px;display:inline-block">✓ Domain uy tín (Trusted Sender)</div>`
        : '';

    const summaryHtml = r.summary
        ? `<div style="padding:8px 12px;border-top:1px solid rgba(255,255,255,.06)">
        <div style="font-size:8px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:rgba(255,255,255,.25);margin-bottom:4px">AI SUMMARY</div>
        <div style="font-size:10px;color:rgba(255,255,255,.6);line-height:1.6">${escHtml(r.summary)}</div>
      </div>`
        : '';

    document.getElementById('sim-result').innerHTML = `
    <div style="border:1px solid ${colorBd};border-radius:10px;overflow:hidden;background:#07090f;animation:fadeIn .3s ease">
      <div style="padding:14px 16px;background:${colorBg};display:flex;align-items:center;gap:12px">
        <div style="font-size:30px;line-height:1">${icon}</div>
        <div style="flex:1">
          <div style="font-size:15px;font-weight:800;color:${color};letter-spacing:.5px">${label}</div>
          ${trustedBadge}
          <div style="font-size:9px;color:rgba(255,255,255,.35);margin-top:3px">Source: ${escHtml(r.source || 'local')} · ${r.analysisTime || 0}ms</div>
        </div>
        <div style="text-align:right">
          <div style="font-size:30px;font-weight:800;font-family:monospace;color:${color};line-height:1">${r.riskPercent || 0}%</div>
          <div style="font-size:8px;color:rgba(255,255,255,.3);letter-spacing:.5px">RISK SCORE</div>
        </div>
      </div>
      <div style="height:4px;background:rgba(255,255,255,.05)">
        <div style="height:100%;width:${r.riskPercent || 0}%;background:${color};transition:width .8s cubic-bezier(.4,0,.2,1)"></div>
      </div>
      ${hybridHtml}
      <div style="padding:8px 12px">
        <div style="font-size:8px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:rgba(255,255,255,.25);margin-bottom:5px">THREATS DETECTED (${threats.length})</div>
        <div style="display:flex;flex-direction:column;gap:3px">${threatHtml}</div>
      </div>
      ${summaryHtml}
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════
// THREAT MAP ENGINE
// ═══════════════════════════════════════════════════════════════
const COUNTRY_COORDS = {
    'vn': [14.0583, 108.2772, 'Việt Nam', '🇻🇳'],
    'cn': [35.8617, 104.1954, 'Trung Quốc', '🇨🇳'],
    'us': [37.0902, -95.7129, 'Hoa Kỳ', '🇺🇸'],
    'ru': [61.5240, 105.3188, 'Nga', '🇷🇺'],
    'uk': [55.3781, -3.4360, 'Anh', '🇬🇧'],
    'ng': [9.0820, 8.6753, 'Nigeria', '🇳🇬'],
    'in': [20.5937, 78.9629, 'Ấn Độ', '🇮🇳'],
    'br': [14.2350, -51.9253, 'Brazil', '🇧🇷'],
    'de': [51.1657, 10.4515, 'Đức', '🇩🇪'],
    'fr': [46.2276, 2.2137, 'Pháp', '🇫🇷'],
    'jp': [36.2048, 138.2529, 'Nhật Bản', '🇯🇵'],
    'kr': [35.9078, 127.7669, 'Hàn Quốc', '🇰🇷'],
    'pk': [30.3753, 69.3451, 'Pakistan', '🇵🇰'],
    'ph': [12.8797, 121.7740, 'Philippines', '🇵🇭'],
    'id': [0.7893, 113.9213, 'Indonesia', '🇮🇩'],
    'tr': [38.9637, 35.2433, 'Thổ Nhĩ Kỳ', '🇹🇷'],
    'za': [-30.5595, 22.9375, 'Nam Phi', '🇿🇦'],
    'mx': [23.6345, -102.5528, 'Mexico', '🇲🇽'],
    'unknown': [20, 0, 'Unknown', '🌐']
};

const TLD_TO_COUNTRY = {
    '.vn': 'vn', '.cn': 'cn', '.ru': 'ru', '.uk': 'uk', '.de': 'de',
    '.fr': 'fr', '.jp': 'jp', '.kr': 'kr', '.br': 'br', '.in': 'in',
    '.id': 'id', '.ph': 'ph', '.pk': 'pk', '.ng': 'ng', '.tr': 'tr',
    '.tk': 'unknown', '.ml': 'unknown', '.ga': 'unknown', '.xyz': 'unknown',
    '.top': 'unknown', '.click': 'unknown', '.work': 'unknown'
};

let leafletMap = null;
let mapMarkers = [];
let mapInit = false;

function initThreatMap() {
    if (mapInit) { refreshMapData(); return; }
    mapInit = true;

    const mapEl = document.getElementById('pg-map-inner');
    if (!mapEl) return;
    mapEl.style.cssText = 'height:200px;border-radius:8px;overflow:hidden;border:1px solid rgba(255,255,255,.1)';
    mapEl.innerHTML = '<div id="leaflet-map" style="width:100%;height:100%"></div>';

    if (typeof L === 'undefined') {
        mapEl.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;font-size:10px;color:rgba(255,255,255,.4);padding:20px;text-align:center">Bản đồ không khả dụng (Leaflet.js chưa tải).<br>Đảm bảo leaflet.js có trong thư mục popup/</div>';
        return;
    }

    try {
        leafletMap = L.map('leaflet-map', {
            zoomControl: false,
            attributionControl: false,
            minZoom: 1, maxZoom: 6,
            zoom: 2, center: [20, 10]
        });

        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            subdomains: 'abcd', maxZoom: 19
        }).addTo(leafletMap);

        refreshMapData();
    } catch (err) {
        mapEl.innerHTML = `<div style="display:flex;align-items:center;justify-content:center;height:100%;font-size:10px;color:#f87171">Lỗi bản đồ: ${err.message}</div>`;
    }
}

function getCountryFromDomain(domain) {
    if (!domain) return 'us';
    const parts = domain.split('.');
    const tld = '.' + parts[parts.length - 1];
    if (TLD_TO_COUNTRY[tld]) return TLD_TO_COUNTRY[tld];
    // Two-part TLD check
    if (parts.length >= 3) {
        const tld2 = '.' + parts.slice(-2).join('.');
        if (TLD_TO_COUNTRY[tld2]) return TLD_TO_COUNTRY[tld2];
    }
    // Free email providers → US
    if (['gmail', 'yahoo', 'hotmail', 'outlook', 'live'].some(f => domain.includes(f))) return 'us';
    // vn check fallback
    if (domain.includes('.vn')) return 'vn';
    return 'us'; // default USA
}

function refreshMapData() {
    chrome.runtime.sendMessage({ action: 'getHistory' }, history => {
        if (!history) return;

        const phishEmails = history.filter(h => h.riskLevel === 'PHISHING' || h.riskLevel === 'SUSPICIOUS');
        const countryCounts = {};
        const domainCounts = {};

        phishEmails.forEach(email => {
            const sender = (email.sender || '').toLowerCase();
            const atIdx = sender.lastIndexOf('@');
            const domain = atIdx >= 0 ? sender.slice(atIdx + 1).trim() : sender;
            if (domain) domainCounts[domain] = (domainCounts[domain] || 0) + 1;
            const cc = getCountryFromDomain(domain);
            countryCounts[cc] = (countryCounts[cc] || 0) + 1;
        });

        // Map markers
        if (leafletMap) {
            mapMarkers.forEach(m => leafletMap.removeLayer(m));
            mapMarkers = [];

            Object.entries(countryCounts).forEach(([cc, count]) => {
                const info = COUNTRY_COORDS[cc];
                if (!info) return;
                const radius = Math.min(22, 7 + count * 2.5);
                const color = count >= 5 ? '#ef4444' : count >= 2 ? '#f59e0b' : '#3b82f6';

                // Pulse circle
                const pulse = L.circleMarker([info[0], info[1]], {
                    radius: radius + 6, color, fillColor: color,
                    fillOpacity: 0.1, weight: 1, opacity: 0.4
                }).addTo(leafletMap);

                // Main circle
                const marker = L.circleMarker([info[0], info[1]], {
                    radius, color, fillColor: color,
                    fillOpacity: 0.65, weight: 2, opacity: 0.9
                }).addTo(leafletMap)
                    .bindTooltip(`${info[3]} ${info[2]}: ${count} email`, {
                        className: 'pg-map-tooltip', direction: 'top'
                    });

                mapMarkers.push(pulse, marker);
            });
        }

        // Country list
        const listEl = document.getElementById('map-country-list');
        if (listEl) {
            const sorted = Object.entries(countryCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
            if (sorted.length === 0) {
                listEl.innerHTML = '<div style="text-align:center;color:rgba(255,255,255,.3);font-size:10px;padding:12px">Chưa có dữ liệu — cần phát hiện email phishing trước</div>';
            } else {
                const maxVal = sorted[0][1];
                listEl.innerHTML = sorted.map(([cc, count]) => {
                    const info = COUNTRY_COORDS[cc] || [0, 0, 'Unknown', '🌐'];
                    const pct = Math.round(count / phishEmails.length * 100);
                    const color = count >= 5 ? '#ef4444' : count >= 2 ? '#f59e0b' : '#3b82f6';
                    return `<div style="display:flex;align-items:center;gap:8px;padding:6px 10px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:6px">
            <span style="font-size:14px">${info[3]}</span>
            <div style="flex:1;min-width:0">
              <div style="font-size:10px;font-weight:600;color:rgba(255,255,255,.85)">${info[2]}</div>
              <div style="height:3px;background:rgba(255,255,255,.05);border-radius:2px;margin-top:3px">
                <div style="height:100%;width:${(count / maxVal * 100).toFixed(0)}%;background:${color};border-radius:2px"></div>
              </div>
            </div>
            <span style="font-size:11px;font-weight:700;font-family:monospace;color:${color};flex-shrink:0">${count}</span>
            <span style="font-size:9px;color:rgba(255,255,255,.3);flex-shrink:0">${pct}%</span>
          </div>`;
                }).join('');
            }
        }

        // Domain list
        const domainEl = document.getElementById('map-domain-breakdown');
        if (domainEl) {
            const topDomains = Object.entries(domainCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
            if (topDomains.length === 0) {
                domainEl.innerHTML = '<div style="text-align:center;color:rgba(255,255,255,.3);font-size:10px;padding:12px">Chưa có dữ liệu</div>';
            } else {
                domainEl.innerHTML = topDomains.map(([dom, cnt]) => `
          <div style="display:flex;align-items:center;gap:8px;padding:5px 10px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:6px">
            <span style="font-size:10px;font-family:monospace;color:rgba(255,255,255,.65);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(dom)}</span>
            <span style="font-size:10px;font-weight:700;font-family:monospace;color:#f87171;flex-shrink:0">${cnt}×</span>
          </div>`).join('');
            }
        }
    });
}

// ═══════════════════════════════════════════════════════════════
// AI CHATBOT ENGINE
// ═══════════════════════════════════════════════════════════════
let chatHistory = [];
let chatTyping = false;

function initChatbot() {
    const sendBtn = document.getElementById('chat-send');
    const input = document.getElementById('chat-input');
    if (!sendBtn) return;

    sendBtn.addEventListener('click', () => sendChatMessage(input.value));
    input.addEventListener('keydown', e => {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendBtn.click(); }
    });

    document.querySelectorAll('.chat-quick').forEach(btn => {
        btn.addEventListener('click', () => sendChatMessage(btn.dataset.q));
    });
}

function appendChatMsg(role, text) {
    const msgs = document.getElementById('chat-msgs');
    if (!msgs) return null;
    const div = document.createElement('div');
    div.className = `chat-bubble chat-${role}`;
    const avatar = role === 'ai' ? '🛡' : '👤';
    // Simple markdown-like: **bold**, line breaks
    const formatted = escHtml(text)
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/\n/g, '<br>');
    div.innerHTML = `<div class="chat-avatar">${avatar}</div><div class="chat-text">${formatted}</div>`;
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
    return div;
}

function showTypingIndicator() {
    const msgs = document.getElementById('chat-msgs');
    if (!msgs) return null;
    const div = document.createElement('div');
    div.className = 'chat-bubble chat-ai chat-typing-bubble';
    div.innerHTML = `<div class="chat-avatar">🛡</div><div class="chat-text chat-typing"><span></span><span></span><span></span></div>`;
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
    return div;
}

async function sendChatMessage(userMsg) {
    userMsg = (userMsg || '').trim();
    if (chatTyping || !userMsg) return;
    chatTyping = true;

    const input = document.getElementById('chat-input');
    const sendBtn = document.getElementById('chat-send');
    if (input) input.value = '';
    if (input) input.disabled = true;
    if (sendBtn) sendBtn.disabled = true;

    appendChatMsg('user', userMsg);
    chatHistory.push({ role: 'user', text: userMsg });

    const typingBubble = showTypingIndicator();

    try {
        // Get Gemini key from settings
        const settings = await new Promise(resolve => {
            chrome.runtime.sendMessage({ action: 'getSettings' }, resolve);
        });

        const geminiKey = settings && settings.geminiKey;

        if (!geminiKey) {
            if (typingBubble) typingBubble.remove();
            appendChatMsg('ai', '⚠️ Chưa cấu hình Gemini API Key.\n\nVui lòng vào tab **Setup** và nhập Gemini API key, sau đó lưu lại.');
            chatTyping = false;
            if (input) input.disabled = false;
            if (sendBtn) sendBtn.disabled = false;
            if (input) input.focus();
            return;
        }

        const systemPrompt = `Bạn là PhishGuard AI Assistant - chuyên gia bảo mật email của PhishGuard Enterprise v7.1.
Trả lời bằng tiếng Việt, ngắn gọn, dùng emoji. Tối đa 180 từ.
Chuyên môn: phishing, email spoofing, OTP scam, credential harvesting, bank fraud, lookalike domains.`;

        const contents = chatHistory.slice(-8).map(m => ({
            role: m.role === 'ai' ? 'model' : 'user',
            parts: [{ text: m.text }]
        }));

        // Các model theo thứ tự ưu tiên (tên chính xác theo Google AI API)
        const MODELS = [
            'gemini-1.5-flash',       // Free tier - 15 req/phút
            'gemini-1.5-flash-8b',    // Free tier - 15 req/phút, nhẹ nhất
            'gemini-2.0-flash-lite',  // Free tier lite version
            'gemini-2.0-flash',       // Có thể cần billing
        ];
        let lastErr = null;
        let aiText = null;

        for (const model of MODELS) {
            try {
                const resp = await fetch(
                    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiKey}`,
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            system_instruction: { parts: [{ text: systemPrompt }] },
                            contents,
                            generationConfig: { maxOutputTokens: 350, temperature: 0.7 }
                        })
                    }
                );

                if (resp.status === 429) {
                    lastErr = 'quota'; continue;
                }
                if (resp.status === 404) {
                    lastErr = `model_${model}_not_found`; continue;
                }
                if (!resp.ok) {
                    const e = await resp.json().catch(() => ({}));
                    lastErr = e?.error?.message || `HTTP ${resp.status}`;
                    continue;
                }

                const data = await resp.json();
                aiText = data?.candidates?.[0]?.content?.parts?.[0]?.text || null;
                if (aiText) break;

            } catch (fetchErr) {
                lastErr = 'network';
                continue;
            }
        }

        if (typingBubble) typingBubble.remove();

        if (aiText) {
            appendChatMsg('ai', aiText);
            chatHistory.push({ role: 'ai', text: aiText });
        } else {
            // --- Rule-based fallback: hoạt động khi mất quota hoặc network lỗi ---
            const fallback = ruleBasedAnswer(userMsg);
            const note = lastErr === 'quota'
                ? '\n\n_(⚠️ Gemini quota hết, đang dùng chế độ offline)_'
                : '\n\n_(📵 Không kết nối được Gemini AI)_';
            appendChatMsg('ai', fallback + note);
            chatHistory.push({ role: 'ai', text: fallback });
        }

    } catch (err) {
        if (typingBubble) typingBubble.remove();
        const m = err.message || '';
        appendChatMsg('ai', `❌ Lỗi không mong muốn: ${m.slice(0, 80)}\n\nThử reload extension và kiểm tra API key.`);

    }

    chatTyping = false;
    if (input) input.disabled = false;
    if (sendBtn) sendBtn.disabled = false;
    if (input) input.focus();
}

// ═══════════════════════════════════════════════════════════════
// RULE-BASED FALLBACK (offline, khi quota Gemini hết)
// ═══════════════════════════════════════════════════════════════
function ruleBasedAnswer(question) {
    const q = question.toLowerCase();

    if (q.match(/phishing|lừa đảo|lừa|scam/)) {
        return '🎣 **Phishing là gì?**\n\nPhishing là hình thức tội phạm mạng giả mạo tổ chức uy tín (ngân hàng, Google...) để đánh cắp thông tin.\n\n🚩 **Dấu hiệu nhận biết:**\n• Domain lạ, sai chính tả (gooogle.com)\n• Yêu cầu OTP, CVV, mật khẩu gấp\n• Link rút gọn (bit.ly, tinyurl)\n• Tạo cảm giác khẩn cấp "24 giờ, hoặc bị khóa"\n\n✅ **Cách xử lý:** KHÔNG click link. Gọi hotline chính thức của tổ chức để xác nhận.';
    }

    if (q.match(/otp|mã xác minh|mã bảo mật|one.?time/)) {
        return '🔑 **OTP Scam**\n\nKhông bao giờ cung cấp OTP cho bất kỳ ai, kể cả nhân viên ngân hàng!\n\n⚠️ **Kịch bản phổ biến:**\n• Giả nhân viên ngân hàng gọi điện xin OTP\n• Email yêu cầu "xác minh danh tính" bằng OTP\n• Tin nhắn "tài khoản bị khóa, nhập OTP để mở"\n\n🛡️ **Nguyên tắc vàng:** OTP là MẬT KHẨU — không ai có quyền hỏi';
    }

    if (q.match(/ngân hàng|bank|vietcombank|techcombank|vcb|atm|thẻ/)) {
        return '🏦 **Bảo vệ tài khoản ngân hàng:**\n\n• ❌ Không cung cấp số thẻ + CVV + OTP qua email/điện thoại\n• ✅ Chỉ giao dịch trên website chính thức (https://)\n• ✅ Bật SMS OTP + xác thực 2 bước\n• ✅ Kiểm tra URL kỹ trước khi đăng nhập\n• 📞 Nếu nghi ngờ: gọi hotline 1800 trên thẻ ngân hàng\n\n🚨 Email ngân hàng THẬT sẽ không bao giờ yêu cầu mật khẩu hay CVV!';
    }

    if (q.match(/link|url|đường dẫn|website|domain/)) {
        return '🔗 **Kiểm tra link an toàn:**\n\n🔴 **Nguy hiểm nếu:**\n• Domain lạ (gooogle.com, vietcombank-secure.tk)\n• Dùng IP thay domain (http://192.168.1.1/login)\n• Link rút gọn bit.ly ẩn đích đến\n• Không có HTTPS (https://)\n\n✅ **Cách kiểm tra:** Hover chuột vào link → xem URL ở thanh trạng thái trước khi click. Dùng tab 🧪 **Sim** để phân tích email nghi ngờ ngay trong PhishGuard!';
    }

    if (q.match(/attachment|file|tệp|đính kèm|exe|zip|doc|macro/)) {
        return '📎 **File đính kèm nguy hiểm:**\n\n🔴 **KHÔNG mở:** .exe, .bat, .vbs, .js, .scr, .com\n⚠️ **Cẩn thận:** .zip, .docm, .xlsm (có macro)\n\n✅ **Quy tắc an toàn:**\n• Không bao giờ mở file từ email không mong đợi\n• Tắt macro trong Office theo mặc định\n• Scan với VirusTotal trước khi mở\n• Ngân hàng/cơ quan nhà nước KHÔNG gửi file .exe';
    }

    if (q.match(/password|mật khẩu|login|đăng nhập|tài khoản/)) {
        return '🔐 **Bảo mật mật khẩu:**\n\n• ❌ Không bao giờ nhập mật khẩu vào link từ email\n• ✅ Luôn vào thẳng website bằng cách gõ URL\n• ✅ Dùng mật khẩu riêng cho mỗi tài khoản\n• ✅ Bật xác thực 2 yếu tố (2FA)\n• 🔄 Đổi mật khẩu ngay nếu nghi bị lộ\n\n💡 Email uy tín KHÔNG bao giờ yêu cầu "nhập mật khẩu để xác minh"!';
    }

    if (q.match(/google|gmail|microsoft|outlook|apple|facebook/)) {
        return '🏢 **Email từ Big Tech (Google, Microsoft...):**\n\nEmail thật từ Google/Microsoft:\n✅ Gửi từ @google.com, @microsoft.com (không phải google-security.tk)\n✅ Không yêu cầu mật khẩu hay OTP\n✅ Link trỏ đến accounts.google.com (không phải domain lạ)\n\n⚠️ Dấu hiệu giả mạo:\n• Domain sai: google-alert.xyz, microsoft-secure.tk\n• Tạo áp lực: "tài khoản bị xóa trong 24 giờ"\n• Link rút gọn hoặc tạo từ form.io, weebly...';
    }

    // Default answer
    return `🛡️ **PhishGuard AI (Chế độ Offline)**\n\nTôi không kết nối được Gemini AI lúc này, nhưng có thể giúp bạn với các chủ đề:\n\n• 🎣 Phishing là gì?\n• 🔑 OTP & mật khẩu bị lừa\n• 🔗 Kiểm tra link/URL\n• 🏦 Bảo vệ ngân hàng\n• 📎 File đính kèm nguy hiểm\n\nHoặc dùng tab **🧪 Sim** để phân tích email trực tiếp mà không cần AI!`;
}


function escHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// ═══════════════════════════════════════════════════════════════
// MEDIA ANALYZER ENGINE
// Upload ảnh/video → Gemini Vision AI → kết quả chi tiết
// ═══════════════════════════════════════════════════════════════

let mediaQueue = [];   // [{file, dataUrl, type, thumbEl, id}]
let mediaScanning = false;
let mediaScanStats = { total: 0, safe: 0, warn: 0, danger: 0 };

function initMediaAnalyzer() {
    const dropZone = document.getElementById('media-drop-zone');
    const fileInput = document.getElementById('media-file-input');
    const scanBtn = document.getElementById('media-scan-btn');
    const clearBtn = document.getElementById('media-clear-btn');

    if (!dropZone) return;

    // Click on drop zone → trigger file input
    dropZone.addEventListener('click', e => {
        if (e.target.tagName === 'LABEL' || e.target.tagName === 'INPUT') return;
        fileInput.click();
    });

    // File input change
    fileInput.addEventListener('change', e => {
        if (e.target.files.length) handleMediaFiles(Array.from(e.target.files));
        fileInput.value = ''; // reset để chọn lại cùng file
    });

    // Drag & drop
    dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', e => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        const files = Array.from(e.dataTransfer.files).filter(f =>
            f.type.startsWith('image/') || f.type.startsWith('video/')
        );
        if (files.length) handleMediaFiles(files);
    });

    // Scan button
    if (scanBtn) scanBtn.addEventListener('click', runMediaScan);

    // Clear button
    if (clearBtn) clearBtn.addEventListener('click', clearMediaQueue);
}

async function handleMediaFiles(files) {
    const MAX_FILES = 12;
    const allowed = files.filter(f =>
        f.type.startsWith('image/') || f.type.startsWith('video/')
    ).slice(0, MAX_FILES - mediaQueue.length);

    if (!allowed.length) return;

    const dropZone = document.getElementById('media-drop-zone');
    const previewSection = document.getElementById('media-preview-section');
    const grid = document.getElementById('media-preview-grid');

    if (dropZone) dropZone.classList.add('has-files');
    if (previewSection) previewSection.style.display = 'block';

    for (const file of allowed) {
        const id = `mf_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
        const isVideo = file.type.startsWith('video/');
        let dataUrl = null;

        try {
            if (isVideo) {
                // Lấy frame đầu của video bằng Canvas
                dataUrl = await getVideoThumbnail(file);
            } else {
                dataUrl = await readFileAsDataUrl(file);
            }
        } catch (e) { continue; }

        // Tạo thumbnail
        const thumbEl = document.createElement('div');
        thumbEl.className = 'media-thumb';
        thumbEl.id = id;
        thumbEl.innerHTML = `
      <img src="${dataUrl || ''}" alt="${escHtml(file.name)}" onerror="this.style.display='none'">
      <span class="media-thumb-badge">${isVideo ? '🎬' : '🖼'} ${formatBytes(file.size)}</span>
      <button class="media-thumb-remove" title="Xóa" data-id="${id}">✕</button>
    `;
        thumbEl.querySelector('.media-thumb-remove').addEventListener('click', e => {
            e.stopPropagation();
            removeMediaItem(id);
        });

        grid.appendChild(thumbEl);

        mediaQueue.push({ id, file, dataUrl, type: isVideo ? 'video' : 'image', thumbEl });
    }

    // Update count
    const countEl = document.getElementById('media-count');
    if (countEl) countEl.textContent = mediaQueue.length;

    // Reset results khi thêm file mới
    const resultsList = document.getElementById('media-results-list');
    if (resultsList) resultsList.innerHTML = '';
    const statsSection = document.getElementById('media-stats-section');
    if (statsSection) statsSection.style.display = 'none';
    mediaScanStats = { total: 0, safe: 0, warn: 0, danger: 0 };
}

function removeMediaItem(id) {
    mediaQueue = mediaQueue.filter(m => m.id !== id);
    const el = document.getElementById(id);
    if (el) el.remove();
    const countEl = document.getElementById('media-count');
    if (countEl) countEl.textContent = mediaQueue.length;
    if (mediaQueue.length === 0) {
        const previewSection = document.getElementById('media-preview-section');
        const dropZone = document.getElementById('media-drop-zone');
        if (previewSection) previewSection.style.display = 'none';
        if (dropZone) dropZone.classList.remove('has-files');
    }
}

function clearMediaQueue() {
    mediaQueue = [];
    const grid = document.getElementById('media-preview-grid');
    if (grid) grid.innerHTML = '';
    const previewSection = document.getElementById('media-preview-section');
    if (previewSection) previewSection.style.display = 'none';
    const dropZone = document.getElementById('media-drop-zone');
    if (dropZone) dropZone.classList.remove('has-files');
    const resultsList = document.getElementById('media-results-list');
    if (resultsList) resultsList.innerHTML = '';
    const statsSection = document.getElementById('media-stats-section');
    if (statsSection) statsSection.style.display = 'none';
    const countEl = document.getElementById('media-count');
    if (countEl) countEl.textContent = '0';
    mediaScanStats = { total: 0, safe: 0, warn: 0, danger: 0 };
}

async function runMediaScan() {
    if (mediaScanning || mediaQueue.length === 0) return;
    mediaScanning = true;

    const scanBtn = document.getElementById('media-scan-btn');
    const progressEl = document.getElementById('media-progress');
    const progressText = document.getElementById('media-progress-text');
    const resultsList = document.getElementById('media-results-list');
    const statsSection = document.getElementById('media-stats-section');

    if (scanBtn) { scanBtn.disabled = true; scanBtn.textContent = '⏳ Đang phân tích...'; }
    if (progressEl) progressEl.style.display = 'block';
    if (resultsList) resultsList.innerHTML = '';
    if (statsSection) statsSection.style.display = 'none';

    mediaScanStats = { total: 0, safe: 0, warn: 0, danger: 0 };

    const total = mediaQueue.length;

    for (let i = 0; i < mediaQueue.length; i++) {
        const item = mediaQueue[i];
        if (progressText) progressText.textContent = `Đang xử lý ${i + 1}/${total}: ${item.file.name}`;

        // Hiệu ứng scanning trên thumbnail
        if (item.thumbEl) item.thumbEl.classList.add('scanning');

        let result = null;

        try {
            if (item.type === 'video') {
                // Với video: cắt 4 frame rồi scan lần lượt
                result = await scanVideoFile(item.file, item.file.name, progressText, i + 1, total);
            } else {
                // Ảnh: gửi dataUrl trực tiếp
                result = await scanSingleImage(item.dataUrl, item.file.name);
            }
        } catch (e) {
            result = { status: 'error', error: e.message, score: 0, threats: [] };
        }

        // Xong scanning → xóa hiệu ứng
        if (item.thumbEl) item.thumbEl.classList.remove('scanning');

        // Cập nhật thumbnail với badge kết quả
        if (item.thumbEl && result) {
            const badgeEl = item.thumbEl.querySelector('.media-thumb-badge');
            if (badgeEl) {
                const s = (result.status || '').toLowerCase();
                const riskIcon = s === 'malicious' ? '🔴' : s === 'suspicious' ? '🟡' : '🟢';
                badgeEl.textContent = `${riskIcon} ${result.score || 0}%`;
            }
        }

        // Render kết quả card
        renderMediaResult(item, result);

        // Cập nhật stats
        mediaScanStats.total++;
        const s = (result.status || '').toLowerCase();
        if (s === 'malicious') mediaScanStats.danger++;
        else if (s === 'suspicious') mediaScanStats.warn++;
        else mediaScanStats.safe++;
        updateMediaStatsUI();

        if (statsSection) statsSection.style.display = 'block';
    }

    if (progressEl) progressEl.style.display = 'none';
    if (scanBtn) { scanBtn.disabled = false; scanBtn.textContent = '🔍 Phân Tích AI (Gemini Vision)'; }
    mediaScanning = false;
}

// ── Scan một ảnh ──────────────────────────────────────────────
function scanSingleImage(dataUrl, fileName) {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Timeout 30s')), 30000);
        chrome.runtime.sendMessage(
            { action: 'scanMedia', mediaItem: { dataUrl, type: 'image', contextHint: fileName } },
            r => {
                clearTimeout(timeout);
                if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
                else resolve(r || { status: 'safe', score: 0, threats: [] });
            }
        );
    });
}

// ── Scan video: cắt frame → scan từng frame ──────────────────
async function scanVideoFile(file, fileName, progressEl, current, total) {
    const frames = await extractVideoFrames(file, 4);
    if (!frames.length) return { status: 'safe', score: 0, threats: [], summary: 'Không thể đọc video frame' };

    if (progressEl) progressEl.textContent = `Video ${current}/${total}: Đang scan ${frames.length} frame...`;

    const frameResults = [];
    for (let fi = 0; fi < frames.length; fi++) {
        try {
            const r = await scanSingleImage(frames[fi].dataUrl, `${fileName}#frame${fi + 1}`);
            frameResults.push(r);
        } catch (e) { /* skip */ }
    }

    if (!frameResults.length) return { status: 'safe', score: 0, threats: [], frames };

    // Lấy frame nguy hiểm nhất
    frameResults.sort((a, b) => (b.score || 0) - (a.score || 0));
    const worst = frameResults[0];
    return {
        ...worst,
        isVideo: true,
        frames: frames.map((f, i) => ({ dataUrl: f.dataUrl, result: frameResults[i] || {} })),
        frameCount: frames.length,
        summary: worst.summary || `Phân tích ${frames.length} frame video`
    };
}

// ── Extract frames từ video bằng Canvas API ──────────────────
function extractVideoFrames(file, count = 4) {
    return new Promise(resolve => {
        const video = document.createElement('video');
        const url = URL.createObjectURL(file);
        const frames = [];

        video.src = url;
        video.muted = true;
        video.preload = 'metadata';

        video.addEventListener('loadedmetadata', () => {
            const duration = video.duration || 1;
            const timestamps = [];
            for (let i = 0; i < count; i++) {
                timestamps.push((duration / (count + 1)) * (i + 1));
            }

            let idx = 0;
            const captureNext = () => {
                if (idx >= timestamps.length) {
                    URL.revokeObjectURL(url);
                    resolve(frames);
                    return;
                }
                video.currentTime = timestamps[idx];
            };

            video.addEventListener('seeked', () => {
                try {
                    const canvas = document.createElement('canvas');
                    canvas.width = Math.min(video.videoWidth, 480);
                    canvas.height = Math.min(video.videoHeight, 270);
                    const ctx = canvas.getContext('2d');
                    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
                    frames.push({ dataUrl: canvas.toDataURL('image/jpeg', 0.75), time: timestamps[idx] });
                } catch { /* skip */ }
                idx++;
                captureNext();
            });

            captureNext();
        });

        video.addEventListener('error', () => { URL.revokeObjectURL(url); resolve([]); });
        // Timeout safety
        setTimeout(() => { URL.revokeObjectURL(url); resolve(frames); }, 12000);
    });
}

// ── Render kết quả card ───────────────────────────────────────
function renderMediaResult(item, result) {
    const list = document.getElementById('media-results-list');
    if (!list) return;

    const s = (result.status || 'safe').toLowerCase();
    const score = result.score || 0;
    const isPhish = s === 'malicious';
    const isSusp = s === 'suspicious';

    const color = isPhish ? '#ef4444' : isSusp ? '#f59e0b' : '#22d3a0';
    const colorBg = isPhish ? 'rgba(239,68,68,.08)' : isSusp ? 'rgba(245,158,11,.08)' : 'rgba(34,211,160,.08)';
    const colorBd = isPhish ? 'rgba(239,68,68,.25)' : isSusp ? 'rgba(245,158,11,.25)' : 'rgba(34,211,160,.2)';
    const label = isPhish ? '⛔ NGUY HIỂM' : isSusp ? '⚠️ NGHI NGỜ' : '✅ AN TOÀN';

    const threats = (result.threats || []).slice(0, 6);
    const threatsHtml = threats.length
        ? threats.map(t => {
            const tc = t.severity === 'critical' ? '#ef4444' : t.severity === 'high' ? '#f59e0b' : t.severity === 'medium' ? '#60a5fa' : '#64748b';
            return `<div class="media-threat-row">
          <div class="media-threat-dot" style="background:${tc}"></div>
          <div class="media-threat-text">${escHtml(t.text || '')}</div>
          <div class="media-threat-score" style="color:${tc}">+${t.score || 0}</div>
        </div>`;
        }).join('')
        : `<div style="font-size:9px;color:rgba(255,255,255,.3);padding:4px 7px">Không phát hiện mối đe dọa</div>`;

    // QR code badge
    const qrHtml = result.qrCodeFound
        ? `<div class="qr-found-badge" style="background:${result.qrCodeUrl ? 'rgba(239,68,68,.12)' : 'rgba(34,211,160,.1)'};color:${result.qrCodeUrl ? '#f87171' : '#6ee7b7'};border:1px solid ${result.qrCodeUrl ? 'rgba(239,68,68,.25)' : 'rgba(34,211,160,.2)'}">
        📲 QR Code ${result.qrCodeUrl ? '→ ' + escHtml((result.qrCodeUrl || '').substring(0, 50)) : 'detected (safe)'}
      </div>`
        : '';

    // Đặc biệt: logo giả mạo, login page giả
    const flagsHtml = [
        result.logoFaked ? `<span style="font-size:8px;background:rgba(239,68,68,.1);color:#f87171;padding:1px 5px;border-radius:3px;border:1px solid rgba(239,68,68,.2)">🏷 Logo giả mạo</span>` : '',
        result.isFakeLoginPage ? `<span style="font-size:8px;background:rgba(239,68,68,.1);color:#f87171;padding:1px 5px;border-radius:3px;border:1px solid rgba(239,68,68,.2)">🔓 Trang login giả</span>` : '',
        result.hasDeepfake ? `<span style="font-size:8px;background:rgba(168,85,247,.1);color:#c084fc;padding:1px 5px;border-radius:3px;border:1px solid rgba(168,85,247,.2)">👤 Deepfake</span>` : '',
        result.hasSensitiveData ? `<span style="font-size:8px;background:rgba(245,158,11,.1);color:#fbbf24;padding:1px 5px;border-radius:3px;border:1px solid rgba(245,158,11,.2)">🔑 Dữ liệu nhạy cảm</span>` : '',
    ].filter(Boolean).join('');

    // Video frame strip
    let frameStripHtml = '';
    if (result.isVideo && result.frames && result.frames.length > 1) {
        frameStripHtml = `<div class="video-frame-strip">
      ${result.frames.map((f, i) => {
            const fs = ((f.result || {}).status || 'safe').toLowerCase();
            const fi = fs === 'malicious' ? '🔴' : fs === 'suspicious' ? '🟡' : '🟢';
            return `<div class="video-frame-item">
          <img src="${f.dataUrl || ''}">
          <div class="frame-label">${fi} f${i + 1}</div>
        </div>`;
        }).join('')}
    </div>`;
    }

    // Summary text
    const summaryHtml = result.summary
        ? `<div style="font-size:9px;color:rgba(255,255,255,.5);padding:4px 8px 6px;line-height:1.5;border-top:1px solid rgba(255,255,255,.05)">${escHtml(result.summary)}</div>`
        : '';

    const card = document.createElement('div');
    card.className = 'media-result-card';
    card.style.borderColor = colorBd;
    card.innerHTML = `
    <div class="media-result-header" style="background:${colorBg}">
      <div class="media-result-thumb">
        <img src="${item.dataUrl || ''}" alt="${escHtml(item.file.name)}">
      </div>
      <div class="media-result-info">
        <div class="media-result-name">${escHtml(item.file.name)}</div>
        <div class="media-result-meta">
          ${item.type === 'video' ? '🎬 Video' : '🖼 Image'} · ${formatBytes(item.file.size)}
          ${result.isVideo ? ` · ${result.frameCount || ''} frames` : ''}
        </div>
        ${qrHtml}
        ${flagsHtml ? `<div style="display:flex;gap:3px;flex-wrap:wrap;margin-top:4px">${flagsHtml}</div>` : ''}
      </div>
      <div style="text-align:right;flex-shrink:0">
        <div class="media-risk-badge" style="background:${colorBg};color:${color};border:1px solid ${colorBd}">${label}</div>
        <div style="font-size:18px;font-weight:800;font-family:monospace;color:${color};margin-top:4px;line-height:1">${score}%</div>
        <div style="font-size:7px;color:rgba(255,255,255,.3)">RISK</div>
      </div>
    </div>
    <div class="media-risk-bar-wrap">
      <div class="media-risk-bar" style="width:${score}%;background:${color}"></div>
    </div>
    ${frameStripHtml}
    <div class="media-threats-body">
      <div style="font-size:8px;font-weight:700;letter-spacing:1px;color:rgba(255,255,255,.25);text-transform:uppercase;margin-bottom:4px">PHÁT HIỆN (${threats.length})</div>
      ${threatsHtml}
    </div>
    ${summaryHtml}
  `;

    list.appendChild(card);
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ── Cập nhật stats bar ────────────────────────────────────────
function updateMediaStatsUI() {
    const el = id => document.getElementById(id);
    if (el('ms-total')) el('ms-total').textContent = mediaScanStats.total;
    if (el('ms-safe')) el('ms-safe').textContent = mediaScanStats.safe;
    if (el('ms-warn')) el('ms-warn').textContent = mediaScanStats.warn;
    if (el('ms-danger')) el('ms-danger').textContent = mediaScanStats.danger;
}

// ── Helpers ───────────────────────────────────────────────────
function readFileAsDataUrl(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = e => resolve(e.target.result);
        reader.onerror = () => reject(new Error('FileReader error'));
        reader.readAsDataURL(file);
    });
}

function getVideoThumbnail(file) {
    return new Promise((resolve, reject) => {
        const video = document.createElement('video');
        const url = URL.createObjectURL(file);
        video.src = url;
        video.muted = true;
        video.preload = 'metadata';
        video.addEventListener('loadeddata', () => {
            video.currentTime = 0.5;
        });
        video.addEventListener('seeked', () => {
            try {
                const c = document.createElement('canvas');
                c.width = 160; c.height = 90;
                c.getContext('2d').drawImage(video, 0, 0, 160, 90);
                URL.revokeObjectURL(url);
                resolve(c.toDataURL('image/jpeg', 0.7));
            } catch (e) { URL.revokeObjectURL(url); reject(e); }
        });
        video.addEventListener('error', () => { URL.revokeObjectURL(url); reject(new Error('Video load error')); });
        setTimeout(() => { URL.revokeObjectURL(url); reject(new Error('Thumbnail timeout')); }, 8000);
    });
}

function formatBytes(bytes) {
    if (!bytes) return '—';
    if (bytes < 1024) return bytes + 'B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(0) + 'KB';
    return (bytes / 1024 / 1024).toFixed(1) + 'MB';
}

// ═══════════════════════════════════════════════════════════════
// INIT — chạy sau khi DOM sẵn sàng
// ═══════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
    initSimulator();
    initChatbot();
    initMediaAnalyzer();

    // Map tab click handler — init map khi user bấm vào tab Map
    const nav = document.getElementById('nav');
    if (nav) {
        nav.addEventListener('click', e => {
            const btn = e.target.closest('[data-tab]');
            if (btn && btn.dataset.tab === 'map') {
                // Delay nhỏ để DOM render xong trước khi init Leaflet
                setTimeout(initThreatMap, 150);
            }
        });
    }
});
