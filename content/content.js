// PhishGuard Enterprise v7.0 — Gmail Content Script
// NEW v7: Hybrid score display · Quarantine badge · Performance bar · Enhanced panel
(function () {
  'use strict';

  let cache = new Map(), currentBody = null, deletedCount = 0;

  // ══════════ DANH MỤC EMAIL ══════════
  const CATEGORIES = [
    {
      id: 'bank', label: '🏦 Ngân hàng', color: '#3b82f6',
      bg: 'rgba(59,130,246,.12)', bd: 'rgba(59,130,246,.3)',
      patterns: [
        'vietcombank', 'techcombank', 'bidv', 'agribank', 'mbbank', 'tpbank', 'vpbank', 'hdbank',
        'sacombank', 'acb', 'ocb', 'seabank', 'vib', 'msb', 'hsbc', 'citibank', 'nam a bank',
        'ngân hàng', 'bank', 'banking', 'atm', 'tài khoản', 'số dư', 'giao dịch', 'chuyển khoản',
        'internet banking', 'mobile banking', 'credit card', 'debit card', 'thẻ tín dụng',
        'vay vốn', 'lãi suất', 'tiết kiệm'
      ]
    },
    {
      id: 'social', label: '📱 Mạng xã hội', color: '#8b5cf6',
      bg: 'rgba(139,92,246,.12)', bd: 'rgba(139,92,246,.3)',
      patterns: [
        'facebook', 'instagram', 'tiktok', 'twitter', 'youtube', 'zalo', 'telegram', 'discord',
        'linkedin', 'pinterest', 'snapchat', 'threads', 'reddit', 'messenger', 'whatsapp',
        'người dùng đã đăng', 'đã theo dõi bạn', 'bình luận mới', 'like', 'share', 'follow',
        'kết bạn', 'friend request', 'mention', 'tagged you'
      ]
    },
    {
      id: 'shopping', label: '🛍 Mua sắm', color: '#f59e0b',
      bg: 'rgba(245,158,11,.12)', bd: 'rgba(245,158,11,.3)',
      patterns: [
        'shopee', 'lazada', 'tiki', 'sendo', 'amazon', 'alibaba', 'grab', 'gojek', 'foodpanda',
        'baemin', 'momo', 'zalopay', 'vnpay', 'đơn hàng', 'order', 'vận chuyển', 'giao hàng',
        'shipping', 'delivery', 'tracking', 'hoàn tiền', 'refund', 'khuyến mãi', 'voucher',
        'flash sale', 'giảm giá', 'mã giảm', 'coupon'
      ]
    },
    {
      id: 'work', label: '💼 Công việc', color: '#10b981',
      bg: 'rgba(16,185,129,.12)', bd: 'rgba(16,185,129,.3)',
      patterns: [
        'google workspace', 'microsoft', 'outlook', 'teams', 'zoom', 'slack', 'notion',
        'jira', 'github', 'gitlab', 'hr', 'human resources', 'payroll', 'hợp đồng',
        'invoice', 'hóa đơn', 'công ty', 'doanh nghiệp', 'tuyển dụng', 'recruitment',
        'meeting', 'cuộc họp', 'deadline', 'dự án', 'project'
      ]
    },
    {
      id: 'gov', label: '🏛 Chính phủ', color: '#ef4444',
      bg: 'rgba(239,68,68,.1)', bd: 'rgba(239,68,68,.25)',

      patterns: [
        'gov.vn', 'chinhphu.vn', 'thuế', 'tax', 'hải quan', 'customs', 'công an', 'police',
        'bảo hiểm xã hội', 'bhxh', 'bảo hiểm y tế', 'bhyt', 'sở tư pháp', 'ubnd', 'bộ ',
        'cục thuế', 'tổng cục'
      ]
    },
    {
      id: 'telecom', label: '📡 Viễn thông', color: '#06b6d4',
      bg: 'rgba(6,182,212,.12)', bd: 'rgba(6,182,212,.3)',
      patterns: [
        'viettel', 'mobifone', 'vinaphone', 'vietnamobile', 'gmobile', 'vnpt', 'fpt',
        'data', '3g', '4g', '5g', 'gói cước', 'gia hạn', 'sim', 'thuê bao'
      ]
    },
    {
      id: 'security', label: '⚠️ Bảo mật', color: '#ef4444',
      bg: 'rgba(239,68,68,.15)', bd: 'rgba(239,68,68,.4)',
      priority: true,
      patterns: [
        'mật khẩu', 'password', 'otp', 'pin', 'xác minh', 'verify', 'đăng nhập', 'login',
        'tài khoản bị', 'account locked', 'security alert', 'cảnh báo bảo mật', 'suspicious'
      ]
    }
  ];

  function detectCategory(d) {
    if (!d) return null;
    const txt = `${d.sender || ''} ${d.subject || ''} ${d.body || ''}`.toLowerCase();
    const priority = CATEGORIES.filter(c => c.priority).find(c => c.patterns.some(p => txt.includes(p)));
    if (priority) return priority;
    return CATEGORIES.filter(c => !c.priority).find(c => c.patterns.some(p => txt.includes(p))) || null;
  }

  // ══════════ BOOT ══════════
  waitFor('[role="main"]', () => {
    injectBar();
    watchInbox();
    watchView();
    setTimeout(scanAll, 1800);
  });

  // ══════════ TOOLBAR ══════════
  function injectBar() {
    if (document.getElementById('pg-bar')) return;
    const bar = document.createElement('div');
    bar.id = 'pg-bar';
    bar.innerHTML = `
      <div class="pg-logo"><div class="pg-logo-icon">🛡</div>PhishGuard <span style="font-size:8px;color:rgba(255,255,255,.3);font-weight:400">v7</span></div>
      <div class="pg-sep"></div>
      <div class="pg-chip chip-ok"><span class="pg-dot-live"></span>HYBRID AI</div>
      <div class="pg-chip chip-stat">Quét: <span id="pg-nt">0</span></div>
      <div class="pg-chip chip-danger">Nguy: <span id="pg-nd">0</span></div>
      <div class="pg-chip" style="background:rgba(168,85,247,.08);color:#c084fc;border:1px solid rgba(168,85,247,.2)" id="pg-chip-quar" style="display:none">🔒 <span id="pg-nquar">0</span></div>
      <div class="pg-chip chip-del" id="pg-chip-del" style="display:none">🗑 <span id="pg-ndd">0</span></div>
      <div class="pg-sp"></div>
      <div id="pg-analysis-bar" style="width:60px;height:4px;background:rgba(255,255,255,.06);border-radius:2px;overflow:hidden;margin-right:6px;display:none">
        <div id="pg-analysis-prog" style="height:100%;background:linear-gradient(90deg,#3b82f6,#60a5fa);border-radius:2px;width:0%;transition:width .3s"></div>
      </div>
      <button class="pg-tb-btn" style="background:rgba(239,68,68,.1);color:#f87171;border-color:rgba(239,68,68,.25)" id="pg-btn-del-all">🗑 Xóa Nguy Hiểm</button>
      <button class="pg-tb-btn" id="pg-btn-hist">📋 Lịch sử</button>
      <button class="pg-tb-btn hi" id="pg-btn-scan">⚡ Quét tất cả</button>
    `;
    document.body.insertBefore(bar, document.body.firstChild);
    document.body.style.marginTop = '40px';
    document.getElementById('pg-btn-hist').addEventListener('click', showHistoryPanel);
    document.getElementById('pg-btn-scan').addEventListener('click', handleScanAll);
    document.getElementById('pg-btn-del-all').addEventListener('click', handleDeleteAllDangerous);
    refreshBar();
  }

  async function handleScanAll() {
    const btn = document.getElementById('pg-btn-scan');
    if (btn) { btn.textContent = '⏳ Đang quét...'; btn.disabled = true; }

    // Show progress bar
    const progBar = document.getElementById('pg-analysis-bar');
    const progFill = document.getElementById('pg-analysis-prog');
    if (progBar) progBar.style.display = 'block';

    cache.clear();
    const allRows = rows();
    allRows.forEach(r => {
      delete r.dataset.pgDone;
      r.querySelectorAll('.pg-badge, .pg-cat-label').forEach(b => b.remove());
    });

    let scanned = 0;
    for (const r of allRows) {
      await scanRow(r);
      await wait(80);
      scanned++;
      const pct = Math.round(scanned / allRows.length * 100);
      if (progFill) progFill.style.width = pct + '%';
    }

    if (progBar) setTimeout(() => { progBar.style.display = 'none'; if (progFill) progFill.style.width = '0%'; }, 1500);
    if (btn) { btn.textContent = '✓ Xong'; btn.disabled = false; setTimeout(() => { btn.textContent = '⚡ Quét tất cả'; }, 2500); }
    refreshBar();
  }

  function refreshBar() {
    send('getStats', {}, s => {
      if (!s) return;
      setText('pg-nt', s.total || 0);
      setText('pg-nd', (s.phishing || 0) + (s.suspicious || 0));
    });
    send('getQuarantine', {}, q => {
      const count = q?.length || 0;
      const chip = document.getElementById('pg-chip-quar');
      if (chip) chip.style.display = count > 0 ? '' : 'none';
      setText('pg-nquar', count);
    });
  }

  // ══════════ XÓA EMAIL — THỰC SỰ ══════════
  // Cách hoạt động:
  // 1. Hover vào row → Gmail render action bar (nút Xóa, Archive...)
  // 2. Tìm nút Xóa trong action bar → click
  // 3. Nếu không tìm thấy → ẩn visual và ghi nhận
  async function realGmailDelete(row) {
    // Trigger hover để Gmail hiện action buttons
    row.dispatchEvent(new MouseEvent('mouseover', { bubbles: true, cancelable: true }));
    row.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true, cancelable: true }));
    await wait(200);

    // Danh sách selector cho nút Delete của Gmail (nhiều phiên bản)
    const selectors = [
      // Data tooltip (tiếng Việt & tiếng Anh)
      '[data-tooltip="Xóa"]',
      '[data-tooltip="Delete"]',
      '[data-tooltip="Xóa vĩnh viễn"]',
      '[data-tooltip="Move to Trash"]',
      // ARIA labels
      '[aria-label="Delete"]',
      '[aria-label="Xóa"]',
      // Gmail internal action codes
      '[act="13"]',
      '.T-I[act="13"]',
      // Gmail class patterns cho delete button trong list view
      'li[role="option"][data-tooltip*="óa"]',
      'li[role="option"][data-tooltip*="elet"]',
    ];

    // Tìm trong row trước
    for (const sel of selectors) {
      const btn = row.querySelector(sel);
      if (btn) { btn.click(); return true; }
    }

    // Tìm toàn document (action bar có thể render ngoài row)
    for (const sel of selectors) {
      const btn = document.querySelector(sel);
      if (btn && isVisible(btn)) { btn.click(); return true; }
    }

    // Fallback: tìm bất kỳ button có text/tooltip chứa từ khóa xóa
    const allButtons = [...row.querySelectorAll('[role="button"], .T-I, li')];
    for (const btn of allButtons) {
      const tip = (btn.getAttribute('data-tooltip') || btn.getAttribute('aria-label') || btn.title || '').toLowerCase();
      if ((tip.includes('xóa') || tip.includes('delete') || tip.includes('trash')) && isVisible(btn)) {
        btn.click();
        return true;
      }
    }

    return false;
  }

  function isVisible(el) {
    return !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  }

  async function deleteEmailRow(row) {
    try {
      const deleted = await realGmailDelete(row);
      row.dataset.pgDeleted = '1';

      if (deleted) {
        // Gmail sẽ tự remove row, thêm animation mượt
        row.style.transition = 'opacity 0.3s, transform 0.3s';
        row.style.opacity = '0.3';
        await wait(600);
        if (document.contains(row)) {
          row.style.opacity = '0';
          row.style.transform = 'translateX(20px)';
          await wait(300);
          row.style.display = 'none';
        }
      } else {
        // Visual hide fallback
        row.style.transition = 'opacity 0.4s, transform 0.4s';
        row.style.opacity = '0';
        row.style.transform = 'translateX(20px)';
        await wait(400);
        row.style.display = 'none';
      }

      const d = rowData(row);
      if (d) send('markDeleted', { emailData: d }, () => { });
      return true;
    } catch { return false; }
  }

  async function handleDeleteAllDangerous() {
    const btn = document.getElementById('pg-btn-del-all');
    const dangerRows = rows().filter(r => {
      if (!r.dataset.pgRes) return false;
      try { return JSON.parse(r.dataset.pgRes).riskLevel === 'PHISHING'; } catch { return false; }
    });

    if (!dangerRows.length) { toast('✓ Không có email PHISHING nào để xóa'); return; }

    if (!confirm(`⚠️ Xóa ${dangerRows.length} email PHISHING vào Thùng rác?`)) return;

    btn.textContent = `⏳ 0/${dangerRows.length}`;
    btn.disabled = true;

    let cnt = 0;
    for (const row of dangerRows) {
      const ok = await deleteEmailRow(row);
      if (ok) {
        cnt++; deletedCount++;
        btn.textContent = `⏳ ${cnt}/${dangerRows.length}`;
        updateDelChip();
      }
      await wait(400); // Đợi Gmail xử lý xong mỗi email
    }

    btn.textContent = `✓ Đã xóa ${cnt}`;
    btn.disabled = false;
    setTimeout(() => { btn.textContent = '🗑 Xóa Nguy Hiểm'; }, 3000);
    toast(`🗑 Đã xóa ${cnt}/${dangerRows.length} email phishing`);
    refreshBar();
  }

  function updateDelChip() {
    const chip = document.getElementById('pg-chip-del');
    const ndd = document.getElementById('pg-ndd');
    if (chip) chip.style.display = '';
    if (ndd) ndd.textContent = deletedCount;
  }

  async function deleteSingleEmail(row, result, emailData) {
    if (!confirm(`⚠️ Xóa email này?\n\nTừ: ${emailData?.sender || 'Unknown'}\nTiêu đề: ${emailData?.subject || 'No subject'}\nRủi ro: ${result?.riskPercent}%`)) return;
    const ok = await deleteEmailRow(row);
    if (ok) {
      deletedCount++;
      updateDelChip();
      toast('🗑 Email đã được xóa vào Thùng rác');
      document.getElementById('pg-panel')?.remove();
    } else {
      toast('⚠️ Không thể tự xóa — hãy xóa thủ công', 'warn');
    }
  }

  // ══════════ INBOX WATCH ══════════
  function watchInbox() {
    new MutationObserver(deb(scanNewRows, 700))
      .observe(document.querySelector('[role="main"]') || document.body, { childList: true, subtree: true });
  }

  function rows() {
    return [...document.querySelectorAll('tr.zA, tr[data-legacy-thread-id]')]
      .filter(r => r.closest('[role="main"]') && !r.dataset.pgDeleted);
  }

  async function scanAll() {
    for (const r of rows().filter(r => !r.dataset.pgDone)) {
      await scanRow(r); await wait(80);
    }
  }

  function scanNewRows() {
    rows().filter(r => !r.dataset.pgDone).forEach(r => scanRow(r));
  }

  async function scanRow(row) {
    if (row.dataset.pgDone) return;
    row.dataset.pgDone = '1';
    const d = rowData(row);
    if (!d) return;

    setBadge(row, 'scanning', '···');

    // Gắn nhãn danh mục ngay lập tức (không cần chờ AI)
    const cat = detectCategory(d);
    if (cat) setCategoryLabel(row, cat);

    const key = `${d.sender}|${d.subject}`;
    let result = cache.get(key);
    if (!result) {
      result = await sendAsync('analyzeEmail', { data: d });
      if (result) cache.set(key, result);
    }
    if (!result) return;

    row.dataset.pgRes = JSON.stringify(result);
    applyRowResult(row, result, d);

    // ── PROACTIVE URL SCAN: quét links ngay từ inbox row ──
    if (d.links && d.links.length > 0) {
      scanRowUrls(row, d, result);
    }

    refreshBar();
  }

  function applyRowResult(row, result, d) {
    const rl = result.riskLevel;
    const hasCred = result.threats?.some(t => t.type === 'credential' || t.type === 'financial');
    let cls, lbl;
    if (rl === 'PHISHING') { cls = 'phishing'; lbl = '⛔ PHISHING'; }
    else if (hasCred && rl === 'SUSPICIOUS') { cls = 'credential'; lbl = '🔑 MẬT KHẨU'; }
    else if (rl === 'SUSPICIOUS') { cls = 'suspicious'; lbl = '⚠️ WARN'; }
    else { cls = 'safe'; lbl = '✓ SAFE'; }

    setBadge(row, cls, lbl, result, d);
    const catLabel = row.querySelector('.pg-cat-label');
    if (catLabel) {
      catLabel.style.cursor = 'pointer';
      catLabel.addEventListener('click', e => { e.stopPropagation(); e.preventDefault(); showPanel(result, d, row); });
    }
    row.classList.remove('pg-row-phishing', 'pg-row-suspicious', 'pg-row-credential');
    if (rl === 'PHISHING') row.classList.add('pg-row-phishing');
    else if (hasCred) row.classList.add('pg-row-credential');
    else if (rl === 'SUSPICIOUS') row.classList.add('pg-row-suspicious');

    // ── Gắn click guard cho email nguy hiểm ──
    if (rl === 'PHISHING' || rl === 'SUSPICIOUS') {
      attachClickGuard(row, result, d);
    }
  }

  // ── Click guard: chặn click vào email nguy hiểm, hiện cảnh báo ──
  function attachClickGuard(row, result, emailData) {
    if (row.dataset.pgGuard) return; // Đã gắn rồi thì bỏ qua
    row.dataset.pgGuard = '1';

    row.addEventListener('click', function handleRowClick(e) {
      // Nếu user đã xác nhận trước đó → cho qua
      if (row.dataset.pgAllowed) return;

      const badgeTarget = e.target.closest('.pg-badge, .pg-cat-label, .pg-url-badge');
      if (badgeTarget) {
        e.stopImmediatePropagation();
        e.preventDefault();
        showPanel(result, emailData, row);
        return;
      }

      // Ngăn Gmail mở email
      e.stopImmediatePropagation();
      e.preventDefault();

      // Hiện dialog cảnh báo
      showClickWarning(result, emailData, row, () => {
        // Callback "Vẫn xem": đánh dấu và trigger click thật
        row.dataset.pgAllowed = '1';
        // Simulate native click để Gmail mở email
        const clone = new MouseEvent('click', { bubbles: true, cancelable: true });
        row.dispatchEvent(clone);
        // Reset sau 3 giây để cảnh báo lại nếu user quay lại
        setTimeout(() => { delete row.dataset.pgAllowed; }, 3000);
      });
    }, true); // capture phase để chặn trước Gmail
  }

  // ── Dialog cảnh báo khi click email nguy hiểm ──
  function showClickWarning(result, emailData, row, onProceed) {
    document.querySelectorAll('.pg-click-warn').forEach(d => d.remove());

    const rl = result.riskLevel;
    const isPhishing = rl === 'PHISHING';
    const hasCred = result.threats?.some(t => t.type === 'credential' || t.type === 'financial');

    const color = isPhishing ? '#ef4444' : hasCred ? '#a855f7' : '#f59e0b';
    const colorBg = isPhishing ? 'rgba(239,68,68,.08)' : hasCred ? 'rgba(168,85,247,.08)' : 'rgba(245,158,11,.08)';
    const colorBd = isPhishing ? 'rgba(239,68,68,.3)' : hasCred ? 'rgba(168,85,247,.3)' : 'rgba(245,158,11,.3)';
    const icon = isPhishing ? '⛔' : hasCred ? '🔑' : '⚠️';
    const title = isPhishing ? 'PHÁT HIỆN EMAIL PHISHING!' : hasCred ? 'EMAIL YÊU CẦU THÔNG TIN NHẠY CẢM!' : 'EMAIL ĐÁNG NGỜ!';
    const riskPct = result.riskPercent || result.score || 0;
    const topThreats = (result.threats || []).slice(0, 3);

    const overlay = document.createElement('div');
    overlay.className = 'pg-click-warn';
    overlay.style.cssText = `
      position:fixed;inset:0;z-index:9999998;
      background:rgba(0,0,0,.55);backdrop-filter:blur(3px);
      display:flex;align-items:center;justify-content:center;
      animation:pgFadeIn .18s ease;
    `;

    const dialog = document.createElement('div');
    dialog.style.cssText = `
      background:#0d0f17;border:1px solid ${colorBd};border-radius:14px;
      width:430px;max-width:calc(100vw - 40px);
      box-shadow:0 24px 80px rgba(0,0,0,.7),0 0 0 1px rgba(255,255,255,.05);
      overflow:hidden;animation:pgSlideUp .22s cubic-bezier(.16,1,.3,1);
      font-family:'Inter','IBM Plex Sans',system-ui,sans-serif;
    `;

    dialog.innerHTML = `
      <!-- Header -->
      <div style="padding:18px 20px 14px;background:${colorBg};border-bottom:1px solid ${colorBd}">
        <div style="display:flex;align-items:flex-start;gap:12px">
          <div style="font-size:28px;line-height:1;flex-shrink:0;margin-top:2px">${icon}</div>
          <div style="flex:1">
            <div style="font-size:13px;font-weight:800;color:${color};letter-spacing:.3px;margin-bottom:4px">${title}</div>
            <div style="font-size:11px;color:rgba(255,255,255,.55);line-height:1.5">
              PhishGuard đã phát hiện ${isPhishing ? 'dấu hiệu lừa đảo' : 'nội dung đáng ngờ'} trong email này.
            </div>
          </div>
          <div style="font-family:'JetBrains Mono','IBM Plex Mono',monospace;font-size:22px;font-weight:800;color:${color};flex-shrink:0">${riskPct}%</div>
        </div>
      </div>

      <!-- Email info -->
      <div style="padding:14px 20px;border-bottom:1px solid rgba(255,255,255,.07)">
        <div style="display:flex;gap:8px;margin-bottom:8px;align-items:flex-start">
          <span style="font-size:9px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;color:rgba(255,255,255,.3);width:56px;flex-shrink:0;padding-top:1px">Gửi từ</span>
          <span style="font-size:11px;color:rgba(255,255,255,.8);font-family:'JetBrains Mono','IBM Plex Mono',monospace;word-break:break-all">${esc(emailData?.sender?.substring(0, 80) || 'Unknown')}</span>
        </div>
        <div style="display:flex;gap:8px;align-items:flex-start">
          <span style="font-size:9px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;color:rgba(255,255,255,.3);width:56px;flex-shrink:0;padding-top:1px">Tiêu đề</span>
          <span style="font-size:11px;color:rgba(255,255,255,.8)">${esc(emailData?.subject?.substring(0, 80) || 'No subject')}</span>
        </div>
      </div>

      <!-- Threat list -->
      ${topThreats.length ? `
      <div style="padding:12px 20px;border-bottom:1px solid rgba(255,255,255,.07)">
        <div style="font-size:9px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:rgba(255,255,255,.25);margin-bottom:7px">Mối Đe Dọa Phát Hiện</div>
        ${topThreats.map(t => {
      const tColor = t.severity === 'critical' ? '#ef4444' : t.severity === 'high' ? '#f59e0b' : '#94a3b8';
      const tIcon = t.severity === 'critical' ? '🔴' : t.severity === 'high' ? '🟡' : '⚪';
      return `<div style="display:flex;gap:8px;align-items:flex-start;margin-bottom:5px;padding:6px 9px;background:rgba(255,255,255,.03);border-radius:6px;border-left:2px solid ${tColor}22">
            <span style="font-size:10px;flex-shrink:0">${tIcon}</span>
            <span style="font-size:10px;color:rgba(255,255,255,.6);line-height:1.4">${esc((t.text || t.description || '').substring(0, 90))}</span>
          </div>`;
    }).join('')}
      </div>` : ''}

      <!-- Buttons -->
      <div style="padding:14px 20px;display:flex;gap:8px;flex-wrap:wrap">
        <button id="pg-warn-close" style="
          flex:1;min-width:100px;padding:10px 12px;border-radius:8px;
          background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);
          color:rgba(255,255,255,.7);font-family:'Inter',sans-serif;font-size:12px;font-weight:600;
          cursor:pointer;transition:all .15s;letter-spacing:.2px;
        ">✕ Đóng</button>
        <button id="pg-warn-reply" style="
          flex:1;min-width:120px;padding:10px 12px;border-radius:8px;
          background:rgba(59,130,246,.12);border:1px solid rgba(59,130,246,.32);
          color:#93c5fd;font-family:'Inter',sans-serif;font-size:12px;font-weight:700;
          cursor:pointer;transition:all .15s;letter-spacing:.2px;
          display:flex;align-items:center;justify-content:center;gap:5px;
        ">📩 Gợi ý trả lời</button>
        <button id="pg-warn-proceed" style="
          flex:1;min-width:100px;padding:10px 12px;border-radius:8px;
          background:${colorBg};border:1px solid ${colorBd};
          color:${color};font-family:'Inter',sans-serif;font-size:12px;font-weight:700;
          cursor:pointer;transition:all .15s;letter-spacing:.2px;
        ">⚠️ Vẫn xem</button>
      </div>

      <!-- Footer note -->
      <div style="padding:0 20px 14px;font-size:9px;color:rgba(255,255,255,.2);text-align:center;line-height:1.5">
        PhishGuard Enterprise · Phân tích bởi Gemini AI + 15 heuristics
      </div>
    `;

    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

    if (!document.getElementById('pg-warn-style')) {
      const st = document.createElement('style');
      st.id = 'pg-warn-style';
      st.textContent = `
        @keyframes pgFadeIn{from{opacity:0}to{opacity:1}}
        @keyframes pgSlideUp{from{opacity:0;transform:translateY(16px) scale(.97)}to{opacity:1;transform:translateY(0) scale(1)}}
        @keyframes pgShake{0%,100%{transform:translateX(0)}20%,60%{transform:translateX(-5px)}40%,80%{transform:translateX(5px)}}
        @keyframes pgCountdown{from{width:100%}to{width:0%}}
        #pg-warn-close:hover{background:rgba(255,255,255,.1)!important;color:rgba(255,255,255,.9)!important}
        #pg-warn-proceed:hover{filter:brightness(1.2);transform:translateY(-1px)}
        #pg-warn-reply:hover{background:rgba(59,130,246,.22)!important;border-color:rgba(59,130,246,.5)!important;transform:translateY(-1px)}
        .pg-reply-textarea:focus{outline:none;border-color:rgba(96,165,250,.5)!important;box-shadow:0 0 0 3px rgba(96,165,250,.08)}
        @keyframes pgSpinR{to{transform:rotate(360deg)}}
      `;
      document.head.appendChild(st);
    }

    const close = () => {
      overlay.style.opacity = '0';
      overlay.style.transition = 'opacity .15s';
      setTimeout(() => overlay.remove(), 150);
    };

    document.getElementById('pg-warn-close').addEventListener('click', close);

    document.getElementById('pg-warn-reply').addEventListener('click', () => {
      close();
      // Hiện modal soạn thảo reply với AI
      setTimeout(() => showReplyModal(result, emailData), 180);
    });

    document.getElementById('pg-warn-proceed').addEventListener('click', () => {
      // ── Bước 1: đóng dialog cảnh báo lớn
      close();
      // ── Bước 2: hiện dialog xác nhận lần 2 (second confirmation)
      setTimeout(() => showSecondConfirm(result, emailData, onProceed), 150);
    });

    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
    const escHandler = e => { if (e.key === 'Escape') { close(); document.removeEventListener('keydown', escHandler); } };
    document.addEventListener('keydown', escHandler);
  }

  // ══════════════════════════════════════════════════════════════
  // XÁC NHẬN LẦN 2 — PREMIUM Security Gate v2
  // • SVG countdown ring animation
  // • Hiển thị đầy đủ threat breakdown + API sources
  // • Checkbox consent form bắt buộc check trước
  // • PHISHING: gõ "XÁC NHẬN" (text highlighted realtime)
  // • Log bypass attempt vào background
  // ══════════════════════════════════════════════════════════════
  function showSecondConfirm(result, emailData, onConfirmed) {
    document.querySelectorAll('.pg-second-confirm').forEach(d => d.remove());

    const isPhishing = result.riskLevel === 'PHISHING';
    const riskPct = result.riskPercent || result.score || 0;
    const threats = (result.threats || []).slice(0, 4);
    const COUNTDOWN = isPhishing ? 6 : 4;

    // ── Màu theo mức độ ──────────────────────────────────────────
    const C = isPhishing ? '#ef4444' : '#f59e0b';
    const CB = isPhishing ? 'rgba(239,68,68,' : 'rgba(245,158,11,';
    const RING_STROKE = isPhishing ? '#ef4444' : '#f59e0b';

    // ── API sources từ threats ───────────────────────────────────
    const apiSources = [...new Set(
      threats.map(t => {
        const txt = (t.text || '').toLowerCase();
        if (txt.includes('urlhaus')) return '🔴 URLHaus';
        if (txt.includes('abuseipdb')) return '🟠 AbuseIPDB';
        if (txt.includes('ipquality')) return '🟡 IPQualityScore';
        if (txt.includes('virustotal') || txt.includes('vt')) return '🦠 VirusTotal';
        if (txt.includes('safe brows')) return '🔍 Safe Browsing';
        if (txt.includes('gemini')) return '✦ Gemini AI';
        return null;
      }).filter(Boolean)
    )];
    if (!apiSources.length) apiSources.push(result.source === 'gemini-ai' ? '✦ Gemini AI' : '📌 Local Engine');

    // ── Checkbox thoả thuận ──────────────────────────────────────
    const CHECKBOXES = isPhishing ? [
      'Tôi hiểu email này có thể là lừa đảo (${riskPct}% nguy cơ)',
      'Tôi sẽ KHÔNG cung cấp mật khẩu, OTP hoặc thông tin cá nhân',
      'Tôi chịu hoàn toàn trách nhiệm nếu tiếp tục'
    ] : [
      'Tôi đã đọc cảnh báo và hiểu nội dung email đáng ngờ',
      'Tôi sẽ không nhấp vào link hoặc tải tệp đính kèm'
    ];

    // ── Overlay + box ─────────────────────────────────────────────
    const overlay = document.createElement('div');
    overlay.className = 'pg-second-confirm';
    overlay.style.cssText = `
      position:fixed;inset:0;z-index:9999999;
      background:rgba(0,0,0,.82);backdrop-filter:blur(8px) saturate(0.4);
      display:flex;align-items:center;justify-content:center;
      animation:pgFadeIn .18s ease;
    `;
    const box = document.createElement('div');
    // ── SVG ring circumference ─────────────────────────────────────
    const R = 38, CIRC = +(2 * Math.PI * R).toFixed(2);

    box.id = 'pg-sc-box';
    box.style.cssText = `
      background:linear-gradient(160deg,#0e1018 0%,#0a0c12 100%);
      border:1.5px solid ${CB}.5)};border-radius:18px;
      width:420px;max-width:calc(100vw - 32px);
      box-shadow:0 0 80px ${CB}.18)},0 0 0 1px rgba(255,255,255,.04),0 32px 100px rgba(0,0,0,.9);
      overflow:hidden;font-family:'Inter','IBM Plex Sans',system-ui,sans-serif;
      animation:pgSlideUp .25s cubic-bezier(.16,1,.3,1);
    `;

    box.innerHTML = `
      <!-- ══ DANGER STRIP ══ -->
      <div style="
        background:linear-gradient(90deg,${CB}.18)} 0%,${CB}.06)} 100%);
        border-bottom:1px solid ${CB}.22)};padding:18px 20px 16px;
        display:flex;align-items:center;gap:16px;position:relative;overflow:hidden;
      ">
        <div style="position:absolute;inset:0;pointer-events:none;
          background:radial-gradient(ellipse at 10% 50%,${CB}.14)} 0%,transparent 60%);
          animation:pgPulseGlow 2.4s ease infinite;"></div>

        <!-- SVG ring -->
        <div style="position:relative;flex-shrink:0;width:84px;height:84px">
          <svg width="84" height="84" viewBox="0 0 84 84" style="transform:rotate(-90deg)">
            <circle cx="42" cy="42" r="${R}" fill="none" stroke="${CB}.12)}" stroke-width="5"/>
            <circle id="pg-sc-ring" cx="42" cy="42" r="${R}" fill="none"
              stroke="${C}" stroke-width="5" stroke-linecap="round"
              stroke-dasharray="${CIRC}" stroke-dashoffset="0"
              style="transition:stroke-dashoffset 1s linear;filter:drop-shadow(0 0 6px ${C})"/>
          </svg>
          <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:1px">
            <div id="pg-sc-cnum" style="font-size:${isPhishing ? '20' : '24'}px;font-weight:900;color:${C};font-family:monospace;line-height:1">
              ${isPhishing ? '☠' : COUNTDOWN}
            </div>
            <div style="font-size:8px;color:rgba(255,255,255,.3);letter-spacing:.3px">${isPhishing ? 'HIGH' : 'giây'}</div>
          </div>
        </div>

        <!-- Title -->
        <div style="flex:1;min-width:0">
          <div style="display:inline-flex;align-items:center;gap:4px;
            background:${CB}.12)};border:1px solid ${CB}.28)};
            border-radius:4px;padding:2px 8px;margin-bottom:7px;">
            <span style="font-size:8px;font-weight:800;color:${C};letter-spacing:1px;text-transform:uppercase">
              ${isPhishing ? '⛔ PHISHING CONFIRMED' : '⚠ SECURITY WARNING'}
            </span>
          </div>
          <div style="font-size:13px;font-weight:800;color:rgba(255,255,255,.95);line-height:1.3;margin-bottom:5px">
            ${isPhishing ? 'Bạn sắp mở email lừa đảo!' : 'Xác nhận truy cập email đáng ngờ'}
          </div>
          <div style="display:flex;align-items:baseline;gap:5px">
            <span style="font-size:26px;font-weight:900;color:${C};font-family:monospace;line-height:1">${riskPct}%</span>
            <span style="font-size:9px;color:rgba(255,255,255,.32)">độ nguy hiểm xác nhận</span>
          </div>
        </div>
      </div>

      <!-- ══ DETECTED BY ══ -->
      <div style="padding:11px 20px;border-bottom:1px solid rgba(255,255,255,.07)">
        <div style="font-size:8px;font-weight:700;letter-spacing:1px;color:rgba(255,255,255,.22);text-transform:uppercase;margin-bottom:6px">Phát hiện bởi</div>
        <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:${threats.length ? '9px' : '0'}">
          ${apiSources.map(s => `<span style="
            padding:3px 9px;border-radius:4px;font-size:9.5px;font-weight:700;letter-spacing:.2px;
            background:${CB}.1)};border:1px solid ${CB}.25)};color:${C};">${s}</span>`).join('')}
        </div>
        ${threats.length ? `<div style="display:flex;flex-direction:column;gap:4px">
          ${threats.map(t => {
      const sv = t.severity === 'critical' ? '#ef4444' : t.severity === 'high' ? '#f59e0b' : '#64748b';
      const ic = t.severity === 'critical' ? '🔴' : t.severity === 'high' ? '🟡' : '⚪';
      return `<div style="display:flex;gap:7px;align-items:flex-start;padding:5px 9px;
              border-radius:6px;background:rgba(255,255,255,.03);border-left:2px solid ${sv}55;">
              <span style="font-size:9px;flex-shrink:0;margin-top:1px">${ic}</span>
              <span style="font-size:9.5px;color:rgba(255,255,255,.55);line-height:1.45">
                ${esc((t.text || '').substring(0, 88))}</span>
            </div>`;
    }).join('')}
        </div>` : ''}
      </div>

      <!-- ══ CONSENT ══ -->
      <div style="padding:11px 20px;border-bottom:1px solid rgba(255,255,255,.07)">
        <div style="font-size:8px;font-weight:700;letter-spacing:1px;color:rgba(255,255,255,.22);text-transform:uppercase;margin-bottom:7px">Tôi xác nhận</div>
        ${CHECKBOXES.map((lbl, i) => `
          <label id="pg-sc-lbl-${i}" style="display:flex;align-items:flex-start;gap:10px;
            margin-bottom:6px;cursor:pointer;padding:5px 7px;border-radius:7px;
            border:1px solid transparent;transition:all .15s;user-select:none;">
            <div id="pg-sc-cbw-${i}" style="width:16px;height:16px;border-radius:4px;flex-shrink:0;
              border:1.5px solid rgba(255,255,255,.18);background:rgba(255,255,255,.04);
              margin-top:1px;display:flex;align-items:center;justify-content:center;transition:all .2s;">
              <span id="pg-sc-tick-${i}" style="font-size:10px;color:#22d3a0;display:none">✓</span>
            </div>
            <span style="font-size:9.5px;color:rgba(255,255,255,.48);line-height:1.5">
              ${lbl.replace('${riskPct}', riskPct)}
            </span>
          </label>`).join('')}
      </div>

      <!-- ══ TEXT INPUT (PHISHING) ══ -->
      ${isPhishing ? `
        <div style="padding:10px 20px;border-bottom:1px solid rgba(255,255,255,.07)">
          <div style="font-size:8.5px;color:rgba(255,255,255,.3);margin-bottom:6px">
            Gõ <span style="color:#ef4444;font-family:monospace;font-weight:700;
              background:rgba(239,68,68,.1);padding:1px 5px;border-radius:3px">XÁC NHẬN</span>
            để mở khóa:
          </div>
          <input id="pg-sc-input" type="text" autocomplete="off" placeholder="Gõ: XÁC NHẬN" style="
            width:100%;box-sizing:border-box;padding:8px 12px;border-radius:8px;
            background:rgba(239,68,68,.06);border:1.5px solid rgba(239,68,68,.22);
            color:#f87171;font-family:monospace;font-size:12px;font-weight:600;
            letter-spacing:.6px;outline:none;transition:all .2s;">
          <div id="pg-sc-hint" style="margin-top:4px;font-size:8px;color:rgba(255,255,255,.2)">
            Xác nhận rằng bạn hiểu rõ rủi ro
          </div>
        </div>` : `
        <div style="padding:7px 20px;border-bottom:1px solid rgba(255,255,255,.07);text-align:center">
          <span style="font-size:9px;color:rgba(255,255,255,.28)">
            Nút mở khóa sau <span id="pg-sc-count" style="color:${C};font-weight:700;font-family:monospace">${COUNTDOWN}</span>s · Khi tất cả ô được tích
          </span>
        </div>`}

      <!-- ══ BUTTONS ══ -->
      <div style="padding:12px 20px;display:flex;gap:8px;background:rgba(0,0,0,.25)">
        <button id="pg-sc-cancel" style="
          flex:1;padding:10px;border-radius:8px;cursor:pointer;
          background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.09);
          color:rgba(255,255,255,.5);font-family:'Inter',sans-serif;font-size:11px;font-weight:600;
          transition:all .15s;">✕ Đóng an toàn</button>
        <button id="pg-sc-confirm" disabled style="
          flex:2;padding:10px;border-radius:8px;cursor:not-allowed;
          background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);
          color:rgba(255,255,255,.18);font-family:'Inter',sans-serif;font-size:11px;font-weight:700;
          transition:all .25s;opacity:.55;
          display:flex;align-items:center;justify-content:center;gap:5px;">🔒 Hoàn thành để mở khóa</button>
      </div>
      <div style="padding:5px 20px 9px;text-align:center;font-size:7.5px;color:rgba(255,255,255,.12)">
        Hành động này được ghi lại · PhishGuard Enterprise v7.2
      </div>
    `;

    overlay.appendChild(box);
    document.body.appendChild(overlay);

    // ── Inject CSS ───────────────────────────────────────────────
    if (!document.getElementById('pg-sc-anim')) {
      const st = document.createElement('style');
      st.id = 'pg-sc-anim';
      st.textContent = `
        @keyframes pgPulseGlow{0%,100%{opacity:.5}50%{opacity:1}}
        @keyframes pgPulse{0%,100%{opacity:1}50%{opacity:.55}}
        #pg-sc-confirm:not([disabled]):hover{
          filter:brightness(1.12);transform:translateY(-1px);
          box-shadow:0 4px 18px ${CB}.22)};
        }
        #pg-sc-cancel:hover{background:rgba(255,255,255,.08)!important;color:rgba(255,255,255,.75)!important}
      `;
      document.head.appendChild(st);
    }

    // ── References ───────────────────────────────────────────────
    const confirmBtn = document.getElementById('pg-sc-confirm');
    const cancelBtn = document.getElementById('pg-sc-cancel');
    const ring = document.getElementById('pg-sc-ring');
    const cnum = document.getElementById('pg-sc-cnum');
    let timerRef = null;

    const closeSecond = () => {
      overlay.style.opacity = '0'; overlay.style.transition = 'opacity .18s';
      clearInterval(timerRef);
      setTimeout(() => overlay.remove(), 180);
    };

    // ── Enable confirm ────────────────────────────────────────────
    const enableConfirm = () => {
      confirmBtn.disabled = false;
      confirmBtn.style.cssText = `
        flex:2;padding:10px;border-radius:8px;cursor:pointer;opacity:1;
        background:linear-gradient(135deg,${CB}.2)},${CB}.12)});
        border:1px solid ${CB}.45)};color:#fff;
        font-family:'Inter',sans-serif;font-size:11px;font-weight:700;
        box-shadow:0 0 20px ${CB}.15)};transition:all .25s;
        display:flex;align-items:center;justify-content:center;gap:5px;`;
      confirmBtn.innerHTML = `${isPhishing ? '⚠️' : '✓'} Xác nhận vào mail`;
    };

    // ── Checkbox tracking ─────────────────────────────────────────
    const cbState = new Array(CHECKBOXES.length).fill(false);
    let textReady = !isPhishing;
    const checkReady = () => { if (cbState.every(Boolean) && textReady) enableConfirm(); };

    CHECKBOXES.forEach((_, i) => {
      const lbl = document.getElementById(`pg-sc-lbl-${i}`);
      const cbw = document.getElementById(`pg-sc-cbw-${i}`);
      const tick = document.getElementById(`pg-sc-tick-${i}`);
      lbl.addEventListener('click', () => {
        cbState[i] = !cbState[i];
        if (cbState[i]) {
          cbw.style.cssText += 'background:rgba(34,211,160,.14);border-color:rgba(34,211,160,.55);';
          tick.style.display = 'block';
          lbl.style.background = 'rgba(34,211,160,.04)';
          lbl.style.borderColor = 'rgba(34,211,160,.12)';
        } else {
          cbw.style.background = 'rgba(255,255,255,.04)'; cbw.style.borderColor = 'rgba(255,255,255,.18)';
          tick.style.display = 'none';
          lbl.style.background = 'transparent'; lbl.style.borderColor = 'transparent';
          // Khoá lại
          if (!confirmBtn.disabled) {
            confirmBtn.disabled = true; confirmBtn.style.cssText = 'flex:2;padding:10px;border-radius:8px;cursor:not-allowed;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);color:rgba(255,255,255,.18);font-family:\'Inter\',sans-serif;font-size:11px;font-weight:700;transition:all .25s;opacity:.55;display:flex;align-items:center;justify-content:center;gap:5px;';
            confirmBtn.innerHTML = '🔒 Hoàn thành để mở khóa';
          }
        }
        checkReady();
      });
    });

    // ── PHISHING: text input ──────────────────────────────────────
    if (isPhishing) {
      const inp = document.getElementById('pg-sc-input');
      const hint = document.getElementById('pg-sc-hint');
      inp.focus();
      // Blinking ring for phishing
      let blink = true;
      timerRef = setInterval(() => {
        blink = !blink;
        if (ring) ring.style.opacity = blink ? '1' : '0.25';
      }, 550);
      inp.addEventListener('input', () => {
        textReady = inp.value.trim().toUpperCase() === 'XÁC NHẬN';
        if (textReady) {
          inp.style.borderColor = 'rgba(34,211,160,.5)'; inp.style.color = '#22d3a0';
          inp.style.background = 'rgba(34,211,160,.06)';
          if (hint) { hint.textContent = '✓ Nhập đúng — hãy tích các ô bên trên'; hint.style.color = '#22d3a0'; }
        } else {
          inp.style.borderColor = 'rgba(239,68,68,.22)'; inp.style.color = '#f87171';
          inp.style.background = 'rgba(239,68,68,.06)';
          if (hint) { hint.textContent = 'Xác nhận rằng bạn hiểu rõ rủi ro'; hint.style.color = 'rgba(255,255,255,.2)'; }
          if (!confirmBtn.disabled) {
            confirmBtn.disabled = true;
            confirmBtn.innerHTML = '🔒 Hoàn thành để mở khóa';
          }
        }
        checkReady();
      });
      inp.addEventListener('keydown', e => { if (e.key === 'Enter' && !confirmBtn.disabled) confirmBtn.click(); });
    } else {
      // ── SUSPICIOUS: SVG ring countdown ────────────────────────
      let left = COUNTDOWN;
      timerRef = setInterval(() => {
        left--;
        const progress = left / COUNTDOWN;
        if (ring) ring.style.strokeDashoffset = CIRC * (1 - progress);
        if (cnum) cnum.textContent = Math.max(0, left);
        if (left <= 0) {
          clearInterval(timerRef);
          if (cnum) { cnum.textContent = '✓'; cnum.style.fontSize = '16px'; }
          if (ring) { ring.style.stroke = '#22d3a0'; ring.style.filter = 'drop-shadow(0 0 8px #22d3a0)'; }
          textReady = true;
          checkReady();
        }
      }, 1000);
    }

    // ── Cancel / confirm / escape ─────────────────────────────────
    cancelBtn.addEventListener('click', closeSecond);

    confirmBtn.addEventListener('click', () => {
      if (confirmBtn.disabled) {
        box.style.animation = 'none'; box.offsetHeight;
        box.style.animation = 'pgShake .35s ease';
        return;
      }
      // Log bypass
      try {
        chrome.runtime.sendMessage({
          action: 'logEvent', event: 'security_bypass',
          data: { sender: emailData?.sender, riskLevel: result.riskLevel, riskPercent: riskPct, ts: new Date().toISOString() }
        });
      } catch (_) { }
      closeSecond();
      setTimeout(() => onConfirmed(), 100);
    });

    overlay.addEventListener('click', e => { if (e.target === overlay) closeSecond(); });
    const escSC = e => { if (e.key === 'Escape') { closeSecond(); document.removeEventListener('keydown', escSC); } };
    document.addEventListener('keydown', escSC);
  }


  async function generateReplyDraft(result, emailData) {
    const settings = await sendAsync('getSettings', {});
    const geminiKey = settings?.geminiKey;
    const isPhishing = result.riskLevel === 'PHISHING';
    const isSuspicious = result.riskLevel === 'SUSPICIOUS';
    const threats = (result.threats || []).slice(0, 4).map(t => t.text || '').join('; ');
    const riskPct = result.riskPercent || result.score || 0;
    const sender = emailData?.sender || 'Người gửi';
    const subject = emailData?.subject || 'Không có tiêu đề';
    const bodyText = (emailData?.body || '').trim().substring(0, 800);

    const offlineTemplates = {
      phishing: `Kính gửi,\n\nTôi đã nhận được email của bạn với tiêu đề "${subject}".\n\nTuy nhiên, hệ thống bảo mật của tôi đã phát hiện đây là email có dấu hiệu PHISHING. Vì lý do an toàn, tôi từ chối thực hiện các yêu cầu trong email này.\n\nTrân trọng.`,
      suspicious: `Kính gửi,\n\nCảm ơn bạn đã liên hệ với tiêu đề "${subject}".\n\nTôi cần xác minh thêm trước khi phản hồi vì email này chứa một số nội dung đáng ngờ. Vui lòng cung cấp thêm thông tin để tôi có thể xác nhận danh tính và mục đích thực sự.\n\nTrân trọng.`,
      safe: `Kính gửi,\n\nCảm ơn bạn đã liên hệ. Tôi đã nhận được email của bạn và sẽ phản hồi chi tiết trong thời gian sớm nhất.\n\nTrân trọng.`
    };

    if (!geminiKey) return isPhishing ? offlineTemplates.phishing : isSuspicious ? offlineTemplates.suspicious : offlineTemplates.safe;

    const MODELS = ['gemini-1.5-flash', 'gemini-1.5-flash-8b', 'gemini-2.0-flash'];
    let promptInstruction = '';
    if (isPhishing) {
      promptInstruction = `Phân tích an toàn: Báo động! Dấu hiệu LỪA ĐẢO (Phishing). Mối đe dọa: ${threats || 'Không rõ'}\nYêu cầu:\n- Viết một email từ chối dứt khoát, chuyên nghiệp nhưng nghiêm khắc.\n- Cảnh báo người gửi rằng hệ thống an ninh đã chặn yêu cầu do có hành vi lừa đảo.\n- Ngắn gọn khoảng 3-5 câu.`;
    } else if (isSuspicious) {
      promptInstruction = `Phân tích an toàn: Đáng ngờ (Suspicious). Mối đe dọa: ${threats || 'Không rõ'}\nYêu cầu:\n- Viết một email cảnh giác, từ chối hoặc yêu cầu xác minh thêm danh tính.\n- Thể hiện sự lịch sự nhưng giữ khoảng cách, không cung cấp thông tin nhạy cảm.\n- Ngắn gọn khoảng 3-4 câu.`;
    } else {
      promptInstruction = `Phân tích an toàn: An toàn (Safe/Neutral).\nYêu cầu:\n- Dựa vào nội dung email gốc, đóng vai một người nhận chuyên nghiệp, viết email phản hồi thật tự nhiên, chi tiết và thấu đáo.\n- Nếu email gốc có câu hỏi, đưa ra câu trả lời hợp lý hoặc hứa sẽ kiểm tra và phản hồi cụ thể.\n- Không được tạo ra các thông tin sai lệch hoặc bịa đặt dữ liệu (chỉ dùng những thông tin cơ bản). Độ dài khoảng 3-6 câu.`;
    }

    const prompt = `Bạn là một trợ lý AI thông minh chuyên xử lý email (PhishGuard AI).\nHãy soạn một email phản hồi hoàn chỉnh bằng tiếng Việt.\n\nTHÔNG TIN EMAIL GỐC:\n- Người gửi: ${sender}\n- Tiêu đề: "${subject}"\n- Nội dung: "${bodyText || '(Không rõ)'}"\n\nCHỈ ĐỊNH CHO AI:\n${promptInstruction}\n\nQUY TẮC:\n- Trả về ĐÚNG phần nội dung (body) của thư, KHÔNG mở bài kiểu "Dưới đây là email...".\n- Có ngắt đoạn rõ ràng, dễ đọc.\n- KHÔNG dùng placeholder ngoặc vuông (như [Tên của bạn]). Dùng đại từ xưng hô chung (Tôi, Chúng tôi).`;

    for (const model of MODELS) {
      try {
        const resp = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiKey}`,
          {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { maxOutputTokens: 600, temperature: 0.7 } })
          });
        if (resp.status === 429 || !resp.ok) continue;
        const data = await resp.json();
        const body = data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
        if (!body) continue;
        return body; // Trả về nội dung AI tạo (vì prompt đã yêu cầu body đầy đủ)
      } catch { continue; }
    }
    return isPhishing ? offlineTemplates.phishing : isSuspicious ? offlineTemplates.suspicious : offlineTemplates.safe;
  }

  async function showReplyModal(result, emailData) {

    document.querySelectorAll('.pg-reply-modal').forEach(d => d.remove());

    const isPhishing = result.riskLevel === 'PHISHING';
    const isSuspicious = result.riskLevel === 'SUSPICIOUS';
    const isSafe = result.riskLevel === 'SAFE' || result.riskLevel === 'NEUTRAL';
    const riskPct = result.riskPercent || result.score || 0;
    const senderEmail = (emailData?.sender || '').match(/<(.+?)>/)?.[1] || emailData?.sender || '';

    const overlay = document.createElement('div');
    overlay.className = 'pg-reply-modal';
    overlay.style.cssText = `
      position:fixed;inset:0;z-index:9999999;
      background:rgba(0,0,0,.6);backdrop-filter:blur(4px);
      display:flex;align-items:center;justify-content:center;
      animation:pgFadeIn .18s ease;
    `;

    // Thay đổi UI theme dựa trên độ an toàn
    let themeColor = 'rgba(96,165,250,';
    let themeBadge = '📧 Tự động Trả lời';
    let themeInfo = `Trợ lý AI Gemini · ${isSafe ? 'Phân tích an toàn' : (isPhishing ? '⛔ PHISHING ' + riskPct + '%' : '⚠️ SUSPICIOUS ' + riskPct + '%')}`;

    if (isPhishing) themeColor = 'rgba(239,68,68,';
    else if (isSuspicious) themeColor = 'rgba(245,158,11,';

    const modal = document.createElement('div');
    modal.style.cssText = `
      background:#0d0f17;border:1px solid ${themeColor}.3);border-radius:16px;
      width:540px;max-width:calc(100vw - 32px);max-height:90vh;
      box-shadow:0 24px 80px rgba(0,0,0,.8),0 0 0 1px rgba(255,255,255,.04);
      overflow:hidden;animation:pgSlideUp .22s cubic-bezier(.16,1,.3,1);
      font-family:'Inter','IBM Plex Sans',system-ui,sans-serif;
      display:flex;flex-direction:column;
    `;

    modal.innerHTML = `
      <!-- Header -->
      <div style="padding:16px 20px 12px;background:${themeColor}.08);border-bottom:1px solid ${themeColor}.2);display:flex;align-items:center;gap:12px;flex-shrink:0">
        <div style="width:36px;height:36px;border-radius:10px;background:${themeColor}.15);display:flex;align-items:center;justify-content:center;font-size:20px;border:1px solid ${themeColor}.3)">
          ✨
        </div>
        <div style="flex:1">
          <div style="font-size:14px;font-weight:800;color:#fff;letter-spacing:.2px;margin-bottom:2px">${themeBadge}</div>
          <div style="font-size:10px;color:rgba(255,255,255,.45);font-weight:500">${themeInfo} · Nhận dạng và soạn thảo thông minh</div>
        </div>
        <button id="pg-reply-close" style="background:none;border:none;color:rgba(255,255,255,.4);font-size:18px;cursor:pointer;padding:4px;line-height:1;transition:color .15s">✕</button>
      </div>

      <!-- To field -->
      <div style="padding:10px 20px;border-bottom:1px solid rgba(255,255,255,.07);display:flex;align-items:center;gap:10px;flex-shrink:0">
        <span style="font-size:9px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;color:rgba(255,255,255,.3);width:36px">Đến</span>
        <div style="flex:1;font-size:11px;font-family:'JetBrains Mono',monospace;color:rgba(255,255,255,.7);background:rgba(255,255,255,.04);padding:5px 10px;border-radius:6px;border:1px solid rgba(255,255,255,.08)">${esc(senderEmail)}</div>
      </div>

      <!-- Subject field -->
      <div style="padding:10px 20px;border-bottom:1px solid rgba(255,255,255,.07);display:flex;align-items:center;gap:10px;flex-shrink:0">
        <span style="font-size:9px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;color:rgba(255,255,255,.3);width:36px">Re</span>
        <div style="flex:1;font-size:11px;color:rgba(255,255,255,.55);background:rgba(255,255,255,.04);padding:5px 10px;border-radius:6px;border:1px solid rgba(255,255,255,.08)">${esc('Re: ' + (emailData?.subject || 'No subject').substring(0, 70))}</div>
      </div>

      <!-- Nội dung (AI generating...) -->
      <div style="padding:14px 20px;flex:1;overflow-y:auto;min-height:0">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
          <span style="font-size:9px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;color:rgba(255,255,255,.3)">Nội dung Email</span>
          <div style="display:flex;gap:6px">
            <button id="pg-reply-regenerate" style="padding:3px 9px;border-radius:5px;border:1px solid rgba(96,165,250,.25);background:rgba(96,165,250,.08);color:#93c5fd;font-size:9px;font-weight:700;cursor:pointer;font-family:'Inter',sans-serif;transition:all .15s">🔁 Tạo lại</button>
            <button id="pg-reply-template-phish" style="padding:3px 9px;border-radius:5px;border:1px solid rgba(239,68,68,.25);background:rgba(239,68,68,.08);color:#f87171;font-size:9px;font-weight:700;cursor:pointer;font-family:'Inter',sans-serif;transition:all .15s">⛔ Từ chối</button>
            <button id="pg-reply-template-report" style="padding:3px 9px;border-radius:5px;border:1px solid rgba(245,158,11,.25);background:rgba(245,158,11,.08);color:#fbbf24;font-size:9px;font-weight:700;cursor:pointer;font-family:'Inter',sans-serif;transition:all .15s">🚨 Báo cáo</button>
          </div>
        </div>
        <div id="pg-reply-loading" style="
          display:flex;align-items:center;gap:10px;padding:20px;
          background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);border-radius:8px;
          font-size:11px;color:rgba(255,255,255,.5);
        ">
          <div style="width:16px;height:16px;border:2px solid rgba(96,165,250,.3);border-top-color:#60a5fa;border-radius:50%;animation:pgSpinR .8s linear infinite;flex-shrink:0"></div>
          Gemini AI đang soạn thảo...
        </div>
        <textarea id="pg-reply-body" class="pg-reply-textarea" style="
          display:none;width:100%;min-height:180px;box-sizing:border-box;
          background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:8px;
          color:rgba(255,255,255,.88);font-family:'Inter',system-ui,sans-serif;font-size:12px;
          line-height:1.7;padding:12px 14px;resize:vertical;
          transition:border .2s;
        "></textarea>
      </div>

      <!-- Action bar -->
      <div style="padding:12px 20px;border-top:1px solid rgba(255,255,255,.07);display:flex;gap:8px;flex-shrink:0;background:rgba(0,0,0,.2)">
        <button id="pg-reply-copy" style="
          flex:1;padding:10px;border-radius:8px;cursor:pointer;
          background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);
          color:rgba(255,255,255,.7);font-family:'Inter',sans-serif;font-size:12px;font-weight:600;
          transition:all .15s;display:flex;align-items:center;justify-content:center;gap:6px;
        ">📋 Sao chép</button>
        <button id="pg-reply-compose" style="
          flex:2;padding:10px;border-radius:8px;cursor:pointer;
          background:linear-gradient(135deg,rgba(37,99,235,.22),rgba(59,130,246,.15));
          border:1px solid rgba(96,165,250,.38);
          color:#93c5fd;font-family:'Inter',sans-serif;font-size:12px;font-weight:700;
          transition:all .15s;display:flex;align-items:center;justify-content:center;gap:6px;
          box-shadow:0 2px 8px rgba(59,130,246,.12);
        ">✉ Mở Gmail Compose</button>
      </div>
    `;

    overlay.appendChild(modal);
    document.body.appendChild(overlay);

    // Tạo template offline
    const senderName = (emailData?.sender || '').replace(/<.*>/, '').trim() || 'bạn';
    const baseSubject = emailData?.subject || 'No subject';

    const TEMPLATE_PHISHING = `Kính gửi,\n\nTôi đã nhận được email của bạn với tiêu đề "${baseSubject}". Tuy nhiên, hệ thống bảo mật đã xác định đây là email PHISHING với độ nguy hiểm ${riskPct}%.\n\nTôi sẽ KHÔNG thực hiện bất kỳ yêu cầu nào trong email này và đã ghi nhận để báo cáo.\n\nNếu đây là nhầm lẫn, vui lòng liên hệ qua kênh chính thức được xác minh.\n\nTrân trọng.`;
    const TEMPLATE_REPORT = `Kính gửi Bộ phận An ninh mạng,\n\nTôi xin báo cáo email lừa đảo nhận được:\n• Người gửi: ${senderEmail}\n• Tiêu đề: "${baseSubject}"\n• Độ nguy hiểm: ${riskPct}% (${result.riskLevel})\n• Dấu hiệu: ${(result.threats || []).slice(0, 3).map(t => t.text).join('; ')}\n\nĐề nghị điều tra và xử lý.\n\nTrân trọng.`;

    const setBody = (text) => {
      const loading = document.getElementById('pg-reply-loading');
      const textarea = document.getElementById('pg-reply-body');
      if (loading) loading.style.display = 'none';
      if (textarea) { textarea.style.display = 'block'; textarea.value = text; }
    };

    // Generate AI draft
    generateReplyDraft(result, emailData).then(draft => setBody(draft)).catch(() => setBody(TEMPLATE_PHISHING));

    // Event handlers
    const closeModal = () => {
      overlay.style.opacity = '0';
      overlay.style.transition = 'opacity .15s';
      setTimeout(() => overlay.remove(), 150);
    };

    document.getElementById('pg-reply-close').addEventListener('click', closeModal);
    overlay.addEventListener('click', e => { if (e.target === overlay) closeModal(); });

    document.getElementById('pg-reply-regenerate').addEventListener('click', () => {
      const loading = document.getElementById('pg-reply-loading');
      const textarea = document.getElementById('pg-reply-body');
      if (loading) { loading.style.display = 'flex'; loading.querySelector('div').style.animation = 'pgSpinR .8s linear infinite'; }
      if (textarea) textarea.style.display = 'none';
      generateReplyDraft(result, emailData).then(draft => setBody(draft)).catch(() => setBody(TEMPLATE_PHISHING));
    });

    document.getElementById('pg-reply-template-phish').addEventListener('click', () => setBody(TEMPLATE_PHISHING));
    document.getElementById('pg-reply-template-report').addEventListener('click', () => setBody(TEMPLATE_REPORT));

    document.getElementById('pg-reply-copy').addEventListener('click', () => {
      const ta = document.getElementById('pg-reply-body');
      if (!ta || !ta.value) return;
      navigator.clipboard.writeText(ta.value).then(() => {
        const btn = document.getElementById('pg-reply-copy');
        if (btn) { btn.textContent = '✅ Đã sao chép!'; btn.style.color = '#22d3a0'; setTimeout(() => { btn.textContent = '📋 Sao chép'; btn.style.color = ''; }, 2000); }
      }).catch(() => {
        const ta2 = document.getElementById('pg-reply-body');
        ta2.select(); document.execCommand('copy');
      });
    });

    document.getElementById('pg-reply-compose').addEventListener('click', () => {
      const ta = document.getElementById('pg-reply-body');
      const body = ta ? encodeURIComponent(ta.value) : '';
      const toAddr = encodeURIComponent(senderEmail);
      const subj = encodeURIComponent('Re: ' + baseSubject);
      // Mở Gmail compose
      const gmailUrl = `https://mail.google.com/mail/?view=cm&to=${toAddr}&su=${subj}&body=${body}`;
      window.open(gmailUrl, '_blank');
    });

    const escR = e => { if (e.key === 'Escape') { closeModal(); document.removeEventListener('keydown', escR); } };
    document.addEventListener('keydown', escR);
  }





  function setBadge(row, cls, label, result, emailData) {

    row.querySelectorAll('.pg-badge').forEach(b => b.remove());
    const cell = row.querySelector('.bog, .y6');
    if (!cell) return;
    const b = document.createElement('span');
    b.className = `pg-badge ${cls}`;
    b.innerHTML = `<span class="pg-dot"></span>${label}`;
    if (result) {
      b.addEventListener('click', e => { e.stopPropagation(); e.preventDefault(); showPanel(result, emailData, row); });
    }
    cell.appendChild(b);
  }

  // ══════════ NHÃN DANH MỤC ══════════
  function setCategoryLabel(row, cat) {
    row.querySelectorAll('.pg-cat-label').forEach(l => l.remove());
    const cell = row.querySelector('.bog, .y6');
    if (!cell) return;
    const lbl = document.createElement('span');
    lbl.className = 'pg-cat-label';
    lbl.style.cssText = `
      display:inline-flex;align-items:center;gap:3px;padding:1px 6px;border-radius:3px;
      margin-left:5px;font-family:var(--mono);font-size:9px;font-weight:600;letter-spacing:.2px;
      vertical-align:middle;white-space:nowrap;cursor:default;
      background:${cat.bg};color:${cat.color};border:1px solid ${cat.bd};
    `;
    lbl.textContent = cat.label;
    lbl.title = `Danh mục: ${cat.label}`;
    cell.appendChild(lbl);
  }

  function rowData(row) {
    const s = row.querySelector('.yP,.zF')?.getAttribute('email') || row.querySelector('.yP,.zF')?.textContent?.trim() || '';
    const sub = row.querySelector('.bog,.y6')?.textContent?.trim() || '';
    const snip = row.querySelector('.y2')?.textContent?.trim() || '';
    if (!s && !sub) return null;

    // ── Extract links từ snippet và row content ──
    const rowText = `${sub} ${snip}`;
    const regexLinks = (rowText.match(/https?:\/\/[^\s"'<>)\]]+/g) || []);
    // Cũng lấy từ <a> tags nếu có trong row
    const aLinks = [...row.querySelectorAll('a[href]')]
      .map(a => a.href)
      .filter(u => u && u.startsWith('http') && !u.includes('mail.google.com'));
    const links = [...new Set([...regexLinks, ...aLinks])].slice(0, 15);

    return { sender: s, subject: sub, body: snip, links, id: row.dataset.legacyThreadId || String(Date.now()) };
  }

  // ══════════ EMAIL VIEW ══════════
  function watchView() {
    new MutationObserver(deb(() => {
      const body = document.querySelector('.a3s.aiL,.a3s');
      if (body && body !== currentBody) { currentBody = body; analyzeView(); }
    }, 500)).observe(document.body, { childList: true, subtree: true });
  }

  async function analyzeView() {
    const view = document.querySelector('.nH.if,.gs,.adn');
    if (!view) return;
    const sEl = view.querySelector('.gD,[data-hovercard-id]');
    const subEl = view.querySelector('.hP');
    const bEl = view.querySelector('.a3s');
    const links = [...(bEl?.querySelectorAll('a') || [])].map(a => a.href).filter(Boolean).slice(0, 15);
    const d = {
      sender: sEl?.getAttribute('email') || sEl?.textContent?.trim() || '',
      subject: subEl?.textContent?.trim() || '',
      body: bEl?.textContent?.trim().substring(0, 2000) || '',
      links
    };
    if (!d.subject && !d.body) return;
    injectBanner(null, view, d);
    const result = await sendAsync('analyzeEmail', { data: d });
    if (result) {
      window.__pgResult = result; window.__pgEmail = d; window.__pgView = view;
      injectBanner(result, view, d);

      // ── AUTO URL SCAN: quét tất cả links trong email ──
      if (bEl) {
        const emailContextHint = `${d.sender} | ${d.subject}`;
        Promise.all([
          scanEmailUrls(bEl, emailContextHint),
          scanEmailMedia(bEl, emailContextHint),
          scanEmailAttachments(view, emailContextHint)
        ]).then(([, , attachResults]) => {
          if (attachResults && attachResults.length) {
            window.__pgAttachmentResults = attachResults;
            renderAttachmentPanel(attachResults);
          }
        }).catch(e => console.debug('[PhishGuard] scan error:', e));
      }
    }
  }


  function injectBanner(result, container, emailData) {
    container.querySelectorAll('.pg-banner').forEach(b => b.remove());
    const banner = document.createElement('div');
    const cat = emailData ? detectCategory(emailData) : null;
    const catTag = cat ? `<span style="padding:1px 6px;border-radius:3px;font-size:9px;font-weight:600;background:${cat.bg};color:${cat.color};border:1px solid ${cat.bd};font-family:var(--mono);margin-left:6px">${cat.label}</span>` : '';

    if (!result) {
      banner.className = 'pg-banner safe';
      banner.innerHTML = `<span class="pg-bn-icon">⟳</span><div class="pg-bn-body"><div class="pg-bn-title">Đang phân tích...${catTag}</div><div class="pg-bn-sub">PhishGuard Enterprise đang kiểm tra</div></div>`;
    } else {
      const hasCred = result.threats?.some(t => t.type === 'credential' || t.type === 'financial');
      const rl = result.riskLevel;
      const aiLbl = { 'gemini-ai': '🤖 Gemini', 'aspnet-backend': '⚙️ Backend', 'local-engine': '📌 Local' }[result.source] || 'Local';
      let cls, icon, title;
      if (rl === 'PHISHING') { cls = 'phishing'; icon = '⛔'; title = 'CẢNH BÁO PHISHING!'; }
      else if (hasCred) { cls = 'credential'; icon = '🔑'; title = 'Yêu Cầu Thông Tin Nhạy Cảm!'; }
      else if (rl === 'SUSPICIOUS') { cls = 'suspicious'; icon = '⚠️'; title = 'Email Đáng Ngờ'; }
      else { cls = 'safe'; icon = '✓'; title = 'Email An Toàn'; }

      banner.className = `pg-banner ${cls}`;
      banner.innerHTML = `
        <span class="pg-bn-icon">${icon}</span>
        <div class="pg-bn-body">
          <div class="pg-bn-title" style="display:flex;align-items:center;flex-wrap:wrap;gap:4px">${title}${catTag}</div>
          <div class="pg-bn-sub">${result.threats?.length || 0} mối đe dọa · ${aiLbl} · ${result.riskPercent}% rủi ro</div>
        </div>
        <div class="pg-bn-score">${result.riskPercent}%</div>
        ${rl !== 'SAFE' ? '<button class="pg-bn-btn pg-bn-del-btn" style="background:rgba(239,68,68,.15);color:#f87171;border-color:rgba(239,68,68,.3)">🗑 Xóa</button>' : ''}
        <button class="pg-bn-btn" id="pg-bn-reply-btn" style="background:rgba(96,165,250,.15);color:#93c5fd;border-color:rgba(96,165,250,.3)">✨ AI Trả lời</button>
        <button class="pg-bn-btn" id="pg-detail-btn">Chi tiết</button>
      `;
      setTimeout(() => {
        banner.querySelector('#pg-bn-reply-btn')?.addEventListener('click', () => {
          if (window.__pgResult && window.__pgEmail) showReplyModal(window.__pgResult, window.__pgEmail);
        });
        banner.querySelector('#pg-detail-btn')?.addEventListener('click', () => {
          if (window.__pgResult) showPanel(window.__pgResult, window.__pgEmail, null);
        });
        banner.querySelector('.pg-bn-del-btn')?.addEventListener('click', () => quickDeleteFromView(window.__pgEmail));
      }, 50);
    }
    container.insertBefore(banner, container.firstChild);
  }

  async function quickDeleteFromView(emailData) {
    if (!emailData || !confirm(`🗑 Xóa email này?\n"${emailData.subject || 'No subject'}"`)) return;
    const sels = ['[data-tooltip="Xóa"]', '[data-tooltip="Delete"]', '[aria-label="Delete"]', '[aria-label="Xóa"]', '[act="13"]'];
    let done = false;
    for (const s of sels) { const b = document.querySelector(s); if (b && isVisible(b)) { b.click(); done = true; break; } }
    send('markDeleted', { emailData }, () => { });
    deletedCount++; updateDelChip();
    toast(done ? '🗑 Đã xóa email' : '⚠️ Không tìm thấy nút xóa — thử xóa thủ công', done ? '' : 'warn');
  }

  // ══════════ SIDE PANEL ══════════
  function showPanel(result, emailData, row) {
    document.getElementById('pg-panel')?.remove();
    const rl = result.riskLevel;
    const hasCred = result.threats?.some(t => t.type === 'credential' || t.type === 'financial');
    const col = rl === 'PHISHING' ? 'var(--crit)' : hasCred ? 'var(--cred)' : rl === 'SUSPICIOUS' ? 'var(--warn)' : 'var(--safe)';
    const r = 28, circ = 2 * Math.PI * r, dash = (result.riskPercent / 100) * circ;
    const threats = result.threats || [], links = result.links || [];
    const isHybrid = result.hybridUsed;
    const aiPct = result.aiScore !== undefined ? ` AI:${result.aiScore}% Local:${result.localScore || 0}%` : '';
    const srcRaw = (result.source || 'local').split('(')[0];
    const srcLabel = {
      'gemini-geminiFlash': '🤖 GEMINI 2.0', 'gemini-geminiPro': '🤖 GEMINI PRO', 'gemini-geminiFlash15': '🤖 GEMINI 1.5',
      'hybrid': '⚡ HYBRID', 'aspnet-backend': '⚙️ BACKEND', 'local-engine': '📌 LOCAL',
      'weighted-local-engine': '📌 LOCAL WE', 'whitelist': '✓ WHITELIST', 'blacklist': '⛔ BLACKLIST'
    }[srcRaw] || (isHybrid ? '⚡ HYBRID' : '📌 LOCAL');
    const hybridInfo = isHybrid && aiPct ? `<span style="font-size:8px;color:var(--dim);font-family:var(--mono)">${aiPct}</span>` : '';
    const cat = emailData ? detectCategory(emailData) : null;

    const catBlock = cat ? `
      <div class="pg-sec">DANH MỤC</div>
      <div class="pg-card" style="border-color:${cat.bd};background:${cat.bg}">
        <span class="pg-ci">${cat.label.split(' ')[0]}</span>
        <div class="pg-cb">
          <div class="pg-ct" style="color:${cat.color}">${cat.label}</div>
          <div class="pg-cs">Phân loại tự động theo người gửi & nội dung</div>
        </div>
      </div>` : '';

    const threatRows = threats.length ? threats.map(t => {
      const isCred = t.type === 'credential' || t.type === 'financial';
      const sc = isCred ? 'sk' : t.severity === 'high' ? 'sh' : t.severity === 'medium' ? 'sm' : 'sl';
      const sl = isCred ? 'CRED' : t.severity === 'high' ? 'HIGH' : t.severity === 'medium' ? 'MED' : 'LOW';
      return `<div class="pg-card ${isCred ? 'cred-card' : ''}">
        <span class="pg-ci">${tIcon(t.type)}</span>
        <div class="pg-cb">
          <div class="pg-ct">${esc(tTitle(t))}</div>
          <div class="pg-cs">${esc((t.evidence || t.text || '').substring(0, 70))}</div>
        </div>
        <span class="pg-sev ${sc}">${sl}</span>
      </div>`;
    }).join('') : `<div class="pg-card"><span class="pg-ci">✓</span><div class="pg-cb"><div class="pg-ct">Không phát hiện mối đe dọa</div></div></div>`;

    const rbCls = rl === 'PHISHING' ? 'rb-c' : hasCred ? 'rb-k' : rl === 'SUSPICIOUS' ? 'rb-w' : 'rb-s';
    const rlLbl = rl === 'PHISHING' ? '⛔ PHISHING' : hasCred ? '🔑 CREDENTIAL' : rl === 'SUSPICIOUS' ? '⚠️ SUSPICIOUS' : '✓ SAFE';
    const panel = document.createElement('div');
    panel.id = 'pg-panel';
    panel.innerHTML = `
      <div class="pg-ph">
        <div class="pg-ph-title">🛡 PHÂN TÍCH<span class="pg-ph-src">${srcLabel}</span>${hybridInfo}</div>
        <button class="pg-close" id="pg-panel-close">✕</button>
      </div>
      <div class="pg-pb">
        <div class="pg-risk">
          <div class="pg-arc">
            <svg width="70" height="70" viewBox="0 0 70 70">
              <circle cx="35" cy="35" r="${r}" fill="none" stroke="rgba(255,255,255,.05)" stroke-width="6"/>
              <circle cx="35" cy="35" r="${r}" fill="none" stroke="${col}" stroke-width="6"
                stroke-dasharray="${dash} ${circ}" stroke-linecap="round"
                style="filter:drop-shadow(0 0 5px ${col});transition:stroke-dasharray 1s ease"/>
            </svg>
            <div class="pg-arc-txt">
              <span class="pg-arc-n" style="color:${col}">${result.riskPercent}</span>
              <span class="pg-arc-l">% RISK</span>
            </div>
          </div>
          <div class="pg-risk-right">
            <div class="pg-rbadge ${rbCls}">${rlLbl}</div>
            <div class="pg-rsummary">${riskSummary(result, hasCred)}</div>
          </div>
        </div>

        ${emailData ? `
        <div class="pg-sec">NGƯỜI GỬI</div>
        <div class="pg-card"><span class="pg-ci">@</span><div class="pg-cb"><div class="pg-ct">${esc(emailData.sender || 'Unknown')}</div><div class="pg-cs">From</div></div></div>
        <div class="pg-card"><span class="pg-ci">◆</span><div class="pg-cb"><div class="pg-ct">${esc((emailData.subject || 'No subject').substring(0, 65))}</div><div class="pg-cs">Subject</div></div></div>
        ` : ''}

        ${catBlock}

        <div class="pg-sec">MỐI ĐE DỌA (${threats.length})</div>
        ${threatRows}

        ${links.length ? `<div class="pg-sec">LINKS (${links.length})</div>
        ${links.slice(0, 5).map(l => `<div class="pg-link">
          <span style="color:var(--dim);font-size:10px">↗</span>
          <span class="pg-lu">${esc(l.url || l)}</span>
          <span class="ls ls-${l.status || 'safe'}">${{ safe: '✓', suspicious: '⚠️', malicious: '⛔' }[l.status || 'safe']}</span>
        </div>`).join('')}` : ''}

        ${result.summary ? `
        <div class="pg-sec">NHẬN XÉT AI</div>
        <div class="pg-card" style="flex-direction:column;gap:5px">
          <div style="font-size:9px;font-weight:700;color:var(--mu)">${srcLabel} · ${result.analysisTime || 0}ms${result.confidence ? ` · ${result.confidence}% conf` : ''}</div>
          <div class="pg-cs" style="color:var(--tx);font-family:var(--font);line-height:1.6">${esc(result.summary)}</div>
        </div>` : ''}

        ${result.indicators?.length ? `
        <div class="pg-sec">ĐIỂM CHÚ Ý</div>
        ${result.indicators.map(i => `<div class="pg-card"><span class="pg-ci">›</span><div class="pg-cb"><div class="pg-cs" style="color:var(--tx)">${esc(i)}</div></div></div>`).join('')}` : ''}

        <div class="pg-actions">
          <button class="pg-btn" style="background:rgba(96,165,250,.15);color:#93c5fd;border-color:rgba(96,165,250,.3)" id="pg-btn-panel-reply">✨ AI Trả lời</button>
          ${rl === 'PHISHING' ? `<button class="pg-btn red" id="pg-btn-delete">🗑 XÓA EMAIL NÀY</button>` : ''}
          ${rl !== 'SAFE' ? `<button class="pg-btn" style="background:rgba(239,68,68,.08);color:#f87171;border-color:rgba(239,68,68,.2)" id="pg-btn-report">⚑ Báo Cáo</button>` : ''}
          <button class="pg-btn green" id="pg-btn-trust">✓ Tin Cậy</button>
          <button class="pg-btn" id="pg-btn-block">⛔ Chặn</button>
        </div>
      </div>
    `;
    document.body.appendChild(panel);
    panel.querySelector('#pg-panel-close')?.addEventListener('click', () => panel.remove());
    panel.querySelector('#pg-btn-panel-reply')?.addEventListener('click', () => {
      showReplyModal(result, emailData || window.__pgEmail);
    });
    panel.querySelector('#pg-btn-delete')?.addEventListener('click', async () => {
      if (row) await deleteSingleEmail(row, result, emailData);
      else { await quickDeleteFromView(emailData || window.__pgEmail); panel.remove(); }
    });
    panel.querySelector('#pg-btn-report')?.addEventListener('click', () => {
      send('reportPhishing', { data: { emailData: emailData || window.__pgEmail, ts: new Date().toISOString() } }, () => { toast('⚑ Đã báo cáo phishing'); panel.remove(); });
    });
    panel.querySelector('#pg-btn-trust')?.addEventListener('click', () => {
      const em = (emailData || window.__pgEmail)?.sender;
      if (em) send('addWhitelist', { email: em }, () => toast('✓ Đã tin cậy người gửi'));
      panel.remove();
    });
    panel.querySelector('#pg-btn-block')?.addEventListener('click', () => {
      const em = (emailData || window.__pgEmail)?.sender;
      if (em) send('addBlacklist', { email: em }, () => toast('⛔ Đã chặn người gửi'));
      panel.remove();
    });
    if (window.__pgAttachmentResults && window.__pgAttachmentResults.length) {
      renderAttachmentPanel(window.__pgAttachmentResults);
    }
  }

  // ══════════ HISTORY PANEL ══════════
  function showHistoryPanel() {
    document.getElementById('pg-panel')?.remove();
    send('getHistory', {}, hist => {
      const items = hist || [];
      const panel = document.createElement('div');
      panel.id = 'pg-panel';
      const dotC = { 'SAFE': 'var(--safe)', 'SUSPICIOUS': 'var(--warn)', 'PHISHING': 'var(--crit)' };
      const tagC = { 'SAFE': 'sl', 'SUSPICIOUS': 'sm', 'PHISHING': 'sh' };
      const tagL = { 'SAFE': 'CLEAN', 'SUSPICIOUS': 'WARN', 'PHISHING': 'PHISH' };
      const histRows = items.slice(0, 120).map(h => `
        <div class="pg-card" style="${h.deleted ? 'opacity:0.4' : ''}">
          <span style="width:6px;height:6px;border-radius:50%;background:${dotC[h.riskLevel] || 'var(--safe)'};flex-shrink:0;margin-top:3px"></span>
          <div class="pg-cb">
            <div class="pg-ct">${esc((h.subject || 'No subject').substring(0, 48))}${h.deleted ? '<span style="font-size:8px;color:var(--dim);margin-left:4px">[🗑 xóa]</span>' : ''}</div>
            <div class="pg-cs">${esc(h.sender || '')} · ${h.riskPercent}% · ${fmtTime(h.timestamp)}</div>
          </div>
          <span class="pg-sev ${tagC[h.riskLevel] || 'sl'}">${tagL[h.riskLevel] || 'OK'}</span>
        </div>`).join('');
      panel.innerHTML = `
        <div class="pg-ph">
          <div class="pg-ph-title">📋 LỊCH SỬ<span class="pg-ph-src">${items.length} bản ghi</span></div>
          <button class="pg-close" id="pg-hist-close">✕</button>
        </div>
        <div class="pg-pb">
          <div style="display:flex;gap:4px;margin-bottom:10px">
            <button class="pg-btn" id="pg-del-phish-hist" style="flex:1;font-size:10px;background:rgba(239,68,68,.08);color:#f87171;border-color:rgba(239,68,68,.2)">🗑 Xóa bản ghi Phishing</button>
            <button class="pg-btn" id="pg-clear-hist" style="font-size:10px">Xóa tất cả</button>
          </div>
          ${items.length ? histRows : '<div style="text-align:center;padding:24px;color:var(--dim);font-size:11px">Chưa có lịch sử</div>'}
        </div>`;
      document.body.appendChild(panel);
      panel.querySelector('#pg-hist-close')?.addEventListener('click', () => panel.remove());
      panel.querySelector('#pg-clear-hist')?.addEventListener('click', () => { send('clearHistory', {}, () => { toast('Đã xóa lịch sử'); panel.remove(); }); });
      panel.querySelector('#pg-del-phish-hist')?.addEventListener('click', () => {
        const n = items.filter(h => h.riskLevel === 'PHISHING').length;
        if (!n) { toast('Không có phishing trong lịch sử'); return; }
        send('clearPhishingHistory', {}, () => { toast(`Đã xóa ${n} bản ghi phishing`); panel.remove(); });
      });
    });
  }

  // ══════════ HELPERS ══════════
  function send(a, x, cb) { chrome.runtime.sendMessage({ action: a, ...x }, r => cb && cb(r)); }
  function sendAsync(a, x) { return new Promise(r => send(a, x, r)); }
  function waitFor(sel, cb) { const t = setInterval(() => { if (document.querySelector(sel)) { clearInterval(t); cb(); } }, 400); }
  function setText(id, v) { const e = document.getElementById(id); if (e) e.textContent = v; }
  function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
  function deb(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
  function wait(ms) { return new Promise(r => setTimeout(r, ms)); }
  function fmtTime(ts) { if (!ts) return ''; const d = (Date.now() - new Date(ts)) / 1000; if (d < 60) return 'vừa xong'; if (d < 3600) return `${~~(d / 60)}p trước`; if (d < 86400) return `${~~(d / 3600)}h trước`; return new Date(ts).toLocaleDateString('vi-VN'); }
  function toast(msg, type = '') {
    document.querySelectorAll('.pg-toast').forEach(t => t.remove());
    const t = document.createElement('div'); t.className = 'pg-toast';
    if (type === 'warn') t.style.cssText = 'border-color:rgba(245,158,11,.4);background:rgba(245,158,11,.1);color:#fbbf24';
    t.textContent = msg; document.body.appendChild(t); setTimeout(() => t.remove(), 2800);
  }
  function riskSummary(r, hasCred) {
    if (hasCred) return '⚠️ Yêu cầu thông tin nhạy cảm — KHÔNG cung cấp mật khẩu';
    const n = r.threats?.length || 0;
    if (r.riskLevel === 'PHISHING') return `${n} mối đe dọa — KHÔNG tương tác`;
    if (r.riskLevel === 'SUSPICIOUS') return `${n} dấu hiệu đáng ngờ — Hãy cẩn thận`;
    return `${n || 'Không có'} mối đe dọa`;
  }
  function tIcon(t) { return { keyword: '◈', sender: '@', link: '↗', domain: '⊘', spoofing: '🎭', urgency: '⏱', credential: '🔑', financial: '💰', social_engineering: '🧠', blacklist: '⛔', style: '◉', spam: '📢', ai_detected: '🤖', suspicious_pattern: '🔍' }[t] || '◆'; }
  function tTitle(t) {
    return {
      keyword: `Từ khóa: "${(t.text || '').substring(0, 35)}"`,
      credential: '⚠️ Yêu cầu mật khẩu / đăng nhập',
      financial: '💰 Yêu cầu thông tin tài chính',
      sender: 'Người gửi đáng ngờ', link: 'Liên kết có thể độc hại',
      domain: 'Domain nguy hiểm', spoofing: 'Giả mạo tổ chức uy tín',
      urgency: 'Ngôn ngữ tạo áp lực khẩn cấp',
      social_engineering: 'Thao túng tâm lý',
      blacklist: 'Người gửi trong danh sách đen',
      style: 'Định dạng bất thường', spam: 'Nội dung spam',
      ai_detected: 'Phát hiện bởi AI', suspicious_pattern: 'Pattern đáng ngờ'
    }[t.type] || t.description || 'Mối đe dọa không xác định';
  }

  async function scanRowUrls(row, emailData, currentResult) {
    const urls = (emailData.links || []).filter(u => u.startsWith('http'));
    if (!urls.length) return;

    const results = await sendAsync('analyzeUrlBatch', {
      urls: urls.slice(0, 5),
      emailContext: `${emailData.sender} | ${emailData.subject}`.substring(0, 300)
    });
    if (!Array.isArray(results)) return;

    const malicious = results.filter(r => r.status === 'malicious');
    const suspicious = results.filter(r => r.status === 'suspicious');
    if (!malicious.length && !suspicious.length) return;

    // Tính URL boost
    let urlBoost = 0;
    const urlThreats = [];
    for (const mr of malicious) {
      urlBoost += Math.min(30, (mr.score || 50) * 0.5);
      urlThreats.push({
        type: 'link', text: `URL độc hại: ${(mr.url || '').substring(0, 60)}`,
        severity: 'critical', score: Math.min(30, (mr.score || 50) * 0.5)
      });
    }
    for (const sr of suspicious) {
      urlBoost += Math.min(15, (sr.score || 30) * 0.3);
      urlThreats.push({
        type: 'link', text: `URL đáng ngờ: ${(sr.url || '').substring(0, 60)}`,
        severity: 'high', score: Math.min(15, (sr.score || 30) * 0.3)
      });
    }

    // Cập nhật risk
    const newRisk = Math.min(100, (currentResult.riskPercent || 0) + Math.round(urlBoost));
    const merged = [...urlThreats, ...(currentResult.threats || [])].slice(0, 15);
    let newLevel = currentResult.riskLevel;
    const types = new Set(merged.map(t => t.type));
    if (newRisk >= 65 && types.size >= 2) newLevel = 'PHISHING';
    else if (newRisk >= 35 && newLevel === 'SAFE') newLevel = 'SUSPICIOUS';
    else if (malicious.length >= 2) newLevel = 'PHISHING';
    else if (malicious.length >= 1 && newLevel === 'SAFE') newLevel = 'SUSPICIOUS';

    // Ghi lại
    currentResult.riskPercent = newRisk;
    currentResult.riskLevel = newLevel;
    currentResult.threats = merged;
    currentResult.urlScanApplied = true;
    row.dataset.pgRes = JSON.stringify(currentResult);

    // Cập nhật visual
    applyRowResult(row, currentResult, emailData);

    // Thêm URL warning badge trên row
    addUrlWarningBadge(row, malicious, suspicious);

    refreshBar();
  }

  function showUrlDetailToast(r) {
    document.querySelectorAll('.pg-url-detail').forEach(d => d.remove());
    const d = document.createElement('div'); d.className = 'pg-url-detail';
    const color = r.status === 'malicious' ? '#ef4444' : r.status === 'suspicious' ? '#f59e0b' : '#10b981';
    d.style.cssText = `position:fixed;bottom:80px;right:20px;width:340px;max-height:280px;overflow-y:auto;background:#1a1a2e;border:1px solid ${color}44;border-radius:10px;padding:12px;z-index:999999;font-family:monospace;font-size:11px;box-shadow:0 8px 32px rgba(0,0,0,0.5);color:#e2e8f0;`;
    const si = r.status === 'malicious' ? '⛔' : r.status === 'suspicious' ? '⚠️' : '✅';
    d.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><b style="color:${color}">${si} URL ${(r.status || 'safe').toUpperCase()} · ${r.score || 0}%</b><button onclick="this.parentElement.parentElement.remove()" style="background:none;border:none;color:#6b7280;cursor:pointer;font-size:14px">✕</button></div><div style="color:#94a3b8;word-break:break-all;margin-bottom:6px;font-size:9px">${esc(r.url?.substring(0, 120) || '')}</div><div style="color:#64748b;font-size:9px;margin-bottom:6px">Nguồn: ${r.source || 'local'}</div>${(r.threats || []).slice(0, 5).map(t => `<div style="margin:3px 0;padding:4px 6px;background:rgba(239,68,68,0.1);border-radius:4px;border-left:2px solid ${t.severity === 'critical' ? '#ef4444' : t.severity === 'high' ? '#f59e0b' : '#6b7280'}"><span style="color:#94a3b8;font-size:9px">${esc((t.text || '').substring(0, 90))}</span></div>`).join('')}${r.geminiReason ? `<div style="margin-top:6px;color:#818cf8;font-size:9px">🤖 ${esc(r.geminiReason.substring(0, 120))}</div>` : ''}`;
    document.body.appendChild(d); setTimeout(() => d.remove(), 8000);
  }

  function renderUrlPanel(results) {
    const panel = document.getElementById('pg-panel'); if (!panel) return;
    panel.querySelectorAll('.pg-url-panel').forEach(el => el.remove());
    const malC = results.filter(r => r.status === 'malicious').length;
    const susC = results.filter(r => r.status === 'suspicious').length;
    const container = document.createElement('div'); container.className = 'pg-url-panel';
    container.innerHTML = `<div class="pg-sec">🔗 URLs (${results.length}) · ⛔${malC} ⚠️${susC} ✓${results.length - malC - susC}</div>${results.map(r => { const color = r.status === 'malicious' ? 'var(--crit)' : r.status === 'suspicious' ? 'var(--warn)' : 'var(--safe)'; const icon = r.status === 'malicious' ? '⛔' : r.status === 'suspicious' ? '⚠️' : '✓'; const top = r.threats?.[0]?.text || r.geminiReason || 'Không có mối đe dọa'; return `<div class="pg-link"><span style="color:${color};font-size:10px;min-width:14px">${icon}</span><span class="pg-lu" style="flex:1">${esc((r.url || '').substring(0, 55))}</span><span style="color:${color};font-size:9px;font-weight:700;font-family:monospace">${r.score || 0}%</span></div><div style="font-size:9px;color:var(--dim);padding:2px 8px 4px 22px;border-bottom:1px solid rgba(255,255,255,0.04)">${esc(top.substring(0, 70))}</div>` }).join('')}`;
    panel.querySelector('.pg-pb')?.appendChild(container);
  }

  // ══════════ MEDIA SCANNER ══════════
  function getImageSrc(img) {
    return img.currentSrc || img.src || img.getAttribute('data-src') || img.getAttribute('data-original-src') || img.getAttribute('data-safe-src') || '';
  }

  function extractAttachmentName(text) {
    if (!text) return '';
    const m = text.match(/([\w\-. ()]+\.(pdf|docx|doc|xlsx|xls|pptx|ppt|zip|rar|7z|tar|gz|eml|msg|apk|exe|js|vbs|ps1|jar|csv|txt|png|jpg|jpeg|gif|webp))/i);
    return m ? m[1].trim() : '';
  }

  function parseSize(text) {
    if (!text) return 0;
    const m = text.match(/(\d+(?:[.,]\d+)?)\s*(KB|MB|GB)/i);
    if (!m) return 0;
    const val = parseFloat(m[1].replace(',', '.'));
    const unit = m[2].toUpperCase();
    if (unit === 'KB') return Math.round(val * 1024);
    if (unit === 'MB') return Math.round(val * 1024 * 1024);
    if (unit === 'GB') return Math.round(val * 1024 * 1024 * 1024);
    return 0;
  }

  function collectAttachments(view) {
    const nodes = new Set([
      ...view.querySelectorAll('a[download]'),
      ...view.querySelectorAll('a[aria-label*="Download"]'),
      ...view.querySelectorAll('a[aria-label*="Tải xuống"]'),
      ...view.querySelectorAll('[data-tooltip*="."]'),
      ...view.querySelectorAll('.aQH a, .aQH span, .aQH div')
    ]);
    const items = [];
    nodes.forEach(n => {
      const text = [
        n.getAttribute('download'),
        n.getAttribute('aria-label'),
        n.getAttribute('data-tooltip'),
        n.textContent
      ].filter(Boolean).join(' ');
      const name = extractAttachmentName(text);
      if (!name) return;
      const size = parseSize(text);
      const url = n.getAttribute('href') || n.getAttribute('data-url') || '';
      items.push({ name, size, url });
    });
    const uniq = new Map();
    items.forEach(it => { if (!uniq.has(it.name)) uniq.set(it.name, it); });
    return [...uniq.values()];
  }

  async function scanEmailAttachments(view, contextHint) {
    const attachments = collectAttachments(view);
    if (!attachments.length) return [];
    const results = [];
    for (const a of attachments.slice(0, 8)) {
      const r = await sendAsync('scanMedia', { mediaItem: { type: 'file', name: a.name, size: a.size || 0, url: a.url || '', contextHint } });
      if (r) results.push({ ...r, name: a.name, size: a.size || 0, url: a.url || '' });
      await wait(80);
    }
    return results;
  }

  async function scanEmailMedia(emailBody, contextHint) {
    if (!emailBody) return;
    const images = [...emailBody.querySelectorAll('img')].map(img => {
      const src = getImageSrc(img);
      if (!src) return null;
      const rect = img.getBoundingClientRect();
      const w = Math.max(img.naturalWidth || 0, rect.width || 0);
      const h = Math.max(img.naturalHeight || 0, rect.height || 0);
      if (w && h && (w < 8 || h < 8)) return null;
      return { img, src };
    }).filter(Boolean);
    const videos = [...emailBody.querySelectorAll('video[src],video source[src]')].map(v => v.src || v.getAttribute('src')).filter(Boolean);
    const mediaItems = [
      ...images.slice(0, 10).map(item => ({ url: item.src, type: 'image', contextHint, el: item.img })),
      ...videos.slice(0, 3).map(vSrc => ({ url: vSrc, type: 'video', contextHint }))
    ];
    if (!mediaItems.length) return;

    mediaItems.forEach(item => { if (item.el) overlayLoadingBadge(item.el); });

    const results = [];
    for (const item of mediaItems) {
      let dataUrl = null;
      if (item.type === 'video') dataUrl = await extractVideoFrameAsDataUrl(item.url);
      const r = await sendAsync('scanMedia', { mediaItem: { url: item.url, dataUrl, type: item.type, contextHint: item.contextHint } });
      if (r) { results.push({ ...r, el: item.el }); if (item.el) overlayMediaBadge(item.el, r); }
      await wait(100);
    }
    const dangerous = results.filter(r => r.status !== 'safe' && r.status !== 'error');
    if (dangerous.length > 0) renderMediaPanel(results);
    return results;
  }

  function renderAttachmentPanel(results) {
    const panel = document.getElementById('pg-panel'); if (!panel) return;
    panel.querySelectorAll('.pg-attach-panel').forEach(el => el.remove());
    const container = document.createElement('div'); container.className = 'pg-attach-panel';
    const stats = { safe: 0, suspicious: 0, malicious: 0 };
    results.forEach(r => { if (stats[r.status] !== undefined) stats[r.status]++; });
    container.innerHTML = `
      <div class="pg-sec">FILE ĐÍNH KÈM (${results.length}) · ⛔${stats.malicious} ⚠️${stats.suspicious} ✓${stats.safe}</div>
      ${results.map(r => {
      const color = r.status === 'malicious' ? 'var(--crit)' : r.status === 'suspicious' ? 'var(--warn)' : 'var(--safe)';
      const icon = r.status === 'malicious' ? '⛔' : r.status === 'suspicious' ? '⚠️' : '✓';
      const sizeText = r.size ? ` · ${formatBytes(r.size)}` : '';
      const top = r.threats?.[0]?.text || r.summary || 'Không có mối đe dọa';
      return `<div class="pg-card">
          <span class="pg-ci">${icon}</span>
          <div class="pg-cb">
            <div class="pg-ct" style="color:${color}">${esc(r.name || r.url || 'File')}${sizeText}</div>
            <div class="pg-cs">${esc(top.substring(0, 70))}</div>
          </div>
          <span class="pg-sev" style="background:rgba(255,255,255,.06);color:${color}">${(r.score || 0)}%</span>
        </div>`;
    }).join('')}
    `;
    panel.querySelector('.pg-pb')?.appendChild(container);
  }

  function formatBytes(bytes) {
    if (!bytes) return '';
    if (bytes < 1024) return bytes + 'B';
    if (bytes < 1024 * 1024) return Math.round(bytes / 1024) + 'KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + 'MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(1) + 'GB';
  }

  function overlayLoadingBadge(imgEl) {
    const wrapper = wrapIfNeeded(imgEl);
    if (wrapper.querySelector('.pg-media-loading')) return;
    const badge = document.createElement('div'); badge.className = 'pg-media-loading';
    badge.style.cssText = 'position:absolute;top:4px;right:4px;padding:2px 6px;border-radius:4px;font-size:9px;font-weight:700;background:rgba(0,0,0,0.7);color:#94a3b8;font-family:monospace;pointer-events:none;z-index:9999;border:1px solid rgba(255,255,255,0.1);';
    badge.textContent = '⟳ Scan...'; wrapper.appendChild(badge);
  }

  function overlayMediaBadge(imgEl, result) {
    const wrapper = imgEl.closest('.pg-media-wrap') || imgEl.parentElement;
    wrapper?.querySelectorAll('.pg-media-loading,.pg-media-badge').forEach(b => b.remove());
    const badge = document.createElement('div'); badge.className = 'pg-media-badge';
    const colorMap = { malicious: '#ef4444', suspicious: '#f59e0b', safe: '#10b981', error: '#6b7280' };
    const iconMap = { malicious: '⛔', suspicious: '⚠️', safe: '✅', error: '?' };
    const s = result.status || 'safe'; const color = colorMap[s] || colorMap.error;
    const extras = [result.qrCodeFound && 'QR', result.isFakeLogin && 'LOGIN', result.logoDetected && ('LOGO:' + result.logoDetected.substring(0, 8))].filter(Boolean).join(' ');
    badge.style.cssText = `position:absolute;top:4px;right:4px;padding:2px 6px;border-radius:4px;font-size:9px;font-weight:700;background:${color}22;color:${color};font-family:monospace;pointer-events:auto;z-index:9999;border:1px solid ${color}55;cursor:pointer;white-space:nowrap;box-shadow:0 2px 8px rgba(0,0,0,0.4);`;
    badge.textContent = `${iconMap[s]} ${s === 'safe' ? '✓' : (result.score || 0) + '%'}${extras ? ' ' + extras : ''}`;
    badge.title = `PhishGuard Media\nStatus: ${s}\nScore: ${result.score || 0}%\n${result.summary || ''}`;
    badge.addEventListener('click', e => { e.preventDefault(); e.stopPropagation(); showMediaDetailToast(result); });
    if (wrapper) wrapper.appendChild(badge);
  }

  function wrapIfNeeded(imgEl) {
    if (imgEl.parentElement?.classList.contains('pg-media-wrap')) return imgEl.parentElement;
    const wrap = document.createElement('span'); wrap.className = 'pg-media-wrap';
    wrap.style.cssText = 'position:relative;display:inline-block;';
    imgEl.parentElement?.insertBefore(wrap, imgEl); wrap.appendChild(imgEl); return wrap;
  }

  function showMediaDetailToast(r) {
    document.querySelectorAll('.pg-media-detail').forEach(d => d.remove());
    const d = document.createElement('div'); d.className = 'pg-media-detail';
    const color = r.status === 'malicious' ? '#ef4444' : r.status === 'suspicious' ? '#f59e0b' : '#10b981';
    d.style.cssText = `position:fixed;bottom:80px;right:20px;width:340px;max-height:320px;overflow-y:auto;background:#1a1a2e;border:1px solid ${color}44;border-radius:10px;padding:12px;z-index:999999;font-family:monospace;font-size:11px;box-shadow:0 8px 32px rgba(0,0,0,0.5);color:#e2e8f0;`;
    const si = r.status === 'malicious' ? '⛔' : r.status === 'suspicious' ? '⚠️' : '✅';
    d.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><b style="color:${color}">${si} Media ${(r.status || 'safe').toUpperCase()} · ${r.score || 0}%</b><button onclick="this.parentElement.parentElement.remove()" style="background:none;border:none;color:#6b7280;cursor:pointer;font-size:14px">✕</button></div><div style="color:#94a3b8;word-break:break-all;margin-bottom:6px;font-size:9px">${esc((r.url || '').substring(0, 100))}</div>${r.qrCodeFound ? `<div style="margin-bottom:5px;padding:5px;background:rgba(245,158,11,0.1);border-radius:4px;border-left:2px solid #f59e0b;font-size:9px">📱 QR Code phát hiện${r.qrCodeUrl ? `<br>URL: <span style="color:#60a5fa">${esc(r.qrCodeUrl.substring(0, 100))}</span>` : ''}</div>` : ''}${r.isFakeLogin ? '<div style="margin-bottom:5px;padding:5px;background:rgba(239,68,68,0.1);border-radius:4px;border-left:2px solid #ef4444;font-size:9px">🚨 Trang đăng nhập giả mạo!</div>' : ''}${r.logoDetected ? `<div style="margin-bottom:5px;padding:5px;background:rgba(245,158,11,0.1);border-radius:4px;border-left:2px solid #f59e0b;font-size:9px">🏷️ Logo: ${esc(r.logoDetected)}</div>` : ''}${r.extractedText ? `<div style="margin-bottom:5px;padding:5px;background:rgba(255,255,255,0.04);border-radius:4px;font-size:9px;color:#94a3b8">📝 ${esc(r.extractedText.substring(0, 150))}</div>` : ''}${(r.threats || []).slice(0, 5).map(t => `<div style="margin:3px 0;padding:4px 6px;background:rgba(239,68,68,0.1);border-radius:4px;border-left:2px solid ${t.severity === 'critical' ? '#ef4444' : t.severity === 'high' ? '#f59e0b' : '#6b7280'}"><span style="color:#94a3b8;font-size:9px">${esc((t.text || '').substring(0, 90))}</span></div>`).join('')}${r.summary ? `<div style="margin-top:6px;color:#818cf8;font-size:9px">🤖 ${esc(r.summary.substring(0, 150))}</div>` : ''}`;
    document.body.appendChild(d); setTimeout(() => d.remove(), 10000);
  }

  function renderMediaPanel(results) {
    const panel = document.getElementById('pg-panel'); if (!panel) return;
    panel.querySelectorAll('.pg-media-panel').forEach(el => el.remove());
    const dangerous = results.filter(r => r.status !== 'safe' && r.status !== 'error');
    if (!dangerous.length) return;
    const container = document.createElement('div'); container.className = 'pg-media-panel';
    container.innerHTML = `<div class="pg-sec">🖼️ MEDIA (${results.length}) · ${dangerous.length} đáng ngờ</div>${results.map(r => { const color = r.status === 'malicious' ? 'var(--crit)' : r.status === 'suspicious' ? 'var(--warn)' : r.status === 'error' ? 'var(--dim)' : 'var(--safe)'; const icon = r.status === 'malicious' ? '⛔' : r.status === 'suspicious' ? '⚠️' : r.status === 'error' ? '?' : '✓'; const extras = [r.qrCodeFound && 'QR', r.isFakeLogin && 'FAKE-LOGIN', r.logoDetected && ('LOGO:' + r.logoDetected.substring(0, 10))].filter(Boolean).join(' '); return `<div class="pg-card"><span class="pg-ci" style="font-size:9px">${r.type === 'video' ? '🎬' : '🖼️'}</span><div class="pg-cb"><div class="pg-ct" style="color:${color}">${icon} ${(r.status || 'safe').toUpperCase()} ${r.score || 0}%${extras ? ' · ' + extras : ''}</div><div class="pg-cs">${esc((r.url || '').substring(0, 55))}</div>${r.threats?.[0] ? `<div class="pg-cs" style="color:var(--mu)">${esc(r.threats[0].text.substring(0, 60))}</div>` : ''}</div></div>` }).join('')}`;
    panel.querySelector('.pg-pb')?.appendChild(container);
  }

  async function extractVideoFrameAsDataUrl(videoUrl) {
    return new Promise(resolve => {
      try {
        const video = document.createElement('video');
        video.crossOrigin = 'anonymous'; video.muted = true; video.style.display = 'none';
        video.src = videoUrl; document.body.appendChild(video);
        const cleanup = () => { try { document.body.removeChild(video); } catch { } };
        const timeout = setTimeout(() => { cleanup(); resolve(null); }, 8000);
        video.addEventListener('loadeddata', () => { video.currentTime = Math.min(2, video.duration * 0.1); });
        video.addEventListener('seeked', () => {
          try {
            clearTimeout(timeout);
            const canvas = document.createElement('canvas');
            canvas.width = Math.min(video.videoWidth, 800); canvas.height = Math.min(video.videoHeight, 600);
            canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height);
            const dataUrl = canvas.toDataURL('image/jpeg', 0.8);
            cleanup(); resolve(dataUrl);
          } catch { cleanup(); resolve(null); }
        });
        video.addEventListener('error', () => { cleanup(); clearTimeout(timeout); resolve(null); });
        video.load();
      } catch { resolve(null); }
    });
  }

})();
