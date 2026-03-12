// ══════════════════════════════════════════════════════════════
// MAIN ANALYSIS PIPELINE
// ══════════════════════════════════════════════════════════════
async function analyzeEmail(email) {
  if (!email?.subject && !email?.body) return mkSafe();
  const startTime = Date.now();
  const sender = (email.sender || '').toLowerCase();
  const trustedSender = isTrustedSender(sender);

  log('debug', 'analyze_start', { sender: email.sender, subject: email.subject, trusted: trustedSender });

  // 1. User whitelist → instant safe
  if (S.whitelist.some(w => sender.includes(w.toLowerCase()))) {
    log('debug', 'whitelist_hit', { sender });
    return { ...mkSafe(), source: 'whitelist' };
  }

  // 2. Blacklist → instant phishing
  if (S.blacklist.some(b => sender.includes(b.toLowerCase()))) {
    const r = mkPhishing('Người gửi trong danh sách đen', 'blacklist', 100);
    record(email, r); updateStats(r); save();
    log('warn', 'blacklist_hit', { sender });
    return r;
  }

  // 3. Trusted sender pre-check: nếu domain uy tín và KHÔNG có dấu hiệu
  // spoofing (domain mismatched), return safe sớm mà không cần AI
  if (trustedSender) {
    // Vẫn cần kiểm tra lookalike vì ai đó có thể fake display name
    const lookalike = detectLookalike(sender, email.subject);
    // Chỉ chặn nếu có lookalike rõ ràng
    if (!lookalike) {
      // Chạy nhanh local để kiểm tra attachment malware và URL executor
      const quickCheck = quickTrustedCheck(email);
      if (!quickCheck.hasCritical) {
        log('debug', 'trusted_sender_safe', { sender, domain: sender.slice(sender.lastIndexOf('@') + 1) });
        const safeResult = {
          ...mkSafe(), source: 'trusted-sender', trustedDomain: true,
          riskPercent: quickCheck.score, summary: `Email từ domain uy tín: ${sender.slice(sender.lastIndexOf('@') + 1)}`
        };
        record(email, safeResult); updateStats(safeResult); save();
        return safeResult;
      }
    }
  }

  // 4. Cache check (15 min)
  const ck = cacheKey(email);
  if (S.aiCache[ck] && Date.now() - S.aiCache[ck].ts < 900000) {
    S.performanceMetrics.cacheHits++;
    log('debug', 'cache_hit', { key: ck });
    return S.aiCache[ck].r;
  }

  // 5. LOCAL ENGINE — fast, comprehensive weighted scan
  const t0 = Date.now();
  const localResult = weightedLocalEngine(email, trustedSender);
  const localTime = Date.now() - t0;
  updateAvg('local', localTime);

  // 6. GEMINI AI (primary)
  let aiResult = null;
  if (S.settings.useGemini && S.settings.geminiKey) {
    const t1 = Date.now();
    aiResult = await callGeminiEnhanced(email, localResult);
    const geminiTime = Date.now() - t1;
    if (aiResult) {
      updateAvg('gemini', geminiTime);
      S.stats.geminiCalls++;
      log('debug', 'gemini_success', { riskLevel: aiResult.riskLevel, riskPercent: aiResult.riskPercent, time: geminiTime });
    }
  }

  // 7. Fallback: ASP.NET backend
  if (!aiResult && S.settings.aiServer) {
    aiResult = await callBackend(email);
    if (aiResult) log('debug', 'backend_fallback_used');
  }

  // 8. HYBRID SCORING
  let result = hybridMerge(aiResult, localResult, S.settings.hybridWeight || 0.65, trustedSender);

  // 9. Safe Browsing — luôn chạy nếu có links (không cần điều kiện riskPercent)
  if (S.settings.safeBrowsing && S.settings.sbKey && email.links?.length) {
    const hits = await sbCheck(email.links.slice(0, 10), S.settings.sbKey);
    if (hits.length) {
      const boost = Math.min(40, hits.length * 15);
      result.riskPercent = Math.min(100, result.riskPercent + boost);
      result.threats.unshift({
        type: 'link', text: `${hits.length} link nguy hiểm (Google Safe Browsing)`,
        severity: 'critical', score: boost, evidence: hits.map(h => h.threat?.url || '').join(', ')
      });
      if (result.riskPercent >= 65) result.riskLevel = 'PHISHING';
      else if (result.riskPercent >= 35) result.riskLevel = 'SUSPICIOUS';
      S.stats.links += email.links.length;
    }
  }

  // 10. VirusTotal domain check
  if (S.settings.virusTotal && S.settings.vtKey && !trustedSender) {
    const domain = extractDomain(email.sender);
    if (domain) {
      const vtResult = await vtCheckDomain(domain, S.settings.vtKey);
      if (vtResult?.malicious > 2) {
        const vtScore = Math.min(35, vtResult.malicious * 5);
        result.riskPercent = Math.min(100, result.riskPercent + vtScore);
        result.threats.unshift({
          type: 'domain', text: `Domain ${domain}: ${vtResult.malicious} engine VT cảnh báo`,
          severity: 'high', score: vtScore, vtStats: vtResult
        });
        if (result.riskPercent >= 65) result.riskLevel = 'PHISHING';
        S.stats.vtCalls++;
      }
    }
  }

  // 11. URLHaus — kiểm tra links trong email với database malware cộng đồng (không cần key)
  if (S.settings.urlhausEnabled && email.links?.length && !trustedSender) {
    const linksToCheck = email.links.slice(0, 5); // tối đa 5 links để tránh chậm
    const urlhausResults = await Promise.all(linksToCheck.map(u => urlhausCheck(u)));
    for (const uh of urlhausResults) {
      if (uh && uh.status !== 'safe') {
        S.stats.urlhausCalls++;
        S.stats.urlhausHits++;
        const uhScore = uh.status === 'malicious' ? 30 : 15;
        result.riskPercent = Math.min(100, result.riskPercent + uhScore);
        result.threats.unshift({
          type: 'link',
          text: `URLHaus: URL malware đã biết (${uh.threatType}${uh.urlStatus ? ' — ' + uh.urlStatus : ''})`,
          severity: uh.status === 'malicious' ? 'critical' : 'high',
          score: uhScore,
          evidence: uh.tags ? `Tags: ${uh.tags}` : ''
        });
        if (result.riskPercent >= 65) result.riskLevel = 'PHISHING';
        else if (result.riskPercent >= 35) result.riskLevel = 'SUSPICIOUS';
        log('warn', 'urlhaus_hit', { threatType: uh.threatType, status: uh.status });
        break; // chỉ cần 1 URL hit là đủ
      } else if (uh) {
        S.stats.urlhausCalls++;
      }
    }
  }

  // 12. AbuseIPDB — kiểm tra IP reputation của mail server sender
  if (S.settings.abuseipdbEnabled && S.settings.abuseipdbKey && !trustedSender) {
    const domain = extractDomain(email.sender);
    if (domain) {
      const ipResult = await abuseIPDBCheck(domain, S.settings.abuseipdbKey);
      S.stats.abuseipdbCalls++;
      if (ipResult && ipResult.abuseScore >= 25) {
        S.stats.abuseipdbHits++;
        const ipScore = Math.min(30, Math.round(ipResult.abuseScore * 0.35));
        result.riskPercent = Math.min(100, result.riskPercent + ipScore);
        result.threats.unshift({
          type: 'domain',
          text: `AbuseIPDB: IP ${ipResult.ip} (${ipResult.countryCode}) — Abuse score ${ipResult.abuseScore}/100, ${ipResult.totalReports} báo cáo`,
          severity: ipResult.abuseScore >= 75 ? 'critical' : ipResult.abuseScore >= 50 ? 'high' : 'medium',
          score: ipScore,
          evidence: `ISP: ${ipResult.isp} | Loại: ${ipResult.usageType}`
        });
        if (result.riskPercent >= 65) result.riskLevel = 'PHISHING';
        else if (result.riskPercent >= 35) result.riskLevel = 'SUSPICIOUS';
        log('warn', 'abuseipdb_hit', { ip: ipResult.ip, abuseScore: ipResult.abuseScore });
      }
    }
  }

  // 13. IPQualityScore — phân tích email sender: disposable? fraud score? compromised?
  if (S.settings.ipqsEnabled && S.settings.ipqsKey && email.sender && !trustedSender) {
    const ipqsResult = await ipqsEmailCheck(email.sender, S.settings.ipqsKey);
    S.stats.ipqsCalls++;
    if (ipqsResult) {
      const threats = [];
      let ipqsScore = 0;

      if (ipqsResult.disposable) {
        threats.push('Email tạm thời (disposable)');
        ipqsScore += 25;
      }
      if (ipqsResult.honeypot) {
        threats.push('Honey-pot/Spam trap');
        ipqsScore += 30;
      }
      if (ipqsResult.recentAbuse) {
        threats.push('Bị báo cáo lạm dụng gần đây');
        ipqsScore += 20;
      }
      if (ipqsResult.leaked) {
        threats.push('Có trong database breach');
        ipqsScore += 12;
      }
      if (!ipqsResult.mxRecords) {
        threats.push('Domain không có MX record hợp lệ');
        ipqsScore += 18;
      }
      if (ipqsResult.fraudScore >= 75) {
        threats.push(`Fraud score rất cao: ${ipqsResult.fraudScore}/100`);
        ipqsScore += 25;
      } else if (ipqsResult.fraudScore >= 50) {
        threats.push(`Fraud score cao: ${ipqsResult.fraudScore}/100`);
        ipqsScore += 12;
      }

      if (threats.length > 0) {
        S.stats.ipqsHits++;
        const finalIpqsScore = Math.min(28, ipqsScore);
        result.riskPercent = Math.min(100, result.riskPercent + finalIpqsScore);
        result.threats.push({
          type: 'spoofing',
          text: `IPQualityScore: ${threats.join(', ')}`,
          severity: ipqsResult.fraudScore >= 75 ? 'critical' : 'high',
          score: finalIpqsScore,
          evidence: `Fraud: ${ipqsResult.fraudScore}/100 | Valid: ${ipqsResult.valid} | Domain age: ${ipqsResult.domain || 'N/A'}`
        });
        if (result.riskPercent >= 65) result.riskLevel = 'PHISHING';
        else if (result.riskPercent >= 35) result.riskLevel = 'SUSPICIOUS';
        log('warn', 'ipqs_hit', { fraudScore: ipqsResult.fraudScore, disposable: ipqsResult.disposable });
      }
    }
  }

  // 14. Auto-Quarantine
  if (S.settings.autoQuarantine && result.riskLevel === 'PHISHING' && result.riskPercent >= 75) {
    addToQuarantine(email, result);
  }

  // 15. Finalize
  const totalTime = Date.now() - startTime;
  result.analysisTime = totalTime;
  result.timestamp = now();
  result.version = VERSION;
  updateAvg('total', totalTime);

  S.aiCache[ck] = { r: result, ts: Date.now() };
  record(email, result);
  updateStats(result);
  updateHourlyStats();
  save();
  doNotify(result, email);
  log('info', 'analysis_complete', {
    sender: email.sender, riskLevel: result.riskLevel,
    riskPercent: result.riskPercent, source: result.source, time: totalTime
  });

  return result;
}


// ── Quick check cho trusted sender — chỉ tìm dấu hiệu rất nghiêm trọng ──
function quickTrustedCheck(email) {
  const text = `${email.subject || ''} ${email.body || ''}`.toLowerCase();
  let score = 0;
  let hasCritical = false;

  // Malware attachment — nghiêm trọng ngay cả với trusted domain
  if (/\.(exe|bat|cmd|scr|pif|msi|vbs|ps1)\b/i.test(text)) {
    score += 55; hasCritical = true;
  }
  // data:/javascript: URI
  if (/data:text|javascript:/i.test(text)) {
    score += 50; hasCritical = true;
  }
  // Yêu cầu CVV/số thẻ hoàn toàn không bình thường ngay cả từ bank
  if (/cvv|cvc|ccv|mã bảo mật thẻ/i.test(text)) {
    score += 45; hasCritical = true;
  }
  // Prize scam + click combo
  if (/trúng thưởng|lucky winner|congratulations.*won/i.test(text) && /click (here|link)|nhấp vào/i.test(text)) {
    score += 40; hasCritical = true;
  }
  return { score: Math.min(30, score), hasCritical };
}

// ══════════════════════════════════════════════════════════════
// HYBRID SCORING ENGINE
// Kết hợp AI confidence + local weighted rules thông minh
// ══════════════════════════════════════════════════════════════
function hybridMerge(aiResult, localResult, aiWeight = 0.65, trustedSender = false) {
  // If no AI result, use local
  if (!aiResult) return { ...localResult, hybridUsed: false };

  const localWeight = 1 - aiWeight;
  const aiConf = (aiResult.confidence || 50) / 100;

  // Adjust AI weight by confidence
  const effectiveAiWeight = aiWeight * (0.5 + aiConf * 0.5);
  const effectiveLocWeight = localWeight * (1.2 - aiConf * 0.4);
  const total = effectiveAiWeight + effectiveLocWeight;

  // Weighted average of risk scores
  const hybridScore = Math.round(
    (aiResult.riskPercent * (effectiveAiWeight / total)) +
    (localResult.riskPercent * (effectiveLocWeight / total))
  );

  // Use highest severity level if scores are close
  const diff = Math.abs(aiResult.riskPercent - localResult.riskPercent);
  let finalScore = diff < 20
    ? Math.max(aiResult.riskPercent, localResult.riskPercent) * 0.85 + hybridScore * 0.15
    : hybridScore;

  // Nếu trusted sender → giảm score đáng kể (domain uy tín nhưng vẫn có signal nhỏ)
  if (trustedSender) finalScore = Math.round(finalScore * 0.4);

  const clampedScore = Math.min(100, Math.round(finalScore));

  // Merge threats: AI threats first, then unique local threats
  const mergedThreats = [...(aiResult.threats || [])];
  for (const lt of (localResult.threats || [])) {
    const isDuplicate = mergedThreats.some(at => at.type === lt.type || (at.score > 0 && Math.abs(at.score - lt.score) < 5));
    if (!isDuplicate) mergedThreats.push(lt);
  }

  // ── THRESHOLDS được nâng cao để giảm false positive ──
  // Normal mode: cần score ≥65% VÀ ít nhất 2 loại threat để gọi PHISHING
  // Aggressive mode: cần score ≥40%
  const uniqueCategories = new Set(mergedThreats.map(t => t.type || t.category));
  const thresholds = S.settings.aggressiveMode
    ? { p: 40, s: 20 }
    : { p: 65, s: 35 };      // < --- nâng từ 45/22 lên 65/35

  // Extra guard: cần ít nhất 2 loại threat khác nhau để gọi PHISHING
  let riskLevel;
  if (clampedScore >= thresholds.p && (S.settings.aggressiveMode || uniqueCategories.size >= 2)) {
    riskLevel = 'PHISHING';
  } else if (clampedScore >= thresholds.s) {
    riskLevel = 'SUSPICIOUS';
  } else {
    riskLevel = 'SAFE';
  }

  return {
    riskLevel,
    riskPercent: clampedScore,
    threats: mergedThreats.sort((a, b) => (b.score || 0) - (a.score || 0)).slice(0, 15),
    source: `hybrid(ai:${Math.round(effectiveAiWeight / total * 100)}%,local:${Math.round(effectiveLocWeight / total * 100)}%)`,
    confidence: Math.round((aiResult.confidence || 60) * 0.7 + 30),
    summary: aiResult.summary,
    indicators: aiResult.indicators,
    hybridUsed: true,
    aiScore: aiResult.riskPercent,
    localScore: localResult.riskPercent,
    aiConfidence: aiResult.confidence
  };
}

// ══════════════════════════════════════════════════════════════
// WEIGHTED LOCAL ENGINE v7 — ML-inspired rule scoring
// ══════════════════════════════════════════════════════════════
function weightedLocalEngine(email, trustedSender = false) {
  let scoreComponents = [];
  const sender = (email.sender || '').toLowerCase();
  const subject = (email.subject || '').toLowerCase();
  const body = (email.body || '').toLowerCase();
  const full = `${sender} ${subject} ${body}`;
  const t0 = Date.now();

  // ──────────────────────────────────────────────────────────────
  // TRUSTED SENDER MODE: chỉ check các dấu hiệu cực kỳ nghiêm trọng
  // (tấn công có thể đến ngay cả từ domain uy tín bị compromise)
  // ──────────────────────────────────────────────────────────────
  if (trustedSender) {
    const attachText = `${subject} ${body}`;
    if (/\.(exe|bat|cmd|scr|pif|msi|vbs|ps1|jar)\b/i.test(attachText)) {
      scoreComponents.push({ type: 'malware', text: 'File thực thi độc hại đính kèm (rất bất thường từ domain uy tín)', score: 60, severity: 'critical', category: 'malware' });
    }
    if (/cvv|cvc|ccv/i.test(full)) {
      scoreComponents.push({ type: 'credential', text: 'Yêu cầu mã CVV thẻ — không bao giờ hợp lệ từ bất kỳ tổ chức nào', score: 55, severity: 'critical', category: 'credential' });
    }
    if (/data:text|javascript:/i.test(body)) {
      scoreComponents.push({ type: 'link', text: 'URL bị obfuscate (data:/javascript:)', score: 50, severity: 'critical', category: 'link' });
    }
    // Trusted sender nhưng có URL điểm xấu (shortener dẫn đến IP)
    const urls = body.match(/https?:\/\/[^\s"'<>]+/g) || [];
    if (urls.some(u => /https?:\/\/\d+\.\d+/.test(u))) {
      scoreComponents.push({ type: 'link', text: 'Chứa URL dẫn đến địa chỉ IP bất thường', score: 35, severity: 'high', category: 'link' });
    }
    // Tính score nhanh và return
    let totalScore = scoreComponents.reduce((s, c) => s + c.score, 0);
    totalScore = Math.min(40, totalScore); // cap ở 40 cho trusted sender
    const thresholds = { p: 65, s: 35 };
    return {
      riskLevel: totalScore >= thresholds.p ? 'PHISHING' : totalScore >= thresholds.s ? 'SUSPICIOUS' : 'SAFE',
      riskPercent: totalScore,
      threats: scoreComponents,
      source: 'weighted-local-engine(trusted)',
      confidence: 70,
      analysisTime: Date.now() - t0,
      timestamp: now()
    };
  }

  // ──────────────────────────────────────────────────────────────
  // FULL ANALYSIS cho domain không quen biết
  // ──────────────────────────────────────────────────────────────

  // ── CREDENTIAL PATTERNS ──────────────────────────
  // Giảm điểm các pattern mà email hợp lệ (bank, Google, MFA...) thường dùng
  const credPatterns = [
    { re: /cvv|cvc|ccv|mã bảo mật thẻ/i, label: 'Yêu cầu mã CVV thẻ tín dụng', pts: 60 },
    { re: /số thẻ|card number|credit card|debit card/i, label: 'Yêu cầu số thẻ', pts: 50 },
    { re: /pin\b|mã pin/i, label: 'Yêu cầu mã PIN', pts: 48 },
    { re: /secret (key|question|answer)/i, label: 'Yêu cầu câu hỏi bí mật', pts: 35 },
    { re: /số tài khoản|account number|stk/i, label: 'Yêu cầu số tài khoản', pts: 40 },
    // Những pattern dưới đây common trong email hợp lệ → giảm điểm xuống
    { re: /otp|mã xác (minh|nhận|thực)/i, label: 'Đề cập OTP (kiểm tra context)', pts: 20 },
    { re: /mật khẩu|password/i, label: 'Đề cập mật khẩu (kiểm tra context)', pts: 15 },
    { re: /verify your (account|identity|email)/i, label: 'Xác minh tài khoản (kiểm tra context)', pts: 18 },
    { re: /update (your )?(payment|billing|card)/i, label: 'Cập nhật thông tin thanh toán', pts: 30 },
    { re: /confirm (your )?(account|identity|details)/i, label: 'Yêu cầu xác nhận thông tin', pts: 22 },
  ];
  credPatterns.forEach(p => {
    if (p.re.test(full)) scoreComponents.push({ type: 'credential', text: p.label, score: p.pts, severity: p.pts >= 45 ? 'critical' : p.pts >= 30 ? 'high' : 'medium', category: 'credential' });
  });

  // ── FINANCIAL SCAM PATTERNS ──────────────────────
  const finPatterns = [
    { re: /trúng thưởng|trúng giải|lucky (draw|winner)|congratulations.*won/i, label: 'Thông báo trúng thưởng giả mạo', pts: 50 },
    { re: /nhận (tiền|quà|thưởng) (ngay|miễn phí|free)/i, label: 'Hứa hẹn nhận tiền/quà miễn phí', pts: 45 },
    { re: /chuyển khoản.*(khẩn|gấp|ngay)|urgent.*(transfer|wire|payment)/i, label: 'Yêu cầu chuyển khoản khẩn cấp', pts: 55 },
    { re: /bitcoin|crypto|binance|usdt|ethereum.*send|invest.*guarantee/i, label: 'Lừa đảo tiền điện tử', pts: 48 },
    { re: /inheritance|thừa kế|million.*(dollar|usd|vnd).*unclaimed/i, label: 'Lừa đảo thừa kế', pts: 58 },
    { re: /money.*laundering|rửa tiền|legal fee.*release|agent fee/i, label: 'Lừa đảo phí giải phóng', pts: 60 },
    { re: /dating|romance.*money|yêu.*chuyển.*tiền/i, label: 'Lừa đảo tình cảm', pts: 52 },
    { re: /gói (vay|tín dụng) ưu đãi.*(không (cần|cần) thế chấp)/i, label: 'Lừa đảo vay tín dụng', pts: 45 },
    { re: /refund.*process|hoàn tiền.*xử lý.*click/i, label: 'Lừa đảo hoàn tiền (kèm link click)', pts: 40 },
    // hóa đơn bình thường không tính
  ];
  finPatterns.forEach(p => {
    if (p.re.test(full)) scoreComponents.push({ type: 'financial', text: p.label, score: p.pts, severity: p.pts >= 50 ? 'critical' : 'high', category: 'financial' });
  });

  // ── URGENCY & THREAT PATTERNS ─────────────────────
  const urgencyHigh = [
    { re: /tài khoản.*(bị|sẽ).*(xóa|khóa|đình chỉ|tạm ngưng)/i, label: 'Đe dọa khóa/xóa tài khoản', pts: 35 },
    { re: /account.*(will be )?(suspended|deleted|terminated|disabled)/i, label: 'Đe dọa tắt tài khoản', pts: 32 },
    { re: /hành động (ngay|khẩn cấp).*kẻo|immediate action.*(or|avoid)/i, label: 'Yêu cầu hành động khẩn cấp kèm đe dọa', pts: 28 },
    { re: /pháp lý|legal action|bị kiện|lawsuit|tòa án/i, label: 'Đe dọa hành động pháp lý', pts: 33 },
    { re: /your (session|account) (has been|is) (compromised|hacked)/i, label: 'Giả mạo cảnh báo bị hack', pts: 38 },
    // Bỏ bớt các pattern generic như "48 giờ", "24 giờ" — quá nhiều false positive
  ];
  urgencyHigh.forEach(p => {
    if (p.re.test(full)) scoreComponents.push({ type: 'urgency', text: p.label, score: p.pts, severity: 'high', category: 'urgency' });
  });

  // ── SENDER ANALYSIS ───────────────────────────────
  const freeDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com', 'ymail.com', 'aol.com', 'icloud.com'];
  const orgKeywords = [
    'paypal', 'vietcombank', 'techcombank', 'bidv', 'agribank', 'mbbank', 'tpbank',
    'vpbank', 'hdbank', 'sacombank', 'acb', 'ocb', 'hsbc', 'citibank', 'apple',
    'amazon', 'netflix', 'facebook', 'meta', 'instagram', 'momo', 'zalopay'
  ];
  const isFreeEmail = freeDomains.some(d => sender.includes('@' + d));
  const senderRaw = email.sender || '';
  const senderDomain = extractDomain(senderRaw.toLowerCase());
  const senderName = extractSenderName(senderRaw).toLowerCase();
  const impersonatedOrg = orgKeywords.find(o => full.includes(o) && isFreeEmail && !sender.includes('@' + o) && !sender.includes(o + '.'));
  if (isFreeEmail && impersonatedOrg) {
    scoreComponents.push({ type: 'spoofing', text: `Giả mạo ${impersonatedOrg} qua email miễn phí`, score: 48, severity: 'critical', category: 'spoofing' });
  }
  const brandDomains = {
    'vietcombank': ['vietcombank.com.vn'],
    'techcombank': ['techcombank.com.vn'],
    'bidv': ['bidv.com.vn'],
    'agribank': ['agribank.com.vn'],
    'mbbank': ['mbbank.com.vn'],
    'tpbank': ['tpbank.vn'],
    'vpbank': ['vpbank.com.vn'],
    'hdbank': ['hdbank.com.vn'],
    'sacombank': ['sacombank.com'],
    'acb': ['acb.com.vn'],
    'ocb': ['ocb.com.vn'],
    'hsbc': ['hsbc.com', 'hsbc.com.vn'],
    'citibank': ['citibank.com', 'citi.com'],
    'paypal': ['paypal.com'],
    'apple': ['apple.com', 'icloud.com'],
    'amazon': ['amazon.com', 'amazon.co.uk'],
    'netflix': ['netflix.com'],
    'facebook': ['facebook.com', 'fb.com', 'facebookmail.com', 'meta.com'],
    'instagram': ['instagram.com'],
    'momo': ['momo.vn'],
    'zalopay': ['zalopay.vn']
  };
  if (senderName && !senderName.includes('@')) {
    const nameBrand = Object.keys(brandDomains).find(b => senderName.includes(b));
    if (nameBrand && senderDomain) {
      const ok = brandDomains[nameBrand].some(d => senderDomain === d || senderDomain.endsWith('.' + d));
      if (!ok) {
        scoreComponents.push({ type: 'spoofing', text: `Mạo danh ${nameBrand} nhưng domain gửi không khớp (${senderDomain})`, score: 44, severity: 'high', category: 'spoofing' });
      }
    }
  }

  // Bad TLD
  const badTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.download', '.work', '.loan', '.pw', '.date', '.win', '.stream', '.party'];
  const badTld = badTlds.find(t => sender.includes(t));
  if (badTld) scoreComponents.push({ type: 'domain', text: `TLD nguy hiểm trong domain người gửi: ${badTld}`, score: 30, severity: 'high', category: 'domain' });

  // IP address sender
  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(sender)) {
    scoreComponents.push({ type: 'domain', text: 'Người gửi dùng địa chỉ IP thay domain', score: 40, severity: 'high', category: 'domain' });
  }

  // Lookalike domain
  const lookalike = detectLookalike(sender, subject);
  if (lookalike) {
    scoreComponents.push({ type: 'spoofing', text: `Domain giả mạo phát hiện: ${lookalike}`, score: 52, severity: 'critical', category: 'spoofing' });
  }

  // ── ATTACHMENT ANALYSIS ───────────────────────────
  const attachText = `${subject} ${body}`;
  if (/\.(exe|bat|cmd|scr|pif|com|msi|vbs|ps1|jar|app)\b/i.test(attachText)) {
    scoreComponents.push({ type: 'malware', text: 'File đính kèm thực thi có thể chứa malware', score: 55, severity: 'critical', category: 'malware' });
  }
  if (/\.(docm|xlsm|pptm|dotm|xlsb)\b/i.test(attachText)) {
    scoreComponents.push({ type: 'malware', text: 'File Office có macro (có thể độc hại)', score: 35, severity: 'high', category: 'malware' });
  }

  // ── URL ANALYSIS (enhanced — sử dụng email.links nếu có) ──────
  const bodyUrls = body.match(/https?:\/\/[^\s"'<>]+/g) || [];
  const allUrls = [...new Set([...(email.links || []), ...bodyUrls])].filter(u => u && u.startsWith('http'));
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'short.io', 'cutt.ly', 'is.gd', 'rb.gy', 't.ly', 'clck.ru'];

  // Phân tích từng URL bằng heuristics nhanh
  let urlDangerScore = 0;
  let urlDangerCount = 0;
  for (const u of allUrls.slice(0, 10)) {
    try {
      const parsed = new URL(u);
      const hostname = parsed.hostname.toLowerCase();
      // IP address URL
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
        urlDangerScore += 35;
        urlDangerCount++;
        scoreComponents.push({ type: 'link', text: `URL dùng địa chỉ IP: ${hostname}`, score: 35, severity: 'high', category: 'link' });
      }
      // Bad TLD
      const badTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.download', '.work', '.loan', '.pw', '.zip'];
      const tldHit = badTlds.find(t => hostname.endsWith(t));
      if (tldHit) {
        urlDangerScore += 25;
        urlDangerCount++;
        scoreComponents.push({ type: 'link', text: `URL có TLD nguy hiểm: ${tldHit} (${hostname})`, score: 25, severity: 'high', category: 'link' });
      }
      // URL shortener
      if (shorteners.some(s => hostname.includes(s))) {
        urlDangerScore += 18;
        urlDangerCount++;
        scoreComponents.push({ type: 'link', text: `URL rút gọn đáng ngờ: ${hostname}`, score: 18, severity: 'medium', category: 'link' });
      }
      // Brand + dangerous keyword in domain
      const dangerKw = ['-secure', '-verify', '-login', '-auth', '-update', '-confirm', '-account', '-banking'];
      const brandNames = ['paypal', 'google', 'apple', 'microsoft', 'amazon', 'facebook', 'netflix', 'vietcombank', 'techcombank', 'bidv', 'momo', 'shopee'];
      for (const brand of brandNames) {
        if (hostname.includes(brand) && dangerKw.some(kw => hostname.includes(kw))) {
          urlDangerScore += 40;
          urlDangerCount++;
          scoreComponents.push({ type: 'link', text: `URL giả mạo brand "${brand}": ${hostname}`, score: 40, severity: 'critical', category: 'link' });
          break;
        }
      }
      // HTTP (not HTTPS) cho trang nhạy cảm
      const sensitiveKw = ['login', 'signin', 'account', 'bank', 'payment', 'verify'];
      if (parsed.protocol === 'http:' && sensitiveKw.some(k => u.toLowerCase().includes(k))) {
        urlDangerScore += 20;
        scoreComponents.push({ type: 'link', text: `URL HTTP không bảo mật cho trang nhạy cảm`, score: 20, severity: 'high', category: 'link' });
      }
    } catch { /* invalid URL, skip */ }
  }
  // Fallback: nếu không phân tích riêng lẻ, vẫn kiểm tra pattern cũ
  if (urlDangerCount === 0) {
    const suspiciousUrls = allUrls.filter(u => shorteners.some(s => u.includes(s)) || /https?:\/\/\d+\.\d+/.test(u));
    if (suspiciousUrls.length > 0) {
      scoreComponents.push({ type: 'link', text: `${suspiciousUrls.length} URL rút gọn/IP đáng ngờ trong nội dung`, score: 22, severity: 'medium', category: 'link' });
    }
  }
  if (/data:text|javascript:/i.test(body)) {
    scoreComponents.push({ type: 'link', text: 'URL bị obfuscate (data:/javascript:)', score: 45, severity: 'critical', category: 'link' });
  }

  // ── STYLE & SPAM ───────────────────────────────────
  const subjectRaw = email.subject || '';
  const capsRatio = subjectRaw.replace(/[^A-Z]/g, '').length / Math.max(1, subjectRaw.replace(/\s/g, '').length);
  if (capsRatio > 0.65 && subjectRaw.length > 10) {
    scoreComponents.push({ type: 'style', text: 'Tiêu đề VIẾT HOA BẤT THƯỜNG', score: 8, severity: 'low', category: 'style' });
  }
  const exclCount = (subjectRaw.match(/!/g) || []).length;
  if (exclCount >= 4) {  // tăng ngưỡng từ 3 lên 4
    scoreComponents.push({ type: 'style', text: `${exclCount} dấu chấm than liên tiếp`, score: 6, severity: 'low', category: 'style' });
  }

  // ── PRIZE/SCAM COMBO ──────────────────────────────
  // Phải có cả 2 dấu hiệu mới tính: trúng thưởng + yêu cầu click cụ thể
  if (/congratulations|chúc mừng|trúng thưởng/i.test(full) && /click (here|below|link).*now|nhấp (vào liên kết|đây ngay)/i.test(full)) {
    scoreComponents.push({ type: 'scam', text: 'Combo trúng thưởng + link yêu cầu click ngay', score: 48, severity: 'high', category: 'scam' });
  }

  // ── SCORE CALCULATION ─────────────────────────────
  // Deduplicate by category (keep highest score per category)
  const byCategory = {};
  for (const c of scoreComponents) {
    const catKey = c.category || c.type;
    if (!byCategory[catKey] || c.score > byCategory[catKey].score) byCategory[catKey] = c;
  }
  const deduped = Object.values(byCategory);

  // Weighted sum with diminishing returns
  let totalScore = 0;
  const sorted = deduped.sort((a, b) => b.score - a.score);
  sorted.forEach((c, i) => {
    const diminish = Math.pow(0.80, i);  // giảm từ 0.85 xuống 0.80 — ít tích lũy hơn
    totalScore += c.score * diminish;
  });

  // Category multipliers (chỉ áp dụng khi có combo nguy hiểm thực sự)
  const catPresent = new Set(deduped.map(c => c.category));
  if (catPresent.has('credential') && catPresent.has('spoofing')) totalScore *= 1.20;
  if (catPresent.has('malware')) totalScore *= 1.12;
  if (catPresent.has('scam') && catPresent.has('urgency') && catPresent.has('credential')) totalScore *= 1.10;

  const finalScore = Math.min(100, Math.round(totalScore));

  // Ngưỡng được nâng lên: 65% PHISHING, 35% SUSPICIOUS
  // Và cần ≥2 category threats để gọi PHISHING (tránh single-signal false positive)
  const thresholds = S.settings.aggressiveMode ? { p: 40, s: 20 } : { p: 65, s: 35 };
  let riskLevel;
  if (finalScore >= thresholds.p && (S.settings.aggressiveMode || catPresent.size >= 2)) {
    riskLevel = 'PHISHING';
  } else if (finalScore >= thresholds.s) {
    riskLevel = 'SUSPICIOUS';
  } else {
    riskLevel = 'SAFE';
  }

  return {
    riskLevel,
    riskPercent: finalScore,
    threats: sorted.slice(0, 12),
    source: 'weighted-local-engine',
    confidence: 65,
    analysisTime: Date.now() - t0,
    categoryBreakdown: Object.fromEntries([...catPresent].map(c => [c, deduped.filter(d => d.category === c).reduce((s, d) => s + d.score, 0)])),
    timestamp: now()
  };
}




// ── LOOKALIKE DOMAIN DETECTION (Enhanced) ────────────────────
function detectLookalike(sender, subject = '') {
  const domain = extractDomain(sender);
  if (!domain) return null;

  const brands = {
    'paypal': ['paypa1', 'paypai', 'paypa-l', 'pay-pal', 'paypall'],
    'google': ['g00gle', 'go0gle', 'googie', 'g0ogle', 'gooogle'],
    'apple': ['app1e', 'appie', 'aple', 'appl3'],
    'microsoft': ['m1crosoft', 'microsoift', 'micros0ft'],
    'amazon': ['amaz0n', 'amzon', 'arnazon'],
    'facebook': ['faceb00k', 'faceboook', 'facebook-login'],
    'vietcombank': ['v1etcombank', 'vietcom-bank', 'vietcombankk'],
    'techcombank': ['t3chcombank', 'techcom-bank'],
    'shopee': ['sh0pee', 'shopeee', 'shopees'],
    'netflix': ['netfl1x', 'netfliix', 'net-flix'],
  };

  // Exact match is fine
  for (const [brand, fakes] of Object.entries(brands)) {
    if (domain.includes(brand)) continue;
    if (fakes.some(f => domain.includes(f))) return `${domain} (giả mạo ${brand})`;
  }

  // Homograph substitutions
  const subs = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', 'vv': 'w', 'rn': 'm' };
  let normalized = domain;
  for (const [fake, real] of Object.entries(subs)) normalized = normalized.replaceAll(fake, real);

  for (const brand of Object.keys(brands)) {
    if (normalized.includes(brand) && !domain.includes(brand)) {
      return `${domain} (giả mạo ${brand})`;
    }
  }

  // Domain with extra words like paypal-secure.com, google-auth.com
  const dangerousPatterns = ['-secure', '-verify', '-login', '-auth', '-update', '-confirm', '-support', '-help', '-account'];
  for (const brand of Object.keys(brands)) {
    if (domain.includes(brand)) {
      const suspicious = dangerousPatterns.some(p => domain.includes(p));
      if (suspicious) return `${domain} (${brand} với subdomain đáng ngờ)`;
    }
  }

  return null;
}

// ══════════════════════════════════════════════════════════════
// GEMINI AI ENHANCED — v7 Prompt Engineering
// ══════════════════════════════════════════════════════════════
async function callGeminiEnhanced(email, localHints) {
  try {
    const model = S.settings.useGemini2 ? 'geminiFlash' : S.settings.useGeminiPro ? 'geminiPro' : 'geminiFlash15';
    const endpoint = `${ENDPOINTS[model]}?key=${S.settings.geminiKey}`;

    const localContext = localHints.threats.length > 0
      ? `\n## Local Rule Engine đã phát hiện:\n${localHints.threats.slice(0, 4).map(t => `- [${t.category}/${t.severity}] ${t.text} (score: ${t.score})`).join('\n')}`
      : '';

    const emailLinks = (email.links || []).slice(0, 8).join('\n') || 'Không có link';
    const emailBody = (email.body || '').substring(0, 1800);

    const prompt = `Bạn là hệ thống AI bảo mật email cấp doanh nghiệp, chuyên phân tích phishing cho người dùng Việt Nam.

## EMAIL CẦN PHÂN TÍCH:
- **Từ**: ${email.sender || 'Unknown'}
- **Tiêu đề**: ${email.subject || 'No subject'}
- **Nội dung** (${emailBody.length} ký tự):
\`\`\`
${emailBody}
\`\`\`
- **Links tìm thấy**:
${emailLinks}
${localContext}

## YÊU CẦU PHÂN TÍCH:
Hãy phân tích toàn diện email này theo các tiêu chí sau:

1. **Kỹ thuật lừa đảo** (spear phishing, BEC, credential harvesting, malware delivery)
2. **Chỉ số social engineering** (urgency, authority, fear, reward)
3. **Dấu hiệu kỹ thuật** (domain spoofing, header anomalies, link mismatch)
4. **Ngữ cảnh Việt Nam** (mạo danh ngân hàng VN, dịch vụ VN, cơ quan chính phủ VN)
5. **Confidence** dựa trên lượng evidence có sẵn

## FORMAT JSON (trả về JSON thuần, KHÔNG có markdown):
{
  "riskLevel": "SAFE|SUSPICIOUS|PHISHING",
  "riskPercent": 0-100,
  "confidence": 0-100,
  "attackType": "phishing|bec|malware|spam|scam|safe",
  "summary": "Tóm tắt ngắn gọn bằng tiếng Việt (1-2 câu)",
  "threats": [
    {
      "type": "credential|financial|spoofing|urgency|link|domain|malware|scam|social_engineering",
      "text": "Mô tả chi tiết mối đe dọa",
      "severity": "low|medium|high|critical",
      "score": 0-60,
      "evidence": "Bằng chứng cụ thể từ email"
    }
  ],
  "indicators": ["Điểm chú ý 1", "Điểm chú ý 2", "..."],
  "recommendation": "Khuyến nghị hành động cho người dùng"
}`;

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.15,
          maxOutputTokens: 1200,
          responseMimeType: 'application/json'
        },
        safetySettings: [
          { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_NONE' }
        ]
      }),
      signal: AbortSignal.timeout(12000)
    });

    if (!response.ok) {
      log('warn', 'gemini_api_error', { status: response.status });
      return null;
    }

    const data = await response.json();
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!text) return null;

    const clean = text.replace(/```json?|```/g, '').trim();
    const parsed = JSON.parse(clean);

    if (!parsed.riskLevel || typeof parsed.riskPercent !== 'number') return null;

    return {
      riskLevel: parsed.riskLevel,
      riskPercent: Math.min(100, Math.max(0, parsed.riskPercent)),
      confidence: Math.min(100, Math.max(0, parsed.confidence || 70)),
      threats: (parsed.threats || []).map(t => ({
        ...t, score: t.score || 20,
        category: t.type
      })),
      summary: parsed.summary,
      indicators: parsed.indicators || [],
      recommendation: parsed.recommendation,
      attackType: parsed.attackType,
      source: `gemini-${model}`
    };
  } catch (err) {
    log('error', 'gemini_exception', { error: err.message });
    return null;
  }
}

// ── ASP.NET Backend ───────────────────────────────────────────
async function callBackend(email) {
  try {
    const url = S.settings.backendUrl || 'http://localhost:5001';
    const res = await fetch(`${url}/api/phishing/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sender: email.sender, subject: email.subject,
        body: (email.body || '').substring(0, 3000),
        links: email.links || [], timestamp: now()
      }),
      signal: AbortSignal.timeout(6000)
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (data?.riskLevel) {
      return { ...data, source: 'aspnet-backend' };
    }
    return null;
  } catch {
    return null;
  }
}

// ── Safe Browsing ─────────────────────────────────────────────
async function sbCheck(urls, key) {
  try {
    const res = await fetch(`${ENDPOINTS.safeBrowsing}?key=${key}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'phishguard-enterprise', clientVersion: VERSION },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: urls.map(u => ({ url: u }))
        }
      }),
      signal: AbortSignal.timeout(5000)
    });
    const d = await res.json();
    return d.matches || [];
  } catch { return []; }
}

// ── VirusTotal ────────────────────────────────────────────────
async function vtCheckDomain(domain, key) {
  try {
    const res = await fetch(`${ENDPOINTS.virusTotal}/domains/${domain}`, {
      headers: { 'x-apikey': key },
      signal: AbortSignal.timeout(7000)
    });
    if (!res.ok) return null;
    const d = await res.json();
    const stats = d.data?.attributes?.last_analysis_stats || {};
    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0
    };
  } catch { return null; }
}

// ══════════════════════════════════════════════════════════════
// URLHaus (abuse.ch) — Malware URL Database
// Không cần API key. Database cộng đồng chứa hàng triệu URL malware.
// Docs: https://urlhaus-api.abuse.ch/
// ══════════════════════════════════════════════════════════════
async function urlhausCheck(url) {
  try {
    const res = await fetch(ENDPOINTS.urlhaus, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `url=${encodeURIComponent(url)}`,
      signal: AbortSignal.timeout(6000)
    });
    if (!res.ok) return null;
    const d = await res.json();

    // query_status: 'is_page' = found, 'no_results' = not found
    if (d.query_status === 'no_results') return { status: 'safe', source: 'urlhaus' };

    // url_status: 'online' / 'offline' / 'unknown'
    const isActive = d.url_status === 'online';
    const threatType = d.threat || 'malware';
    const tags = (d.tags || []).join(', ');

    return {
      status: isActive ? 'malicious' : 'suspicious',
      threatType,
      urlStatus: d.url_status,
      tags,
      dateAdded: d.date_added,
      source: 'urlhaus'
    };
  } catch (err) {
    log('debug', 'urlhaus_error', { error: err.message });
    return null;
  }
}

// ══════════════════════════════════════════════════════════════
// AbuseIPDB — IP Address Reputation Check
// Free: 1,000 req/ngày. Cần API key tại https://www.abuseipdb.com
// Kiểm tra IP của mail server sender có trong blacklist toàn cầu không.
// ══════════════════════════════════════════════════════════════
async function abuseIPDBCheck(domain, key) {
  try {
    // Resolve domain → IP qua DNS-over-HTTPS (Cloudflare)
    const dnsRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`, {
      headers: { 'Accept': 'application/dns-json' },
      signal: AbortSignal.timeout(4000)
    });
    if (!dnsRes.ok) return null;
    const dnsData = await dnsRes.json();
    const ip = dnsData.Answer?.find(r => r.type === 1)?.data;
    if (!ip) return null;

    // Check IP reputation trên AbuseIPDB
    const res = await fetch(`${ENDPOINTS.abuseIPDB}?ipAddress=${ip}&maxAgeInDays=90&verbose`, {
      headers: {
        'Key': key,
        'Accept': 'application/json'
      },
      signal: AbortSignal.timeout(6000)
    });
    if (!res.ok) return null;
    const d = await res.json();
    const data = d.data || {};

    return {
      ip,
      abuseScore: data.abuseConfidenceScore || 0,   // 0–100: xác suất là malicious
      totalReports: data.totalReports || 0,
      countryCode: data.countryCode || '',
      usageType: data.usageType || '',               // 'Data Center/Web Hosting', 'ISP/Hosting', ...
      isp: data.isp || '',
      isPublic: data.isPublic,
      lastReported: data.lastReportedAt || null,
      source: 'abuseipdb'
    };
  } catch (err) {
    log('debug', 'abuseipdb_error', { error: err.message });
    return null;
  }
}

// ══════════════════════════════════════════════════════════════
// IPQualityScore — Email Validation & Fraud Detection
// Free: 5,000 req/tháng. Đăng ký key tại https://www.ipqualityscore.com
// Kiểm tra sender email: disposable? compromised? spam trap? fraud score?
// ══════════════════════════════════════════════════════════════
async function ipqsEmailCheck(email, key) {
  try {
    const encodedEmail = encodeURIComponent(email);
    const res = await fetch(`${ENDPOINTS.ipqs}/${key}/${encodedEmail}?timeout=3&fast=1&abuse_strictness=1`, {
      signal: AbortSignal.timeout(7000)
    });
    if (!res.ok) return null;
    const d = await res.json();
    if (!d.success) return null;

    return {
      fraudScore: d.fraud_score || 0,          // 0–100: điểm nguy cơ tổng hợp
      valid: d.valid,                           // email có tồn tại thật không
      disposable: d.disposable,                 // email dùng một lần (tempmail)
      honeypot: d.honeypot,                     // bẫy spam
      recentAbuse: d.recent_abuse,              // bị báo cáo gần đây
      spamTrap: d.spam_trap_score,             // 'none' / 'low' / 'medium' / 'high'
      leaked: d.leaked,                         // có trong database breach không
      domain: d.domain_age?.human || '',        // tuổi domain gửi mail
      mxRecords: d.mx_records,                  // có MX record hợp lệ không
      source: 'ipqs'
    };
  } catch (err) {
    log('debug', 'ipqs_error', { error: err.message });
    return null;
  }
}

// ── URL Context Menu Check ────────────────────────────────────
async function checkUrl(url) {
  const results = [];

  if (S.settings.sbKey) {
    const hits = await sbCheck([url], S.settings.sbKey);
    if (hits.length) return { url, status: 'malicious', reason: 'Google Safe Browsing', source: 'safe-browsing', hits };
  }
  if (S.settings.vtKey) {
    try {
      const enc = btoa(url).replace(/=+$/, '');
      const res = await fetch(`${ENDPOINTS.virusTotal}/urls/${enc}`, { headers: { 'x-apikey': S.settings.vtKey } });
      if (res.ok) {
        const d = await res.json();
        const m = d.data?.attributes?.last_analysis_stats?.malicious || 0;
        if (m > 1) return { url, status: 'malicious', reason: `VirusTotal: ${m} engines`, source: 'virustotal' };
        if (m === 1) return { url, status: 'suspicious', reason: 'VirusTotal: 1 engine cảnh báo', source: 'virustotal' };
      }
    } catch { }
  }

  const local = detectLookalike(url, '');
  if (local) return { url, status: 'suspicious', reason: `Domain giả mạo: ${local}`, source: 'local' };
  if (/https?:\/\/\d{1,3}\.\d{1,3}/.test(url)) return { url, status: 'malicious', reason: 'IP address URL', source: 'local' };
  const badTlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top'];
  if (badTlds.some(t => url.includes(t))) return { url, status: 'suspicious', reason: 'TLD đáng ngờ', source: 'local' };

  return { url, status: 'safe', source: 'local' };
}

// ══════════════════════════════════════════════════════════════
// URL DEEP ANALYSIS ENGINE v2
// 15+ heuristics + Gemini AI + VT URL scan + redirect chain
// ══════════════════════════════════════════════════════════════

// ── Shannon entropy để phát hiện domain ngẫu nhiên ────────────
function shannonEntropy(s) {
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  const len = s.length;
  return -Object.values(freq).reduce((sum, f) => {
    const p = f / len;
    return sum + p * Math.log2(p);
  }, 0);
}

// ── Phân tích heuristics thuần local cho một URL ──────────────
function urlHeuristics(rawUrl) {
  const threats = [];
  let score = 0;
  let parsed;

  try { parsed = new URL(rawUrl); } catch { return { score: 50, threats: [{ type: 'url', text: 'URL không hợp lệ / malformed', severity: 'high', score: 50 }] }; }

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl = rawUrl.toLowerCase();
  const path = parsed.pathname;
  const params = [...parsed.searchParams.keys()];

  // ── WHITELIST DOMAIN CHUẨN (SAFE DOMAINS) ──────────────
  // Tránh báo cáo nhầm các link bình thường thành suspicious/malicious
  const safeDomains = [
    'google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'github.com', 'microsoft.com',
    'apple.com', 'linkedin.com', 'twitter.com', 'x.com', 'instagram.com', 'tiktok.com',
    'netflix.com', 'amazon.com', 'wikipedia.org', 'yahoo.com', 'bing.com', 'reddit.com',
    'shopee.vn', 'lazada.vn', 'tiki.vn', 'zalo.me', 'vtv.vn', 'vnexpress.net', 'dantri.com.vn',
    'tuoitre.vn', 'thanhnien.vn', 'vietcombank.com.vn', 'techcombank.com.vn', 'mbbank.com.vn',
    'agribank.com.vn', 'bidv.com.vn', 'vpbank.com.vn', 'tpbank.vn', 'acb.com.vn',
    'chinhphu.vn', 'gov.vn', 'edu.vn', 'gstatic.com', 'googleusercontent.com'
  ];

  // Nếu domain (hoặc subdomain cấp cao) nằm trong danh sách an toàn tuyệt đối
  const isSafeDomain = safeDomains.some(safe => hostname === safe || hostname.endsWith('.' + safe));
  if (isSafeDomain) {
    // Với domain an toàn, chỉ đánh dấu nếu path/query có vấn đề RẤT nghiêm trọng 
    // như open redirect mập mờ hoặc file exe, nếu không cho qua an toàn.
    const dangerExt = /\.(exe|bat|cmd|scr|pif|vbs|ps1|msi)(\?|$)/i;
    if (dangerExt.test(path)) {
      threats.push({ type: 'url', text: `Domain uy tín nhưng chứa file thực thi nghi ngờ`, severity: 'high', score: 45 });
      score += 45;
    }
    const isHttp = parsed.protocol === 'http:';
    if (isHttp && fullUrl.includes('login')) {
      threats.push({ type: 'url', text: `Domain uy tín nhưng dùng HTTP không bảo mật`, severity: 'medium', score: 20 });
      score += 20;
    }

    // Nếu vẫn sạch, trả về safe ngay lập tức
    if (score === 0) return { score: 0, status: 'safe', threats: [] };
  }


  // 1. IP address thay vì domain → rất nguy hiểm
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    threats.push({ type: 'url', text: `URL dùng địa chỉ IP thay vì domain: ${hostname}`, severity: 'critical', score: 60 });
    score += 60;
  }

  // 2. Bad TLD mở rộng (40+ TLD nguy hiểm)
  const badTlds = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.download', '.work',
    '.loan', '.pw', '.cc', '.date', '.win', '.stream', '.party', '.racing', '.review',
    '.science', '.faith', '.trade', '.webcam', '.accountant', '.men', '.creditcard',
    '.zip', '.mov', '.onion', '.bit', '.biz' // .zip và .mov bị lợi dụng
  ];
  const tldHit = badTlds.find(t => hostname.endsWith(t));
  if (tldHit) {
    threats.push({ type: 'url', text: `TLD rủi ro cao: ${tldHit}`, severity: 'high', score: 32 });
    score += 32;
  }

  // 3. Shannon entropy domain cao → tên ngẫu nhiên (DGA malware)
  const domainPart = hostname.split('.')[0];
  const entropy = shannonEntropy(domainPart);
  if (entropy > URL_SCAN_CONFIG.highEntropyThresh && domainPart.length > 8) {
    threats.push({ type: 'url', text: `Domain entropy cao (${entropy.toFixed(2)}) — có thể DGA malware`, severity: 'high', score: 38 });
    score += 38;
  }

  // 4. Quá nhiều subdomain (prefix abuse)
  const subdomainCount = hostname.split('.').length - 2;
  if (subdomainCount >= URL_SCAN_CONFIG.maxSubdomains) {
    threats.push({ type: 'url', text: `Chuỗi subdomain bất thường: ${hostname}`, severity: 'medium', score: 22 });
    score += 22;
  }

  // 5. URL rất dài → thường dùng để obfuscate
  if (rawUrl.length > 300) {
    threats.push({ type: 'url', text: `URL quá dài (${rawUrl.length} ký tự) — dấu hiệu obfuscation`, severity: 'medium', score: 18 });
    score += 18;
  }

  // 6. Path depth quá sâu
  const pathDepth = path.split('/').filter(Boolean).length;
  if (pathDepth > URL_SCAN_CONFIG.maxPathDepth) {
    threats.push({ type: 'url', text: `Path URL quá sâu (${pathDepth} cấp)`, severity: 'low', score: 12 });
    score += 12;
  }

  // 7. Open redirect params trong query string
  const redirectParams = ['url', 'redirect', 'next', 'goto', 'link', 'target', 'redir', 'return', 'returnUrl', 'destination', 'out'];
  const openRedirect = params.find(p => redirectParams.includes(p.toLowerCase()));
  if (openRedirect) {
    const val = parsed.searchParams.get(openRedirect) || '';
    if (val.startsWith('http') || val.startsWith('//')) {
      threats.push({ type: 'url', text: `Open redirect parameter: ?${openRedirect}=${val.substring(0, 50)}`, severity: 'high', score: 40 });
      score += 40;
    }
  }

  // 8. File extension nguy hiểm trong URL path
  const dangerExt = /\.(exe|bat|cmd|scr|pif|vbs|ps1|msi|jar|apk|dmg|sh|dll|hta|jse|wsf)(\?|$)/i;
  if (dangerExt.test(path)) {
    threats.push({ type: 'url', text: `URL trỏ trực tiếp đến file thực thi nguy hiểm`, severity: 'critical', score: 65 });
    score += 65;
  }

  // 9. Data URI hoặc javascript: protocol
  if (/^(data:|javascript:|vbscript:)/i.test(rawUrl)) {
    threats.push({ type: 'url', text: 'Protocol nguy hiểm trong URL (data:/javascript:)', severity: 'critical', score: 75 });
    score += 75;
  }

  // 10. URL rút gọn (shortener services)
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.io', 'rebrand.ly',
    'cutt.ly', 'is.gd', 'buff.ly', 'tiny.cc', 'clck.ru', 'rb.gy', 'dub.sh', 't.ly'];
  if (shorteners.some(s => hostname.includes(s))) {
    threats.push({ type: 'url', text: `Dịch vụ rút gọn URL: ${hostname} — không biết URL đích`, severity: 'high', score: 28 });
    score += 28;
  }

  // 11. Homograph Unicode trong domain
  const hasUnicode = /[^\u0000-\u007F]/.test(hostname);
  if (hasUnicode) {
    threats.push({ type: 'url', text: `Domain chứa ký tự Unicode (homograph attack): ${hostname}`, severity: 'critical', score: 55 });
    score += 55;
  }

  // 12. Keyword injection: brand name + thêm từ nguy hiểm trong domain
  const dangerKeywords = ['-secure', '-verify', '-login', '-auth', '-update', '-confirm', '-support',
    '-account', '-bank', '-banking', '-signin', '-wallet', '-payment', '-invoice', '-alert', '-reset'];
  const brands = ['paypal', 'google', 'apple', 'microsoft', 'amazon', 'facebook', 'netflix',
    'vietcombank', 'techcombank', 'bidv', 'agribank', 'momo', 'zalopay', 'shopee', 'lazada'];
  for (const brand of brands) {
    if (hostname.includes(brand) && dangerKeywords.some(kw => hostname.includes(kw))) {
      threats.push({ type: 'url', text: `Domain kết hợp brand "${brand}" + từ khóa lừa đảo`, severity: 'critical', score: 58 });
      score += 58;
      break;
    }
  }

  // 13. Lookalike domain (tái dùng detectLookalike)
  const lookalike = detectLookalike(hostname, '');
  if (lookalike) {
    threats.push({ type: 'url', text: `Domain giả mạo phát hiện: ${lookalike}`, severity: 'critical', score: 52 });
    score += 52;
  }

  // 14. Nhiều query params lạ (tracking + payload)
  if (params.length > 12) {
    threats.push({ type: 'url', text: `URL có ${params.length} query params — bất thường`, severity: 'low', score: 10 });
    score += 10;
  }

  // 15. HTTP (không HTTPS) cho các trang nhạy cảm
  const sensitiveKeywords = ['login', 'signin', 'account', 'bank', 'payment', 'secure', 'verify'];
  if (parsed.protocol === 'http:' && sensitiveKeywords.some(k => fullUrl.includes(k))) {
    threats.push({ type: 'url', text: `HTTP (không bảo mật) cho trang nhạy cảm: ${hostname}`, severity: 'high', score: 35 });
    score += 35;
  }

  const capped = Math.min(100, score);
  const status = capped >= 45 ? 'malicious' : capped >= 20 ? 'suspicious' : 'safe';
  return { score: capped, status, threats };
}

// ── Phân tích sâu một URL đơn (heuristics + API) ─────────────
async function analyzeUrlDeep(rawUrl) {
  if (!rawUrl) return { url: rawUrl, status: 'safe', score: 0, threats: [], source: 'local' };

  const h = urlHeuristics(rawUrl);
  let result = { url: rawUrl, status: h.status, score: h.score, threats: h.threats, source: 'url-heuristics' };

  // Safe Browsing check
  if (S.settings.sbKey) {
    const hits = await sbCheck([rawUrl], S.settings.sbKey);
    if (hits.length > 0) {
      result.status = 'malicious';
      result.score = Math.min(100, result.score + 50);
      result.threats.unshift({ type: 'url', text: `Google Safe Browsing: ${hits[0].threatType || 'THREAT'}`, severity: 'critical', score: 50 });
      result.source = 'safe-browsing';
    }
  }

  // VirusTotal URL check (không chỉ domain)
  if (S.settings.vtKey && result.status !== 'malicious') {
    const vtR = await vtCheckUrlFull(rawUrl, S.settings.vtKey);
    if (vtR) {
      if (vtR.malicious > 3) {
        result.status = 'malicious';
        result.score = Math.min(100, result.score + Math.min(45, vtR.malicious * 8));
        result.threats.unshift({ type: 'url', text: `VirusTotal: ${vtR.malicious} engines cảnh báo MALICIOUS`, severity: 'critical', score: Math.min(45, vtR.malicious * 8) });
        result.source = 'virustotal-url';
      } else if (vtR.malicious > 0 || vtR.suspicious > 2) {
        result.status = result.status === 'safe' ? 'suspicious' : result.status;
        result.score = Math.min(100, result.score + 20);
        result.threats.push({ type: 'url', text: `VirusTotal: ${vtR.malicious}M/${vtR.suspicious}S engines cảnh báo`, severity: 'high', score: 20 });
      }
      result.vtStats = vtR;
      S.stats.vtCalls++;
    }
  }

  // Cập nhật stats
  S.stats.urlsScanned = (S.stats.urlsScanned || 0) + 1;
  if (result.status === 'malicious') S.stats.urlsMalicious = (S.stats.urlsMalicious || 0) + 1;
  else if (result.status === 'suspicious') S.stats.urlsSuspicious = (S.stats.urlsSuspicious || 0) + 1;

  log('debug', 'url_deep_analyzed', { url: rawUrl.substring(0, 80), status: result.status, score: result.score });
  return result;
}

// ── Batch URL scanner — song song, tối đa 20 URLs ────────────
async function analyzeUrlBatch(urls, emailContext = '') {
  if (!Array.isArray(urls) || urls.length === 0) return [];

  const unique = [...new Set(urls.filter(u => u && u.startsWith('http')))].slice(0, 30);
  log('info', 'url_batch_start', { count: unique.length });

  // Chạy heuristics trước (đồng thời, không cần API)
  const hResults = unique.map(url => ({ url, ...urlHeuristics(url) }));

  // Gemini phân tích context URL nếu có key
  let geminiUrlMap = {};
  if (S.settings.geminiKey && unique.length > 0) {
    const batchResult = await callGeminiUrlScan(unique.slice(0, URL_SCAN_CONFIG.geminiUrlBatch), emailContext);
    if (batchResult) geminiUrlMap = batchResult;
  }

  // API checks cho URLs nghi ngờ (score > 15 hoặc Gemini đánh dấu)
  const results = await Promise.all(hResults.map(async hr => {
    const gemini = geminiUrlMap[hr.url];
    let final = { ...hr, source: 'url-heuristics' };

    // Merge Gemini result nếu có
    if (gemini) {
      const mergedScore = Math.round(hr.score * 0.4 + gemini.score * 0.6);
      final = {
        ...final,
        score: Math.min(100, mergedScore),
        status: mergedScore >= 45 ? 'malicious' : mergedScore >= 20 ? 'suspicious' : 'safe',
        threats: [...(gemini.threats || []), ...hr.threats].slice(0, 8),
        geminiReason: gemini.reason,
        source: 'url-hybrid'
      };
    }

    // Safe Browsing chỉ cho URL đã bị nghi ngờ (tiết kiệm quota)
    if (final.score >= 20 && S.settings.sbKey) {
      const hits = await sbCheck([hr.url], S.settings.sbKey);
      if (hits.length > 0) {
        final.status = 'malicious';
        final.score = Math.min(100, final.score + 40);
        final.threats.unshift({ type: 'url', text: `Google Safe Browsing THREAT`, severity: 'critical', score: 40 });
        final.source = 'safe-browsing';
      }
    }

    return final;
  }));

  // Cập nhật stats tổng
  S.stats.urlsScanned = (S.stats.urlsScanned || 0) + results.length;
  S.stats.urlsMalicious = (S.stats.urlsMalicious || 0) + results.filter(r => r.status === 'malicious').length;
  S.stats.urlsSuspicious = (S.stats.urlsSuspicious || 0) + results.filter(r => r.status === 'suspicious').length;
  save();

  log('info', 'url_batch_done', { total: results.length, malicious: results.filter(r => r.status === 'malicious').length });
  return results;
}

// ── Gemini phân tích batch URLs ────────────────────────────────
async function callGeminiUrlScan(urls, emailContext) {
  try {
    const endpoint = `${ENDPOINTS.geminiFlash}?key=${S.settings.geminiKey}`;
    const prompt = `Bạn là hệ thống phân tích URL bảo mật. Phân tích TỪNG URL sau và trả JSON.

## CONTEXT EMAIL:
${emailContext ? emailContext.substring(0, 300) : 'Không có context'}

## DANH SÁCH URLs cần phân tích:
${urls.map((u, i) => `${i + 1}. ${u}`).join('\n')}

## YÊU CẦU:
Với mỗi URL, đánh giá:
- Domain có phải lookalike/typosquat không?
- URL có chứa keyword lừa đảo không?
- Path/params có bất thường không?
- URL có trỏ đến landing page phishing không?

## RETURN FORMAT (JSON array, không markdown):
[
  {
    "url": "url đầy đủ",
    "score": 0-100,
    "status": "safe|suspicious|malicious",
    "reason": "Lý do ngắn bằng tiếng Việt",
    "threats": [{"type": "url", "text": "mô tả", "severity": "low|medium|high|critical", "score": 0-60}]
  }
]`;

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.1, maxOutputTokens: 1500, responseMimeType: 'application/json' },
        safetySettings: [{ category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_NONE' }]
      }),
      signal: AbortSignal.timeout(15000)
    });

    if (!res.ok) return null;
    const data = await res.json();
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!text) return null;

    const parsed = JSON.parse(text.replace(/```json?|```/g, '').trim());
    if (!Array.isArray(parsed)) return null;

    // Convert array → map keyed by url
    const map = {};
    for (const item of parsed) {
      if (item.url) map[item.url] = item;
    }
    S.stats.geminiCalls++;
    log('debug', 'gemini_url_scan_done', { urls: parsed.length });
    return map;
  } catch (err) {
    log('error', 'gemini_url_scan_error', { error: err.message });
    return null;
  }
}

// ── VirusTotal URL scan đầy đủ (submit + get report) ─────────
async function vtCheckUrlFull(url, key) {
  try {
    // VT dùng base64url-encoded URL để lookup
    const encoded = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const res = await fetch(`${ENDPOINTS.virusTotal}/urls/${encoded}`, {
      headers: { 'x-apikey': key },
      signal: AbortSignal.timeout(8000)
    });

    if (res.status === 404) {
      // URL chưa có trong VT database — submit để scan
      try {
        const submitRes = await fetch(`${ENDPOINTS.virusTotal}/urls`, {
          method: 'POST',
          headers: { 'x-apikey': key, 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `url=${encodeURIComponent(url)}`,
          signal: AbortSignal.timeout(5000)
        });
        if (!submitRes.ok) return null;
        // Sau khi submit cần đợi 10-15s mới có kết quả → trả null ngay
        return null;
      } catch { return null; }
    }

    if (!res.ok) return null;
    const d = await res.json();
    const stats = d.data?.attributes?.last_analysis_stats || {};
    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      total: Object.values(stats).reduce((a, b) => a + b, 0)
    };
  } catch { return null; }
}



// ── Batch Analysis ────────────────────────────────────────────
async function analyzeBatch(emails) {
  const results = [];
  for (const e of (emails || [])) {
    results.push({ emailId: e.id, result: await analyzeEmail(e) });
    await delay(60);
  }
  log('info', 'batch_complete', { count: emails?.length || 0 });
  return results;
}

// ══════════════════════════════════════════════════════════════
// MEDIA SCANNER ENGINE — Gemini Vision AI
// Quét ảnh JPG/PNG/GIF/WebP và video frames trong email
// Phát hiện: QR code độc, logo giả mạo, trang đăng nhập giả
// ══════════════════════════════════════════════════════════════

// ── Danh sách MIME type hỗ trợ cho Gemini Vision ─────────────
const SUPPORTED_MEDIA = {
  image: ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp'],
  video: ['video/mp4', 'video/webm', 'video/ogg', 'video/avi']
};

// ── Fetch ảnh từ URL → base64 (chỉ fetch ảnh public) ─────────
async function fetchImageAsBase64(imageUrl) {
  try {
    const url = new URL(imageUrl);
    // Chỉ fetch HTTPS, bỏ qua data URI (đã có sẵn base64)
    if (imageUrl.startsWith('data:')) {
      const [meta, b64] = imageUrl.split(',');
      const mime = meta.match(/data:([^;]+)/)?.[1] || 'image/jpeg';
      return { base64: b64, mimeType: mime };
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;

    const res = await fetch(imageUrl, {
      signal: AbortSignal.timeout(8000),
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; PhishGuard/7.1)' }
    });
    if (!res.ok) return null;

    const contentType = res.headers.get('content-type') || 'image/jpeg';
    const mimeType = contentType.split(';')[0].trim();
    if (![...SUPPORTED_MEDIA.image].includes(mimeType)) return null;

    // Giới hạn 4MB
    const blob = await res.blob();
    if (blob.size > 4 * 1024 * 1024) return null;

    return new Promise(resolve => {
      const reader = new FileReader();
      reader.onloadend = () => {
        const result = reader.result;
        const b64 = result.split(',')[1];
        resolve({ base64: b64, mimeType });
      };
      reader.onerror = () => resolve(null);
      reader.readAsDataURL(blob);
    });
  } catch { return null; }
}

// ── Gemini Vision (nâng cấp) — phân tích sâu 12 điểm ────────
async function callGeminiVision(base64Data, mimeType, contextHint = '') {
  if (!S.settings.geminiKey) return null;

  // Model fallback: thử lần lượt cho đến khi có quota
  const VISION_MODELS = [
    'gemini-1.5-flash',
    'gemini-1.5-flash-8b',
    'gemini-2.0-flash',
  ];

  const prompt = `Bạn là chuyên gia An ninh mạng AI — nhiệm vụ phân tích ảnh/frame từ email để phát hiện PHISHING và MALWARE. Hãy kiểm tra kỹ TỪNG chi tiết.

CONTEXT: ${contextHint || 'Ảnh/media trong email cần xét duyệt'}

=== 12 ĐIỂM PHÂN TÍCH BẮT BUỘC ===

1. QR CODE: Tìm mọi QR code (kể cả bị mờ hoặc một phần). Nếu thấy → đọc chính xác URL bên trong.

2. LOGO GIẢ MẠO: Logo ngân hàng VN (Vietcombank, BIDV, Techcombank, Agribank, MBBank, TPBank, Sacombank, VPBank, ACB, OCB, VIB, SHB, HDBank, Nam A Bank, MSB, SeABank, BVBank, ABBank, NCB, PVcomBank, Lien Viet Post Bank, Bac A Bank, Ocean Bank, GPBank, CB Bank)? Logo Tech (Google, Apple, Microsoft, Meta, PayPal, Amazon, Grab, Shopee, Lazada, Zalo, MoMo, VNPay, ZaloPay, ShopeePay, Moca)? Logo chính phủ VN (Bộ Công An, UBND, Thuế, Hải Quan)? Kiểm tra: sai tên, font chữ sai, màu sắc sai, chất lượng thấp, logo bị kéo dài/méo.

3. TRANG ĐĂNG NHẬP GIẢ: Có form nhập username/password/OTP/số thẻ/PIN không? Giao diện có giống một dịch vụ uy tín không? URL trong ảnh có khớp với thương hiệu không?

4. DỮ LIỆU NHẠY CẢM: Số thẻ (16 chữ số), số tài khoản ngân hàng, mã CVV/CVC (3-4 số), mã OTP, số CMND/CCCD, địa chỉ ví crypto, private key.

5. TEXT LỪA ĐẢO: Yêu cầu chuyển tiền gấp, thông báo trúng thưởng/nhận thưởng, "cập nhật thông tin hoặc bị khóa", yêu cầu mua thẻ cào/gift card, tạo panic/sợ hãi, hạn chót 24h/48h.

6. DEEPFAKE/CEO FRAUD: Ảnh người thật (nhà lãnh đạo, cán bộ, người nổi tiếng) kèm text yêu cầu chuyển tiền hoặc cung cấp thông tin.

7. WATERMARK GIẢ MẠO: Con dấu/chữ ký/watermark từ cơ quan nhà nước, tòa án, ngân hàng trên giấy tờ giả.

8. URL NGUY HIỂM TRONG ẢNH: Text URL trong ảnh nhìn giống domain uy tín nhưng sai chính tả (goog1e.com, vietcombank.vn.verify.tk...), domain lạ (.tk, .ml, .ga, .xyz), IP address.

9. MALWARE VISUAL CUE: Screenshot hướng dẫn tải file .exe/.apk, lệnh cmd/powershell, "enable macro", "allow content", "install this".

10. INVOICE/HÓA ĐƠN GIẢ: Hóa đơn giả với số tiền lớn, yêu cầu thanh toán qua link/QR.

11. ẢNH PRODUCT FAKE: Sản phẩm "quá rẻ" hoặc hàng giả thương hiệu để dụ click.

12. METADATA VISUAL: Chất lượng ảnh cực thấp (che giấu chi tiết), ảnh chụp màn hình (screenshot of screenshot), watermark bị xóa thô.

=== OUTPUT (JSON thuần, KHÔNG dùng markdown) ===
{
  "riskLevel": "SAFE|SUSPICIOUS|MALICIOUS",
  "riskScore": <0-100>,
  "confidence": <0-100>,
  "qrCodeFound": <boolean>,
  "qrCodeUrl": <string|null>,
  "logoDetected": <"bank_name"|"tech_brand"|null>,
  "logoFaked": <boolean>,
  "isFakeLoginPage": <boolean>,
  "hasSensitiveData": <boolean>,
  "sensitiveDataTypes": <["card_number"|"otp"|"password"|"account_number"|"national_id"|"crypto"]>,
  "hasDeepfake": <boolean>,
  "hasFakeDocument": <boolean>,
  "hasMalwareInstruction": <boolean>,
  "threats": [
    {
      "type": "qr|logo_fake|login_page|sensitive_data|scam_text|deepfake|fake_doc|malware_install|dangerous_url|fake_invoice|malicious_download",
      "text": "<mô tả chi tiết bằng tiếng Việt>",
      "severity": "low|medium|high|critical",
      "score": <0-60>,
      "evidence": "<bằng chứng cụ thể quan sát được trong ảnh>"
    }
  ],
  "extractedUrls": ["<url1>", "<url2>"],
  "extractedText": "<text quan trọng trong ảnh tối đa 300 ký tự>",
  "summary": "<tóm tắt ngắn bằng tiếng Việt>",
  "reasoning": "<lý do phân tích điểm rủi ro này>"
}`;

  for (const model of VISION_MODELS) {
    try {
      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${S.settings.geminiKey}`;
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{
            parts: [
              { text: prompt },
              { inlineData: { mimeType, data: base64Data } }
            ]
          }],
          generationConfig: {
            temperature: 0.05,      // rất thấp → deterministic
            maxOutputTokens: 1500,
            responseMimeType: 'application/json'
          },
          safetySettings: [
            { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_NONE' },
            { category: 'HARM_CATEGORY_HARASSMENT', threshold: 'BLOCK_NONE' },
            { category: 'HARM_CATEGORY_HATE_SPEECH', threshold: 'BLOCK_NONE' },
            { category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_NONE' }
          ]
        }),
        signal: AbortSignal.timeout(25000)
      });

      if (res.status === 429) { continue; }  // quota → thử model khác
      if (!res.ok) { log('warn', 'gemini_vision_error', { model, status: res.status }); continue; }

      const data = await res.json();
      const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!text) continue;

      // Parse JSON linh hoạt
      let parsed;
      try {
        const clean = text.replace(/```json?\s*|\s*```/g, '').trim();
        parsed = JSON.parse(clean);
      } catch {
        const m = text.match(/\{[\s\S]+\}/);
        if (!m) continue;
        parsed = JSON.parse(m[0]);
      }

      S.stats.geminiCalls++;
      log('info', 'gemini_vision_done', { model, riskLevel: parsed.riskLevel, score: parsed.riskScore, qr: parsed.qrCodeFound, threats: parsed.threats?.length });
      return parsed;

    } catch (err) {
      log('warn', 'gemini_vision_model_fail', { model, error: err.message });
      continue;
    }
  }

  log('warn', 'gemini_vision_all_failed', {});
  return null;
}


// ── Local image heuristics (không cần AI) ─────────────────────
function mediaUrlHeuristics(url, type) {
  if (!url) return { score: 0, threats: [] };
  const u = url.toLowerCase();
  const threats = [];
  let score = 0;

  // IP address URL
  if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(url)) {
    threats.push({ type: 'ip_url', text: 'Ảnh/media trỏ đến IP address thay vì domain', severity: 'high', score: 35 });
    score += 35;
  }
  // Suspicious TLD
  if (/\.(tk|ml|ga|cf|gq|pw|xyz|top|click|download|monster|onion)\//.test(u)) {
    threats.push({ type: 'bad_tld', text: 'Domain TLD đáng ngờ trong URL ảnh', severity: 'medium', score: 25 });
    score += 25;
  }
  // Base64 data URI → thường an toàn, không cộng điểm
  // Long query string có thể là tracking
  if ((url.match(/[?&]/g) || []).length > 5) {
    threats.push({ type: 'tracking', text: 'URL ảnh có nhiều tham số theo dõi', severity: 'low', score: 5 });
    score += 5;
  }
  // Pixel tracking (1x1)
  if (/[?&](w=1|h=1|width=1|height=1|1x1|pixel)/i.test(url)) {
    threats.push({ type: 'tracking_pixel', text: 'Tracking pixel 1×1 phát hiện (thu thập IP/địa chỉ)', severity: 'medium', score: 20 });
    score += 20;
  }
  // Known phishing patterns in path
  if (/(verify|confirm|secure|update|account|login|signin|banking|paypal|apple|google|amazon)/i.test(url) &&
    !/google\.com|apple\.com|microsoft\.com|amazon\.com|paypal\.com/i.test(url)) {
    threats.push({ type: 'phishing_path', text: 'URL ảnh chứa từ khóa đáng ngờ', severity: 'medium', score: 18 });
    score += 18;
  }
  return { score: Math.min(score, 100), threats };
}

// ── Phân tích file attachment (local heuristics + VirusTotal) ──
async function scanFileAttachment(fileInfo) {
  // fileInfo: { name, type, size, hash?, url? }
  const { name = '', type = '', size = 0 } = fileInfo;
  const nameLow = name.toLowerCase();
  const threats = [];
  let score = 0;

  // === Local heuristics cho file ===

  // Executable và script nguy hiểm nhất
  const EXE_EXTS = ['.exe', '.com', '.bat', '.cmd', '.pif', '.scr', '.msi', '.vbs', '.vbe',
    '.js', '.jse', '.wsf', '.wsh', '.ps1', '.ps2', '.psm1', '.reg', '.hta',
    '.cpl', '.msc', '.jar', '.apk', '.ipa', '.deb', '.rpm'];
  const ext = '.' + nameLow.split('.').pop();
  if (EXE_EXTS.includes(ext)) {
    threats.push({ type: 'attachment_exe', text: `File thực thi nguy hiểm: ${ext}`, severity: 'critical', score: 85 });
    score += 85;
  }

  // Archive có thể chứa malware
  else if (['.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.img'].includes(ext)) {
    threats.push({ type: 'archive_suspicious', text: `File nén có thể chứa malware: ${ext}`, severity: 'medium', score: 30 });
    score += 30;
  }

  // Office macro-enabled
  else if (['.docm', '.xlsm', '.pptm', '.dotm', '.xlam', '.xltm'].includes(ext)) {
    threats.push({ type: 'macro_doc', text: `File Office macro-enabled: ${ext} — thường được dùng để phát tán malware`, severity: 'high', score: 65 });
    score += 65;
  }

  // Office thông thường có thể chứa macro ẩn
  else if (['.doc', '.xls', '.ppt', '.dot', '.xlt', '.pot'].includes(ext)) {
    threats.push({ type: 'office_old_format', text: `File Office định dạng cũ có thể chứa macro: ${ext}`, severity: 'medium', score: 25 });
    score += 25;
  }

  // PDF có thể có JavaScript/exploit
  else if (ext === '.pdf') {
    // Kích thước nhỏ + tên không rõ ràng → đáng ngờ
    if (size > 0 && size < 50000 && /invoice|payment|receipt|urgent|verify|account|update/i.test(name)) {
      threats.push({ type: 'suspicious_pdf', text: 'PDF nhỏ với tên đáng ngờ — có thể là phishing PDF', severity: 'medium', score: 30 });
      score += 30;
    }
  }

  // Double extension (file.pdf.exe trick)
  const parts = nameLow.split('.');
  if (parts.length >= 3) {
    const realExt = '.' + parts[parts.length - 1];
    const fakeExt = '.' + parts[parts.length - 2];
    const dangerousReal = EXE_EXTS.includes(realExt);
    const harmlessFake = ['.pdf', '.doc', '.jpg', '.png', '.txt', '.xlsx'].includes(fakeExt);
    if (dangerousReal && harmlessFake) {
      threats.push({ type: 'double_extension', text: `Kỹ thuật double extension: ${name} — file thật là ${realExt} nhưng giả vờ là ${fakeExt}`, severity: 'critical', score: 90 });
      score = Math.max(score, 90);
    }
  }

  // Tên file chứa từ khóa social engineering
  if (/invoice|payment|receipt|contract|urgent|secret|password|credential|bank|salary|bonus|reward|prize|confirm|verify/i.test(name)) {
    threats.push({ type: 'se_filename', text: `Tên file sử dụng social engineering: "${name}"`, severity: 'medium', score: 20 });
    score += 20;
  }

  // Size bất thường
  if (size > 50 * 1024 * 1024) { // >50MB
    threats.push({ type: 'large_file', text: 'File quá lớn trong email (>50MB)', severity: 'low', score: 10 });
    score += 10;
  }

  // === VirusTotal Hash Check ===
  if (fileInfo.hash && S.settings.vtKey) {
    try {
      const vtRes = await fetch(`${ENDPOINTS.virusTotal}/files/${fileInfo.hash}`, {
        headers: { 'x-apikey': S.settings.vtKey },
        signal: AbortSignal.timeout(8000)
      });
      if (vtRes.ok) {
        const vtData = await vtRes.json();
        const stats = vtData?.data?.attributes?.last_analysis_stats;
        if (stats) {
          const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
          const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.harmless || 0);
          if (malicious > 0) {
            const vtScore = Math.min(90, malicious * 6);
            threats.unshift({
              type: 'virustotal',
              text: `VirusTotal: ${malicious}/${total} engines phát hiện malware trong file này`,
              severity: malicious >= 5 ? 'critical' : 'high',
              score: vtScore,
              vtEngines: malicious, vtTotal: total
            });
            score = Math.max(score, vtScore);
          }
        }
      }
    } catch (e) {
      log('warn', 'virustotal_hash_fail', { error: e.message });
    }
  }

  const finalScore = Math.min(score, 100);
  const status = finalScore >= 60 ? 'malicious' : finalScore >= 25 ? 'suspicious' : 'safe';
  return { name, type: 'file', status, score: finalScore, threats, ext };
}

// ── Scan một media item (ảnh hoặc base64 frame từ video) ─────
async function scanMediaItem(mediaItem) {
  if (!mediaItem) return { status: 'error', error: 'No media item' };

  const { url, dataUrl, type = 'image', contextHint = '' } = mediaItem;

  // Nếu là file đính kèm → dùng file scanner
  if (type === 'file') {
    return scanFileAttachment(mediaItem);
  }

  try {
    let imgData = null;

    // Nếu đã có base64 (từ video frame hoặc content script)
    if (dataUrl) {
      const [meta, b64] = dataUrl.split(',');
      const mime = meta?.match(/data:([^;]+)/)?.[1] || 'image/jpeg';
      imgData = { base64: b64, mimeType: mime };
    } else if (url) {
      imgData = await fetchImageAsBase64(url);
    }

    // URL heuristics (chạy song song, không cần đợi Vision)
    const urlHeur = mediaUrlHeuristics(url, type);

    if (!imgData) {
      return {
        url, type, status: urlHeur.score >= 45 ? 'malicious' : urlHeur.score >= 20 ? 'suspicious' : 'safe',
        score: urlHeur.score,
        threats: urlHeur.threats,
        source: 'url-heuristics-only',
        confidence: 50
      };
    }

    // Gọi Gemini Vision với prompt nâng cấp
    const visionResult = await callGeminiVision(imgData.base64, imgData.mimeType, contextHint);

    let finalScore = 0;
    let threats = [];

    if (visionResult) {
      finalScore = visionResult.riskScore || 0;
      threats = [...(visionResult.threats || [])];

      // Scan QR code URL nếu tìm thấy
      if (visionResult.qrCodeFound && visionResult.qrCodeUrl) {
        try {
          const qrUrlResult = await analyzeUrlDeep(visionResult.qrCodeUrl);
          const qrScore = Math.min(70, qrUrlResult.score || 0);
          if (qrUrlResult.status !== 'safe') {
            finalScore = Math.min(100, finalScore + qrScore);
            threats.unshift({
              type: 'qr_malicious', text: `🔴 QR Code → URL nguy hiểm: ${visionResult.qrCodeUrl.substring(0, 80)}`,
              severity: 'critical', score: qrScore, evidence: visionResult.qrCodeUrl
            });
            S.stats.qrCodesFound = (S.stats.qrCodesFound || 0) + 1;
          } else {
            threats.push({ type: 'qr_safe', text: `QR Code → ${visionResult.qrCodeUrl.substring(0, 60)}`, severity: 'low', score: 0 });
            S.stats.qrCodesFound = (S.stats.qrCodesFound || 0) + 1;
          }
        } catch { }
      }

      // Scan URLs tìm thấy trong ảnh
      if (Array.isArray(visionResult.extractedUrls) && visionResult.extractedUrls.length > 0) {
        for (const extractedUrl of visionResult.extractedUrls.slice(0, 3)) {
          try {
            const uResult = await analyzeUrlDeep(extractedUrl);
            if (uResult.status !== 'safe') {
              const uScore = Math.min(50, uResult.score);
              finalScore = Math.min(100, finalScore + uScore * 0.5);
              threats.push({
                type: 'url_in_image',
                text: `URL trong ảnh bị đánh dấu nguy hiểm: ${extractedUrl.substring(0, 60)}`,
                severity: 'high', score: uScore
              });
            }
          } catch { }
        }
      }

      // Tăng điểm khi nhiều flags xuất hiện cùng nhau (chain amplification)
      const criticalFlags = [
        visionResult.isFakeLoginPage,
        visionResult.logoFaked,
        visionResult.hasSensitiveData,
        visionResult.hasDeepfake,
        visionResult.hasFakeDocument,
        visionResult.hasMalwareInstruction
      ].filter(Boolean).length;

      if (criticalFlags >= 2) {
        finalScore = Math.min(100, finalScore + criticalFlags * 10);
      }

      // Merge URL heuristics (trọng số nhẹ 20%)
      finalScore = Math.min(100, Math.round(finalScore * 0.8 + urlHeur.score * 0.2));
      threats = [...threats, ...urlHeur.threats].slice(0, 12);

    } else {
      // Gemini không available → URL heuristics là chính
      finalScore = urlHeur.score;
      threats = urlHeur.threats;
    }

    // Ngưỡng phân loại media (khác email)
    const finalStatus = finalScore >= 50 ? 'malicious' : finalScore >= 25 ? 'suspicious' : 'safe';

    // Cập nhật stats
    S.stats.mediaScanned = (S.stats.mediaScanned || 0) + 1;
    if (finalStatus === 'malicious') S.stats.mediaMalicious = (S.stats.mediaMalicious || 0) + 1;

    const result = {
      url, type, status: finalStatus,
      score: finalScore,
      threats,
      qrCodeFound: visionResult?.qrCodeFound || false,
      qrCodeUrl: visionResult?.qrCodeUrl || null,
      logoDetected: visionResult?.logoDetected || null,
      logoFaked: visionResult?.logoFaked || false,
      isFakeLoginPage: visionResult?.isFakeLoginPage || false,
      hasSensitiveData: visionResult?.hasSensitiveData || false,
      sensitiveDataTypes: visionResult?.sensitiveDataTypes || [],
      hasDeepfake: visionResult?.hasDeepfake || false,
      hasFakeDocument: visionResult?.hasFakeDocument || false,
      hasMalwareInstruction: visionResult?.hasMalwareInstruction || false,
      extractedUrls: visionResult?.extractedUrls || [],
      extractedText: visionResult?.extractedText || null,
      summary: visionResult?.summary || null,
      reasoning: visionResult?.reasoning || null,
      confidence: visionResult?.confidence || (visionResult ? 85 : 45),
      source: visionResult ? 'gemini-vision-v2' : 'url-heuristics'
    };

    log('info', 'media_scanned', { url: (url || '').substring(0, 60), status: finalStatus, score: finalScore, threats: threats.length });
    save();
    return result;
  } catch (err) {
    log('error', 'media_scan_exception', { error: err.message });
    return { url, type, status: 'error', error: err.message, score: 0, threats: [] };
  }
}


// ── Batch scan nhiều media items ──────────────────────────────
async function scanMediaBatch(items) {
  if (!Array.isArray(items) || items.length === 0) return [];
  const results = [];
  for (const item of items.slice(0, 15)) {  // max 15 items/email
    const r = await scanMediaItem(item);
    results.push(r);
    await delay(200); // tránh rate limit Gemini Vision
  }
  log('info', 'media_batch_done', { total: results.length, malicious: results.filter(r => r.status === 'malicious').length });
  return results;
}



// ── Report ────────────────────────────────────────────────────
async function doReport(data) {
  S.stats.reported++;

  const sender = data?.emailData?.sender || data?.url || 'Người dùng hệ thống';
  const subject = data?.emailData?.subject || data?.title || 'Báo cáo nghi ngờ Phishing';
  const date = data?.reportedAt || new Date().toISOString();
  const threatData = (data?.url) ? `URL bị báo cáo: ${data.url}` : 'Email có dấu hiệu lừa đảo, yêu cầu phân tích thêm.';

  log('info', 'phishing_reported', { sender });
  save();
  try {
    const backendUrl = 'http://localhost:5000'; // Override backend port
    await fetch(`${backendUrl}/api/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sender, subject, date, threatData }),
      signal: AbortSignal.timeout(5000)
    });
  } catch (e) { console.error('Lỗi kết nối Backend Admin:', e); }
  return { ok: true };
}

// ── Auto Quarantine ───────────────────────────────────────────
function addToQuarantine(email, result) {
  const entry = {
    id: `q_${Date.now()}`,
    sender: email.sender,
    subject: email.subject,
    riskLevel: result.riskLevel,
    riskPercent: result.riskPercent,
    confidence: result.confidence,
    mainThreat: result.threats?.[0]?.text || 'Unknown',
    quarantinedAt: now()
  };
  S.quarantine.push(entry);
  S.stats.quarantined = (S.stats.quarantined || 0) + 1;
  log('warn', 'email_quarantined', entry);
}

// ── Notification ──────────────────────────────────────────────
function doNotify(result, email) {
  if (!S.settings.notifications) return;
  if (S.settings.notifyLevel === 'phishing' && result.riskLevel !== 'PHISHING') return;
  if (result.riskLevel === 'SAFE') return;

  const isPhish = result.riskLevel === 'PHISHING';
  const hasCred = result.threats?.some(t => t.type === 'credential' || t.type === 'financial');
  const hasMalware = result.threats?.some(t => t.type === 'malware');

  const title = hasMalware ? '🦠 Nguy cơ Malware!' :
    isPhish ? '🚨 Phishing Phát Hiện!' :
      hasCred ? '🔑 Yêu Cầu Thông Tin Nhạy Cảm' : '⚠️ Email Đáng Ngờ';

  const mainThreat = result.threats?.[0]?.text || '';
  chrome.notifications.create(`pg_${Date.now()}`, {
    type: 'basic', iconUrl: 'icons/icon48.png',
    title,
    message: `"${(email.subject || '').substring(0, 55)}"\nRủi ro: ${result.riskPercent}% | ${mainThreat.substring(0, 60)}`,
    priority: isPhish || hasMalware ? 2 : 1
  });
}

// ══════════════════════════════════════════════════════════════
// EXPORT / LOGGING SYSTEM
// ══════════════════════════════════════════════════════════════
function buildExport(format = 'json') {
  const exportData = {
    metadata: {
      version: VERSION, exportedAt: now(),
      totalRecords: S.history.length, totalLogs: S.logs.length
    },
    stats: S.stats,
    history: S.history.map(h => ({
      id: h.id, sender: h.sender, subject: h.subject,
      riskLevel: h.riskLevel, riskPercent: h.riskPercent,
      confidence: h.confidence, source: h.source,
      threatCount: h.threatCount, deleted: h.deleted,
      falsePositive: h.falsePositive || false,
      timestamp: h.timestamp
    })),
    quarantine: S.quarantine,
    logs: S.logs.slice(-1000)
  };

  if (format === 'csv') {
    return historyToCSV(S.history);
  }
  return exportData;
}

function historyToCSV(history) {
  const headers = ['ID', 'Timestamp', 'Sender', 'Subject', 'RiskLevel', 'RiskPercent', 'Confidence', 'Source', 'ThreatCount', 'Deleted'];
  const rows = history.map(h => [
    h.id || '', h.timestamp || '', h.sender || '', `"${(h.subject || '').replace(/"/g, '""')}"`,
    h.riskLevel || '', h.riskPercent || 0, h.confidence || 0,
    h.source || '', h.threatCount || 0, h.deleted ? 'true' : 'false'
  ].join(','));
  return [headers.join(','), ...rows].join('\n');
}

// ══════════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════════
function record(email, r) {
  S.history.push({
    id: `${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
    sender: email.sender, subject: email.subject,
    riskLevel: r.riskLevel, riskPercent: r.riskPercent,
    threatCount: r.threats?.length || 0, source: r.source,
    confidence: r.confidence || 0, deleted: false, falsePositive: false,
    attackType: r.attackType, hybridUsed: r.hybridUsed || false,
    aiScore: r.aiScore, localScore: r.localScore,
    analysisTime: r.analysisTime,
    timestamp: now()
  });
}

function updateStats(r) {
  S.stats.total++;
  if (r.riskLevel === 'PHISHING') S.stats.phishing++;
  else if (r.riskLevel === 'SUSPICIOUS') S.stats.suspicious++;
  else S.stats.safe++;

  S.stats.riskScoreSum = (S.stats.riskScoreSum || 0) + r.riskPercent;
  S.stats.avgRiskScore = Math.round(S.stats.riskScoreSum / S.stats.total);

  // By source
  const src = (r.source || 'unknown').split('(')[0];
  S.stats.bySource[src] = (S.stats.bySource[src] || 0) + 1;

  // By category
  for (const t of (r.threats || [])) {
    const cat = t.category || t.type || 'other';
    S.stats.byCategory[cat] = (S.stats.byCategory[cat] || 0) + 1;
  }
}

function updateHourlyStats() {
  const h = new Date().getHours();
  if (!Array.isArray(S.stats.byHour)) S.stats.byHour = new Array(24).fill(0);
  S.stats.byHour[h]++;
}

function updateAvg(type, ms) {
  const pm = S.performanceMetrics;
  if (type === 'total') {
    pm.analysisCounts++;
    pm.totalAnalysisTime += ms;
    pm.avgAnalysisTime = Math.round(pm.totalAnalysisTime / pm.analysisCounts);
  } else if (type === 'gemini') {
    pm.geminiAvgTime = pm.geminiAvgTime ? Math.round((pm.geminiAvgTime + ms) / 2) : ms;
  } else if (type === 'local') {
    pm.localAvgTime = pm.localAvgTime ? Math.round((pm.localAvgTime + ms) / 2) : ms;
  }
}

function mkSafe() {
  return { riskLevel: 'SAFE', riskPercent: 0, threats: [], source: 'local-engine', confidence: 100, timestamp: now() };
}
function mkPhishing(text, type, score) {
  return {
    riskLevel: 'PHISHING', riskPercent: score,
    threats: [{ type, text, severity: 'critical', score }],
    source: type, confidence: 100, timestamp: now()
  };
}
function extractDomain(s) { const m = s?.match(/@([\w.-]+)/); return m?.[1] || ''; }
function extractSenderName(s) {
  if (!s) return '';
  const m = s.match(/^(.*?)</);
  const raw = m ? m[1] : s;
  return raw.replace(/["']/g, '').trim();
}
function cacheKey(e) { return `${(e.subject || '').trim().toLowerCase().substring(0, 40)}|${(e.sender || '').trim().toLowerCase()}`; }
function delay(ms) { return new Promise(r => setTimeout(r, ms)); }
function now() { return new Date().toISOString(); }
function deepMerge(target, source) {
  const out = { ...target };
  for (const k of Object.keys(source)) {
    if (source[k] && typeof source[k] === 'object' && !Array.isArray(source[k]) && typeof target[k] === 'object') {
      out[k] = deepMerge(target[k], source[k]);
    } else {
      out[k] = source[k];
    }
  }
  return out;
}
