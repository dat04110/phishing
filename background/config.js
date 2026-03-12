// ============================================================
// PhishGuard Enterprise v7.1 — ULTRA EDITION
// Hybrid Scoring · Weighted Rules · Advanced AI · Export Logs
// Timeline Analytics · Threat Intelligence · Auto-Quarantine
// URL Deep Scanner · Media (Image/Video) AI Scanner
// ============================================================
'use strict';

const VERSION = '7.1.0';

const ENDPOINTS = {
  geminiFlash: 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent',
  geminiPro: 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent',
  geminiFlash15: 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent',
  geminiVision: 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent',
  safeBrowsing: 'https://safebrowsing.googleapis.com/v4/threatMatches:find',
  virusTotal: 'https://www.virustotal.com/api/v3',
  // ── NEW APIs v7.2 ─────────────────────────────────────────────
  urlhaus: 'https://urlhaus-api.abuse.ch/v1/url/',           // abuse.ch — no key needed
  abuseIPDB: 'https://api.abuseipdb.com/api/v2/check',       // IP reputation
  ipqs: 'https://www.ipqualityscore.com/api/json/email'      // Email fraud score
};

// ── URL SCANNER CONFIG ────────────────────────────────────────
const URL_SCAN_CONFIG = {
  maxRedirects: 6,
  fetchTimeout: 5000,
  geminiUrlBatch: 10,   // max URLs per Gemini call
  vtCacheTTL: 3600000, // 1h
  highEntropyThresh: 3.8,
  maxSubdomains: 4,
  maxPathDepth: 7
};

// ── KNOWN SAFE DOMAINS (whitelist for media fetch) ────────────
const TRUSTED_IMG_HOSTS = new Set([
  'gmail.com', 'googleusercontent.com', 'gstatic.com', 'google.com',
  'facebook.com', 'fbcdn.net', 'instagram.com', 'cdninstagram.com',
  'twimg.com', 'twitter.com', 'linkedin.com', 'licdn.com'
]);

// ── RULE WEIGHTS (adjusted - less aggressive) ────────────────
const RULE_WEIGHTS = {
  credential: { base: 55, multiplier: 1.4, category: 'credential' },
  financial_request: { base: 50, multiplier: 1.3, category: 'financial' },
  urgency_high: { base: 35, multiplier: 1.2, category: 'urgency' },
  urgency_medium: { base: 20, multiplier: 1.0, category: 'urgency' },
  spoofing: { base: 45, multiplier: 1.35, category: 'spoofing' },
  lookalike_domain: { base: 48, multiplier: 1.4, category: 'spoofing' },
  free_email_imperson: { base: 40, multiplier: 1.3, category: 'spoofing' },
  bad_tld: { base: 28, multiplier: 1.1, category: 'domain' },
  ip_sender: { base: 38, multiplier: 1.2, category: 'domain' },
  url_shortener: { base: 22, multiplier: 1.0, category: 'link' },
  ip_url: { base: 32, multiplier: 1.15, category: 'link' },
  caps_abuse: { base: 8, multiplier: 0.8, category: 'style' },
  exclamation_abuse: { base: 6, multiplier: 0.8, category: 'style' },
  no_unsubscribe: { base: 10, multiplier: 0.9, category: 'spam' },
  long_redirect_chain: { base: 18, multiplier: 1.0, category: 'link' },
  mismatched_links: { base: 25, multiplier: 1.1, category: 'link' },
  attachment_exe: { base: 45, multiplier: 1.3, category: 'malware' },
  attachment_macro: { base: 35, multiplier: 1.2, category: 'malware' },
  data_request: { base: 30, multiplier: 1.1, category: 'social' },
  prize_scam: { base: 42, multiplier: 1.3, category: 'scam' },
  fake_invoice: { base: 38, multiplier: 1.2, category: 'scam' },
  threat_language: { base: 32, multiplier: 1.2, category: 'urgency' },
  romance_scam: { base: 35, multiplier: 1.2, category: 'scam' },
  crypto_scam: { base: 40, multiplier: 1.3, category: 'scam' },
};

// ── TRUSTED SENDER DOMAINS — email từ domain này được giảm trọng số mạnh ──
// Cập nhật danh sách này khi cần thêm domain khác
const TRUSTED_SENDER_DOMAINS = new Set([
  // Google ecosystem
  'google.com', 'gmail.com', 'googlemail.com', 'accounts.google.com',
  'mail.google.com', 'no-reply.google.com', 'google.com.vn',
  'youtube.com', 'youtubemail.com',
  // Microsoft
  'microsoft.com', 'outlook.com', 'hotmail.com', 'live.com',
  'microsoftonline.com', 'office.com', 'office365.com', 'azure.com',
  'office-365.com', 'sharepoint.com',
  // Apple
  'apple.com', 'icloud.com', 'me.com', 'mac.com',
  // Social media
  'facebook.com', 'facebookmail.com', 'fb.com', 'meta.com',
  'instagram.com', 'twitter.com', 'x.com', 'linkedin.com', 'tiktok.com',
  // Vietnamese banks
  'vietcombank.com.vn', 'techcombank.com.vn', 'mbbank.com.vn',
  'agribank.com.vn', 'bidv.com.vn', 'vpbank.com.vn', 'tpbank.vn',
  'acb.com.vn', 'hdbank.com.vn', 'sacombank.com', 'ocb.com.vn',
  'vib.com.vn', 'msb.com.vn', 'seabank.com.vn', 'bacabank.com.vn',
  'pvcombank.com.vn', 'kienlongbank.com', 'lottebank.com',
  'cbbank.vn', 'gpbank.com.vn', 'publicbank.com.vn',
  // Vietnamese services  
  'shopee.vn', 'lazada.vn', 'tiki.vn', 'sendo.vn',
  'momo.vn', 'zalopay.vn', 'vnpay.vn', 'napas.com.vn',
  'zalo.me', 'viber.com', 'grab.com', 'gojek.com',
  'viettel.com.vn', 'mobifone.vn', 'vinaphone.vn', 'vnpt.vn', 'fpt.net',
  'gov.vn', 'chinhphu.vn', 'bhxh.gov.vn', 'customs.gov.vn',
  // International e-commerce & finance  
  'amazon.com', 'amazon.co.uk', 'paypal.com', 'stripe.com',
  'netflix.com', 'spotify.com', 'adobe.com', 'dropbox.com',
  'github.com', 'gitlab.com', 'atlassian.com', 'slack.com', 'zoom.us',
  // News & media
  'vnexpress.net', 'tuoitre.vn', 'thanhnien.vn', 'dantri.com.vn',
  'vtv.vn', 'vov.vn',
]);

// ── Kiểm tra domain có phải trusted không (match exact hoặc subdomain) ──
function isTrustedSender(sender) {
  if (!sender) return false;
  const lower = sender.toLowerCase();
  // Lấy domain từ email (phần sau @)
  const atIdx = lower.lastIndexOf('@');
  const domain = atIdx >= 0 ? lower.slice(atIdx + 1).trim() : lower;
  // Exact match
  if (TRUSTED_SENDER_DOMAINS.has(domain)) return true;
  // Subdomain match (e.g. noreply.google.com → google.com)
  for (const trusted of TRUSTED_SENDER_DOMAINS) {
    if (domain.endsWith('.' + trusted) || domain === trusted) return true;
  }
  return false;
}
