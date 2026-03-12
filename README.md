<<<<<<< HEAD
# PhishGuard Enterprise v7.0 — ULTRA EDITION

## 🆕 Tính năng mới v7.0

| Feature | Mô tả |
|---|---|
| ⚡ **Hybrid Scoring Engine** | Kết hợp Gemini AI + Weighted Rule Engine với trọng số động |
| 🧠 **Weighted Rule Engine** | 25+ rule với weight, multiplier, category, diminishing returns |
| 📊 **Analytics Dashboard** | Timeline hourly chart, threat category breakdown, source stats |
| 🔒 **Auto-Quarantine** | Tự động cách ly email PHISHING ≥75% confidence |
| 🪵 **Logging System** | Ghi log chi tiết với level: debug/info/warn/error |
| ⬇ **Export JSON/CSV** | Xuất toàn bộ dữ liệu lịch sử + logs ra file |
| 📈 **Performance Metrics** | Avg analysis time, Gemini avg, cache hits |
| 🔍 **Hourly Activity Chart** | Biểu đồ bar theo 24h trong ngày |
| ⚖ **Configurable AI Weight** | Slider điều chỉnh tỉ lệ AI vs Local engine (0-100%) |
| 💎 **Gemini 2.0 Flash** | Hỗ trợ model mới nhất, nhanh và chính xác hơn |
| 🎯 **Confidence Threshold** | Ngưỡng tối thiểu để áp dụng kết quả AI |
| ↺ **False Positive Marking** | Double-click history item để đánh dấu false positive |
| 🗂 **History Search** | Tìm kiếm lịch sử theo subject/sender |
| 📋 **Enhanced Panel** | Hiển thị AI score vs Local score, hybrid info |
| 🏷 **Attack Type Label** | Phân loại: phishing/bec/malware/spam/scam |

---

## ⚡ Hybrid Scoring Engine

```
Email
  │
  ├─→ [Whitelist/Blacklist] → Instant result
  │
  ├─→ [Cache 15min] → Return cached
  │
  ├─→ Weighted Local Engine
  │     ├ 25+ pattern categories
  │     ├ Diminishing returns scoring
  │     ├ Category multipliers (cred+spoofing = ×1.25)
  │     └ Threat deduplication
  │
  ├─→ Gemini AI (enhanced prompt v7)
  │     ├ Gemini 2.0 Flash (mới nhất)
  │     ├ Attack type classification
  │     ├ Evidence-based threats
  │     └ Vietnamese context
  │
  ├─→ [Hybrid Merge] ← CỐT LÕI v7
  │     ├ Effective AI weight = aiWeight × (0.5 + confidence×0.5)
  │     ├ Effective Local weight = localWeight × (1.2 - confidence×0.4)
  │     ├ Weighted average of risk scores
  │     ├ Merge threats (no duplicates)
  │     └ Apply category thresholds
  │
  ├─→ [Safe Browsing] → Boost score
  ├─→ [VirusTotal] → Domain check
  └─→ [Auto-Quarantine] if score ≥ 75%
```

---

## 📁 Cấu trúc file

```
phishguard-v7/
├── manifest.json
├── background.js          ← Service worker (Hybrid AI pipeline)
├── content/
│   ├── content.js         ← Gmail injection + Delete + Progress bar
│   └── content.css
├── popup/
│   ├── popup.html         ← 7 tabs: Dash/Analytics/History/Quarantine/Lists/Logs/Settings
│   └── popup.js
└── icons/                 ← icon16/32/48/128.png (cần tự thêm)
```

---

## 🚀 Cài đặt

1. Mở `chrome://extensions/`
2. Bật **Developer mode**
3. Click **Load unpacked** → chọn thư mục `phishguard-v7/`
4. Mở Gmail → toolbar HYBRID AI xuất hiện

---

## ⚙️ Cấu hình tối ưu

### Hybrid Weight (Settings):
- **70-80%** — Nếu bạn có Gemini API key tốt
- **40-50%** — Nếu muốn rule engine đóng vai trò ngang bằng
- **20-30%** — Nếu AI không ổn định/không có key

### Confidence Threshold:
- **40%** — Cân bằng (mặc định)
- **60%+** — Chỉ dùng AI khi rất tự tin
- **20%** — Aggressive, dùng AI nhiều hơn

### Log Level:
- **info** — Sản xuất (mặc định)
- **debug** — Phát triển/debug
- **warn** — Chỉ cảnh báo

---

## 📊 Export Data

### JSON Export:
```json
{
  "metadata": { "version": "7.0", "exportedAt": "...", "totalRecords": 150 },
  "stats": { "total": 150, "phishing": 12, "suspicious": 23, ... },
  "history": [ { "sender": "...", "riskLevel": "PHISHING", ... } ],
  "quarantine": [...],
  "logs": [...]
}
```

### CSV Export:
```
ID,Timestamp,Sender,Subject,RiskLevel,RiskPercent,Confidence,Source,ThreatCount,Deleted
log_123,2025-01-01T...,spammer@evil.tk,"Trúng thưởng!!!",PHISHING,87,92,...
```

---

## 🔒 Quarantine

Email bị auto-quarantine khi:
- `riskLevel === PHISHING` **AND**
- `riskPercent >= 75` **AND**  
- `Auto-Quarantine` được bật trong Settings

Xem và release email từ tab **Quarantine** trong popup.
=======
# EMAILPHISHINGAI
>>>>>>> ee38760862ff121fe605e3ef3213435b752e4636
