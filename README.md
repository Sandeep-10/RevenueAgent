# ⚡ RevenueAgent: Autonomous Agentic Checkout & Mandate Security Gate

> An AI-native, zero-trust conversational checkout assistant powered by Groq (gpt-oss-120b), FastAPI, and Razorpay Test Mode. Built for autonomous agent-to-agent commerce (NPCI UAP, ACP/AP2 ready) with cryptographic audit logging and deterministic bundle upsells.

---

## 🏛️ Architecture: 3-Tier Security Mandate Protocol

`
+-------------------------------------------------------------------------+
|                         REVENUEAGENT LIFECYCLE                         |
+-------------------------------------------------------------------------+

  [Buyer Budget & Goal]
           │
           ▼
  1. INTENT MANDATE        --> Sets ceiling budget & goal bounds
           │
           ▼
  2. CART MANDATE (DRAFT)  --> Deterministic catalog pricing + automated upsells
           │
           ▼
  [EXPLICIT CONFIRMATION GATE: tok_appr_...]  (Human/Agent Authorization)
           │
           ▼
  3. PAYMENT MANDATE       --> Razorpay Modal Order / Hosted Link Fallback
           │
           ▼
  4. PAYMENT CAPTURED      --> Cryptographic HMAC-SHA256 signature verification
           │
           ▼
  [TAMPER-EVIDENT AUDIT LEDGER] (Immutable SHA-256 Hash Chain)
`

---

## 🌟 Key Highlights

- **Deterministic Financial Engine**: LLM never computes prices, discounts, taxes, or currencies. Integer paise calculations are enforced strictly on the server against an authoritative product catalog.
- **AOV Growth via Bundle Upsells**: Automatically applies bundle rules (e.g. 10% off accessories when paired with earbuds) to maximize merchant revenue within buyer budget limits.
- **Cryptographic Audit Trail**: Every intent, search, cart mutation, user approval, payment creation, and webhook verification is appended to a tamper-evident HMAC-SHA256 hash-chained ledger.
- **Resilient Failover**: If direct order creation encounters transient gateway errors (e.g. 504 Timeout), the agent recovers automatically by generating a secure hosted Razorpay Payment Link (https://rzp.io/i/...).
- **Apple HIG Studio UI**: Clean, light-mode dashboard with real-time pipeline telemetry, responsive mandate cards, markdown rendering, and live audit telemetry stream.

---

## 🚀 Quick Start

### 1. Clone & Install Dependencies

`ash
git clone https://github.com/Sreshtakautilya/RevenueAgent.git
cd RevenueAgent
pip install -r requirements.txt
playwright install chromium
`

### 2. Configure Environment Variables

Create .env based on .env.example:

`ini
RAZORPAY_KEY_ID=rzp_test_your_key_id
RAZORPAY_KEY_SECRET=your_key_secret
RAZORPAY_WEBHOOK_SECRET=your_webhook_secret
GROQ_API_KEY=gsk_your_groq_api_key
`

### 3. Run Server

`ash
python server.py
`
Open **http://127.0.0.1:8000** in your browser.

### 4. Run Automated Browser Test Suite

`ash
python test_browser_flows.py
`

---

## 🔒 Security & Mandate Guarantees

1. **Gated Payment Creation**: Razorpay orders are rejected by the security layer unless the parent Cart Mandate is in APPROVED status with a valid pproval_token.
2. **Re-Carting Prevention**: Once a cart is approved or paid, subsequent queries cannot accidentally trigger duplicate carts.
3. **Strict Catalog Matching**: Out-of-catalog items create an Intent Mandate only without generating empty ghost carts.
