# ⚡ RevenueAgent: Autonomous Agentic Checkout & Mandate Security Gate

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![LangChain](https://img.shields.io/badge/LangChain-v0.3-green.svg)](https://langchain.com/)
[![Groq](https://img.shields.io/badge/Groq-gpt--oss--120b-f55036.svg)](https://groq.com/)
[![Razorpay](https://img.shields.io/badge/Razorpay-Test%20Mode-0c2340.svg)](https://razorpay.com/)
[![Playwright](https://img.shields.io/badge/Playwright-E2E%20Tested-45ba4b.svg)](https://playwright.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **RevenueAgent** is a zero-trust, conversational checkout engine for merchants on **Razorpay Test-Mode APIs**. It transforms traditional merchant catalogs into agentic, machine-transactable endpoints, grows Average Order Value (AOV) via deterministic bundle upsells, and enforces zero-trust financial boundaries via a **3-Tier Cryptographic Mandate Protocol** (NPCI UAP, ACP/AP2 ready).

---

## 🧭 Why Now?
With NPCI’s Unified Agent Protocol (UAP) and the global protocol race (ACP, AP2, x402), **agent-to-agent autonomous commerce** is the defining open problem of the year. However, autonomous agents cannot be given unconstrained wallet access due to hallucination risks, price tampering, and runaway prompts.

**RevenueAgent** solves this by establishing strict boundaries:
- **The LLM is a conversational concierge** (intent discovery, natural recommendations, negotiation).
- **The financial state machine is 100% deterministic code** (zero-trust pricing, cryptographic approval tokens, tamper-evident audit ledger, and automated failover).

---

## 🏛️ Architecture: 3-Tier Security Mandate Protocol

`mermaid
flowchart TD
    A[Buyer Goal & Budget Cap] --> B[1. Intent Mandate]
    B --> C[Catalog Search & Upsell Engine]
    C --> D[2. Cart Mandate Draft]
    D --> E{Explicit Confirmation Gate}
    E -->|Reject / Change| C
    E -->|Approved: tok_appr_...| F[3. Payment Mandate]
    F -->|Standard Flow| G[Razorpay Modal Order]
    F -->|Simulated 504 Failure| H[Hosted Payment Link Failover]
    G --> I[HMAC Cryptographic Verification]
    H --> I
    I --> J[4. Payment Captured & Verified]
    
    subgraph Cryptographic Audit Trail
        K[(Immutable SHA-256 Hash Chain)]
    end
    B -.-> K
    D -.-> K
    E -.-> K
    F -.-> K
    I -.-> K
`

---

## 🌟 Core Pillars & Capabilities

### 1. Zero-Trust Server-Side Pricing
- Integer **paise calculations** are computed strictly on the backend against an authoritative catalog.
- The LLM cannot invent prices, mutate quantities without validation, or bypass budget caps.

### 2. AOV Growth via Deterministic Upsell Bundling
- Intelligent bundle rules dynamically pair complementary products (e.g., **10% off Silicone Case** when paired with **Earbuds**).
- Maximizes merchant revenue while respecting buyer budget limits.

### 3. Cryptographic Tamper-Evident Audit Ledger
- Every state transition (Intent, Search, Cart Assembly, User Approval, Payment Creation, Webhook Verification) is appended to an immutable **HMAC-SHA256 hash-chained log**:
  \text{Hash}_n = \text{SHA256}(\text{Hash}_{n-1} + \text{Timestamp} + \text{Payload})
- Built-in /api/verify-audit endpoint validates ledger integrity in real-time.

### 4. Graceful Gateway Failover
- Intercepts transient gateway errors (e.g. 504 Gateway Timeout during direct Razorpay order creation).
- Automatically recovers by generating a secure hosted **Razorpay Payment Link** (https://rzp.io/i/...) without losing cart state.

### 5. Re-Carting & No-Match Guards
- **Re-Carting Lock**: Once a cart mandate is APPROVED or PAID, subsequent prompts cannot trigger accidental duplicate drafts.
- **No-Match Guard**: Searching for out-of-catalog items (e.g., "shoes under ₹2,000") establishes an Intent Mandate only, gracefully listing store alternatives without creating empty ghost carts.

---

## 🚀 Quick Start

### 1. Clone & Install Dependencies

`ash
git clone https://github.com/Sandeep-10/RevenueAgent.git
cd RevenueAgent
pip install -r requirements.txt
playwright install chromium
`

### 2. Configure Environment Variables

Create .env based on .env.example:

`ini
# Razorpay Test Mode Credentials
RAZORPAY_KEY_ID=rzp_test_your_key_id
RAZORPAY_KEY_SECRET=your_key_secret
RAZORPAY_WEBHOOK_SECRET=your_webhook_secret

# Groq LLM API Key (gpt-oss-120b)
GROQ_API_KEY=gsk_your_groq_api_key
`

### 3. Start the Server

`ash
python server.py
`
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** to view the Apple HIG Studio Dashboard.

### 4. Run Automated Browser Test Suite

`ash
python test_browser_flows.py
`

---

## 🧪 Test Suite Coverage (9/9 Scenarios)

| # | Test Scenario | Verified Behavior |
|---|---|---|
| **1** | **UI Shell & Badges** | Apple HIG Studio layout, live environment badges, telemetry streams. |
| **2** | **Unmatched Query Guard** | "shoes under 2000" creates Intent only; zero ghost carts created. |
| **3** | **Conversational Cart Flow** | Groq agent parses intent, applies 10% bundle discount, yields 	ok_appr_.... |
| **4** | **Approval Lock Gate** | Locks cart into APPROVED status, enables Razorpay checkout button. |
| **5** | **Razorpay HMAC Capture** | Verified signature callback transitions mandate to PAYMENT_CAPTURED. |
| **6** | **Catalog Tile Click** | Direct catalog selection binds zero-trust cart mandate immediately. |
| **7** | **Cryptographic Audit Chain** | Verifies complete mathematical integrity across all hash-chained events. |
| **8** | **Webhook Ingestion** | HMAC-authenticated webhook processing and status sync. |
| **9** | **Gateway Timeout Failover** | Gracefully falls back to hosted payment link upon simulated gateway error. |

---

## 📡 API Reference

| Endpoint | Method | Description |
|---|---|---|
| /api/chat | POST | Conversational turn with Groq LLM and contextual mandate state. |
| /api/mandates | GET | Fetches active Intent, Cart, and Payment mandate states. |
| /api/new-order | POST | Initializes a fresh buyer session and sets initial Intent Mandate. |
| /api/approve-cart | POST | Validates pproval_token and transitions cart to APPROVED. |
| /api/create-order | POST | Generates standard Razorpay Order for approved carts. |
| /api/verify-payment | POST | Validates Razorpay HMAC signature and captures payment. |
| /api/verify-audit | GET | Cryptographically verifies the tamper-evident hash chain. |
| /api/webhook | POST | Ingests and verifies Razorpay webhook events. |

---

## 📄 License
Distributed under the MIT License. See LICENSE for more information.
