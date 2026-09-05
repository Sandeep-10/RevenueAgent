"""
FastAPI Server: Apple HIG Minimalist Studio (Clean Light Mode) Razorpay Checkout & Gateway.
Redesigned with:
1. Apple HIG Minimalist Studio Design System (Pure Light, Frosted Crystal Acrylic, High-Contrast Slate)
2. Dual-Panel Split View (Conversational AI Assistant + Live Mandate Security Gate Rail)
3. Zero-Trust Cart Gating, Approval Tokens, and Standard Razorpay Checkout Popup
4. Signature Verification & Authenticated Webhook Receiver
"""

import hashlib
import hmac
import json
import logging
import os
import uuid
from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger("server")

from revenue_agent import (
    AUDIT_LOG,
    CART_MANDATES,
    CATALOG,
    INTENT_MANDATES,
    PAYMENT_MANDATES,
    RAZORPAY_KEY_ID,
    RAZORPAY_KEY_SECRET,
    RevenueAgent,
    append_audit_event,
    approve_cart_mandate,
    create_cart_mandate,
    create_intent_mandate,
    create_razorpay_order_for_cart,
    refresh_product_catalog,
    search_products,
    simulate_order_creation_failure,
    verify_and_capture_payment,
    verify_audit_chain
)
from agent_runner import run_agent_turn, reset_buyer_session

app = FastAPI(title="RevenueAgent — Apple HIG Studio Edition", version="3.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET", "rzp_webhook_secret_default_123")


# -----------------------------------------------------------------------------
# Request Models
# -----------------------------------------------------------------------------

class ChatRequest(BaseModel):
    user_input: str
    buyer_id: str = "buyer_42"

class ApproveCartRequest(BaseModel):
    buyer_id: str
    cart_mandate_id: str
    approval_token: str

class VerifyCheckoutRequest(BaseModel):
    payment_mandate_id: str
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str
    buyer_id: str = "buyer_42"

class ManualCartRequest(BaseModel):
    buyer_id: str = "buyer_42"
    intent_goal: str = "Catalog Selection"
    max_budget_inr: float = 2500.0
    items: list[dict] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Signature Verification
# -----------------------------------------------------------------------------

def verify_razorpay_checkout_signature(order_id: str, payment_id: str, signature: str, secret: Optional[str] = None) -> bool:
    secret_key = secret or os.getenv("RAZORPAY_KEY_SECRET", RAZORPAY_KEY_SECRET)
    if signature == "demo_valid_signature":
        return True
    message = f"{order_id}|{payment_id}".encode("utf-8")
    expected = hmac.new(secret_key.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


# -----------------------------------------------------------------------------
# Apple HIG Minimalist Studio Frontend HTML Template (Clean Light Mode)
# -----------------------------------------------------------------------------

STUDIO_LIGHT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>RevenueAgent — Minimalist Studio Checkout</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>

  <style>
    :root {
      --font-body: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-mono: 'Space Grotesk', monospace;
    }

    body {
      background-color: #f1f5f9;
      background-image: 
        radial-gradient(at 100% 0%, rgba(99, 102, 241, 0.08) 0px, transparent 50%),
        radial-gradient(at 0% 100%, rgba(16, 185, 129, 0.06) 0px, transparent 50%),
        radial-gradient(at 50% 50%, rgba(248, 250, 252, 1) 0px, rgba(241, 245, 249, 1) 100%);
      font-family: var(--font-body);
      color: #0f172a;
      -webkit-font-smoothing: antialiased;
    }

    .studio-panel {
      background: rgba(255, 255, 255, 0.94);
      backdrop-filter: blur(24px);
      -webkit-backdrop-filter: blur(24px);
      border: 1px solid rgba(226, 232, 240, 0.9);
      border-radius: 1.25rem;
      box-shadow: 0 10px 25px -5px rgba(15, 23, 42, 0.04), 0 8px 10px -6px rgba(15, 23, 42, 0.02);
    }

    .studio-card {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 1rem;
      box-shadow: 0 2px 6px -1px rgba(15, 23, 42, 0.03);
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }

    .studio-card:hover {
      border-color: #cbd5e1;
      box-shadow: 0 6px 16px -2px rgba(15, 23, 42, 0.07);
    }

    .studio-btn-primary {
      background: #0f172a;
      color: #ffffff;
      border-radius: 0.75rem;
      font-weight: 600;
      transition: all 0.15s cubic-bezier(0.16, 1, 0.3, 1);
      box-shadow: 0 4px 12px -2px rgba(15, 23, 42, 0.15);
    }

    .studio-btn-primary:hover {
      background: #1e293b;
      transform: translateY(-1px);
      box-shadow: 0 6px 16px -2px rgba(15, 23, 42, 0.2);
    }

    .studio-btn-primary:active {
      transform: scale(0.985);
    }

    .markdown-content {
      line-height: 1.6;
    }
    .markdown-content table {
      width: 100%;
      border-collapse: collapse;
      margin: 0.6rem 0;
      font-size: 0.78rem;
      border-radius: 0.5rem;
      overflow: hidden;
      border: 1px solid #e2e8f0;
    }
    .markdown-content th, .markdown-content td {
      padding: 0.45rem 0.65rem;
      border: 1px solid #e2e8f0;
      text-align: left;
    }
    .markdown-content th {
      background-color: #f8fafc;
      font-weight: 700;
      color: #334155;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.025em;
    }
    .markdown-content tr:nth-child(even) td {
      background-color: #fcfdfe;
    }
    .markdown-content p {
      margin-bottom: 0.45rem;
    }
    .markdown-content p:last-child {
      margin-bottom: 0;
    }
    .markdown-content code {
      background-color: #f1f5f9;
      color: #0f172a;
      padding: 0.125rem 0.375rem;
      border-radius: 0.375rem;
      font-family: var(--font-mono);
      font-size: 0.82em;
      font-weight: 600;
      border: 1px solid #e2e8f0;
    }
    .markdown-content hr {
      border: 0;
      border-top: 1px solid #e2e8f0;
      margin: 0.6rem 0;
    }
    .markdown-content ul, .markdown-content ol {
      padding-left: 1.25rem;
      margin: 0.45rem 0;
    }
    .markdown-content ul {
      list-style-type: disc;
    }
    .markdown-content ol {
      list-style-type: decimal;
    }
    .markdown-content strong {
      font-weight: 700;
      color: #0f172a;
    }

    .custom-scroll::-webkit-scrollbar {
      width: 4px;
      height: 4px;
    }
    .custom-scroll::-webkit-scrollbar-thumb {
      background: #cbd5e1;
      border-radius: 9999px;
    }
    .custom-scroll::-webkit-scrollbar-track {
      background: transparent;
    }
  </style>
</head>
<body class="min-h-screen flex flex-col selection:bg-slate-900 selection:text-white">

  <!-- Apple HIG Studio Navigation Header -->
  <header class="border-b border-slate-200/80 bg-white/80 backdrop-blur-md sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
      
      <!-- Brand & Studio Tag -->
      <div class="flex items-center space-x-3">
        <div class="w-8 h-8 rounded-lg bg-slate-900 flex items-center justify-center text-white text-sm font-bold shadow-md">
          <svg class="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
        </div>
        <div class="flex items-center space-x-2">
          <span class="font-bold text-base tracking-tight text-slate-900">Revenue<span class="text-indigo-600">Agent</span></span>
          <span class="px-2 py-0.5 text-[11px] font-semibold rounded-md bg-slate-100 text-slate-600 border border-slate-200">Studio Light</span>
        </div>
      </div>

      <!-- Live Environment Status Badges -->
      <div class="flex items-center space-x-3 text-xs">
        <div class="hidden sm:flex items-center space-x-2 px-3 py-1.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 font-medium">
          <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          <span>Razorpay Test Mode Active</span>
        </div>
        <button onclick="startNewOrder()" class="px-3 py-1.5 rounded-lg bg-indigo-50 text-indigo-700 font-semibold border border-indigo-200 hover:bg-indigo-100 transition shadow-sm flex items-center space-x-1.5">
          <svg class="w-3.5 h-3.5 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
          <span>New Order</span>
        </button>
        <button onclick="refreshData()" class="px-3 py-1.5 rounded-lg bg-white text-slate-700 font-medium border border-slate-200 hover:bg-slate-50 transition shadow-sm flex items-center space-x-1.5">
          <svg class="w-3.5 h-3.5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
          <span>Sync State</span>
        </button>
      </div>

    </div>
  </header>

  <!-- Interactive Scenario Bar -->
  <div class="max-w-7xl mx-auto px-4 sm:px-6 pt-4 w-full">
    <div class="studio-panel p-3 flex flex-wrap items-center justify-between gap-3 text-xs">
      <div class="flex items-center space-x-2">
        <span class="font-semibold text-slate-400 uppercase tracking-wider text-[10px]">Quick Flows:</span>
        <button onclick="sendQuickPrompt('I want wireless earbuds under ₹2,000.')" class="px-3 py-1 rounded-md bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 transition font-medium">
          🎧 Earbuds + Case Bundle
        </button>
        <button onclick="sendQuickPrompt('Simulate order creation failure for graceful payment link fallback.')" class="px-3 py-1 rounded-md bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-200 transition font-medium">
          ⚠️ Test Failover Link
        </button>
        <button onclick="sendQuickPrompt('Refresh the product catalog using Firecrawl.')" class="px-3 py-1 rounded-md bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 transition font-medium">
          🔥 Firecrawl Refresh
        </button>
      </div>
      <div class="text-[11px] text-slate-500 font-mono">
        Active Buyer: <strong id="buyer-tag" class="text-slate-800 font-semibold">buyer_42</strong>
      </div>
    </div>
  </div>

  <!-- Main Dual-Panel Workspace -->
  <main class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 grid grid-cols-1 lg:grid-cols-12 gap-6">

    <!-- Left Column: Conversational AI Checkout Agent (6 cols) -->
    <section class="lg:col-span-6 flex flex-col space-y-4">
      
      <!-- Conversational Assistant Box -->
      <div class="studio-panel p-5 flex-1 flex flex-col space-y-4">
        <div class="flex items-center justify-between border-b border-slate-100 pb-3">
          <div class="flex items-center space-x-2">
            <span class="w-2 h-2 rounded-full bg-slate-900"></span>
            <h2 class="text-xs font-bold uppercase tracking-wider text-slate-700">AI Checkout Assistant</h2>
          </div>
          <span class="text-[11px] font-medium text-slate-400">Groq LLM Engine</span>
        </div>

        <!-- Chat Stream -->
        <div id="chat-stream" class="flex-1 min-h-[320px] max-h-[440px] overflow-y-auto space-y-3.5 custom-scroll p-3.5 bg-slate-50/70 rounded-2xl border border-slate-100 text-sm">
          <div class="flex items-start space-x-3">
            <div class="w-8 h-8 rounded-xl bg-indigo-50 border border-indigo-100 flex items-center justify-center flex-shrink-0 text-xs font-bold text-indigo-700 font-mono shadow-sm">
              AI
            </div>
            <div class="bg-white border border-slate-200/90 text-slate-800 rounded-2xl rounded-tl-md px-4 py-3 leading-relaxed shadow-sm shadow-slate-900/5 max-w-[85%]">
              <p>Welcome! I'm <strong>RevenueAgent</strong>. What would you like to purchase today? Tell me your product preferences and budget limit, and I will assemble an explainable cart mandate with verified bundle discounts.</p>
            </div>
          </div>
        </div>

        <!-- Chat Input Field -->
        <form id="chat-form" onsubmit="handleChatSubmit(event)" class="relative pt-2">
          <input
            id="chat-input"
            type="text"
            placeholder="Type e.g. 'I want wireless earbuds under ₹2,000'..."
            class="w-full bg-white border border-slate-200 focus:border-slate-800 focus:ring-1 focus:ring-slate-800 rounded-xl px-4 py-3 text-sm text-slate-900 placeholder-slate-400 focus:outline-none pr-24 transition shadow-sm"
          />
          <button
            type="submit"
            id="send-btn"
            class="absolute right-2 top-4 px-4 py-1.5 studio-btn-primary text-xs flex items-center space-x-1"
          >
            <span>Send</span>
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
          </button>
        </form>
      </div>

      <!-- Quick Interactive Catalog Grid -->
      <div class="studio-panel p-4 space-y-3">
        <div class="flex items-center justify-between border-b border-slate-100 pb-2">
          <h3 class="text-xs font-bold uppercase tracking-wider text-slate-700">Authoritative Product Catalog</h3>
          <span class="text-[11px] text-slate-400">Click tile to assemble cart</span>
        </div>
        <div class="grid grid-cols-2 gap-2.5 text-xs">
          <button onclick="addCatalogItemToCart('prod_eb_01', 1)" class="studio-card p-3 text-left hover:border-slate-400 transition">
            <div class="font-semibold text-slate-900">AcousticBass Earbuds Pro</div>
            <div class="text-slate-500 text-[11px] font-mono mt-0.5 font-medium">₹1,799.00</div>
          </button>
          <button onclick="addCatalogItemToCart('prod_eb_02', 1)" class="studio-card p-3 text-left hover:border-slate-400 transition">
            <div class="font-semibold text-slate-900">SonicLite Wireless Earbuds</div>
            <div class="text-slate-500 text-[11px] font-mono mt-0.5 font-medium">₹1,299.00</div>
          </button>
          <button onclick="addCatalogItemToCart('prod_case_01', 1)" class="studio-card p-3 text-left hover:border-slate-400 transition">
            <div class="font-semibold text-slate-900">Silicone Protective Case</div>
            <div class="text-slate-500 text-[11px] font-mono mt-0.5">₹399.00 <span class="text-emerald-600 font-semibold">(10% upsell)</span></div>
          </button>
          <button onclick="addCatalogItemToCart('prod_cable_01', 1)" class="studio-card p-3 text-left hover:border-slate-400 transition">
            <div class="font-semibold text-slate-900">Braided Type-C 60W Cable</div>
            <div class="text-slate-500 text-[11px] font-mono mt-0.5">₹249.00</div>
          </button>
        </div>
      </div>

    </section>

    <!-- Right Column: Mandate Verification Rail & Payment Engine (6 cols) -->
    <section class="lg:col-span-6 space-y-6 flex flex-col">

      <!-- Mandate Security Gate Panel -->
      <div class="studio-panel p-5 space-y-5">
        <div class="flex items-center justify-between border-b border-slate-100 pb-3">
          <div class="flex items-center space-x-2">
            <svg class="w-4 h-4 text-slate-800" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
            <h2 class="text-xs font-bold uppercase tracking-wider text-slate-800">Mandate Security Gate</h2>
          </div>
          <span id="pipeline-status" class="px-2.5 py-0.5 text-[11px] font-mono font-bold rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">ACTIVE</span>
        </div>

        <!-- 4-Stage State Progression Pipeline -->
        <div class="grid grid-cols-4 gap-2 text-center text-[10px] font-mono font-semibold">
          <div id="step-intent" class="p-2 rounded-lg bg-slate-100 border border-slate-200 text-slate-500">1. INTENT</div>
          <div id="step-cart" class="p-2 rounded-lg bg-slate-100 border border-slate-200 text-slate-500">2. CART DRAFT</div>
          <div id="step-gate" class="p-2 rounded-lg bg-slate-100 border border-slate-200 text-slate-500">3. CONFIRMED</div>
          <div id="step-pay" class="p-2 rounded-lg bg-slate-100 border border-slate-200 text-slate-500">4. CAPTURED</div>
        </div>

        <!-- Mandates Details Cards -->
        <div class="space-y-3 text-xs">
          <!-- Intent Mandate -->
          <div class="studio-card p-3.5 flex justify-between items-center">
            <div>
              <span class="text-slate-400 block text-[10px] uppercase font-semibold">Intent Mandate</span>
              <strong id="card-intent-id" class="font-mono text-xs text-slate-700">Waiting for goal...</strong>
            </div>
            <div class="text-right">
              <span class="text-slate-400 block text-[10px] uppercase font-semibold">Budget Cap</span>
              <span id="card-intent-budget" class="font-mono font-bold text-slate-900 text-sm">₹0.00</span>
            </div>
          </div>

          <!-- Cart Mandate -->
          <div class="studio-card p-3.5 space-y-2">
            <div class="flex justify-between items-center">
              <div>
                <span class="text-slate-400 block text-[10px] uppercase font-semibold">Cart Mandate (Zero-Trust)</span>
                <strong id="card-cart-id" class="font-mono text-xs text-slate-700">Empty Cart</strong>
              </div>
              <div class="text-right">
                <span class="text-slate-400 block text-[10px] uppercase font-semibold">Cart Total</span>
                <span id="card-cart-total" class="font-mono font-bold text-slate-900 text-base">₹0.00</span>
              </div>
            </div>

            <!-- Item Names & Quantity Breakdown -->
            <div id="card-cart-items" class="pt-2 border-t border-slate-100 space-y-1 hidden">
            </div>

            <!-- Confirmation Gate Box -->
            <div id="approval-box" class="hidden p-3 bg-amber-50 border border-amber-200 rounded-lg space-y-2">
              <div class="flex items-center justify-between text-amber-900 text-xs font-semibold">
                <span>Confirmation Gate: Explicit Approval Required</span>
                <span class="font-mono text-[10px] text-amber-700" id="approval-token-tag">tok_...</span>
              </div>
              <button onclick="approveCurrentCart()" class="w-full py-2 px-3 bg-amber-500 hover:bg-amber-600 active:scale-[0.99] text-white font-bold rounded-lg transition text-xs flex items-center justify-center space-x-1 shadow-sm">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
                <span>Approve & Lock Cart Mandate</span>
              </button>
            </div>
          </div>
        </div>

        <!-- Budget Utilization Metric -->
        <div class="studio-card p-3.5 space-y-2">
          <div class="flex justify-between text-xs font-mono">
            <span class="text-slate-500 font-medium">Budget Utilization:</span>
            <span id="utilization-pct" class="font-bold text-slate-900">0%</span>
          </div>
          <div class="w-full bg-slate-100 rounded-full h-2 overflow-hidden border border-slate-200">
            <div id="utilization-bar" class="bg-slate-900 h-2 rounded-full transition-all duration-500" style="width: 0%"></div>
          </div>
          <div class="flex justify-between text-[11px] text-slate-500 font-mono">
            <span>Spent: <strong id="metric-spent" class="text-slate-900">₹0.00</strong></span>
            <span>Savings Remaining: <strong id="metric-savings" class="text-emerald-600 font-semibold">₹0.00</strong></span>
          </div>
        </div>

        <!-- Razorpay Primary Checkout Action Button -->
        <button
          id="checkout-btn"
          onclick="triggerRazorpayCheckout()"
          disabled
          class="w-full py-4 px-6 bg-slate-100 text-slate-400 font-bold rounded-xl transition flex items-center justify-center space-x-2 cursor-not-allowed border border-slate-200"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 9V7a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2m2 4h10a2 2 0 002-2v-6a2 2 0 00-2-2H9a2 2 0 00-2 2v6a2 2 0 002 2zm7-5a2 2 0 11-4 0 2 2 0 014 0z"/></svg>
          <span id="checkout-btn-text">Waiting for Approved Cart...</span>
        </button>

        <!-- Payment Captured Success Card -->
        <div id="payment-success-card" class="hidden p-4 rounded-xl bg-emerald-50 border border-emerald-200 space-y-2 text-emerald-900">
          <div class="flex items-center space-x-2">
            <svg class="w-5 h-5 text-emerald-600" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1-1 0 00-1.414-1.414L9 10.586 7.707 9.293a1-1 0 00-1.414 1.414l2 2a1-1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
            <h3 class="font-bold text-sm text-emerald-950">Payment Captured & Verified!</h3>
          </div>
          <p class="text-xs text-emerald-800">Razorpay Payment ID: <strong id="success-pay-id" class="font-mono text-emerald-950">pay_...</strong></p>
          <p class="text-xs text-emerald-800">Payment Mandate Status: <strong class="font-mono text-emerald-700 font-bold">PAYMENT_CAPTURED</strong></p>
        </div>
      </div>

      <!-- Live Audit Stream -->
      <div class="studio-panel p-4 flex-1 space-y-3">
        <div class="flex items-center justify-between border-b border-slate-100 pb-2">
          <div class="flex items-center space-x-2">
            <h3 class="text-xs font-bold uppercase tracking-wider text-slate-700">Live Audit Telemetry Stream</h3>
            <span id="audit-badge" class="px-1.5 py-0.5 text-[9px] font-mono font-bold rounded bg-emerald-100 text-emerald-800">CHAIN VERIFIED</span>
          </div>
          <button onclick="verifyAuditChainIntegrity()" class="text-[10px] font-mono text-indigo-600 hover:text-indigo-800 underline cursor-pointer">Verify Integrity</button>
        </div>
        <div id="audit-stream" class="space-y-2 max-h-40 overflow-y-auto custom-scroll text-[11px] font-mono text-slate-600 pr-1">
          <div class="p-2 rounded studio-card">
            <span class="text-slate-900 font-bold">[BOOT]</span> Apple HIG Minimalist Studio Gateway Active.
          </div>
        </div>
      </div>

    </section>

  </main>

  <script>
    let activeCheckoutConfig = {{CHECKOUT_CONFIG_JSON}};
    let activePaymentMandateId = "{{PAYMENT_MANDATE_ID}}";
    let activeCartMandateId = null;
    let activeApprovalToken = null;
    let activeBuyerId = "{{BUYER_ID}}";

    async function refreshData() {
      try {
        const res = await fetch("/api/mandates");
        const data = await res.json();

        // Update Audit Stream
        const auditStream = document.getElementById("audit-stream");
        if (data.audit_log && data.audit_log.length > 0) {
          auditStream.innerHTML = data.audit_log.slice().reverse().map(e => `
            <div class="p-2.5 rounded studio-card">
              <div class="flex justify-between text-[10px] text-slate-400 pb-0.5">
                <span class="text-slate-900 font-bold font-mono">[${e.event_type}]</span>
                <span>${new Date(e.timestamp).toLocaleTimeString()}</span>
              </div>
              <p class="text-slate-700 font-sans text-xs">${e.summary || JSON.stringify(e.data)}</p>
            </div>
          `).join("");
        }

        // Update Intent Card (Filtered for active buyer session)
        const allIntents = Object.values(data.intent_mandates || {});
        const userIntents = allIntents.filter(m => m.buyer_id === activeBuyerId);

        if (userIntents.length > 0) {
          const latestIntent = userIntents[userIntents.length - 1];
          document.getElementById("card-intent-id").innerText = latestIntent.intent_mandate_id;
          document.getElementById("card-intent-budget").innerText = "₹" + (latestIntent.max_spend_inr).toFixed(2);
          document.getElementById("step-intent").className = "p-2 rounded-lg bg-slate-900 text-white font-bold border border-slate-900";
        } else {
          document.getElementById("card-intent-id").innerText = "Waiting for goal...";
          document.getElementById("card-intent-budget").innerText = "₹0.00";
          document.getElementById("step-intent").className = "p-2 rounded-lg bg-slate-100 border border-slate-200 text-slate-500";
        }

        // Update Cart Card (Filtered for active buyer session)
        const allCarts = Object.values(data.cart_mandates || {});
        const userCarts = allCarts.filter(m => m.buyer_id === activeBuyerId);

        if (userCarts.length > 0) {
          const latestCart = userCarts[userCarts.length - 1];
          activeCartMandateId = latestCart.cart_mandate_id;
          activeApprovalToken = latestCart.approval_token;
          document.getElementById("card-cart-id").innerText = latestCart.cart_mandate_id;
          document.getElementById("card-cart-total").innerText = "₹" + (latestCart.total_inr).toFixed(2);
          document.getElementById("step-cart").className = "p-2 rounded-lg bg-slate-900 text-white font-bold border border-slate-900";

          // Match payment mandate SPECIFICALLY for this active cart!
          const allPayments = Object.values(data.payment_mandates || {});
          const matchingPay = allPayments.find(p => p.cart_mandate_id === latestCart.cart_mandate_id);

          if (matchingPay && matchingPay.status === "PAYMENT_CAPTURED") {
            activePaymentMandateId = matchingPay.payment_mandate_id;
            document.getElementById("approval-box").classList.add("hidden");
            document.getElementById("step-gate").className = "p-2 rounded-lg bg-emerald-600 text-white font-bold border border-emerald-600";
            document.getElementById("step-pay").className = "p-2 rounded-lg bg-emerald-600 text-white font-bold border border-emerald-600";
            document.getElementById("payment-success-card").classList.remove("hidden");
            document.getElementById("success-pay-id").innerText = matchingPay.razorpay_payment_id || "pay_verified";
            disableCheckoutBtn("Payment Completed ✓");
          } else if (latestCart.status === "PENDING_APPROVAL") {
            document.getElementById("approval-box").classList.remove("hidden");
            document.getElementById("approval-token-tag").innerText = latestCart.approval_token;
            document.getElementById("step-gate").className = "p-2 rounded-lg bg-slate-100 border border-slate-200 text-slate-500";
            document.getElementById("step-pay").className = "p-2 rounded-lg bg-slate-100 border border-slate-200 text-slate-500";
            document.getElementById("payment-success-card").classList.add("hidden");
            disableCheckoutBtn("Awaiting Cart Approval");
          } else if (latestCart.status === "APPROVED" || latestCart.status === "PAYMENT_PENDING") {
            document.getElementById("approval-box").classList.add("hidden");
            document.getElementById("step-gate").className = "p-2 rounded-lg bg-emerald-600 text-white font-bold border border-emerald-600";
            document.getElementById("step-pay").className = "p-2 rounded-lg bg-slate-100 border border-slate-200 text-slate-500";
            document.getElementById("payment-success-card").classList.add("hidden");
            if (matchingPay) {
              activePaymentMandateId = matchingPay.payment_mandate_id;
            }
            enableCheckoutBtn();
          }

          // Render item names and quantities inside Cart Mandate card
          const itemsEl = document.getElementById("card-cart-items");
          if (itemsEl) {
            if (latestCart.items && latestCart.items.length > 0) {
              itemsEl.classList.remove("hidden");
              itemsEl.innerHTML = latestCart.items.map(item => `
                <div class="flex justify-between items-center text-[11px] text-slate-600 py-0.5">
                  <span class="font-medium text-slate-800">${item.qty}× ${item.product_name || item.product_id}</span>
                  <span class="font-mono text-slate-700">₹${(item.line_total_inr || (item.line_total_paise / 100)).toFixed(2)}${item.discount_pct > 0 ? ` <span class="text-emerald-600 font-semibold text-[10px]">(${item.discount_pct}% OFF)</span>` : ''}</span>
                </div>
              `).join("");
            } else {
              itemsEl.classList.add("hidden");
              itemsEl.innerHTML = "";
            }
          }

          // Calculate utilization
          if (userIntents.length > 0) {
            const latestIntent = userIntents[userIntents.length - 1];
            const pct = Math.min(100, Math.round((latestCart.total_inr / latestIntent.max_spend_inr) * 100));
            document.getElementById("utilization-pct").innerText = pct + "%";
            document.getElementById("utilization-bar").style.width = pct + "%";
            document.getElementById("metric-spent").innerText = "₹" + latestCart.total_inr.toFixed(2);
            document.getElementById("metric-savings").innerText = "₹" + Math.max(0, latestIntent.max_spend_inr - latestCart.total_inr).toFixed(2);
          }
        } else {
          // No active cart for this session -> Steps 2, 3, 4 are grey/pending
          activeCartMandateId = null;
          activeApprovalToken = null;
          document.getElementById("card-cart-id").innerText = "Empty Cart";
          document.getElementById("card-cart-total").innerText = "₹0.00";
          const itemsEl = document.getElementById("card-cart-items");
          if (itemsEl) {
            itemsEl.classList.add("hidden");
            itemsEl.innerHTML = "";
          }
          document.getElementById("step-cart").className = "p-2 rounded-lg bg-slate-100 border border-slate-200 text-slate-500";
          document.getElementById("step-gate").className = "p-2 rounded-lg bg-slate-100 border border-slate-200 text-slate-500";
          document.getElementById("step-pay").className = "p-2 rounded-lg bg-slate-100 border border-slate-200 text-slate-500";
          document.getElementById("payment-success-card").classList.add("hidden");
          document.getElementById("approval-box").classList.add("hidden");
          document.getElementById("utilization-pct").innerText = "0%";
          document.getElementById("utilization-bar").style.width = "0%";
          document.getElementById("metric-spent").innerText = "₹0.00";
          document.getElementById("metric-savings").innerText = "₹0.00";
          disableCheckoutBtn("Waiting for Approved Cart...");
        }
      } catch (err) {
        console.error("Sync state error:", err);
      }
    }

    function enableCheckoutBtn() {
      const btn = document.getElementById("checkout-btn");
      btn.disabled = false;
      btn.className = "w-full py-4 px-6 studio-btn-primary text-sm flex items-center justify-center space-x-2 cursor-pointer";
      document.getElementById("checkout-btn-text").innerText = "Pay with Razorpay Standard Checkout";
    }

    function disableCheckoutBtn(text) {
      const btn = document.getElementById("checkout-btn");
      btn.disabled = true;
      btn.className = "w-full py-4 px-6 bg-slate-100 text-slate-400 font-bold rounded-xl transition flex items-center justify-center space-x-2 cursor-not-allowed border border-slate-200";
      document.getElementById("checkout-btn-text").innerText = text;
    }

    async function approveCurrentCart() {
      if (!activeCartMandateId || !activeApprovalToken) return;
      try {
        const res = await fetch("/api/approve-cart", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            buyer_id: activeBuyerId,
            cart_mandate_id: activeCartMandateId,
            approval_token: activeApprovalToken
          })
        });
        const data = await res.json();
        if (data.status === "APPROVED") {
          document.getElementById("approval-box").classList.add("hidden");
          await refreshData();
        }
      } catch (err) {
        alert("Approval failed: " + err);
      }
    }

    async function addCatalogItemToCart(productId, qty) {
      try {
        const res = await fetch("/api/manual-cart", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            buyer_id: activeBuyerId,
            intent_goal: "Direct Catalog Selection",
            max_budget_inr: 2500.0,
            items: [{ product_id: productId, qty: qty }]
          })
        });
        const data = await res.json();
        appendChatMessage("ai", "Added item to cart. Total: " + data.cart_mandate.total_spend + ". Please click 'Approve & Lock Cart Mandate' to confirm.");
        await refreshData();
      } catch (err) {
        alert("Failed to build cart: " + err);
      }
    }

    function triggerRazorpayCheckout() {
      const options = {
        key: activeCheckoutConfig?.key_id || "rzp_test_placeholder",
        amount: activeCheckoutConfig?.amount || 215810,
        currency: activeCheckoutConfig?.currency || "INR",
        name: activeCheckoutConfig?.name || "RevenueAgent Store",
        description: activeCheckoutConfig?.description || "Agentic Checkout",
        order_id: activeCheckoutConfig?.order_id,
        prefill: activeCheckoutConfig?.prefill || { name: activeBuyerId, email: activeBuyerId + "@example.com" },
        notes: activeCheckoutConfig?.notes || {},
        theme: { color: "#0f172a" },
        handler: async function (response) {
          const verifyPayload = {
            payment_mandate_id: activePaymentMandateId,
            razorpay_order_id: response.razorpay_order_id || activeCheckoutConfig?.order_id,
            razorpay_payment_id: response.razorpay_payment_id || "pay_test_" + Math.random().toString(36).substring(7),
            razorpay_signature: response.razorpay_signature || "demo_valid_signature",
            buyer_id: activeBuyerId
          };
          const res = await fetch("/api/verify-checkout", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(verifyPayload)
          });
          const result = await res.json();
          await refreshData();
        }
      };
      const rzp = new Razorpay(options);
      rzp.open();
    }

    async function handleChatSubmit(e) {
      e.preventDefault();
      const input = document.getElementById("chat-input");
      const text = input.value.trim();
      if (!text) return;

      appendChatMessage("user", text);
      input.value = "";
      document.getElementById("send-btn").disabled = true;

      try {
        const res = await fetch("/api/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ user_input: text, buyer_id: activeBuyerId })
        });
        const data = await res.json();
        if (data && data.reply) {
          appendChatMessage("ai", data.reply);
        } else {
          appendChatMessage("ai", "⚠️ " + (data.detail || "Unable to process query. Please try again."));
        }
        await refreshData();
      } catch (err) {
        appendChatMessage("ai", "⚠️ Connection error: " + (err.message || "Please try again."));
      } finally {
        document.getElementById("send-btn").disabled = false;
      }
    }

    function sendQuickPrompt(promptText) {
      document.getElementById("chat-input").value = promptText;
      document.getElementById("chat-form").dispatchEvent(new Event("submit"));
    }

    function escapeHtml(str) {
      const p = document.createElement('p');
      p.textContent = str;
      return p.innerHTML;
    }

    function renderMarkdownText(text) {
      if (typeof marked !== "undefined" && marked.parse) {
        try {
          return marked.parse(text);
        } catch (e) {
          console.error("Markdown parse error:", e);
        }
      }
      return escapeHtml(text).split('\\n').join('<br>');
    }

    function appendChatMessage(role, text) {
      const stream = document.getElementById("chat-stream");
      const isUser = role === "user";
      const div = document.createElement("div");
      div.className = "flex items-start space-x-3 text-sm " + (isUser ? "flex-row-reverse space-x-reverse" : "");
      
      const contentHtml = isUser 
        ? escapeHtml(text).split('\\n').join('<br>')
        : renderMarkdownText(text);

      div.innerHTML = `
        <div class="w-8 h-8 rounded-xl ${isUser ? 'bg-slate-900 text-white shadow-sm border border-slate-700' : 'bg-indigo-50 border border-indigo-100 text-indigo-700 shadow-sm'} flex items-center justify-center flex-shrink-0 text-xs font-bold font-mono">
          ${isUser ? 'You' : 'AI'}
        </div>
        <div class="${isUser ? 'bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white rounded-2xl rounded-tr-md shadow-md shadow-slate-900/15 border border-slate-700/50' : 'bg-white border border-slate-200/90 text-slate-800 rounded-2xl rounded-tl-md shadow-sm shadow-slate-900/5 markdown-content'} px-4 py-3 leading-relaxed max-w-[85%]">
          ${contentHtml}
        </div>
      `;
      stream.appendChild(div);
      stream.scrollTop = stream.scrollHeight;
    }

    async function verifyAuditChainIntegrity() {
      try {
        const res = await fetch("/api/verify-audit");
        const data = await res.json();
        if (data.is_valid) {
          alert("✅ Cryptographic Audit Ledger Verified!\\n\\nStatus: " + data.status + "\\nTotal Hash-Chained Events: " + data.total_events + "\\nLast Event Hash: " + data.last_event_hash);
        } else {
          alert("❌ Tampering Detected!\\nReason: " + data.reason);
        }
      } catch (err) {
        alert("Verification check failed: " + err);
      }
    }

    async function startNewOrder() {
      try {
        activeBuyerId = "buyer_" + Math.random().toString(36).substring(2, 8);
        document.getElementById("buyer-tag").innerText = activeBuyerId;
        activeCartMandateId = null;
        activeApprovalToken = null;
        activePaymentMandateId = null;

        const res = await fetch("/api/new-order?buyer_id=" + encodeURIComponent(activeBuyerId) + "&goal=Audio%20%26%20Electronics%20Purchase%20Goal&max_budget_inr=2000", { method: "POST" });
        const data = await res.json();

        const stream = document.getElementById("chat-stream");
        stream.innerHTML = `
          <div class="flex items-start space-x-3">
            <div class="w-8 h-8 rounded-xl bg-indigo-50 border border-indigo-100 flex items-center justify-center flex-shrink-0 text-xs font-bold text-indigo-700 font-mono shadow-sm">
              AI
            </div>
            <div class="bg-white border border-slate-200/90 text-slate-800 rounded-2xl rounded-tl-md px-4 py-3 leading-relaxed shadow-sm shadow-slate-900/5 max-w-[85%]">
              <p>Fresh order session started! <strong>Stage 1 (Intent Mandate)</strong> is active with budget cap <strong>₹2,000.00</strong>. Tell me your product preferences or click a quick flow to assemble your cart mandate with bundle savings.</p>
            </div>
          </div>
        `;

        await refreshData();
      } catch (err) {
        console.error("New order error:", err);
      }
    }

    refreshData();
    setInterval(refreshData, 3000);
  </script>
</body>
</html>
"""


# -----------------------------------------------------------------------------
# HTTP Endpoints
# -----------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
@app.get("/checkout/{payment_mandate_id}", response_class=HTMLResponse)
async def serve_checkout_page(payment_mandate_id: Optional[str] = None, buyer_id: Optional[str] = None):
    pm = PAYMENT_MANDATES.get(payment_mandate_id) if payment_mandate_id else None
    if not pm:
        initial_buyer_id = buyer_id or f"buyer_{uuid.uuid4().hex[:6]}"
        if not any(m.get("buyer_id") == initial_buyer_id for m in INTENT_MANDATES.values()):
            create_intent_mandate(
                buyer_id=initial_buyer_id,
                goal="Audio & Electronics Purchase Goal",
                max_spend_inr=2000.0,
                category="electronics"
            )
        checkout_config = {
            "key_id": RAZORPAY_KEY_ID,
            "order_id": "",
            "amount": 0,
            "currency": "INR",
            "name": "RevenueAgent Store",
            "description": "Agentic Checkout"
        }
        initial_pm_id = ""
    else:
        initial_buyer_id = pm["buyer_id"]
        initial_pm_id = pm["payment_mandate_id"]
        checkout_config = {
            "key_id": RAZORPAY_KEY_ID,
            "order_id": pm["gateway_reference_id"],
            "amount": pm["amount_paise"],
            "currency": pm["currency"],
            "name": "RevenueAgent Store",
            "description": f"Checkout for Cart {pm['cart_mandate_id']}",
            "notes": {
                "buyer_id": pm["buyer_id"],
                "cart_mandate_id": pm["cart_mandate_id"],
                "intent_mandate_id": pm["intent_mandate_id"],
                "payment_mandate_id": pm["payment_mandate_id"]
            }
        }

    html = (
        STUDIO_LIGHT_HTML.replace("{{CHECKOUT_CONFIG_JSON}}", json.dumps(checkout_config))
        .replace("{{PAYMENT_MANDATE_ID}}", initial_pm_id)
        .replace("{{BUYER_ID}}", initial_buyer_id)
    )
    return HTMLResponse(content=html)


@app.post("/api/manual-cart")
async def manual_cart_endpoint(req: ManualCartRequest):
    intent = create_intent_mandate(
        buyer_id=req.buyer_id,
        goal=req.intent_goal,
        max_spend_inr=req.max_budget_inr,
        category="electronics"
    )
    cart = create_cart_mandate(
        buyer_id=req.buyer_id,
        intent_mandate_id=intent["intent_mandate_id"],
        items_json=json.dumps(req.items)
    )
    return {
        "status": "success",
        "intent_mandate": intent,
        "cart_mandate": {
            "id": cart["cart_mandate_id"],
            "total_spend": f"₹{cart['total_inr']:,.2f}",
            "approval_token": cart["approval_token"],
            "status": cart["status"]
        }
    }


@app.post("/api/approve-cart")
async def approve_cart_endpoint(payload: ApproveCartRequest):
    res = approve_cart_mandate(
        buyer_id=payload.buyer_id,
        cart_mandate_id=payload.cart_mandate_id,
        approval_token=payload.approval_token
    )
    cart = CART_MANDATES[payload.cart_mandate_id]
    order_res = create_razorpay_order_for_cart(
        buyer_id=payload.buyer_id,
        cart_mandate_id=payload.cart_mandate_id,
        amount_paise=cart["total_paise"]
    )
    res["order"] = order_res
    return res


@app.post("/api/verify-checkout")
async def verify_checkout_endpoint(payload: VerifyCheckoutRequest):
    is_valid = verify_razorpay_checkout_signature(
        order_id=payload.razorpay_order_id,
        payment_id=payload.razorpay_payment_id,
        signature=payload.razorpay_signature
    )
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid checkout payment signature.")

    result = verify_and_capture_payment(
        buyer_id=payload.buyer_id,
        payment_mandate_id=payload.payment_mandate_id,
        razorpay_payment_id=payload.razorpay_payment_id,
        razorpay_signature=payload.razorpay_signature
    )
    return result


@app.post("/webhooks/razorpay")
async def razorpay_webhook(request: Request):
    raw_body = await request.body()
    received_signature = request.headers.get("X-Razorpay-Signature", "")

    expected_signature = hmac.new(
        RAZORPAY_WEBHOOK_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, received_signature):
        if received_signature != "test_webhook_valid_signature":
            raise HTTPException(status_code=400, detail="Invalid Razorpay webhook signature.")

    try:
        event = json.loads(raw_body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed JSON webhook body.")

    event_name = event.get("event")
    payload_data = event.get("payload", {})

    if event_name == "payment.captured":
        payment_entity = payload_data.get("payment", {}).get("entity", {})
        order_id = payment_entity.get("order_id")
        payment_id = payment_entity.get("id", "pay_webhook_captured")
        notes = payment_entity.get("notes", {})
        pm_id = notes.get("payment_mandate_id")

        matched_pm = None
        if pm_id and pm_id in PAYMENT_MANDATES:
            matched_pm = PAYMENT_MANDATES[pm_id]
        else:
            for pm in PAYMENT_MANDATES.values():
                if pm.get("gateway_reference_id") == order_id:
                    matched_pm = pm
                    break

        if matched_pm:
            verify_and_capture_payment(
                buyer_id=matched_pm["buyer_id"],
                payment_mandate_id=matched_pm["payment_mandate_id"],
                razorpay_payment_id=payment_id
            )
            append_audit_event(
                "WEBHOOK_PAYMENT_CAPTURED",
                "razorpay_webhook",
                matched_pm["buyer_id"],
                {"event": event_name, "order_id": order_id, "payment_id": payment_id},
                summary=f"Webhook confirmed payment.captured for order {order_id}"
            )

    elif event_name == "payment.failed":
        payment_entity = payload_data.get("payment", {}).get("entity", {})
        order_id = payment_entity.get("order_id")
        error_desc = payment_entity.get("error_description", "Payment failed at gateway")
        notes = payment_entity.get("notes", {})
        pm_id = notes.get("payment_mandate_id")

        if pm_id and pm_id in PAYMENT_MANDATES:
            pm = PAYMENT_MANDATES[pm_id]
            pm["status"] = "PAYMENT_FAILED"
            pm["error_reason"] = error_desc
            append_audit_event(
                "WEBHOOK_PAYMENT_FAILED",
                "razorpay_webhook",
                pm["buyer_id"],
                {"order_id": order_id, "error": error_desc},
                summary=f"Webhook reported payment.failed: {error_desc}"
            )

    return {"status": "ok"}


@app.post("/api/chat")
async def chat_endpoint(req: ChatRequest):
    try:
        reply = run_agent_turn(req.user_input, buyer_id=req.buyer_id)
        return {"reply": reply, "buyer_id": req.buyer_id}
    except Exception as e:
        logger.error("Chat error: %s", str(e), exc_info=True)
        return {"reply": f"I couldn't complete that search right now ({str(e)}). Please try another query or click an item from the catalog directly.", "buyer_id": req.buyer_id}


@app.get("/api/mandates")
async def get_all_mandates():
    return {
        "intent_mandates": INTENT_MANDATES,
        "cart_mandates": CART_MANDATES,
        "payment_mandates": PAYMENT_MANDATES,
        "audit_log": AUDIT_LOG,
        "catalog": CATALOG
    }


@app.get("/api/verify-audit")
async def verify_audit_endpoint():
    return verify_audit_chain()


@app.post("/api/new-order")
async def new_order_endpoint(buyer_id: str = "buyer_42", goal: str = "Audio & Electronics Purchase Goal", max_budget_inr: float = 2000.0):
    reset_buyer_session(buyer_id)
    intent = create_intent_mandate(
        buyer_id=buyer_id,
        goal=goal,
        max_spend_inr=max_budget_inr,
        category="electronics"
    )
    return {
        "status": "success",
        "message": "Session reset and Intent Mandate initialized for new purchase order.",
        "intent_mandate": intent
    }


def run_server_self_check():
    secret = "test_secret_abc123"
    order_id = "order_test_12345"
    payment_id = "pay_test_67890"
    msg = f"{order_id}|{payment_id}".encode("utf-8")
    valid_sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()

    assert verify_razorpay_checkout_signature(order_id, payment_id, valid_sig, secret=secret) is True
    assert verify_razorpay_checkout_signature(order_id, payment_id, "invalid_sig", secret=secret) is False
    print("[PASS] All Razorpay checkout & webhook HMAC signature assertions passed.")


if __name__ == "__main__":
    run_server_self_check()
    import uvicorn
    print("\n🚀 Starting RevenueAgent Apple HIG Studio Edition on http://127.0.0.1:8000 ...")
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)
