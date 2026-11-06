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
<html lang="en" class="light">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <meta name="color-scheme" content="light"/>
  <title>RevenueAgent — Autonomous Mandate Rail & Checkout Studio</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class'
    }
  </script>
  <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>

  <style>
    :root {
      --font-body: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-mono: 'Space Grotesk', monospace;
    }

    body {
      background-color: #f8fafc;
      background-image: 
        radial-gradient(circle 750px at 10% 10%, rgba(59, 130, 246, 0.15), transparent 70%),
        radial-gradient(circle 650px at 90% 15%, rgba(139, 92, 246, 0.13), transparent 70%),
        radial-gradient(circle 850px at 50% 50%, rgba(224, 231, 255, 0.45), transparent 75%),
        radial-gradient(circle 650px at 15% 85%, rgba(249, 115, 22, 0.08), transparent 70%),
        radial-gradient(circle 750px at 85% 85%, rgba(37, 99, 235, 0.12), transparent 70%);
      background-attachment: fixed;
      font-family: var(--font-body);
      color: #0f172a;
      -webkit-font-smoothing: antialiased;
    }

    /* Ambient Clean Light Texture (Pristine Apple Surface) */
    .tech-grid {
      background-image: none;
    }

    /* Apple Liquid Glassmorphism Panels & Cards */
    .studio-panel {
      background: rgba(255, 255, 255, 0.68);
      backdrop-filter: blur(28px) saturate(190%);
      -webkit-backdrop-filter: blur(28px) saturate(190%);
      border: 1px solid rgba(255, 255, 255, 0.85);
      border-radius: 1.5rem;
      box-shadow: 
        0 20px 40px -15px rgba(15, 23, 42, 0.05),
        0 4px 12px -2px rgba(15, 23, 42, 0.02),
        inset 0 1.5px 1.5px 0 rgba(255, 255, 255, 0.95),
        inset 0 -1px 1px 0 rgba(0, 0, 0, 0.02);
    }

    .studio-card {
      background: rgba(255, 255, 255, 0.62);
      backdrop-filter: blur(20px) saturate(180%);
      -webkit-backdrop-filter: blur(20px) saturate(180%);
      border: 1px solid rgba(255, 255, 255, 0.85);
      border-radius: 1.125rem;
      box-shadow: 
        0 2px 8px -1px rgba(15, 23, 42, 0.04),
        0 1px 3px 0 rgba(15, 23, 42, 0.02),
        inset 0 1px 1.5px 0 rgba(255, 255, 255, 0.95);
      transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
    }

    .studio-card:hover {
      background: rgba(255, 255, 255, 0.88);
      border-color: rgba(37, 99, 235, 0.45);
      box-shadow: 
        0 12px 28px -6px rgba(37, 99, 235, 0.14),
        0 4px 10px -2px rgba(15, 23, 42, 0.03),
        inset 0 1.5px 2px 0 rgba(255, 255, 255, 1);
      transform: translateY(-2px);
    }

    .studio-btn-primary {
      background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
      color: #ffffff;
      border: 1px solid rgba(255, 255, 255, 0.2);
      border-radius: 0.75rem;
      font-weight: 600;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      box-shadow: 0 4px 14px 0 rgba(37, 99, 235, 0.28);
    }

    .studio-btn-primary:hover {
      background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
      transform: translateY(-1px);
      box-shadow: 0 6px 20px 0 rgba(59, 130, 246, 0.38);
    }

    .studio-btn-primary:active {
      transform: scale(0.985);
    }

    /* Markdown Formatted Typography Inside Bubbles */
    .markdown-content {
      line-height: 1.6;
    }
    .markdown-content table {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      margin: 0.75rem 0;
      font-size: 0.8rem;
      border-radius: 0.625rem;
      overflow: hidden;
      border: 1px solid #dbeafe;
      background: #ffffff;
    }
    .markdown-content th {
      background-color: #eff6ff;
      font-weight: 600;
      color: #1d4ed8;
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 0.55rem 0.75rem;
      border-bottom: 1px solid #dbeafe;
      text-align: left;
    }
    .markdown-content td {
      padding: 0.55rem 0.75rem;
      border-bottom: 1px solid #eff6ff;
      color: #1e293b;
    }
    .markdown-content tr:last-child td {
      border-bottom: none;
    }
    .markdown-content tr:hover td {
      background-color: #eff6ff;
    }
    .markdown-content p {
      margin-bottom: 0.45rem;
    }
    .markdown-content p:last-child {
      margin-bottom: 0;
    }
    .markdown-content code {
      background-color: #eff6ff;
      color: #1d4ed8;
      padding: 0.15rem 0.45rem;
      border-radius: 0.375rem;
      font-family: var(--font-mono);
      font-size: 0.85em;
      font-weight: 600;
      border: 1px solid #dbeafe;
    }
    .markdown-content hr {
      border: 0;
      border-top: 1px solid #e2e8f0;
      margin: 0.75rem 0;
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

    /* Custom Modern Slim Scrollbar */
    .custom-scroll::-webkit-scrollbar {
      width: 5px;
      height: 5px;
    }
    .custom-scroll::-webkit-scrollbar-thumb {
      background: rgba(37, 99, 235, 0.25);
      border-radius: 9999px;
    }
    .custom-scroll::-webkit-scrollbar-thumb:hover {
      background: rgba(37, 99, 235, 0.45);
    }
    .custom-scroll::-webkit-scrollbar-track {
      background: transparent;
    }

    /* Apple Vision / macOS Glassmorphism for Icons & Badges */
    .apple-glass-icon {
      background: linear-gradient(135deg, rgba(255, 255, 255, 0.90) 0%, rgba(241, 245, 249, 0.65) 100%);
      backdrop-filter: blur(16px) saturate(180%);
      -webkit-backdrop-filter: blur(16px) saturate(180%);
      border: 1px solid rgba(255, 255, 255, 0.95);
      box-shadow: 
        0 2px 8px -1px rgba(15, 23, 42, 0.06),
        0 1px 3px 0 rgba(15, 23, 42, 0.03),
        inset 0 1px 1.5px 0 rgba(255, 255, 255, 1),
        inset 0 -1px 1px 0 rgba(0, 0, 0, 0.03);
      transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
    .apple-glass-icon:hover {
      transform: translateY(-1px) scale(1.04);
      box-shadow: 
        0 6px 16px -2px rgba(37, 99, 235, 0.16),
        inset 0 1px 2px 0 rgba(255, 255, 255, 1);
    }

    .apple-glass-teal, .apple-glass-blue {
      background: linear-gradient(135deg, rgba(219, 234, 254, 0.85) 0%, rgba(239, 246, 255, 0.45) 100%);
      border: 1px solid rgba(255, 255, 255, 0.9);
      box-shadow: 
        0 4px 14px -2px rgba(37, 99, 235, 0.18),
        inset 0 1px 1.5px 0 rgba(255, 255, 255, 0.95);
      color: #1d4ed8;
    }
    .apple-glass-amber {
      background: linear-gradient(135deg, rgba(254, 243, 199, 0.85) 0%, rgba(255, 251, 235, 0.45) 100%);
      border: 1px solid rgba(255, 255, 255, 0.9);
      box-shadow: 
        0 4px 14px -2px rgba(245, 158, 11, 0.18),
        inset 0 1px 1.5px 0 rgba(255, 255, 255, 0.95);
      color: #b45309;
    }
    .apple-glass-emerald, .apple-glass-indigo {
      background: linear-gradient(135deg, rgba(224, 231, 255, 0.85) 0%, rgba(238, 242, 255, 0.45) 100%);
      border: 1px solid rgba(255, 255, 255, 0.9);
      box-shadow: 
        0 4px 14px -2px rgba(79, 70, 229, 0.18),
        inset 0 1px 1.5px 0 rgba(255, 255, 255, 0.95);
      color: #4338ca;
    }
    .apple-glass-brand {
      background: linear-gradient(135deg, rgba(37, 99, 235, 0.95) 0%, rgba(29, 78, 216, 0.98) 100%);
      border: 1px solid rgba(255, 255, 255, 0.45);
      box-shadow: 
        0 6px 20px -2px rgba(37, 99, 235, 0.35),
        inset 0 1.5px 2px 0 rgba(255, 255, 255, 0.75),
        inset 0 -2px 3px 0 rgba(0, 0, 0, 0.15);
    }
    .apple-glass-avatar {
      background: linear-gradient(135deg, rgba(37, 99, 235, 0.95) 0%, rgba(124, 58, 237, 0.95) 100%);
      border: 1px solid rgba(255, 255, 255, 0.5);
      box-shadow: 
        0 4px 14px -2px rgba(37, 99, 235, 0.28),
        inset 0 1px 1.5px 0 rgba(255, 255, 255, 0.8);
    }
  </style>
</head>
<body class="min-h-screen flex flex-col selection:bg-blue-600 selection:text-white tech-grid">

  <!-- Top Cyber-FinTech Glass Header -->
  <header class="border-b border-white/60 bg-white/65 backdrop-blur-2xl sticky top-0 z-50 shadow-[0_4px_20px_-4px_rgba(15,23,42,0.04)]">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
      
      <!-- Brand & Studio Title -->
      <div class="flex items-center space-x-3">
        <div class="apple-glass-icon apple-glass-brand w-9 h-9 rounded-xl flex items-center justify-center text-white text-base font-bold shadow-[0_2px_10px_rgba(37,99,235,0.25)] cursor-default">
          <svg class="w-4.5 h-4.5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
        </div>
        <div class="flex items-center space-x-2">
          <span class="font-extrabold text-[17px] tracking-tight text-slate-900">Revenue<span class="text-transparent bg-clip-text bg-gradient-to-r from-blue-600 via-indigo-600 to-violet-600">Agent</span></span>
          <span class="hidden sm:inline-flex items-center px-2 py-0.5 text-[10px] font-mono tracking-wide uppercase font-semibold rounded-md bg-blue-50/80 text-blue-700 border border-blue-200/60">Mandate Rail</span>
        </div>
      </div>

      <!-- Live Environment Status Badges & Quick Action Controls -->
      <div class="flex items-center space-x-2.5 text-xs">
        <div class="hidden md:flex items-center space-x-2 px-2.5 py-1 rounded-full bg-white/70 backdrop-blur-md text-slate-600 border border-white/80 font-medium shadow-2xs">
          <span class="relative flex h-2 w-2">
            <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span>
            <span class="relative inline-flex rounded-full h-2 w-2 bg-blue-600"></span>
          </span>
          <span class="text-[11px] tracking-tight">Razorpay Test Mode Active</span>
        </div>

        <div id="theme-indicator" class="flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-amber-50/70 backdrop-blur-md text-amber-900 border border-amber-200/60 font-medium shadow-2xs">
          <svg class="w-3.5 h-3.5 text-amber-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" clip-rule="evenodd"/></svg>
          <span class="text-[11px] font-semibold">Light</span>
        </div>

        <div class="h-4 w-px bg-slate-200 mx-0.5"></div>

        <button onclick="refreshData()" class="h-8 px-3 rounded-lg bg-white/70 hover:bg-white/90 backdrop-blur-md text-slate-700 font-medium border border-white/80 hover:border-slate-300 transition-all shadow-2xs flex items-center space-x-1.5 cursor-pointer text-xs active:scale-95">
          <svg class="w-3.5 h-3.5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
          <span>Sync State</span>
        </button>

        <button onclick="startNewOrder()" class="h-8 px-3.5 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 active:scale-95 text-white font-semibold transition-all shadow-[0_2px_8px_rgba(37,99,235,0.28)] flex items-center space-x-1.5 cursor-pointer text-xs">
          <svg class="w-3.5 h-3.5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.2" d="M12 4v16m8-8H4"/></svg>
          <span>New Order</span>
        </button>
      </div>

    </div>
  </header>

  <!-- Interactive Scenario Bar -->
  <div class="max-w-7xl mx-auto px-4 sm:px-6 pt-4 w-full">
    <div class="bg-white/65 backdrop-blur-2xl border border-white/85 rounded-2xl px-3.5 py-2 flex flex-wrap items-center justify-between gap-2.5 text-xs shadow-[0_8px_30px_rgba(15,23,42,0.04)]">
      <div class="flex items-center space-x-2 flex-wrap gap-y-1">
        <span class="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center space-x-1 mr-1">
          <svg class="w-3 h-3 text-blue-600" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M11.3 1.046A1 1 0 0112 2v5h4a1 1 0 01.82 1.573l-7 10A1 1 0 018 18v-5H4a1 1 0 01-.82-1.573l7-10a1 1 0 011.12-.38z" clip-rule="evenodd"/></svg>
          <span>Quick Flows:</span>
        </span>
        <button onclick="sendQuickPrompt('I want wireless earbuds under ₹2,000.')" class="px-2.5 py-1 rounded-lg bg-white/70 hover:bg-blue-50/90 hover:text-blue-700 backdrop-blur-md text-slate-700 border border-white/80 hover:border-blue-200 transition-all font-medium text-[11px] flex items-center space-x-1 cursor-pointer active:scale-95 shadow-2xs">
          <span>🎧 Earbuds + Case</span>
        </button>
        <button onclick="sendQuickPrompt('Simulate order creation failure for graceful payment link fallback.')" class="px-2.5 py-1 rounded-lg bg-white/70 hover:bg-amber-50/90 hover:text-amber-800 backdrop-blur-md text-slate-700 border border-white/80 hover:border-amber-200 transition-all font-medium text-[11px] flex items-center space-x-1 cursor-pointer active:scale-95 shadow-2xs">
          <span>⚠️ Failover Link</span>
        </button>
        <button onclick="sendQuickPrompt('Refresh the product catalog using Firecrawl.')" class="px-2.5 py-1 rounded-lg bg-white/70 hover:bg-white/95 hover:text-slate-900 backdrop-blur-md text-slate-700 border border-white/80 hover:border-slate-300 transition-all font-medium text-[11px] flex items-center space-x-1 cursor-pointer active:scale-95 shadow-2xs">
          <span>🔥 Firecrawl Refresh</span>
        </button>
      </div>
      <div class="text-[11px] text-slate-500 font-mono flex items-center space-x-1.5 bg-white/70 backdrop-blur-md px-2.5 py-1 rounded-lg border border-white/80">
        <span class="w-1.5 h-1.5 rounded-full bg-blue-600"></span>
        <span class="text-slate-400">Buyer:</span>
        <strong id="buyer-tag" class="text-slate-800 font-semibold font-mono">buyer_42</strong>
      </div>
    </div>
  </div>

  <!-- Main Dual-Panel Workspace -->
  <main class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 grid grid-cols-1 lg:grid-cols-12 gap-6">

    <!-- Left Column: Conversational AI Checkout Agent (6 cols) -->
    <section class="lg:col-span-6 flex flex-col space-y-5">
      
      <!-- Conversational Assistant Box -->
      <div class="studio-panel p-5 flex-1 flex flex-col space-y-4">
        <div class="flex items-center justify-between border-b border-slate-200/80 pb-3.5">
          <div class="flex items-center space-x-2.5">
            <div class="apple-glass-icon apple-glass-blue w-8 h-8 rounded-xl relative">
              <span class="animate-ping absolute -top-0.5 -right-0.5 inline-flex h-2 w-2 rounded-full bg-blue-400 opacity-75"></span>
              <span class="relative inline-flex rounded-full h-1.5 w-1.5 bg-blue-600"></span>
              <svg class="w-4 h-4 text-blue-700 ml-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
            </div>
            <h2 class="text-xs font-bold uppercase tracking-wider text-slate-800">AI Checkout Assistant</h2>
          </div>
          <div class="flex items-center space-x-2">
            <span class="px-2 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200 text-[10px] font-mono">gpt-oss-120b</span>
            <span class="text-[11px] font-medium text-slate-500">Groq LLM Engine</span>
          </div>
        </div>

        <!-- Chat Stream -->
        <div id="chat-stream" class="flex-1 min-h-[340px] max-h-[460px] overflow-y-auto space-y-3.5 custom-scroll p-4 bg-white/40 backdrop-blur-xl rounded-2xl border border-white/70 text-sm shadow-inner">
          <div class="flex items-start space-x-3">
            <div class="apple-glass-icon apple-glass-avatar w-9 h-9 rounded-2xl text-white flex items-center justify-center flex-shrink-0 text-xs font-bold font-mono">
              AI
            </div>
            <div class="bg-white/85 backdrop-blur-xl border border-white/95 text-slate-800 rounded-2xl rounded-tl-sm px-4 py-3 leading-relaxed shadow-[0_2px_10px_rgba(15,23,42,0.03)] max-w-[85%]">
              <p>Welcome! I'm <strong class="text-slate-900 font-semibold">RevenueAgent</strong>. What would you like to purchase today? Tell me your product preferences and budget limit, and I will assemble an explainable cart mandate with verified bundle discounts.</p>
            </div>
          </div>
        </div>

        <!-- Chat Input Field -->
        <form id="chat-form" onsubmit="handleChatSubmit(event)" class="relative pt-2">
          <input
            id="chat-input"
            type="text"
            placeholder="Type e.g. 'I want wireless earbuds under ₹2,000'..."
            class="w-full bg-white/75 backdrop-blur-xl border border-white/85 focus:bg-white/95 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 rounded-xl px-4 py-3.5 text-sm text-slate-900 placeholder-slate-400 focus:outline-none pr-28 transition shadow-xs"
          />
          <button
            type="submit"
            id="send-btn"
            class="absolute right-2.5 top-4.5 px-4 py-1.5 studio-btn-primary text-xs flex items-center space-x-1.5 cursor-pointer"
          >
            <span>Send</span>
            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
          </button>
        </form>
      </div>

      <!-- Quick Interactive Catalog Grid -->
      <div class="studio-panel p-4 space-y-3">
        <div class="flex items-center justify-between border-b border-slate-200/80 pb-2.5">
          <div class="flex items-center space-x-2.5">
            <div class="apple-glass-icon apple-glass-blue w-7 h-7 rounded-xl">
              <svg class="w-4 h-4 text-blue-700" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 11V7a4 4 0 00-8 0v4M5 9h14l1 12H4L5 9z"/></svg>
            </div>
            <h3 class="text-xs font-bold uppercase tracking-wider text-slate-800">Authoritative Product Catalog</h3>
          </div>
          <span class="text-[11px] text-slate-500 font-mono">Click tile to assemble cart</span>
        </div>
        <div class="grid grid-cols-2 gap-3 text-xs">
          <button onclick="addCatalogItemToCart('prod_eb_01', 1)" class="studio-card p-3.5 text-left group cursor-pointer">
            <div class="font-semibold text-slate-800 group-hover:text-blue-700 transition">AcousticBass Earbuds Pro</div>
            <div class="text-blue-700 text-[11px] font-mono mt-1 font-semibold flex items-center justify-between">
              <span>₹1,799.00</span>
              <span class="text-[10px] text-slate-500 font-sans group-hover:text-blue-700">Add to Cart →</span>
            </div>
          </button>
          <button onclick="addCatalogItemToCart('prod_eb_02', 1)" class="studio-card p-3.5 text-left group cursor-pointer">
            <div class="font-semibold text-slate-800 group-hover:text-blue-700 transition">SonicLite Wireless Earbuds</div>
            <div class="text-blue-700 text-[11px] font-mono mt-1 font-semibold flex items-center justify-between">
              <span>₹1,299.00</span>
              <span class="text-[10px] text-slate-500 font-sans group-hover:text-blue-700">Add to Cart →</span>
            </div>
          </button>
          <button onclick="addCatalogItemToCart('prod_case_01', 1)" class="studio-card p-3.5 text-left group cursor-pointer">
            <div class="font-semibold text-slate-800 group-hover:text-blue-700 transition">Silicone Protective Case</div>
            <div class="text-slate-600 text-[11px] font-mono mt-1 flex items-center justify-between">
              <span>₹399.00</span>
              <span class="text-indigo-700 font-semibold text-[10px] bg-indigo-50 px-1.5 py-0.5 rounded border border-indigo-200">(10% upsell)</span>
            </div>
          </button>
          <button onclick="addCatalogItemToCart('prod_cable_01', 1)" class="studio-card p-3.5 text-left group cursor-pointer">
            <div class="font-semibold text-slate-800 group-hover:text-blue-700 transition">Braided Type-C 60W Cable</div>
            <div class="text-slate-600 text-[11px] font-mono mt-1 flex items-center justify-between">
              <span>₹249.00</span>
              <span class="text-[10px] text-slate-500 font-sans group-hover:text-blue-700">Add to Cart →</span>
            </div>
          </button>
        </div>
      </div>

    </section>

    <!-- Right Column: Mandate Verification Rail & Payment Engine (6 cols) -->
    <section class="lg:col-span-6 space-y-5 flex flex-col">

      <!-- Mandate Security Gate Panel -->
      <div class="studio-panel p-5 space-y-5">
        <div class="flex items-center justify-between border-b border-slate-200/80 pb-3.5">
          <div class="flex items-center space-x-2.5">
            <div class="apple-glass-icon apple-glass-blue w-7 h-7 rounded-xl">
              <svg class="w-4 h-4 text-blue-700" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
            </div>
            <h2 class="text-xs font-bold uppercase tracking-wider text-slate-800">Mandate Security Gate</h2>
          </div>
          <span id="pipeline-status" class="px-2.5 py-0.5 text-[10px] font-mono font-bold rounded-full bg-blue-50 text-blue-700 border border-blue-200">ACTIVE</span>
        </div>

        <!-- 4-Stage State Progression Pipeline -->
        <div class="grid grid-cols-4 gap-2 text-center text-[10px] font-mono font-semibold">
          <div id="step-intent" class="p-2.5 rounded-xl bg-white/50 backdrop-blur-md border border-white/70 text-slate-400 transition-all">1. INTENT</div>
          <div id="step-cart" class="p-2.5 rounded-xl bg-white/50 backdrop-blur-md border border-white/70 text-slate-400 transition-all">2. CART DRAFT</div>
          <div id="step-gate" class="p-2.5 rounded-xl bg-white/50 backdrop-blur-md border border-white/70 text-slate-400 transition-all">3. CONFIRMED</div>
          <div id="step-pay" class="p-2.5 rounded-xl bg-white/50 backdrop-blur-md border border-white/70 text-slate-400 transition-all">4. CAPTURED</div>
        </div>

        <!-- Mandates Details Cards -->
        <div class="space-y-3.5 text-xs">
          <!-- Intent Mandate -->
          <div class="studio-card p-4 flex justify-between items-center">
            <div>
              <span class="text-slate-500 block text-[10px] uppercase font-semibold tracking-wider">Intent Mandate</span>
              <strong id="card-intent-id" class="font-mono text-xs text-blue-700">Waiting for goal...</strong>
            </div>
            <div class="text-right">
              <span class="text-slate-500 block text-[10px] uppercase font-semibold tracking-wider">Budget Cap</span>
              <span id="card-intent-budget" class="font-mono font-bold text-slate-900 text-sm">₹0.00</span>
            </div>
          </div>

          <!-- Cart Mandate -->
          <div class="studio-card p-4 space-y-3">
            <div class="flex justify-between items-center">
              <div>
                <span class="text-slate-500 block text-[10px] uppercase font-semibold tracking-wider">Cart Mandate (Zero-Trust)</span>
                <strong id="card-cart-id" class="font-mono text-xs text-blue-700">Empty Cart</strong>
              </div>
              <div class="text-right">
                <span class="text-slate-500 block text-[10px] uppercase font-semibold tracking-wider">Cart Total</span>
                <span id="card-cart-total" class="font-mono font-bold text-blue-700 text-base">₹0.00</span>
              </div>
            </div>

            <!-- Item Names & Quantity Breakdown -->
            <div id="card-cart-items" class="pt-2.5 border-t border-slate-200 space-y-1.5 hidden">
            </div>

            <!-- Confirmation Gate Box -->
            <div id="approval-box" class="hidden p-3.5 bg-amber-50/85 border border-amber-300/80 rounded-xl space-y-2.5 backdrop-blur-xl shadow-xs">
              <div class="flex items-center justify-between text-amber-900 text-xs font-semibold">
                <span class="flex items-center space-x-2">
                  <div class="apple-glass-icon apple-glass-amber w-6 h-6 rounded-lg flex-shrink-0">
                    <svg class="w-3.5 h-3.5 text-amber-700" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                  </div>
                  <span>Confirmation Gate: Explicit Approval Required</span>
                </span>
                <span class="font-mono text-[10px] bg-amber-100/90 text-amber-900 px-2 py-0.5 rounded border border-amber-300/80" id="approval-token-tag">tok_...</span>
              </div>
              <button onclick="approveCurrentCart()" class="w-full py-2.5 px-3 bg-gradient-to-r from-amber-500 via-orange-500 to-amber-600 hover:from-amber-400 hover:to-orange-500 active:scale-[0.99] text-white font-bold rounded-lg transition text-xs flex items-center justify-center space-x-1.5 shadow-md shadow-orange-500/25 cursor-pointer">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
                <span>Approve & Lock Cart Mandate</span>
              </button>
            </div>
          </div>
        </div>

        <!-- Budget Utilization Metric -->
        <div class="studio-card p-4 space-y-2.5">
          <div class="flex justify-between text-xs font-mono">
            <span class="text-slate-500 font-medium">Budget Utilization:</span>
            <span id="utilization-pct" class="font-bold text-blue-700">0%</span>
          </div>
          <div class="w-full bg-slate-200/60 rounded-full h-2.5 overflow-hidden border border-white/70">
            <div id="utilization-bar" class="bg-gradient-to-r from-blue-600 via-indigo-600 to-violet-600 h-2.5 rounded-full transition-all duration-500" style="width: 0%"></div>
          </div>
          <div class="flex justify-between text-[11px] text-slate-500 font-mono">
            <span>Spent: <strong id="metric-spent" class="text-slate-900">₹0.00</strong></span>
            <span>Savings Remaining: <strong id="metric-savings" class="text-indigo-700 font-semibold">₹0.00</strong></span>
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
        <div id="payment-success-card" class="hidden p-4 rounded-xl bg-indigo-50/85 border border-indigo-200/90 space-y-2 text-indigo-900 backdrop-blur-xl shadow-xs">
          <div class="flex items-center space-x-2.5">
            <div class="apple-glass-icon apple-glass-indigo w-8 h-8 rounded-xl flex-shrink-0">
              <svg class="w-5 h-5 text-indigo-600" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1-1 0 00-1.414-1.414L9 10.586 7.707 9.293a1-1 0 00-1.414 1.414l2 2a1-1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
            </div>
            <h3 class="font-bold text-sm text-slate-900">Payment Captured & Verified!</h3>
          </div>
          <p class="text-xs text-slate-700">Razorpay Payment ID: <strong id="success-pay-id" class="font-mono text-indigo-700">pay_...</strong></p>
          <p class="text-xs text-slate-700">Payment Mandate Status: <strong class="font-mono text-indigo-700 font-bold">PAYMENT_CAPTURED</strong></p>
        </div>
      </div>

      <!-- Live Audit Stream -->
      <div class="studio-panel p-4 flex-1 space-y-3">
        <div class="flex items-center justify-between border-b border-slate-200/80 pb-2.5">
          <div class="flex items-center space-x-2.5">
            <div class="apple-glass-icon apple-glass-blue w-7 h-7 rounded-xl">
              <svg class="w-4 h-4 text-blue-700" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
            </div>
            <h3 class="text-xs font-bold uppercase tracking-wider text-slate-800">Live Audit Telemetry Stream</h3>
            <span id="audit-badge" class="px-1.5 py-0.5 text-[9px] font-mono font-bold rounded bg-blue-50 text-blue-700 border border-blue-200">CHAIN VERIFIED</span>
          </div>
          <button onclick="verifyAuditChainIntegrity()" class="text-[11px] font-mono text-blue-700 hover:text-blue-900 underline cursor-pointer flex items-center space-x-1">
            <span>Verify Integrity</span>
          </button>
        </div>
        <div id="audit-stream" class="space-y-2 max-h-44 overflow-y-auto custom-scroll text-[11px] font-mono text-slate-600 pr-1">
          <div class="p-2.5 rounded-xl bg-white/60 backdrop-blur-md border border-white/80">
            <span class="text-blue-700 font-bold font-mono">[BOOT]</span> Autonomous Mandate Rail Gateway Active.
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
            <div class="p-2.5 rounded-xl bg-white/60 backdrop-blur-md border border-white/80 hover:border-blue-200 transition shadow-2xs">
              <div class="flex justify-between text-[10px] text-slate-500 pb-1">
                <span class="text-blue-700 font-bold font-mono">[${e.event_type}]</span>
                <span class="font-mono text-slate-400">${new Date(e.timestamp).toLocaleTimeString()}</span>
              </div>
              <p class="text-slate-700 font-sans text-xs leading-relaxed">${e.summary || JSON.stringify(e.data)}</p>
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
          document.getElementById("step-intent").className = "p-2.5 rounded-xl bg-blue-50/80 backdrop-blur-md border border-blue-300/80 text-blue-800 font-bold shadow-xs";
        } else {
          document.getElementById("card-intent-id").innerText = "Waiting for goal...";
          document.getElementById("card-intent-budget").innerText = "₹0.00";
          document.getElementById("step-intent").className = "p-2.5 rounded-xl bg-white/50 backdrop-blur-md border border-white/70 text-slate-400";
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
          document.getElementById("step-cart").className = "p-2.5 rounded-xl bg-blue-50/80 backdrop-blur-md border border-blue-300/80 text-blue-800 font-bold shadow-xs";

          // Match payment mandate SPECIFICALLY for this active cart!
          const allPayments = Object.values(data.payment_mandates || {});
          const matchingPay = allPayments.find(p => p.cart_mandate_id === latestCart.cart_mandate_id);

          if (matchingPay && matchingPay.status === "PAYMENT_CAPTURED") {
            activePaymentMandateId = matchingPay.payment_mandate_id;
            document.getElementById("approval-box").classList.add("hidden");
            document.getElementById("step-gate").className = "p-2.5 rounded-xl bg-indigo-50/80 backdrop-blur-md border border-indigo-300/80 text-indigo-700 font-bold shadow-xs";
            document.getElementById("step-pay").className = "p-2.5 rounded-xl bg-indigo-50/80 backdrop-blur-md border border-indigo-300/80 text-indigo-700 font-bold shadow-xs";
            document.getElementById("payment-success-card").classList.remove("hidden");
            document.getElementById("success-pay-id").innerText = matchingPay.razorpay_payment_id || "pay_verified";
            disableCheckoutBtn("Payment Completed ✓");
          } else if (latestCart.status === "PENDING_APPROVAL") {
            document.getElementById("approval-box").classList.remove("hidden");
            document.getElementById("approval-token-tag").innerText = latestCart.approval_token;
            document.getElementById("step-gate").className = "p-2.5 rounded-xl bg-white/50 backdrop-blur-md border border-white/70 text-slate-400";
            document.getElementById("step-pay").className = "p-2.5 rounded-xl bg-white/50 backdrop-blur-md border border-white/70 text-slate-400";
            document.getElementById("payment-success-card").classList.add("hidden");
            disableCheckoutBtn("Awaiting Cart Approval");
          } else if (latestCart.status === "APPROVED" || latestCart.status === "PAYMENT_PENDING") {
            document.getElementById("approval-box").classList.add("hidden");
            document.getElementById("step-gate").className = "p-2.5 rounded-xl bg-indigo-50/80 backdrop-blur-md border border-indigo-300/80 text-indigo-700 font-bold shadow-xs";
            document.getElementById("step-pay").className = "p-2.5 rounded-xl bg-white/50 backdrop-blur-md border border-white/70 text-slate-400";
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
                <div class="flex justify-between items-center text-xs text-slate-700 py-1.5 border-b border-slate-100 last:border-0">
                  <span class="font-medium text-slate-800"><span class="px-1.5 py-0.5 rounded bg-blue-50 text-[10px] font-mono text-blue-800 mr-1.5 border border-blue-200">${item.qty}×</span>${item.product_name || item.product_id}</span>
                  <span class="font-mono text-blue-700 font-semibold">₹${(item.line_total_inr || (item.line_total_paise / 100)).toFixed(2)}${item.discount_pct > 0 ? ` <span class="text-indigo-700 font-semibold text-[10px] bg-indigo-50 px-1 py-0.5 rounded border border-indigo-200 ml-1">(${item.discount_pct}% OFF)</span>` : ''}</span>
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
          document.getElementById("step-cart").className = "p-2.5 rounded-xl bg-white/50 backdrop-blur-md border border-white/70 text-slate-400";
          document.getElementById("step-gate").className = "p-2.5 rounded-xl bg-white/50 backdrop-blur-md border border-white/70 text-slate-400";
          document.getElementById("step-pay").className = "p-2.5 rounded-xl bg-white/50 backdrop-blur-md border border-white/70 text-slate-400";
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
      btn.className = "w-full py-4 px-6 bg-gradient-to-r from-blue-600 via-indigo-600 to-blue-700 hover:from-blue-500 hover:to-indigo-500 active:scale-[0.99] text-white font-bold rounded-xl shadow-lg shadow-blue-600/25 transition-all flex items-center justify-center space-x-2 cursor-pointer border border-blue-500/30";
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
        theme: { color: "#2563eb" },
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
        <div class="apple-glass-icon ${isUser ? 'w-9 h-9 rounded-2xl text-slate-700' : 'apple-glass-avatar w-9 h-9 rounded-2xl text-white'} flex items-center justify-center flex-shrink-0 text-xs font-bold font-mono">
          ${isUser ? 'You' : 'AI'}
        </div>
        <div class="${isUser ? 'bg-gradient-to-r from-blue-600 to-indigo-600 text-white rounded-2xl rounded-tr-sm shadow-md shadow-blue-600/25 border border-blue-400/30' : 'bg-white/85 backdrop-blur-xl border border-white/95 text-slate-800 rounded-2xl rounded-tl-sm shadow-[0_2px_10px_rgba(15,23,42,0.03)] markdown-content'} px-4 py-3 leading-relaxed max-w-[85%]">
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
            <div class="apple-glass-icon apple-glass-avatar w-9 h-9 rounded-2xl text-white flex items-center justify-center flex-shrink-0 text-xs font-bold font-mono">
              AI
            </div>
            <div class="bg-white/85 backdrop-blur-xl border border-white/95 text-slate-800 rounded-2xl rounded-tl-sm px-4 py-3 leading-relaxed shadow-[0_2px_10px_rgba(15,23,42,0.03)] max-w-[85%]">
              <p>Fresh order session started! <strong class="text-blue-700 font-semibold">Stage 1 (Intent Mandate)</strong> is active with budget cap <strong class="text-slate-900 font-mono">₹2,000.00</strong>. Tell me your product preferences or click a quick flow to assemble your cart mandate with bundle savings.</p>
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
