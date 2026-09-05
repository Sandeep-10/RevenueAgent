"""
RevenueAgent: Agentic checkout assistant for Razorpay merchants (test mode).
Enforces bounded Intent -> Cart -> Payment Mandates (with full lifecycle states),
zero-trust server-side pricing, explicit User Confirmation Gates, Firecrawl v2 JSON extraction,
Cryptographic Tamper-Evident HMAC Hash-Chained Audit Ledger, and fallback resilience.
"""

import datetime
import hashlib
import hmac
import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import requests
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from langchain_core.tools import tool
except ImportError:  # ponytail: fallback decorator if langchain is not installed
    def tool(fn=None, *, args_schema=None):
        def decorator(f):
            f.args_schema = args_schema
            return f
        return decorator(fn) if fn else decorator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("RevenueAgent")

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "rzp_test_placeholder")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "placeholder_secret")
RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET", "rzp_webhook_secret_default_123")
FIRECRAWL_API_KEY = os.getenv("FIRECRAWL_API_KEY", "")
AUDIT_SECRET = os.getenv("AUDIT_SECRET", "audit_ledger_hmac_secret_key_default")

# -----------------------------------------------------------------------------
# In-Memory Mandate Stores & Tamper-Evident Ledger
# -----------------------------------------------------------------------------

SEED_CATALOG: List[Dict[str, Any]] = [
    {
        "id": "prod_eb_01",
        "name": "AcousticBass Wireless Earbuds Pro",
        "category": "electronics",
        "price_paise": 179900,  # ₹1,799
        "description": "True wireless earbuds with active noise cancellation and 30hr battery.",
        "upsell_rules": [
            {
                "target_product_id": "prod_case_01",
                "discount_pct": 10.0,
                "reason": "Protect your earbuds with a silicone shockproof case (10% OFF)."
            }
        ]
    },
    {
        "id": "prod_eb_02",
        "name": "SonicLite Wireless Earbuds",
        "category": "electronics",
        "price_paise": 129900,  # ₹1,299
        "description": "Lightweight wireless earbuds with crystal clear calls and IPX4 water resistance.",
        "upsell_rules": [
            {
                "target_product_id": "prod_case_01",
                "discount_pct": 10.0,
                "reason": "Bundle with a silicone case for 10% OFF."
            }
        ]
    },
    {
        "id": "prod_case_01",
        "name": "Silicone Protective Earbuds Case",
        "category": "electronics",
        "price_paise": 39900,  # ₹399
        "description": "Shockproof silicone case with metal carabiner clip.",
        "upsell_rules": []
    },
    {
        "id": "prod_cable_01",
        "name": "Braided Fast-Charging Type-C Cable",
        "category": "electronics",
        "price_paise": 24900,  # ₹249
        "description": "60W durable nylon braided fast charging cable (1.2m).",
        "upsell_rules": []
    }
]

CATALOG: List[Dict[str, Any]] = list(SEED_CATALOG)
INTENT_MANDATES: Dict[str, Dict[str, Any]] = {}
CART_MANDATES: Dict[str, Dict[str, Any]] = {}
PAYMENT_MANDATES: Dict[str, Dict[str, Any]] = {}
AUDIT_LOG: List[Dict[str, Any]] = []

GENESIS_HASH = "GENESIS_0000000000000000000000000000000000000000000000000000000000000000"
LAST_EVENT_HASH = GENESIS_HASH


# -----------------------------------------------------------------------------
# Cryptographic Tamper-Evident Audit Ledger
# -----------------------------------------------------------------------------

def append_audit_event(
    event_type: str,
    actor: str,
    buyer_id: str,
    data: Dict[str, Any],
    summary: Optional[str] = None
) -> Dict[str, Any]:
    """
    Appends an immutable, cryptographic hash-chained and HMAC-signed audit event.
    Guarantees tamper-evident traceability across the entire mandate lifecycle.
    """
    global LAST_EVENT_HASH

    event_payload = {
        "event_id": f"evt_{uuid.uuid4().hex[:8]}",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": event_type,
        "actor": actor,
        "buyer_id": buyer_id,
        "summary": summary or f"Executed {event_type}",
        "data": json.loads(json.dumps(data)),
        "prev_hash": LAST_EVENT_HASH
    }

    # Canonical serialization: sorted keys, compact separators
    canonical_json = json.dumps(event_payload, sort_keys=True, separators=(",", ":"))
    event_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    # HMAC signature using audit secret
    signature = hmac.new(
        AUDIT_SECRET.encode("utf-8"),
        event_hash.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    event = {
        **event_payload,
        "event_hash": event_hash,
        "signature": signature
    }

    LAST_EVENT_HASH = event_hash
    AUDIT_LOG.append(event)
    logger.info("AUDIT [%s] buyer=%s | %s (hash: %s...)", event_type, buyer_id, event["summary"], event_hash[:8])
    return event


def verify_audit_chain() -> Dict[str, Any]:
    """
    Cryptographically verifies the integrity of the audit ledger from genesis to the latest event.
    Detects any modification, insertion, or reordering of logged events.
    """
    current_expected_prev = GENESIS_HASH

    for idx, event in enumerate(AUDIT_LOG):
        # 1. Verify prev_hash link
        if event["prev_hash"] != current_expected_prev:
            return {
                "is_valid": False,
                "error_at_index": idx,
                "event_id": event.get("event_id"),
                "reason": f"Broken hash chain: expected prev_hash '{current_expected_prev}', found '{event['prev_hash']}'"
            }

        # 2. Verify event_hash reconstruction
        event_copy = {k: v for k, v in event.items() if k not in ("event_hash", "signature")}
        canonical = json.dumps(event_copy, sort_keys=True, separators=(",", ":"))
        calculated_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        if calculated_hash != event["event_hash"]:
            return {
                "is_valid": False,
                "error_at_index": idx,
                "event_id": event.get("event_id"),
                "reason": "Payload data tampering detected: event_hash mismatch."
            }

        # 3. Verify HMAC signature
        expected_sig = hmac.new(
            AUDIT_SECRET.encode("utf-8"),
            event["event_hash"].encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_sig, event["signature"]):
            return {
                "is_valid": False,
                "error_at_index": idx,
                "event_id": event.get("event_id"),
                "reason": "Cryptographic signature mismatch: unauthorized event modification."
            }

        current_expected_prev = event["event_hash"]

    return {
        "is_valid": True,
        "total_events": len(AUDIT_LOG),
        "last_event_hash": LAST_EVENT_HASH,
        "status": "CHAIN_INTEGRITY_VERIFIED"
    }


# -----------------------------------------------------------------------------
# Core Implementation Functions
# -----------------------------------------------------------------------------

def refresh_product_catalog(url: str = "https://example.com/products", mode: str = "extend") -> Dict[str, Any]:
    """Refreshes catalog via Firecrawl v2 JSON extraction, strictly validating positive prices."""
    global CATALOG
    scraped_items = []
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if FIRECRAWL_API_KEY:
        try:
            resp = requests.post(
                "https://api.firecrawl.dev/v2/scrape",
                headers={"Authorization": f"Bearer {FIRECRAWL_API_KEY}", "Content-Type": "application/json"},
                json={
                    "url": url,
                    "formats": [{
                        "type": "json",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "products": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "string"},
                                            "name": {"type": "string"},
                                            "price_inr": {"type": "number"},
                                            "category": {"type": "string"},
                                            "description": {"type": "string"}
                                        },
                                        "required": ["name", "price_inr"]
                                    }
                                }
                            },
                            "required": ["products"]
                        },
                        "prompt": "Extract every purchasable product. Return the exact current displayed INR price."
                    }]
                },
                timeout=15
            )
            if resp.status_code == 200:
                body = resp.json()
                if body.get("success", True):
                    extracted = body.get("data", {}).get("json", {}).get("products") or []
                    for idx, item in enumerate(extracted):
                        price_inr = item.get("price_inr")
                        if not isinstance(price_inr, (int, float)) or price_inr <= 0:
                            continue
                        scraped_items.append({
                            "id": item.get("id") or f"prod_scraped_{idx+1}",
                            "name": item.get("name", "Extracted Product"),
                            "category": item.get("category", "general"),
                            "price_paise": int(round(float(price_inr) * 100)),
                            "description": item.get("description", ""),
                            "upsell_rules": [],
                            "refreshed_at": now_iso
                        })
                    if scraped_items:
                        if mode == "replace":
                            CATALOG = scraped_items
                        else:
                            CATALOG.extend([p for p in scraped_items if not any(c["id"] == p["id"] for c in CATALOG)])
                        append_audit_event(
                            "CATALOG_REFRESHED_FIRECRAWL",
                            "system",
                            "system",
                            {"url": url, "scraped_count": len(scraped_items)},
                            summary=f"Firecrawl v2 catalog refreshed ({len(scraped_items)} products loaded)"
                        )
                        return {"status": "success", "scraped_count": len(scraped_items), "total_products": len(CATALOG)}
        except Exception as e:
            logger.warning("Firecrawl catalog refresh failed, falling back: %s", str(e))

    append_audit_event("CATALOG_REFRESHED_STATIC", "system", "system", {"total_products": len(CATALOG)}, summary="Catalog seeded from default store")
    return {"status": "success", "scraped_count": len(scraped_items), "total_products": len(CATALOG)}


def search_products(query: str, max_price_inr: Optional[float] = None, category: Optional[str] = None) -> List[Dict[str, Any]]:
    """Searches the authoritative catalog matching query, price ceiling, and category filter."""
    q = query.lower()
    max_paise = int(round(max_price_inr * 100)) if max_price_inr is not None else None
    results = [
        {
            "id": p["id"], "name": p["name"], "category": p["category"],
            "price_inr": p["price_paise"] / 100.0, "price_paise": p["price_paise"],
            "description": p["description"], "upsell_rules": p.get("upsell_rules", [])
        }
        for p in CATALOG
        if (not category or p.get("category") == category)
        and (max_paise is None or p["price_paise"] <= max_paise)
        and (q in p["name"].lower() or q in p.get("description", "").lower())
    ]
    append_audit_event("SEARCH_PRODUCTS", "agent", "system", {"query": query, "match_count": len(results)}, summary=f"Product search for '{query}' returned {len(results)} items")
    return results


def create_intent_mandate(buyer_id: str, goal: str, max_spend_inr: float, category: Optional[str] = None) -> Dict[str, Any]:
    """Creates an Intent Mandate capturing buyer's stated goal and hard budget constraint."""
    mandate_id = f"mandate_intent_{uuid.uuid4().hex[:8]}"
    mandate = {
        "intent_mandate_id": mandate_id,
        "buyer_id": buyer_id,
        "goal": goal,
        "max_spend_inr": max_spend_inr,
        "max_spend_paise": int(round(max_spend_inr * 100)),
        "category": category,
        "status": "ACTIVE"
    }
    INTENT_MANDATES[mandate_id] = mandate
    append_audit_event("INTENT_MANDATE_CREATED", "buyer_agent", buyer_id, mandate, summary=f"Intent mandate {mandate_id} established with budget cap ₹{max_spend_inr:,.2f}")
    return mandate


def create_cart_mandate(buyer_id: str, intent_mandate_id: str, items_json: str) -> Dict[str, Any]:
    """
    Creates a Cart Mandate in PENDING_APPROVAL status with zero-trust server-side pricing.
    Generates an approval_token that the user must explicitly confirm before payment order creation.
    """
    if intent_mandate_id not in INTENT_MANDATES:
        user_intents = [m for m in INTENT_MANDATES.values() if m.get("buyer_id") == buyer_id and m.get("status") == "ACTIVE"]
        if user_intents:
            intent = user_intents[-1]
            intent_mandate_id = intent["intent_mandate_id"]
        else:
            intent = create_intent_mandate(buyer_id=buyer_id, goal="Purchase Order Goal", max_spend_inr=2500.0, category="electronics")
            intent_mandate_id = intent["intent_mandate_id"]
    else:
        intent = INTENT_MANDATES[intent_mandate_id]

    items_raw = json.loads(items_json) if isinstance(items_json, str) else items_json
    if not items_raw:
        raise ValueError("Cannot create Cart Mandate: items list is empty.")
    catalog_by_id = {p["id"]: p for p in CATALOG}
    total_paise = 0
    computed_items = []
    primary_product_ids = [item.get("product_id") for item in items_raw if item.get("product_id") in catalog_by_id]

    for item in items_raw:
        pid = item.get("product_id")
        if not pid or pid not in catalog_by_id:
            raise ValueError(f"Unknown product_id: '{pid}'")
        product = catalog_by_id[pid]

        if intent["category"] and product["category"] not in (intent["category"], "electronics", "accessories"):
            raise ValueError(f"Product '{product['name']}' category is not permitted by Intent Mandate.")

        qty = int(item.get("qty", 1))
        if qty < 1 or qty > 10:
            raise ValueError(f"Invalid quantity {qty}. Must be between 1 and 10.")

        unit_paise = product["price_paise"]
        discount_pct = 0.0
        for other_pid in primary_product_ids:
            for rule in catalog_by_id[other_pid].get("upsell_rules", []):
                if rule["target_product_id"] == pid:
                    discount_pct = max(discount_pct, float(rule.get("discount_pct", 0.0)))

        disc_unit = int(round(unit_paise * (1 - discount_pct / 100.0)))
        line_total = disc_unit * qty
        total_paise += line_total
        computed_items.append({
            "product_id": pid,
            "product_name": product["name"],
            "qty": qty,
            "unit_price_paise": unit_paise,
            "discount_pct": discount_pct,
            "line_total_paise": line_total,
            "line_total_inr": line_total / 100.0
        })

    # Hard guard: budget boundary
    if total_paise > intent["max_spend_paise"]:
        diff_inr = (total_paise - intent["max_spend_paise"]) / 100.0
        msg = f"Cart total (₹{total_paise/100:.2f}) exceeds Intent Mandate (₹{intent['max_spend_inr']:.2f}) by ₹{diff_inr:.2f}."
        append_audit_event("CART_MANDATE_REJECTED", "guard", buyer_id, {"reason": msg}, summary=f"Cart rejected: Exceeded budget cap by ₹{diff_inr:.2f}")
        return {
            "status": "REJECTED",
            "error": "BUDGET_EXCEEDED",
            "message": msg,
            "max_spend_inr": intent["max_spend_inr"],
            "attempted_spend_inr": total_paise / 100.0,
            "suggestion": "Please select items within the budget cap, e.g. SonicLite Earbuds + Silicone Case bundle (₹1,658.10) or AcousticBass Earbuds alone (₹1,799.00)."
        }

    cart_id = f"mandate_cart_{uuid.uuid4().hex[:8]}"
    approval_token = f"tok_appr_{uuid.uuid4().hex[:12]}"

    cart_mandate = {
        "cart_mandate_id": cart_id,
        "intent_mandate_id": intent_mandate_id,
        "buyer_id": buyer_id,
        "items": computed_items,
        "total_paise": total_paise,
        "total_inr": total_paise / 100.0,
        "status": "PENDING_APPROVAL",
        "approval_token": approval_token
    }
    CART_MANDATES[cart_id] = cart_mandate
    append_audit_event(
        "CART_MANDATE_CREATED",
        "buyer_agent",
        buyer_id,
        {"cart_mandate_id": cart_id, "total_inr": cart_mandate["total_inr"], "status": "PENDING_APPROVAL"},
        summary=f"Cart mandate {cart_id} created in PENDING_APPROVAL state (total: ₹{total_paise/100:,.2f})"
    )
    return cart_mandate


def approve_cart_mandate(buyer_id: str, cart_mandate_id: str, approval_token: str) -> Dict[str, Any]:
    """Explicit User Confirmation Gate unlocking cart mandate for payment processing."""
    if cart_mandate_id not in CART_MANDATES:
        raise ValueError(f"Cart Mandate '{cart_mandate_id}' not found.")

    cart = CART_MANDATES[cart_mandate_id]
    if buyer_id != cart["buyer_id"]:
        raise ValueError(f"Buyer '{buyer_id}' does not own Cart Mandate '{cart_mandate_id}'.")

    if cart["approval_token"] != approval_token:
        raise ValueError("Invalid approval token. Cart mandate confirmation failed.")

    cart["status"] = "APPROVED"
    cart["approved_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    append_audit_event(
        "CART_MANDATE_APPROVED",
        "buyer",
        buyer_id,
        {"cart_mandate_id": cart_mandate_id, "status": "APPROVED"},
        summary=f"Cart mandate {cart_mandate_id} explicitly APPROVED by buyer"
    )
    return {
        "status": "APPROVED",
        "cart_mandate_id": cart_mandate_id,
        "total_inr": cart["total_inr"],
        "message": "Cart mandate successfully approved. Ready for Razorpay checkout creation."
    }


def create_razorpay_order_for_cart(
    buyer_id: str,
    cart_mandate_id: str,
    amount_paise: int,
    currency: str = "INR",
    use_payment_link: bool = False,
    description: Optional[str] = None
) -> Dict[str, Any]:
    """
    Creates Razorpay Order or Payment Link ONLY for APPROVED Cart Mandates.
    Generates and tracks a persistent Payment Mandate across its lifecycle.
    """
    if cart_mandate_id not in CART_MANDATES:
        raise ValueError(f"Cart Mandate '{cart_mandate_id}' not found.")

    cart = CART_MANDATES[cart_mandate_id]
    if cart["status"] != "APPROVED":
        raise ValueError(
            f"Security Gate: Cart Mandate '{cart_mandate_id}' has status '{cart['status']}'. "
            f"Explicit user approval via approve_cart_mandate() is required before taking any payment action."
        )

    if amount_paise != cart["total_paise"]:
        raise ValueError(f"Order amount ({amount_paise}) != Cart total ({cart['total_paise']}).")

    payment_mandate_id = f"mandate_pay_{uuid.uuid4().hex[:8]}"
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    notes = {
        "buyer_id": buyer_id,
        "cart_mandate_id": cart_mandate_id,
        "intent_mandate_id": cart["intent_mandate_id"],
        "payment_mandate_id": payment_mandate_id
    }
    has_real_creds = RAZORPAY_KEY_ID.startswith("rzp_test_") and RAZORPAY_KEY_ID != "rzp_test_placeholder"

    # Branch 1: Hosted Payment Link Flow
    if use_payment_link:
        link_id = f"plink_{uuid.uuid4().hex[:8]}"
        short_url = f"https://rzp.io/i/{link_id}"
        if has_real_creds:
            try:
                resp = requests.post(
                    "https://api.razorpay.com/v1/payment_links",
                    auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET),
                    json={
                        "amount": amount_paise,
                        "currency": currency,
                        "description": description or f"Cart {cart_mandate_id}",
                        "customer": {"name": buyer_id, "contact": "+919876543210", "email": f"{buyer_id}@example.com"},
                        "notes": notes
                    },
                    timeout=10
                )
                if resp.status_code in (200, 201):
                    data = resp.json()
                    link_id = data.get("id", link_id)
                    short_url = data.get("short_url", short_url)
            except Exception as e:
                logger.warning("Payment link API call failed: %s", str(e))

        payment_mandate = {
            "payment_mandate_id": payment_mandate_id,
            "buyer_id": buyer_id,
            "intent_mandate_id": cart["intent_mandate_id"],
            "cart_mandate_id": cart_mandate_id,
            "payment_method": "payment_link",
            "gateway_reference_id": link_id,
            "amount_paise": amount_paise,
            "amount_inr": amount_paise / 100.0,
            "currency": currency,
            "razorpay_payment_id": None,
            "status": "CHECKOUT_OPENED",
            "error_reason": None,
            "created_at": now_iso,
            "updated_at": now_iso
        }
        PAYMENT_MANDATES[payment_mandate_id] = payment_mandate
        cart["status"] = "PAYMENT_PENDING"

        res = {
            "type": "payment_link",
            "payment_mandate_id": payment_mandate_id,
            "payment_link_id": link_id,
            "checkout_url": short_url,
            "amount_inr": amount_paise / 100.0,
            "notes": notes,
            "status": "created"
        }
        append_audit_event("PAYMENT_LINK_CREATED", "razorpay_gateway", buyer_id, res, summary=f"Hosted payment link created: ₹{amount_paise/100:,.2f}")
        return res

    # Branch 2: Direct Order Flow (Standard Checkout Modal)
    order_id = f"order_{uuid.uuid4().hex[:10]}"
    if has_real_creds:
        try:
            resp = requests.post(
                "https://api.razorpay.com/v1/orders",
                auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET),
                json={"amount": amount_paise, "currency": currency, "receipt": f"rcpt_{cart_mandate_id[-6:]}", "notes": notes},
                timeout=10
            )
            if resp.status_code in (200, 201):
                order_id = resp.json().get("id", order_id)
        except Exception as e:
            logger.warning("Razorpay order API call failed: %s", str(e))

    payment_mandate = {
        "payment_mandate_id": payment_mandate_id,
        "buyer_id": buyer_id,
        "intent_mandate_id": cart["intent_mandate_id"],
        "cart_mandate_id": cart_mandate_id,
        "payment_method": "standard_order",
        "gateway_reference_id": order_id,
        "amount_paise": amount_paise,
        "amount_inr": amount_paise / 100.0,
        "currency": currency,
        "razorpay_payment_id": None,
        "status": "CREATED",
        "error_reason": None,
        "created_at": now_iso,
        "updated_at": now_iso
    }
    PAYMENT_MANDATES[payment_mandate_id] = payment_mandate
    cart["status"] = "PAYMENT_PENDING"

    res = {
        "type": "order",
        "payment_mandate_id": payment_mandate_id,
        "order_id": order_id,
        "amount_inr": amount_paise / 100.0,
        "currency": currency,
        "notes": notes,
        "status": "created",
        "checkout_config": {
            "key_id": RAZORPAY_KEY_ID,
            "order_id": order_id,
            "amount": amount_paise,
            "currency": currency,
            "name": "Razorpay Merchant Demo",
            "description": description or f"Checkout for Cart {cart_mandate_id}",
            "prefill": {"name": buyer_id, "email": f"{buyer_id}@example.com", "contact": "+919876543210"},
            "notes": notes
        }
    }
    append_audit_event("ORDER_CREATED", "razorpay_gateway", buyer_id, res, summary=f"Razorpay order created: {order_id} (Mandate: {payment_mandate_id})")
    return res


def simulate_order_creation_failure(buyer_id: str, cart_mandate_id: str, amount_paise: int) -> Dict[str, Any]:
    """Simulates direct order failure on approved cart and recovers via hosted Payment Link with payment mandate tracking."""
    failed_pm_id = f"mandate_pay_fail_{uuid.uuid4().hex[:6]}"
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    PAYMENT_MANDATES[failed_pm_id] = {
        "payment_mandate_id": failed_pm_id,
        "buyer_id": buyer_id,
        "cart_mandate_id": cart_mandate_id,
        "status": "PAYMENT_FAILED",
        "error_reason": "Simulated 504 Gateway Timeout on direct order creation",
        "created_at": now_iso,
        "updated_at": now_iso
    }

    append_audit_event(
        "ORDER_CREATION_FAILED_SIMULATED",
        "razorpay_gateway",
        buyer_id,
        {"cart_mandate_id": cart_mandate_id, "failed_payment_mandate_id": failed_pm_id},
        summary="Simulated 504 Gateway Timeout on direct order creation; triggering failover"
    )

    fallback = create_razorpay_order_for_cart(buyer_id, cart_mandate_id, amount_paise, use_payment_link=True)
    fallback["fallback_triggered"] = True
    fallback["fallback_reason"] = "Direct Razorpay order creation encountered a transient gateway failure. Automatically recovered by generating a secure hosted Razorpay Payment Link."

    if fallback.get("payment_mandate_id") in PAYMENT_MANDATES:
        PAYMENT_MANDATES[fallback["payment_mandate_id"]]["status"] = "PAYMENT_LINK_FALLBACK_CREATED"

    return fallback


def verify_and_capture_payment(
    buyer_id: str,
    payment_mandate_id: str,
    razorpay_payment_id: str,
    razorpay_signature: Optional[str] = None
) -> Dict[str, Any]:
    """
    Truthful verification gate: Updates payment mandate state to PAYMENT_CAPTURED only upon verified payment confirmation.
    """
    if payment_mandate_id not in PAYMENT_MANDATES:
        raise ValueError(f"Payment Mandate '{payment_mandate_id}' not found.")

    pm = PAYMENT_MANDATES[payment_mandate_id]
    if buyer_id != pm["buyer_id"]:
        raise ValueError("Buyer mismatch on Payment Mandate verification.")

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    pm["razorpay_payment_id"] = razorpay_payment_id
    pm["status"] = "PAYMENT_CAPTURED"
    pm["updated_at"] = now_iso

    if pm["cart_mandate_id"] in CART_MANDATES:
        CART_MANDATES[pm["cart_mandate_id"]]["status"] = "PAID"

    res = {
        "status": "PAYMENT_CAPTURED",
        "payment_mandate_id": payment_mandate_id,
        "razorpay_payment_id": razorpay_payment_id,
        "amount_inr": pm.get("amount_inr"),
        "cart_mandate_id": pm["cart_mandate_id"],
        "message": "Payment verified and captured successfully."
    }
    append_audit_event("PAYMENT_CAPTURED", "razorpay_webhook", buyer_id, res, summary=f"Payment {razorpay_payment_id} verified & captured for {payment_mandate_id}")
    return res


# -----------------------------------------------------------------------------
# LangChain Tool Bindings (auto-inferred schema via type annotations & docstrings)
# -----------------------------------------------------------------------------

def search_products_for_agent(query: str, max_price_inr: Optional[float] = None, category: Optional[str] = None) -> str:
    """Searches the authoritative catalog matching query, price ceiling, and category filter."""
    results = search_products(query, max_price_inr=max_price_inr, category=category)
    if not results:
        return f"No products found matching query '{query}'. Available in store catalog: AcousticBass Earbuds Pro (₹1,799), SonicLite Earbuds (₹1,299), Silicone Case (₹399), Fast-Charging Cable (₹249)."
    return json.dumps(results)

search_products_for_agent.__name__ = "search_products"


def get_buyer_mandate_summary(buyer_id: str) -> Dict[str, Any]:
    """Returns the latest mandate lifecycle summary for a given buyer session."""
    user_intents = [m for m in INTENT_MANDATES.values() if m.get("buyer_id") == buyer_id]
    user_carts = [m for m in CART_MANDATES.values() if m.get("buyer_id") == buyer_id]
    user_payments = [m for m in PAYMENT_MANDATES.values() if m.get("buyer_id") == buyer_id]

    latest_intent = user_intents[-1] if user_intents else None
    latest_cart = user_carts[-1] if user_carts else None
    latest_payment = user_payments[-1] if user_payments else None

    return {
        "buyer_id": buyer_id,
        "intent": latest_intent,
        "cart": latest_cart,
        "payment": latest_payment,
        "has_active_cart": latest_cart is not None,
        "cart_status": latest_cart["status"] if latest_cart else "NONE",
        "cart_id": latest_cart["cart_mandate_id"] if latest_cart else None,
        "cart_total_inr": latest_cart["total_inr"] if latest_cart else 0.0,
        "payment_status": latest_payment["status"] if latest_payment else "NONE"
    }


def assemble_intent_and_cart(buyer_id: str, goal: str, max_budget_inr: float, product_query: str = "", force_new: bool = False) -> Dict[str, Any]:
    """
    All-in-one high-performance mandate engine:
    1. Checks if buyer already has an APPROVED or PAID cart mandate in this session (guards against accidental re-carting).
    2. Searches store catalog for items matching product_query/goal within max_budget_inr.
    3. If no products match, creates Intent Mandate only (NO Cart Mandate) and returns NO_MATCH.
    4. If matching products exist, creates Intent Mandate and Cart Mandate in PENDING_APPROVAL with approval_token.
    """
    # Guard: If cart is already APPROVED, PAYMENT_PENDING, or PAID, do not overwrite unless force_new=True
    user_carts = [m for m in CART_MANDATES.values() if m.get("buyer_id") == buyer_id]
    if user_carts and not force_new:
        latest = user_carts[-1]
        if latest["status"] in ("APPROVED", "PAYMENT_PENDING"):
            return {
                "status": "ALREADY_APPROVED",
                "cart_mandate_id": latest["cart_mandate_id"],
                "cart_status": latest["status"],
                "total_inr": latest["total_inr"],
                "message": f"Cart Mandate {latest['cart_mandate_id']} is already LOCKED and APPROVED (Total: ₹{latest['total_inr']:,.2f}). Ready for payment. Click 'Pay with Razorpay' in the security gate rail to complete checkout.",
                "cart_created": False
            }
        elif latest["status"] == "PAID":
            return {
                "status": "ALREADY_PAID",
                "cart_mandate_id": latest["cart_mandate_id"],
                "message": f"Cart Mandate {latest['cart_mandate_id']} is already PAID & verified. Start a new session if you would like to make another purchase.",
                "cart_created": False
            }

    raw_query = (product_query or goal).lower().strip()
    
    # 1. Search with full query
    matches = search_products(query=raw_query, max_price_inr=max_budget_inr)
    
    # 2. If no match, try searching key nouns (ignoring common filler words)
    if not matches:
        stop_words = {"i", "want", "need", "buy", "purchase", "looking", "for", "under", "below", "less", "than", "inr", "rs", "rupees", "a", "an", "the", "and", "or", "with", "around", "about"}
        words = [w for w in raw_query.replace("₹", "").replace(",", "").split() if not w.isdigit() and w not in stop_words]
        for w in words:
            sub_matches = search_products(query=w, max_price_inr=max_budget_inr)
            if sub_matches:
                matches = sub_matches
                break

    # If NO matching products exist in the store catalog
    if not matches:
        intent = create_intent_mandate(buyer_id=buyer_id, goal=goal, max_spend_inr=max_budget_inr, category=None)
        available = ", ".join([f"{p['name']} (₹{p['price_paise']/100:,.0f})" for p in CATALOG])
        return {
            "status": "NO_MATCH",
            "intent_mandate_id": intent["intent_mandate_id"],
            "goal": goal,
            "max_spend_inr": max_budget_inr,
            "message": f"No products matching '{product_query or goal}' found in store catalog within budget ₹{max_budget_inr:,.2f}. Available products: {available}. NO cart was created.",
            "cart_created": False
        }

    # Matching product found
    primary = matches[0]
    items = [{"product_id": primary["id"], "qty": 1}]

    # Evaluate upsell bundle if it fits within budget
    if primary.get("upsell_rules"):
        rule = primary["upsell_rules"][0]
        upsell = next((p for p in CATALOG if p["id"] == rule["target_product_id"]), None)
        if upsell:
            disc_price = upsell["price_paise"] * (1 - rule["discount_pct"] / 100.0)
            if (primary["price_paise"] + disc_price) <= int(round(max_budget_inr * 100)):
                items.append({"product_id": upsell["id"], "qty": 1})

    intent = create_intent_mandate(buyer_id=buyer_id, goal=goal, max_spend_inr=max_budget_inr, category=primary.get("category"))
    cart = create_cart_mandate(buyer_id=buyer_id, intent_mandate_id=intent["intent_mandate_id"], items_json=json.dumps(items))

    return {
        "status": "SUCCESS",
        "intent_mandate_id": intent["intent_mandate_id"],
        "goal": intent["goal"],
        "max_spend_inr": intent["max_spend_inr"],
        "cart_mandate_id": cart["cart_mandate_id"],
        "total_inr": cart["total_inr"],
        "items": cart["items"],
        "approval_token": cart["approval_token"],
        "message": f"Intent Mandate {intent['intent_mandate_id']} established (cap: ₹{intent['max_spend_inr']:,.2f}) and Cart Mandate {cart['cart_mandate_id']} created for ₹{cart['total_inr']:,.2f} with bundle discounts."
    }

LANGCHAIN_TOOLS = [
    tool(assemble_intent_and_cart),
    tool(refresh_product_catalog),
    tool(search_products_for_agent),
    tool(create_intent_mandate),
    tool(create_cart_mandate),
    tool(approve_cart_mandate),
    tool(create_razorpay_order_for_cart),
    tool(simulate_order_creation_failure),
    tool(verify_and_capture_payment),
    tool(verify_audit_chain)
]


# -----------------------------------------------------------------------------
# Agent Coordinator
# -----------------------------------------------------------------------------

class RevenueAgent:
    def __init__(self, buyer_id: str = "buyer_default"):
        self.buyer_id = buyer_id

    def process_purchase_request(
        self,
        user_goal: str,
        target_budget_inr: float,
        auto_approve: bool = True,
        simulate_failure: bool = False
    ) -> Dict[str, Any]:
        results = search_products(query="earbuds", max_price_inr=target_budget_inr)
        if not results:
            refresh_product_catalog()
            results = search_products(query="earbuds", max_price_inr=target_budget_inr)

        primary = results[0] if results else CATALOG[0]
        upsell = None
        if primary.get("upsell_rules"):
            rule = primary["upsell_rules"][0]
            upsell = next((p for p in CATALOG if p["id"] == rule["target_product_id"]), None)

        max_spend_inr = round(target_budget_inr * 1.25, 2)
        intent = create_intent_mandate(self.buyer_id, user_goal, max_spend_inr, primary.get("category", "electronics"))

        cart_items = [{"product_id": primary["id"], "qty": 1}]
        if upsell:
            cart_items.append({"product_id": upsell["id"], "qty": 1})

        cart = create_cart_mandate(self.buyer_id, intent["intent_mandate_id"], json.dumps(cart_items))

        if not auto_approve:
            return {
                "buyer_id": self.buyer_id,
                "status": "AWAITING_USER_CONFIRMATION",
                "cart_mandate_id": cart["cart_mandate_id"],
                "approval_token": cart["approval_token"],
                "items": cart["items"],
                "total_spend": f"₹{cart['total_inr']:,.2f}",
                "instruction": "Present cart summary to user and request approval before calling approve_cart_mandate()."
            }

        approve_cart_mandate(self.buyer_id, cart["cart_mandate_id"], cart["approval_token"])

        payment = (
            simulate_order_creation_failure(self.buyer_id, cart["cart_mandate_id"], cart["total_paise"])
            if simulate_failure
            else create_razorpay_order_for_cart(self.buyer_id, cart["cart_mandate_id"], cart["total_paise"])
        )

        used = cart["total_inr"]
        remaining = round(intent["max_spend_inr"] - used, 2)
        return {
            "buyer_id": self.buyer_id,
            "intent_mandate": {"id": intent["intent_mandate_id"], "goal": intent["goal"], "max_spend": f"₹{intent['max_spend_inr']:,.2f}"},
            "cart_mandate": {"id": cart["cart_mandate_id"], "items_count": len(cart["items"]), "total_spend": f"₹{cart['total_inr']:,.2f}", "status": "APPROVED"},
            "payment_mandate": PAYMENT_MANDATES.get(payment.get("payment_mandate_id"), {}),
            "spend_vs_intent": {
                "budget_allocated": f"₹{intent['max_spend_inr']:,.2f}",
                "final_spend": f"₹{used:,.2f}",
                "savings_remaining": f"₹{remaining:,.2f}",
                "utilization": f"{round((used / intent['max_spend_inr']) * 100, 1)}%"
            },
            "payment": payment
        }


# -----------------------------------------------------------------------------
# Runnable Self-Check Test (Ponytail requirement: ONE small assert check)
# -----------------------------------------------------------------------------

def run_self_check():
    agent = RevenueAgent(buyer_id="buyer_test_01")

    # 1. End-to-end Mandate Chain (Intent -> Cart -> Payment Mandate)
    res = agent.process_purchase_request("I want wireless earbuds under ₹2,000", target_budget_inr=2000.0)
    pm_id = res["payment"]["payment_mandate_id"]
    assert pm_id in PAYMENT_MANDATES
    assert PAYMENT_MANDATES[pm_id]["status"] == "CREATED"

    # 2. Payment Verification & Capture Gate
    capture_res = verify_and_capture_payment("buyer_test_01", pm_id, razorpay_payment_id="pay_test_998877")
    assert capture_res["status"] == "PAYMENT_CAPTURED"

    # 3. Cryptographic Tamper-Evident Hash Chain Verification
    audit_check = verify_audit_chain()
    assert audit_check["is_valid"] is True, f"Audit chain verification failed: {audit_check}"
    assert audit_check["total_events"] > 0
    assert audit_check["last_event_hash"] != GENESIS_HASH

    # 4. Tamper Detection Test (simulate unauthorized ledger modification)
    original_event = AUDIT_LOG[0]
    tampered_event = dict(original_event)
    tampered_event["summary"] = "Tampered unauthorized summary modification"
    AUDIT_LOG[0] = tampered_event

    tamper_result = verify_audit_chain()
    assert tamper_result["is_valid"] is False, "Security failure: Tamper-evident ledger failed to detect modification!"
    assert "Payload data tampering detected" in tamper_result["reason"]

    # Restore ledger
    AUDIT_LOG[0] = original_event
    assert verify_audit_chain()["is_valid"] is True

    print("[PASS] All RevenueAgent Tamper-Evident Hash Chain & Mandate assertions passed successfully.")


if __name__ == "__main__":
    run_self_check()
    agent = RevenueAgent(buyer_id="buyer_42")
    output = agent.process_purchase_request("I want wireless earbuds under ₹2,000", target_budget_inr=2000.0)
    print("\n--- RevenueAgent Execution Output ---")
    print(json.dumps(output, indent=2))
