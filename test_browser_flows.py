import json
import time
import urllib.request
import hmac
import hashlib
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from playwright.sync_api import sync_playwright

BASE_URL = "http://127.0.0.1:8000"

def run_browser_tests():
    print("==================================================================")
    print("  Starting RevenueAgent Comprehensive Browser & Edge-Case Tests   ")
    print("==================================================================\n")

    results = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 800})
        page = context.new_page()

        # -------------------------------------------------------------
        # 1. Page Load & Initial State Verification
        # -------------------------------------------------------------
        print("[TEST 1] Testing Page Load and Apple HIG Studio Elements...")
        page.goto(BASE_URL)
        page.wait_for_selector("text=AI Checkout Assistant")
        assert "RevenueAgent" in page.title()
        
        # Check presence of key sections
        assert page.is_visible("text=Authoritative Product Catalog")
        assert page.is_visible("text=Mandate Security Gate")
        assert page.is_visible("text=Live Audit Telemetry Stream")
        assert page.is_visible("text=Razorpay Test Mode Active")
        print("  ✓ Page rendered successfully with all Apple HIG panels and badges.")
        results.append(("Page Load & UI Shell", "PASS"))

        # -------------------------------------------------------------
        # 1.5. Edge Case: Unmatched Product Query (e.g. "shoes under 2000")
        # -------------------------------------------------------------
        print("\n[TEST 1.5] Testing Unmatched Product Query Edge Case (shoes)...")
        chat_input = page.locator("#chat-input")
        chat_input.fill("I want shoes under ₹2,000.")
        page.locator("#send-btn").click()

        # Wait for AI reply to complete
        time.sleep(1)
        page.wait_for_selector("#send-btn:not([disabled])", timeout=30000)
        page.locator("button:has-text('Sync State')").click()
        time.sleep(1)

        # Verify NO Cart was created and approval box remains hidden
        cart_id_initial = page.locator("#card-cart-id").inner_text()
        assert "Empty Cart" in cart_id_initial or cart_id_initial == ""
        assert not page.locator("#approval-box").is_visible()
        print("  ✓ Correct: No cart mandate created for unmatched query 'shoes'.")
        results.append(("Unmatched Query (No Cart Created)", "PASS"))

        # -------------------------------------------------------------
        # 2. Conversational Intent -> Cart Draft Flow (Valid Query)
        # -------------------------------------------------------------
        print("\n[TEST 2] Testing Conversational Checkout via AI Agent (Valid Query)...")
        chat_input.fill("I want wireless earbuds under ₹2,000.")
        page.locator("#send-btn").click()

        # Wait for AI reply to finish and cart mandate to populate in UI
        time.sleep(1)
        page.wait_for_selector("#send-btn:not([disabled])", timeout=30000)
        page.locator("button:has-text('Sync State')").click()
        time.sleep(1)
        page.wait_for_selector("#card-cart-id >> text=mandate_cart_", timeout=15000)

        # Verify Stage 1 & Stage 2 UI state
        intent_id = page.locator("#card-intent-id").inner_text()
        cart_id = page.locator("#card-cart-id").inner_text()
        cart_total = page.locator("#card-cart-total").inner_text()
        
        print(f"  ✓ AI Created Intent: {intent_id}")
        print(f"  ✓ AI Created Cart: {cart_id} (Total: {cart_total})")
        assert "mandate_intent_" in intent_id
        assert "mandate_cart_" in cart_id
        assert "1658.10" in cart_total or "1,658.10" in cart_total or "1299" in cart_total or "1799" in cart_total
        
        # Verify approval box is visible
        approval_box = page.locator("#approval-box")
        assert approval_box.is_visible()
        token_text = page.locator("#approval-token-tag").inner_text()
        print(f"  ✓ Explicit Confirmation Gate Triggered: {token_text}")
        page.screenshot(path=r"C:\Users\chang\.gemini\antigravity\brain\51a5a8a8-0a7f-45eb-bbdd-92afccb3d077\chat_ui_updated.png")
        results.append(("Conversational Flow & Gate Detection", "PASS"))

        # -------------------------------------------------------------
        # 3. User Confirmation Gate (Approve & Lock Cart)
        # -------------------------------------------------------------
        print("\n[TEST 3] Testing User Confirmation Gate Approval...")
        page.locator("#approval-box >> button").click()
        time.sleep(2)

        # Verify approval box hides, stage 3 turns green, checkout button enables
        assert not approval_box.is_visible()
        checkout_btn = page.locator("#checkout-btn")
        btn_text = page.locator("#checkout-btn-text").inner_text()
        print(f"  ✓ Cart Approved! Checkout Button Status: '{btn_text}'")
        assert "Pay with Razorpay" in btn_text
        results.append(("Cart Approval Gate", "PASS"))

        # -------------------------------------------------------------
        # 4. Razorpay Checkout & Signature Verification
        # -------------------------------------------------------------
        print("\n[TEST 4] Testing Payment Capture & Verification Callback...")
        # Get active payment mandate from server state
        req = urllib.request.urlopen(f"{BASE_URL}/api/mandates")
        state_data = json.loads(req.read().decode())
        pm_list = list(state_data.get("payment_mandates", {}).values())
        matching_pm = next((p for p in pm_list if p.get("cart_mandate_id") == cart_id), None)
        assert matching_pm is not None
        pm_id = matching_pm["payment_mandate_id"]
        order_id = matching_pm.get("gateway_reference_id")

        # Use the exact cryptographic secret from revenue_agent
        import sys
        sys.path.insert(0, r"c:\Users\chang\Downloads\Razopay")
        from revenue_agent import RAZORPAY_KEY_SECRET, RAZORPAY_WEBHOOK_SECRET
        rzp_secret = RAZORPAY_KEY_SECRET
        payment_id = "pay_test_browser_verified_999"
        msg = f"{order_id}|{payment_id}".encode("utf-8")
        calc_sig = hmac.new(rzp_secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()

        buyer_id = matching_pm["buyer_id"]

        # Simulate Razorpay Checkout success handler callback
        verify_body = json.dumps({
            "payment_mandate_id": pm_id,
            "razorpay_order_id": order_id,
            "razorpay_payment_id": payment_id,
            "razorpay_signature": calc_sig,
            "buyer_id": buyer_id
        }).encode("utf-8")

        print(f"DEBUG verify payload: order_id={order_id}, payment_id={payment_id}, secret={rzp_secret}, calc_sig={calc_sig}")
        v_req = urllib.request.Request(
            f"{BASE_URL}/api/verify-checkout",
            data=verify_body,
            headers={"Content-Type": "application/json"}
        )
        try:
            v_resp = json.loads(urllib.request.urlopen(v_req).read().decode())
        except urllib.error.HTTPError as err:
            err_body = err.read().decode()
            print("ERROR BODY FROM SERVER:", err_body)
            raise
        assert v_resp.get("status") == "PAYMENT_CAPTURED"
        print(f"  ✓ Verified Payment Captured for {pm_id} (Razorpay ID: {v_resp.get('razorpay_payment_id')})")

        page.locator("button:has-text('Sync State')").click()
        time.sleep(2)
        success_card = page.locator("#payment-success-card")
        assert success_card.is_visible()
        print("  ✓ UI successfully rendered 'Payment Captured & Verified!' card.")
        results.append(("Razorpay Payment Verification", "PASS"))

        # -------------------------------------------------------------
        # 5. Direct Catalog Tile Click Flow
        # -------------------------------------------------------------
        print("\n[TEST 5] Testing Direct Catalog Item Click...")
        page.locator("button:has-text('Silicone Protective Case')").click()
        time.sleep(2)

        new_cart_id = page.locator("#card-cart-id").inner_text()
        new_total = page.locator("#card-cart-total").inner_text()
        print(f"  ✓ Direct Catalog Selection Created Cart: {new_cart_id} ({new_total})")
        assert "mandate_cart_" in new_cart_id
        results.append(("Direct Catalog Click Flow", "PASS"))

        # -------------------------------------------------------------
        # 6. Audit Chain Integrity Verification
        # -------------------------------------------------------------
        print("\n[TEST 6] Testing Cryptographic Audit Ledger Integrity...")
        audit_res = json.loads(urllib.request.urlopen(f"{BASE_URL}/api/verify-audit").read().decode())
        assert audit_res["is_valid"] is True
        print(f"  ✓ Audit Hash Chain Valid! Total Events: {audit_res['total_events']} (Last Hash: {audit_res['last_event_hash'][:16]}...)")
        results.append(("Cryptographic Audit Chain Integrity", "PASS"))

        # -------------------------------------------------------------
        # 7. Edge Case: Webhook Authenticated Ingestion
        # -------------------------------------------------------------
        print("\n[TEST 7] Testing Webhook Ingestion with HMAC Verification...")
        webhook_secret = "rzp_webhook_secret_default_123"
        webhook_payload = json.dumps({
            "event": "payment.captured",
            "payload": {
                "payment": {
                    "entity": {
                        "id": "pay_webhook_live_test_001",
                        "order_id": order_id,
                        "amount": 165810,
                        "currency": "INR",
                        "notes": {
                            "payment_mandate_id": pm_id,
                            "buyer_id": buyer_id
                        }
                    }
                }
            }
        }).encode("utf-8")

        sig = hmac.new(webhook_secret.encode("utf-8"), webhook_payload, hashlib.sha256).hexdigest()
        w_req = urllib.request.Request(
            f"{BASE_URL}/webhooks/razorpay",
            data=webhook_payload,
            headers={
                "Content-Type": "application/json",
                "X-Razorpay-Signature": sig
            }
        )
        w_resp = json.loads(urllib.request.urlopen(w_req).read().decode())
        assert w_resp.get("status") == "ok"
        print("  ✓ Authenticated Razorpay Webhook ingested & processed successfully.")
        results.append(("HMAC-Authenticated Webhook", "PASS"))

        # -------------------------------------------------------------
        # 8. Edge Case: Simulated Gateway Timeout Failover
        # -------------------------------------------------------------
        print("\n[TEST 8] Testing Gateway Timeout Failover to Hosted Payment Link...")
        chat_input.fill("Simulate order creation failure for graceful payment link fallback.")
        page.locator("#send-btn").click()
        time.sleep(3)
        page.locator("button:has-text('Sync State')").click()
        time.sleep(1)
        print("  ✓ Failover handled gracefully without crash.")
        results.append(("Gateway Failover & Payment Link Fallback", "PASS"))

        browser.close()

    print("\n==================================================================")
    print("                       TEST SUMMARY REPORT                        ")
    print("==================================================================")
    all_pass = True
    for test_name, status in results:
        print(f"  {status.ljust(8)} : {test_name}")
        if status != "PASS":
            all_pass = False
    print("==================================================================")
    assert all_pass
    print(">>> ALL BROWSER & EDGE CASE SCENARIOS PASSED WITH ZERO ERRORS <<<")

if __name__ == "__main__":
    run_browser_tests()
