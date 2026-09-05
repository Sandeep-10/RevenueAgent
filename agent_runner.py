"""
Agent Runner: Interactive Groq + LangChain Agent for RevenueAgent.
Connects ChatGroq with LANGCHAIN_TOOLS to handle conversational checkout,
intent/cart mandates, explicit user confirmation gates, and Razorpay test payments.
"""

import os
import sys

# Ensure UTF-8 output encoding on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from dotenv import load_dotenv
load_dotenv()

from langchain_groq import ChatGroq
from langchain.agents import create_agent
from revenue_agent import LANGCHAIN_TOOLS

GROQ_API_KEY = os.getenv("GROQ_API_KEY") or os.getenv("GROQ_KEY") 
SYSTEM_PROMPT = """You are RevenueAgent, an autonomous agentic checkout assistant for Razorpay in test mode.
Every transaction is strictly bounded by zero-trust cryptographic mandates: Intent -> Cart -> Payment.

Operational State Machine:
1. BUYER CONTEXT IN MESSAGE:
   The message prefix `[buyer_id=... | cart_status=... | payment_status=...]` provides the current security mandate state.

2. IF `cart_status=APPROVED` or `cart_status=PAYMENT_PENDING`:
   - The cart is ALREADY approved and locked! DO NOT call `assemble_intent_and_cart` or recreate a cart.
   - If buyer asks questions, confirms payment, or chats, answer helpfully and guide them to click "Pay with Razorpay Standard Checkout" in the right panel to complete checkout.
   - ONLY create a new cart if the buyer explicitly says "reset", "clear cart", "cancel cart", or "start a new order".

3. IF `cart_status=PAID`:
   - The order has been paid and verified! Congratulate the buyer. Only create a new cart if they ask to start a new order.

4. IF `cart_status=PENDING_APPROVAL`:
   - If buyer confirms (e.g. "approve", "confirm", "proceed", "yes", "ok"): call `approve_cart_mandate` with `buyer_id`, `cart_mandate_id`, and `approval_token`.
   - If buyer asks to change items: call `create_cart_mandate` to update the draft.

5. IF `cart_status=NONE` (Fresh session / shopping query):
   - Call `assemble_intent_and_cart` with `buyer_id`, `goal`, `max_budget_inr`, and `product_query`.
   - If status is 'NO_MATCH': inform the buyer that no matching products were found in our store catalog and list available items. NO cart was created.
   - If status is 'SUCCESS': present the breakdown, bundle savings, and `approval_token`, directing buyer to click "Approve & Lock Cart Mandate".

Formatting & Presentation:
- Respond in clean, readable markdown (tables for cart items, clear bullet points for totals and savings).
- Do not output raw JSON text or system dictionaries to the user.
- Maintain a helpful, polished, e-commerce concierge tone.
"""


def build_revenue_agent(model_name: str = "openai/gpt-oss-120b", api_key: str = GROQ_API_KEY):
    """Initializes ChatGroq and compiles the LangChain agent graph."""
    llm = ChatGroq(
        model=model_name,
        temperature=0,
        api_key=api_key
    )
    agent = create_agent(
        model=llm,
        tools=LANGCHAIN_TOOLS,
        system_prompt=SYSTEM_PROMPT
    )
    return agent


_GLOBAL_AGENT = None
_BUYER_HISTORIES = {}

def get_agent():
    global _GLOBAL_AGENT
    if _GLOBAL_AGENT is None:
        _GLOBAL_AGENT = build_revenue_agent()
    return _GLOBAL_AGENT


def reset_buyer_session(buyer_id: str = "buyer_42"):
    """Resets conversational memory and mandate state for a new order session."""
    global _BUYER_HISTORIES
    if buyer_id in _BUYER_HISTORIES:
        _BUYER_HISTORIES[buyer_id] = []


def run_agent_turn(user_input: str, buyer_id: str = "buyer_42", agent=None) -> str:
    """Executes a conversational turn preserving conversation history per buyer with real-time mandate state context."""
    from revenue_agent import get_buyer_mandate_summary
    global _BUYER_HISTORIES
    agent_inst = agent or get_agent()
    if buyer_id not in _BUYER_HISTORIES:
        _BUYER_HISTORIES[buyer_id] = []

    summary = get_buyer_mandate_summary(buyer_id)
    cart_desc = f"cart_status={summary['cart_status']}" + (f" ({summary['cart_id']}, ₹{summary['cart_total_inr']:,.2f})" if summary['cart_id'] else "")
    formatted_input = f"[buyer_id={buyer_id} | {cart_desc} | payment_status={summary['payment_status']}] {user_input}"
    _BUYER_HISTORIES[buyer_id].append({"role": "user", "content": formatted_input})

    # Retain the most recent 10 messages for local context
    if len(_BUYER_HISTORIES[buyer_id]) > 10:
        _BUYER_HISTORIES[buyer_id] = _BUYER_HISTORIES[buyer_id][-10:]

    state = agent_inst.invoke({"messages": _BUYER_HISTORIES[buyer_id]})
    _BUYER_HISTORIES[buyer_id] = state["messages"]
    return state["messages"][-1].content


def start_interactive_chat(buyer_id: str = "buyer_42"):
    """Starts an interactive command-line session with RevenueAgent."""
    print("=" * 64)
    print("  RevenueAgent: Live Conversational Checkout Assistant  ")
    print(f"  Session Buyer ID: {buyer_id} | Type 'exit' to quit")
    print("=" * 64 + "\n")

    agent = build_revenue_agent()
    messages = []

    while True:
        try:
            user_input = input("Buyer > ").strip()
            if not user_input or user_input.lower() in ("exit", "quit"):
                print("Ending checkout session. Goodbye!")
                break

            formatted_input = f"[buyer_id={buyer_id}] {user_input}"
            messages.append({"role": "user", "content": formatted_input})

            state = agent.invoke({"messages": messages})
            reply = state["messages"][-1].content
            messages = state["messages"]

            print(f"\nRevenueAgent > {reply}\n")
        except KeyboardInterrupt:
            print("\nSession interrupted.")
            break
        except Exception as e:
            print(f"\n[Error] {e}\n")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--chat":
        start_interactive_chat()
    else:
        print("================================================================")
        print("  RevenueAgent: Groq + LangChain Conversational Checkout Agent  ")
        print("================================================================\n")

        agent = build_revenue_agent()

        test_prompt = "I want wireless earbuds under INR 2,000."
        print(f"User: {test_prompt}\n")
        print("RevenueAgent executing reasoning and tool calls...\n")
        response = run_agent_turn(test_prompt, buyer_id="buyer_42", agent=agent)
        print("Assistant Response:\n")
        print(response)
        print("\nTip: Run `python agent_runner.py --chat` for an interactive CLI session.")
