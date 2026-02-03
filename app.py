from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash
)
from itsdangerous import URLSafeSerializer, BadSignature

app = Flask(__name__)
app.secret_key = "dev-secret-change-me"  # for PoC only

# ---- "Database" (keep simple for PoC) ----

@dataclass(frozen=True)
class Item:
    id: str
    name: str
    price: int  # in P-coins

ITEMS: Dict[str, Item] = {
    "vanilla": Item("vanilla", "Vanilla", 25),
    "choco":   Item("choco", "Chocolate", 30),
    "mango":   Item("mango", "Mango", 28),
    "mint":    Item("mint", "Mint", 27),
}

# serializer for signed cart tokens (defense option)
signer = URLSafeSerializer(app.secret_key, salt="cart-v1")


# ---- Helpers ----

def init_user() -> None:
    """Initialize a demo wallet and empty cart in the session."""
    session.setdefault("balance", 100)  # user starts with 100 P-coins
    session.setdefault("cart", [])       # list of (item_id, qty)

def get_cart() -> List[Tuple[str, int]]:
    init_user()
    return list(session["cart"])

def set_cart(cart: List[Tuple[str, int]]) -> None:
    session["cart"] = cart

def calc_server_total(cart: List[Tuple[str, int]]) -> int:
    total = 0
    for item_id, qty in cart:
        item = ITEMS.get(item_id)
        if not item:
            continue
        total += item.price * qty
    return total

def sanitize_qty(value: str, *, min_v: int = 1, max_v: int = 20) -> int:
    try:
        n = int(value)
    except ValueError:
        return min_v
    return max(min_v, min(max_v, n))


# ---- Routes ----

@app.get("/")
def index():
    return redirect(url_for("shop"))

@app.get("/shop")
def shop():
    init_user()
    cart = get_cart()
    total = calc_server_total(cart)

    # Defense option: signed cart token the server can verify later
    cart_token = signer.dumps({"cart": cart})

    return render_template(
        "shop.html",
        items=ITEMS.values(),
        cart=cart,
        total=total,
        balance=session["balance"],
        cart_token=cart_token,
    )

@app.post("/cart/add")
def cart_add():
    init_user()
    item_id = request.form.get("item_id", "")
    qty = sanitize_qty(request.form.get("qty", "1"))

    if item_id not in ITEMS:
        flash("Invalid item.", "error")
        return redirect(url_for("shop"))

    cart = get_cart()
    cart.append((item_id, qty))
    set_cart(cart)
    return redirect(url_for("shop"))

@app.post("/cart/clear")
def cart_clear():
    init_user()
    set_cart([])
    return redirect(url_for("shop"))

@app.get("/wallet")
def wallet():
    init_user()
    return render_template("wallet.html", balance=session["balance"])

@app.post("/wallet/topup")
def wallet_topup():
    init_user()
    amount = sanitize_qty(request.form.get("amount", "10"), min_v=1, max_v=1000)
    session["balance"] += amount
    flash(f"Topped up {amount} P-coins.", "ok")
    return redirect(url_for("wallet"))

@app.get("/checkout")
def checkout():
    init_user()
    cart = get_cart()
    server_total = calc_server_total(cart)
    cart_token = signer.dumps({"cart": cart})
    return render_template(
        "cart.html",
        cart=cart,
        items=ITEMS,
        server_total=server_total,
        balance=session["balance"],
        cart_token=cart_token,
    )

# ---------------------------
# VULNERABLE CHECKOUT (PoC)
# ---------------------------
@app.post("/pay/vuln")
def pay_vuln():
    """
    Vulnerability:
    The server trusts client-supplied totals/price fields.
    Attacker changes 'client_total' from e.g. 110 to 1 in devtools.
    """
    init_user()
    cart = get_cart()
    server_total = calc_server_total(cart)

    # Client-supplied total (tamper target)
    client_total_raw = request.form.get("client_total", "0")
    try:
        client_total = int(client_total_raw)
    except ValueError:
        client_total = 0

    # VULN: server uses client_total instead of server_total
    charged = max(0, client_total)

    if charged > session["balance"]:
        flash("Not enough P-coins (vulnerable flow).", "error")
        return redirect(url_for("checkout"))

    session["balance"] -= charged
    set_cart([])

    return render_template(
        "result.html",
        mode="VULNERABLE",
        cart_before=cart,
        client_total=client_total,
        server_total=server_total,
        charged=charged,
        balance=session["balance"],
        notes=[
            "Server trusted client_total.",
            "Parameter tampering allows paying less than real price.",
        ],
    )

# ---------------------------
# FIXED CHECKOUT (Defense)
# ---------------------------
@app.post("/pay/fixed")
def pay_fixed():
    """
    Fix:
    Ignore any client totals and calculate server-side.
    Optionally verify a signed cart token to detect tampering of cart content.
    """
    init_user()
    cart = get_cart()
    server_total = calc_server_total(cart)

    # (Optional) verify signed cart token (proof of integrity)
    token = request.form.get("cart_token", "")
    token_ok = False
    token_cart = None
    try:
        data = signer.loads(token)
        token_cart = data.get("cart")
        token_ok = (token_cart == cart)
    except BadSignature:
        token_ok = False

    # Client-supplied total still collected for demonstration, but ignored:
    client_total_raw = request.form.get("client_total", "0")
    try:
        client_total = int(client_total_raw)
    except ValueError:
        client_total = 0

    charged = server_total  # FIX: always server_total

    if charged > session["balance"]:
        flash("Not enough P-coins (fixed flow).", "error")
        return redirect(url_for("checkout"))

    session["balance"] -= charged
    set_cart([])

    notes = [
        "Server ignored client_total and charged server_total.",
        "Server_total computed from server-side item prices.",
    ]
    if token:
        notes.append(f"Signed cart token verification: {'OK' if token_ok else 'FAILED'}")
        if not token_ok:
            notes.append("Token mismatch indicates tampering or stale cart state.")

    return render_template(
        "result.html",
        mode="FIXED",
        cart_before=cart,
        client_total=client_total,
        server_total=server_total,
        charged=charged,
        balance=session["balance"],
        notes=notes,
    )


if __name__ == "__main__":
    app.run(debug=True)
