#!/usr/bin/env python3
"""
Provably-fair local lottery on BTCPay Server + Lightning preimages.
Version 2: English, Noderunners-style UI, security hardening.

HOW IT WORKS
------------
1. Buyers pick a number of tickets on the page; the app creates a BTCPay
   invoice (amount = count × price) and sends them to checkout. After paying,
   BTCPay redirects back to PUBLIC_URL/?invoice=<id> and the page shows their
   ticket numbers. POS sales work too: the app also polls BTCPay for any
   settled invoices between START_TIME and END_TIME.
   Ticket count is derived from the AMOUNT PAID (never from client-editable
   metadata). Each invoice yields a Lightning preimage as proof of payment.
2. The public page (/) shows the number of tickets sold and their ticket
   numbers. By default these are the BTCPay invoice IDs (TICKET_MODE=invoice);
   set TICKET_MODE=salted to publish a salted hash instead.
3. When END_TIME passes, the ticket list is frozen and a commitment hash of
   the frozen list is published BEFORE the drawing block is known.
4. The first Bitcoin block with a timestamp >= END_TIME decides the draw.
   For prize n: SHA256(blockhash + frozen list + n) mod remaining tickets.
   The winning ticket leaves the pool; the buyer's other tickets stay in.
   PRIZE_COUNT sets how many prizes are drawn from that one block.
5. The winning ticket number is published. The preimage is never published.
   At the counter the organizer either:
     a) VERIFIES: types the preimage the winner shows from their wallet, and
        the server answers match / no match (recommended), or
     b) REVEALS: with the admin token, shows the stored preimage to compare
        by eye (fallback, only on a screen the public can't see).

CONFIGURATION IS VIA ENVIRONMENT VARIABLES — see the CONFIG section.
Run with a real WSGI server behind HTTPS (see bottom of file).

CHECK BEFORE GOING LIVE
-----------------------
- Confirm where your BTCPay version puts the Lightning preimage in the
  payment-methods response (fetch_invoice_preimage) — test with curl first.
- Confirm BTCPay's public receipt page for an invoice does NOT expose the
  preimage. If it does, never share raw invoice IDs (this app already hides
  them on the public page).
- Set TICKET_PRICE_SATS to the exact ticket price used in your POS.
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime

from flask import Flask, jsonify, render_template_string, request

# ---------------------------------------------------------------------------
# CONFIG — set via environment variables (never hardcode secrets in the file)
# ---------------------------------------------------------------------------

BTCPAY_URL = os.environ.get("BTCPAY_URL", "https://your-btcpay.example").rstrip("/")
BTCPAY_API_KEY = os.environ.get("BTCPAY_API_KEY", "")
BTCPAY_STORE_ID = os.environ.get("BTCPAY_STORE_ID", "")

START_TIME = os.environ.get("LOTTERY_START", "2026-09-13T10:00:00+02:00")
END_TIME = os.environ.get("LOTTERY_END", "2026-09-13T17:00:00+02:00")

# Public URL of this lottery page; BTCPay redirects buyers back here after paying.
PUBLIC_URL = os.environ.get("PUBLIC_URL", "http://127.0.0.1:5000").rstrip("/")

TICKET_PRICE_SATS = int(os.environ.get("TICKET_PRICE_SATS", "2100"))
MAX_TICKETS_PER_INVOICE = int(os.environ.get("MAX_TICKETS_PER_INVOICE", "50"))

# Number of prizes drawn from the same block. Prize 1 is drawn first.
# Each winning ticket is removed from the pool; the buyer's other tickets stay in.
PRIZE_COUNT = int(os.environ.get("PRIZE_COUNT", "1"))
# Optional labels, "|" separated, e.g. "Hardware wallet|T-shirt|Sticker pack"
PRIZE_LABELS = [x.strip() for x in os.environ.get("PRIZE_LABELS", "").split("|") if x.strip()]

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
# "invoice": ticket numbers are the real BTCPay invoice IDs (e.g. "AbC123…-1").
# "salted":  ticket numbers are an HMAC of the invoice ID; raw IDs stay private.
TICKET_MODE = os.environ.get("TICKET_MODE", "invoice").lower()
TICKET_SALT = os.environ.get("TICKET_SALT", "")

# Cloudflare (and similar) block Python's default urllib User-Agent (error 1010).
USER_AGENT = "btcpay-lottery/1.0"

POLL_INTERVAL_INVOICES = 15
POLL_INTERVAL_BLOCKS = 20
BLOCK_API = os.environ.get("BLOCK_API", "https://mempool.space/api")

DATA_FILE = os.environ.get("DATA_FILE", "lottery_data.json")

if not ADMIN_TOKEN:
    raise SystemExit("Set ADMIN_TOKEN (e.g. `python3 -c 'import secrets;print(secrets.token_hex(32))'`).")
if PRIZE_COUNT < 1:
    raise SystemExit("PRIZE_COUNT must be at least 1.")
if TICKET_MODE not in ("invoice", "salted"):
    raise SystemExit("TICKET_MODE must be 'invoice' or 'salted'.")
if TICKET_MODE == "salted" and not TICKET_SALT:
    raise SystemExit("TICKET_MODE=salted requires TICKET_SALT.")

# ---------------------------------------------------------------------------
# STATE + PERSISTENCE
# ---------------------------------------------------------------------------

_lock = threading.Lock()


def _load():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE) as f:
            return json.load(f)
    return {"phase": "sales", "invoices": {}, "commitment": None, "winner": None}


def _save(state):
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, DATA_FILE)  # atomic write


STATE = _load()

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------


def parse_iso(s: str) -> float:
    return datetime.fromisoformat(s).timestamp()


START_UNIX = parse_iso(START_TIME)
END_UNIX = parse_iso(END_TIME)


def public_ticket_base(invoice_id: str) -> str:
    """Public ticket number for an invoice: the invoice ID itself, or a salted hash."""
    if TICKET_MODE == "invoice":
        return invoice_id
    d = hmac.new(TICKET_SALT.encode(), invoice_id.encode(), hashlib.sha256).hexdigest()
    return d[:8].upper()


def ticket_ids_for(invoice_id: str, count: int) -> list:
    base = public_ticket_base(invoice_id)
    return [f"{base}-{i + 1}" for i in range(count)]


def all_ticket_ids(state) -> list:
    out = []
    for inv in state["invoices"].values():
        out.extend(inv["ticket_ids"])
    return sorted(out)


# ---------------------------------------------------------------------------
# BTCPAY GREENFIELD API
# ---------------------------------------------------------------------------


def _btcpay_get(path: str, params: dict = None):
    url = f"{BTCPAY_URL}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params, doseq=True)
    req = urllib.request.Request(url, headers={"Authorization": f"token {BTCPAY_API_KEY}", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


def _btcpay_post(path: str, body: dict):
    req = urllib.request.Request(
        f"{BTCPAY_URL}{path}",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"token {BTCPAY_API_KEY}", "Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


def create_ticket_invoice(count: int) -> dict:
    """Create a BTCPay invoice for `count` tickets. Returns {"id", "checkoutLink"}.
    API key needs the btcpay.store.cancreateinvoice permission."""
    body = {
        "amount": str(count * TICKET_PRICE_SATS),
        "currency": "SATS",
        "metadata": {"itemDesc": f"Lottery ticket x{count}", "ticketCount": count},
        "checkout": {
            # BTCPay replaces {InvoiceId} with the real ID on redirect
            "redirectURL": f"{PUBLIC_URL}/?invoice={{InvoiceId}}",
            "redirectAutomatically": True,
        },
    }
    inv = _btcpay_post(f"/api/v1/stores/{BTCPAY_STORE_ID}/invoices", body)
    return {"id": inv["id"], "checkoutLink": inv["checkoutLink"]}


def fetch_invoice(invoice_id: str) -> dict:
    return _btcpay_get(f"/api/v1/stores/{BTCPAY_STORE_ID}/invoices/{invoice_id}")


def fetch_settled_invoices_in_window():
    """All Settled invoices created in [START, END], with pagination."""
    out, skip, take = [], 0, 100
    while True:
        page = _btcpay_get(
            f"/api/v1/stores/{BTCPAY_STORE_ID}/invoices",
            {
                "startDate": int(START_UNIX),
                "endDate": int(END_UNIX),
                "status": ["Settled"],
                "skip": skip,
                "take": take,
            },
        )
        out.extend(page)
        if len(page) < take:
            return out
        skip += take


def fetch_invoice_preimage(invoice_id: str):
    """
    Locate the Lightning preimage in the payment-methods response.
    Field names vary by BTCPay version — verify with:
      curl -H "Authorization: token $KEY" \
        $BTCPAY_URL/api/v1/stores/$STORE/invoices/$ID/payment-methods
    """
    methods = _btcpay_get(f"/api/v1/stores/{BTCPAY_STORE_ID}/invoices/{invoice_id}/payment-methods")
    for m in methods:
        pm = (m.get("paymentMethodId") or m.get("paymentMethod") or "").lower()
        if "ln" not in pm and "lightning" not in pm:
            continue
        for p in m.get("payments", []):
            for key in ("preimage", "paymentProof"):
                v = p.get(key)
                if v:
                    return v
            details = p.get("details") or {}
            if isinstance(details, dict):
                for key in ("preimage", "paymentProof"):
                    if details.get(key):
                        return details[key]
    return None


def ticket_count_from_invoice(inv: dict) -> int:
    """Derive ticket count from amount paid, in sats. Never trust metadata."""
    amount = float(inv.get("amount", 0))
    currency = (inv.get("currency") or "").upper()
    if currency == "SATS":
        sats = amount
    elif currency == "BTC":
        sats = amount * 100_000_000
    else:
        # Fiat-priced tickets: convert via your own fixed rule, or price in SATS.
        # Refusing here is safer than guessing.
        return 0
    count = int(sats // TICKET_PRICE_SATS)
    return max(0, min(count, MAX_TICKETS_PER_INVOICE))


def ingest_invoice(inv: dict) -> bool:
    """Register a settled invoice as tickets. Returns True if (now) registered."""
    inv_id = inv["id"]
    with _lock:
        if inv_id in STATE["invoices"]:
            return True
        if STATE["phase"] != "sales":
            return False
    if inv.get("status") not in ("Settled",):
        return False
    created = inv.get("createdTime")
    if created is not None and not (START_UNIX <= float(created) <= END_UNIX):
        return False
    try:
        preimage = fetch_invoice_preimage(inv_id)
    except Exception as e:
        print(f"[sync] preimage lookup failed for {inv_id}: {e}")
        return False
    if not preimage:
        return False
    count = ticket_count_from_invoice(inv)
    if count == 0:
        print(f"[sync] {inv_id} paid below ticket price / unknown currency, skipped")
        return False
    with _lock:
        if STATE["phase"] != "sales":
            return False
        STATE["invoices"][inv_id] = {
            "ticket_ids": ticket_ids_for(inv_id, count),
            "preimage_sha256": hashlib.sha256(preimage.encode()).hexdigest(),
            "preimage": preimage,
            "created": created,
        }
        _save(STATE)
        print(f"[sync] {inv_id}: {count} ticket(s)")
    return True


def sync_invoices():
    try:
        invoices = fetch_settled_invoices_in_window()
    except Exception as e:  # network / auth / JSON errors
        print(f"[sync] failed: {e}")
        return
    for inv in invoices:
        ingest_invoice(inv)


# ---------------------------------------------------------------------------
# BLOCKCHAIN
# ---------------------------------------------------------------------------


def _get(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read().decode().strip()


def tip_height() -> int:
    return int(_get(f"{BLOCK_API}/blocks/tip/height"))


def block_info(height: int) -> dict:
    h = _get(f"{BLOCK_API}/block-height/{height}")
    info = json.loads(_get(f"{BLOCK_API}/block/{h}"))
    return {"height": height, "hash": h, "timestamp": info["timestamp"]}


def wait_for_drawing_block(end_unix: int) -> dict:
    """First block whose timestamp >= end_unix. Retries on network errors."""
    seen = None
    while True:
        try:
            h = tip_height()
            if h != seen:
                seen = h
                info = block_info(h)
                if info["timestamp"] >= end_unix:
                    return info
        except Exception as e:
            print(f"[block] poll error: {e}")
        time.sleep(POLL_INTERVAL_BLOCKS)


# ---------------------------------------------------------------------------
# DRAW
# ---------------------------------------------------------------------------


def commitment_of(tickets: list) -> str:
    return hashlib.sha256(",".join(tickets).encode()).hexdigest()


def draw(tickets: list, block_hash: str, prize_count: int = 1) -> list:
    """
    Draw up to `prize_count` winners from one block.
    Round n:  SHA256(blockhash + "," + <frozen sorted list> + "," + n)  mod  <remaining tickets>
    The winning ticket is removed from the pool before the next round; other
    tickets of the same buyer stay in. The frozen list in the hash input never
    changes, so anyone can replay every round with just the block hash.
    """
    frozen = sorted(tickets)
    pool = list(frozen)
    results = []
    for n in range(1, min(prize_count, len(frozen)) + 1):
        hash_input = block_hash + "," + ",".join(frozen) + "," + str(n)
        digest = hashlib.sha256(hash_input.encode()).hexdigest()
        idx = int(digest, 16) % len(pool)
        ticket = pool.pop(idx)
        results.append({
            "prize": n,
            "label": PRIZE_LABELS[n - 1] if n - 1 < len(PRIZE_LABELS) else f"Prize {n}",
            "hash_input": hash_input,
            "sha256": digest,
            "index": idx,
            "pool_size": len(pool) + 1,
            "ticket": ticket,
            "claimed": False,
        })
    return results


def invoice_for_ticket(state, ticket_id: str):
    for inv_id, inv in state["invoices"].items():
        if ticket_id in inv["ticket_ids"]:
            return inv_id
    return None


def background_loop():
    while time.time() < END_UNIX:
        if time.time() >= START_UNIX:
            sync_invoices()
        time.sleep(POLL_INTERVAL_INVOICES)

    sync_invoices()  # final sweep for invoices created before END_TIME
    with _lock:
        tickets = all_ticket_ids(STATE)
        STATE["phase"] = "drawing"
        STATE["commitment"] = {
            "ticket_count": len(tickets),
            "prize_count": PRIZE_COUNT,
            "sha256_of_ticket_list": commitment_of(tickets),
            "rule": "first Bitcoin block with timestamp >= END_TIME; prize n = "
                    "SHA256(blockhash,list,n) mod remaining tickets, winning ticket removed",
            "end_time": END_TIME,
        }
        _save(STATE)
    print(f"[draw] sales closed, {len(tickets)} tickets frozen, commitment published")

    if not tickets:
        with _lock:
            STATE["phase"] = "no_entries"
            _save(STATE)
        return

    blk = wait_for_drawing_block(int(END_UNIX))
    winners = draw(tickets, blk["hash"], PRIZE_COUNT)
    with _lock:
        STATE["winner"] = {
            "block_height": blk["height"],
            "block_hash": blk["hash"],
            "block_timestamp": blk["timestamp"],
            "ticket_list": tickets,
            "prizes": winners,
        }
        STATE["phase"] = "winner"
        _save(STATE)
    for w in winners:
        print(f"[draw] {w['label']}: {w['ticket']} (block {blk['height']})")


# ---------------------------------------------------------------------------
# WEB
# ---------------------------------------------------------------------------

app = Flask(__name__)

# Very small in-memory rate limiter for admin endpoints: 10 attempts / 10 min / IP
_attempts = defaultdict(list)


def _rate_limited(ip: str, limit=10, window=600) -> bool:
    now = time.time()
    _attempts[ip] = [t for t in _attempts[ip] if now - t < window]
    if len(_attempts[ip]) >= limit:
        return True
    _attempts[ip].append(now)
    return False


def _prize_from(payload: dict):
    """Look up the prize entry (default: prize 1) from the stored draw."""
    try:
        n = int(payload.get("prize", 1))
    except (TypeError, ValueError):
        return None
    with _lock:
        w = STATE["winner"]
        if not w:
            return None
        for p in w["prizes"]:
            if p["prize"] == n:
                return dict(p)
    return None


def _admin_ok(payload: dict) -> bool:
    token = str(payload.get("token", ""))
    return hmac.compare_digest(token.encode(), ADMIN_TOKEN.encode())


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline' "
        "https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/api/status")
def api_status():
    with _lock:
        w = STATE["winner"]
        public_winner = None
        if w:
            public_winner = {k: v for k, v in w.items()}  # no preimage in here anyway
        return jsonify(
            {
                "phase": STATE["phase"],
                "start_time": START_TIME,
                "end_time": END_TIME,
                "ticket_price_sats": TICKET_PRICE_SATS,
                "ticket_mode": TICKET_MODE,
                "max_per_invoice": MAX_TICKETS_PER_INVOICE,
                "prize_count": PRIZE_COUNT,
                "prize_labels": PRIZE_LABELS,
                "sales_open": STATE["phase"] == "sales" and START_UNIX <= time.time() < END_UNIX,
                "tickets": all_ticket_ids(STATE),
                "commitment": STATE["commitment"],
                "winner": public_winner,
            }
        )


@app.route("/api/buy", methods=["POST"])
def api_buy():
    """Create a BTCPay invoice for N tickets and return the checkout link."""
    if _rate_limited(request.remote_addr, limit=20, window=300):
        return jsonify({"error": "too many requests, slow down"}), 429
    now = time.time()
    with _lock:
        open_for_sales = STATE["phase"] == "sales"
    if not open_for_sales or not (START_UNIX <= now < END_UNIX):
        return jsonify({"error": "ticket sales are closed"}), 400
    try:
        count = int((request.get_json(silent=True) or {}).get("count", 0))
    except (TypeError, ValueError):
        count = 0
    if not (1 <= count <= MAX_TICKETS_PER_INVOICE):
        return jsonify({"error": f"choose between 1 and {MAX_TICKETS_PER_INVOICE} tickets"}), 400
    try:
        inv = create_ticket_invoice(count)
    except Exception as e:
        print(f"[buy] invoice creation failed: {e}")
        return jsonify({"error": "could not create invoice, try again"}), 502
    return jsonify(inv)


@app.route("/api/my-tickets")
def api_my_tickets():
    """After redirect: check (and if needed fetch right away) the buyer's invoice."""
    if _rate_limited(request.remote_addr, limit=60, window=300):
        return jsonify({"error": "too many requests"}), 429
    inv_id = request.args.get("invoice", "").strip()
    if not inv_id or len(inv_id) > 64:
        return jsonify({"error": "invalid invoice"}), 400
    with _lock:
        known = STATE["invoices"].get(inv_id)
    if known:
        return jsonify({"status": "settled", "tickets": known["ticket_ids"]})
    try:
        inv = fetch_invoice(inv_id)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return jsonify({"error": "unknown invoice"}), 404
        return jsonify({"status": "pending"})
    except Exception:
        return jsonify({"status": "pending"})
    if ingest_invoice(inv):
        with _lock:
            return jsonify({"status": "settled", "tickets": STATE["invoices"][inv_id]["ticket_ids"]})
    return jsonify({"status": inv.get("status", "pending").lower()})


@app.route("/api/lookup", methods=["POST"])
def api_lookup():
    """Buyer enters their BTCPay invoice ID to find their public ticket numbers."""
    if _rate_limited(request.remote_addr, limit=30):
        return jsonify({"error": "too many requests"}), 429
    inv_id = str((request.get_json(silent=True) or {}).get("invoice_id", "")).strip()
    with _lock:
        inv = STATE["invoices"].get(inv_id)
    if not inv:
        return jsonify({"error": "no paid tickets found for that invoice"}), 404
    return jsonify({"tickets": inv["ticket_ids"]})


@app.route("/api/verify", methods=["POST"])
def api_verify():
    """Organizer types the preimage shown by the winner; server answers yes/no."""
    if _rate_limited(request.remote_addr):
        return jsonify({"error": "too many attempts, wait 10 minutes"}), 429
    payload = request.get_json(silent=True) or {}
    if not _admin_ok(payload):
        return jsonify({"error": "invalid token"}), 403
    claimed = str(payload.get("preimage", "")).strip().lower()
    prize = _prize_from(payload)
    if prize is None:
        return jsonify({"error": "no winner yet / unknown prize"}), 400
    with _lock:
        inv_id = invoice_for_ticket(STATE, prize["ticket"])
        stored = STATE["invoices"][inv_id]["preimage_sha256"]
    ok = hmac.compare_digest(hashlib.sha256(claimed.encode()).hexdigest(), stored)
    if ok:
        with _lock:
            for p in STATE["winner"]["prizes"]:
                if p["prize"] == prize["prize"]:
                    p["claimed"] = True
            _save(STATE)
    return jsonify({"match": ok, "prize": prize["prize"]})


@app.route("/api/reveal", methods=["POST"])
def api_reveal():
    """Fallback: show stored preimage. Only use on a screen the public can't see."""
    if _rate_limited(request.remote_addr):
        return jsonify({"error": "too many attempts, wait 10 minutes"}), 429
    payload = request.get_json(silent=True) or {}
    if not _admin_ok(payload):
        return jsonify({"error": "invalid token"}), 403
    prize = _prize_from(payload)
    if prize is None:
        return jsonify({"error": "no winner yet / unknown prize"}), 400
    with _lock:
        inv_id = invoice_for_ticket(STATE, prize["ticket"])
        return jsonify({"prize": prize["prize"], "preimage": STATE["invoices"][inv_id]["preimage"]})


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Noderunners Lottery</title>
<link href="https://fonts.googleapis.com/css2?family=Source+Sans+Pro:wght@300;400;700;900&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#050505; --panel:#111; --line:#242424;
    --txt:#c8c8c8; --muted:#777;
    --orange:#fd6d00; --orange-2:#f37021; --green:#45ff2a;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--txt);
       font-family:'Source Sans Pro',Helvetica,Arial,sans-serif;font-size:17px;line-height:1.5}
  a{color:var(--orange)}
  header{border-bottom:3px solid var(--orange);padding:22px 20px;display:flex;align-items:center;gap:14px}
  header .bolt{width:34px;height:34px;flex:none}
  header .brand{font-weight:900;text-transform:uppercase;letter-spacing:.08em;font-size:15px;color:#fff}
  header .brand small{display:block;font-weight:300;letter-spacing:0;text-transform:none;color:var(--muted);font-size:13px}
  main{max-width:720px;margin:0 auto;padding:28px 20px 60px}
  h1{font-size:44px;line-height:1;font-weight:900;text-transform:uppercase;color:#fff;margin:0 0 6px}
  .phase{display:inline-block;padding:4px 12px;border:1px solid var(--line);border-radius:999px;
         text-transform:uppercase;letter-spacing:.08em;font-size:12px;font-weight:700;color:var(--muted)}
  .phase.live{border-color:var(--green);color:var(--green)}
  .phase.done{border-color:var(--orange);color:var(--orange)}
  .panel{background:var(--panel);border:1px solid var(--line);padding:20px;margin-top:22px}
  .panel h2{margin:0 0 10px;font-size:14px;text-transform:uppercase;letter-spacing:.08em;color:var(--orange)}
  .big{font-size:64px;font-weight:900;line-height:1;color:#fff;font-variant-numeric:tabular-nums}
  .sub{color:var(--muted);font-size:14px;margin-top:4px}
  .tickets{columns:3;column-gap:16px;font-family:monospace;font-size:14px;margin-top:14px;color:#9a9a9a}
  @media (max-width:520px){.tickets{columns:2}h1{font-size:34px}.big{font-size:52px}}
  .tickets div{break-inside:avoid;padding:2px 0;border-bottom:1px dashed #1c1c1c}
  .winner{border:2px solid var(--orange);background:#0d0a06}
  .winner .ticket{font-family:monospace;font-size:38px;font-weight:700;color:var(--orange);word-break:break-all}
  .claimed{color:var(--green);font-weight:700}
  .mono{font-family:monospace;font-size:13px;color:#9a9a9a;word-break:break-all}
  .buyrow{display:flex;gap:10px;align-items:stretch}
  .buyrow input{width:110px;margin:0;font-size:22px;font-weight:700;text-align:center}
  .buyrow button{margin:0;flex:1}
  label{display:block;font-size:13px;color:var(--muted);margin-top:14px}
  input,select{width:100%;padding:11px 12px;background:#000;border:1px solid var(--line);color:#fff;
        font-family:monospace;font-size:15px;margin-top:6px}
  input:focus,select:focus{outline:2px solid var(--orange);outline-offset:0}
  .prize{padding:12px 0;border-top:1px dashed #2a2a2a}
  .prize:first-of-type{border-top:0}
  .prize .lbl{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
  button{margin-top:12px;padding:12px 18px;background:var(--orange);color:#000;border:0;
         font-weight:900;text-transform:uppercase;letter-spacing:.08em;font-size:14px;cursor:pointer}
  button.ghost{background:transparent;color:var(--txt);border:1px solid var(--line)}
  button:hover{background:var(--orange-2)}
  button.ghost:hover{background:#1a1a1a}
  button:focus-visible{outline:2px solid var(--green);outline-offset:2px}
  .result{margin-top:12px;font-family:monospace;font-size:15px;word-break:break-all}
  .ok{color:var(--green)} .bad{color:var(--orange)}
  details{margin-top:18px}
  summary{cursor:pointer;color:var(--muted);font-size:14px}
  footer{max-width:720px;margin:0 auto;padding:0 20px 40px;color:var(--muted);font-size:13px}
  @media (prefers-reduced-motion:no-preference){.pulse{animation:p 2s ease-in-out infinite}}
  @keyframes p{50%{opacity:.4}}
</style>
</head>
<body>
<header>
  <svg class="bolt" viewBox="0 0 24 24" aria-hidden="true"><path fill="#fd6d00" d="M13 2 3 14h7l-1 8 10-12h-7z"/></svg>
  <div class="brand">Noderunners<small>Lightning lottery</small></div>
</header>

<main>
  <h1>Lottery</h1>
  <span class="phase" id="phase">loading</span>

  <section class="panel" id="buy-panel" hidden>
    <h2>Buy tickets</h2>
    <div class="buyrow">
      <input id="buy-count" type="number" min="1" value="1" inputmode="numeric" aria-label="Number of tickets">
      <button id="buy-btn">Buy tickets</button>
    </div>
    <div class="sub" id="buy-total"></div>
    <div class="result" id="buy-result"></div>
  </section>

  <section class="panel winner" id="my-panel" hidden>
    <h2>Your tickets</h2>
    <div id="my-result" class="result"></div>
  </section>

  <section class="panel">
    <h2>Tickets sold</h2>
    <div class="big" id="count">–</div>
    <div class="sub" id="window"></div>
    <div class="tickets" id="tickets"></div>
    <details id="lookup" hidden>
      <summary>Find my ticket number</summary>
      <label>Your BTCPay invoice ID (from your wallet or receipt)
        <input id="lookup-id" autocomplete="off" spellcheck="false">
      </label>
      <button class="ghost" id="lookup-btn">Look up</button>
      <div class="result" id="lookup-result"></div>
    </details>
  </section>

  <section id="draw"></section>

  <section class="panel" id="verify-panel" hidden>
    <h2>Claim at the counter</h2>
    <p>Winner: open the payment in your wallet and show the <strong>preimage</strong>.
       No name, no email, no KYC — your wallet is the proof.</p>
    <label>Prize being claimed
      <select id="v-prize"></select>
    </label>
    <label>Preimage shown by the winner
      <input id="v-preimage" autocomplete="off" spellcheck="false">
    </label>
    <label>Organizer token
      <input id="v-token" type="password" autocomplete="off">
    </label>
    <button id="verify-btn">Verify preimage</button>
    <button class="ghost" id="reveal-btn">Reveal stored preimage</button>
    <div class="result" id="v-result"></div>
  </section>
</main>

<footer>
  Provably fair: the ticket list is frozen and its SHA-256 published before the drawing block exists.
  Prize n = SHA256(blockhash + "," + sorted ticket list + "," + n) mod remaining tickets; each winning ticket leaves the pool. Check it yourself with any node.
</footer>

<script>
const $ = id => document.getElementById(id);
const el = (tag, text, cls) => { const e = document.createElement(tag); if (text != null) e.textContent = text; if (cls) e.className = cls; return e; };

async function post(url, body){
  const r = await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  return {ok:r.ok, data: await r.json().catch(()=>({}))};
}

function renderDraw(d){
  const box = $('draw'); box.replaceChildren();
  if (d.phase === 'sales') return;

  if (d.commitment){
    const p = el('section', null, 'panel');
    p.append(el('h2','Sales closed — list frozen'));
    p.append(el('div', `${d.commitment.ticket_count} tickets · SHA-256 of ticket list:`, 'sub'));
    p.append(el('div', d.commitment.sha256_of_ticket_list, 'mono'));
    p.append(el('div', `Rule: ${d.commitment.rule} (${d.commitment.end_time})`, 'sub'));
    box.append(p);
  }
  if (d.phase === 'drawing'){
    const p = el('section', null, 'panel');
    p.append(el('h2','Waiting for the next block'));
    p.append(el('div','Miners are picking the winner…','pulse'));
    box.append(p);
  }
  if (d.phase === 'no_entries'){
    box.append(Object.assign(el('section', null, 'panel'), {textContent:'No paid tickets — no draw.'}));
  }
  if (d.winner){
    const w = d.winner;
    const p = el('section', null, 'panel winner');
    p.append(el('h2', w.prizes.length > 1 ? 'Winning tickets' : 'Winning ticket'));
    for (const pr of w.prizes){
      const row = el('div', null, 'prize');
      if (w.prizes.length > 1) row.append(el('div', pr.label, 'lbl'));
      row.append(el('div', pr.ticket, 'ticket'));
      if (pr.claimed) row.append(el('div','Claimed — preimage verified.','claimed'));
      p.append(row);
    }
    const det = el('details'); det.append(el('summary','Verify the draw'));
    det.append(el('div', `Block ${w.block_height} — ${w.block_hash}`, 'mono'));
    for (const pr of w.prizes){
      det.append(el('div', `${pr.label}: index ${pr.index} of ${pr.pool_size} remaining`, 'sub'));
      det.append(el('div', `SHA-256: ${pr.sha256}`, 'mono'));
    }
    p.append(det);
    box.append(p);
    const sel = $('v-prize');
    if (sel.options.length !== w.prizes.length){
      sel.replaceChildren(...w.prizes.map(pr => Object.assign(el('option', `${pr.label} — ${pr.ticket}`), {value: pr.prize})));
    }
    $('verify-panel').hidden = false;
  }
}

let PRICE = 0;
function updateTotal(){
  const n = parseInt($('buy-count').value || '0', 10);
  $('buy-total').textContent = n > 0 ? `${n} × ${PRICE} sats = ${n * PRICE} sats` : '';
}
$('buy-count').addEventListener('input', updateTotal);

$('buy-btn').onclick = async () => {
  const count = parseInt($('buy-count').value || '0', 10);
  const r = $('buy-result'); r.textContent = 'Creating invoice…'; r.className = 'result';
  $('buy-btn').disabled = true;
  const {ok, data} = await post('/api/buy', {count});
  $('buy-btn').disabled = false;
  if (!ok){ r.textContent = data.error || 'Error'; r.className = 'result bad'; return; }
  r.textContent = 'Redirecting to checkout…';
  window.location.href = data.checkoutLink;
};

const myInvoice = new URLSearchParams(location.search).get('invoice');
let myPollTimer = null;
async function checkMyTickets(){
  if (!myInvoice) return;
  const panel = $('my-panel'), r = $('my-result'); panel.hidden = false;
  const res = await fetch('/api/my-tickets?invoice=' + encodeURIComponent(myInvoice));
  const d = await res.json().catch(()=>({}));
  if (d.status === 'settled'){
    r.replaceChildren(el('div','Payment confirmed. Your ticket numbers:','ok'), el('div', d.tickets.join('  '), 'ticket'),
      el('div','Keep this page or a screenshot. To claim, you show the preimage from your wallet.','sub'));
    clearInterval(myPollTimer);
  } else if (d.error){
    r.textContent = d.error; r.className = 'result bad'; clearInterval(myPollTimer);
  } else {
    r.textContent = `Waiting for payment confirmation (${d.status || 'pending'})…`; r.className = 'result pulse';
  }
}

async function refresh(){
  const d = await (await fetch('/api/status')).json();
  PRICE = d.ticket_price_sats;
  $('buy-panel').hidden = !d.sales_open;
  $('buy-count').max = d.max_per_invoice;
  updateTotal();
  const labels = {sales:'Sales open', drawing:'Drawing', winner:'Winner announced', no_entries:'No entries'};
  const fmt = iso => new Date(iso).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
  let label = labels[d.phase] || d.phase;
  if (d.phase === 'sales' && !d.sales_open){
    label = Date.now() < new Date(d.start_time).getTime() ? `Sales open at ${fmt(d.start_time)}` : 'Sales closed';
  }
  const ph = $('phase'); ph.textContent = label;
  ph.className = 'phase ' + (d.sales_open?'live':d.phase==='winner'?'done':'');
  $('count').textContent = d.tickets.length;
  $('window').textContent = `${d.ticket_price_sats} sats per ticket · ${d.start_time} → ${d.end_time}`;
  $('tickets').replaceChildren(...d.tickets.map(t => el('div', t)));
  $('lookup').hidden = d.ticket_mode !== 'salted';
  renderDraw(d);
}

$('lookup-btn').onclick = async () => {
  const {ok, data} = await post('/api/lookup', {invoice_id: $('lookup-id').value});
  const r = $('lookup-result');
  r.textContent = ok ? 'Your tickets: ' + data.tickets.join(', ') : (data.error || 'Not found');
  r.className = 'result ' + (ok ? 'ok' : 'bad');
};
$('verify-btn').onclick = async () => {
  const {ok, data} = await post('/api/verify', {token: $('v-token').value, preimage: $('v-preimage').value, prize: $('v-prize').value});
  const r = $('v-result');
  if (!ok){ r.textContent = data.error || 'Error'; r.className='result bad'; return; }
  r.textContent = data.match ? 'MATCH — hand over the prize.' : 'NO MATCH — wrong preimage.';
  r.className = 'result ' + (data.match ? 'ok' : 'bad');
  if (data.match) refresh();
};
$('reveal-btn').onclick = async () => {
  if (!confirm('Only do this on a screen the public cannot see. Continue?')) return;
  const {ok, data} = await post('/api/reveal', {token: $('v-token').value, prize: $('v-prize').value});
  const r = $('v-result');
  r.textContent = ok ? 'Stored preimage: ' + data.preimage : (data.error || 'Error');
  r.className = 'result ' + (ok ? '' : 'bad');
};

refresh(); setInterval(refresh, 5000);
if (myInvoice){ checkMyTickets(); myPollTimer = setInterval(checkMyTickets, 3000); }
</script>
</body>
</html>"""


if __name__ == "__main__":
    threading.Thread(target=background_loop, daemon=True).start()
    # Dev only. In production run e.g.:
    #   waitress-serve --listen=127.0.0.1:5000 lottery_app_v2:app
    # behind an HTTPS reverse proxy (Caddy/nginx), and start the background
    # thread from a single worker process.
    app.run(host="127.0.0.1", port=5000, debug=False)
