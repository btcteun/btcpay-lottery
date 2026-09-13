# CLAUDE.md — context for future work on this project

This file explains what this project is, how it got here, and which decisions
are deliberate. Read it before changing anything.

## What it is

A provably fair lottery for a **local, physical event** (Noderunners). People
buy tickets with Lightning through BTCPay Server, the winner(s) are drawn from
a Bitcoin block hash, and the prize is collected **in person** by showing the
Lightning **preimage** from the buyer's own wallet. No accounts, no names, no
email, no KYC.

Single-file Flask app (`app.py`), state in one JSON file, runs in Docker.

## How we got here (decision log)

1. **Original idea:** BTCPay invoices + a success URL to claim.
   Rejected: a success/redirect URL is not proof of anything — anyone can open it.
   Verification must be server-side (BTCPay API) and the proof must be cryptographic.

2. **Proof of ownership = Lightning preimage.** The payer's wallet stores the
   preimage after a successful payment; BTCPay stores it too. Matching them
   proves this wallet paid this invoice. Chosen over BIP-322 signed messages
   because it works with almost any Lightning wallet at a market stall.
   On-chain payments are not supported for this reason.

3. **Fairness = future block hash.** Nobody (including the organizer) can
   predict a block hash. Rule: the *first block with timestamp >= END_TIME*.
   Before that block exists the ticket list is frozen and its SHA-256 is
   published (commitment). Anyone can replay the draw with any node.

4. **Multiple prizes** are drawn from the *same* block:
   `prize n = SHA256(blockhash + "," + frozen_sorted_list + "," + n) mod remaining`.
   The winning ticket leaves the pool; the buyer's other tickets stay in.
   The hash input always uses the frozen list (never the shrinking pool) so a
   verifier only needs the block hash and the published list. One block per
   prize was rejected as slow with no fairness gain.

5. **Ticket count comes from the amount paid**, never from invoice metadata
   (buyers could influence metadata). Tickets must be priced in SATS or BTC;
   fiat-priced invoices are skipped on purpose.

6. **Ticket numbers = BTCPay invoice IDs** (`<invoiceId>-<n>`). The owner
   asked for real IDs. A `TICKET_MODE=salted` alternative (HMAC of the ID)
   exists because publishing invoice IDs could leak the preimage *if* BTCPay's
   public receipt page exposes payment details — this has not been verified.

7. **Buying on the page:** quantity field → `POST /api/buy` → Greenfield
   invoice with `redirectURL = PUBLIC_URL/?invoice={InvoiceId}` → BTCPay
   checkout → redirect back → `/api/my-tickets` fetches that invoice
   immediately and shows the ticket numbers. POS sales on the same store are
   picked up by the poller too.

8. **Claiming at the counter:** organizer types the preimage the winner shows
   → `/api/verify` answers match/no-match. The preimage is compared by hash
   and **never published**. `/api/reveal` (show stored preimage) exists as a
   fallback only, for a screen the public can't see.

9. **Security pass** (v2) fixed: metadata-based ticket count, missing rate
   limits, non-constant-time token compare, hardcoded secrets, `innerHTML`
   XSS, unscoped/unpaginated invoice fetch, dying background thread, dev server
   on 0.0.0.0. Added CSP and other headers, atomic state writes.

10. **Docker:** `python:3.12-slim`, non-root uid 10001, waitress, single
    process (the draw thread and the in-memory rate limiter must live in one
    process). Host bind mount `./data`, filename from `DATA_FILENAME` in `.env`
    so each event keeps its own audit file.

11. **UI:** English, styled after noderunners.network — near-black background,
    Bitcoin orange `#fd6d00`, green `#45ff2a` for "live/ok", Source Sans Pro,
    uppercase headings. Everything rendered with `textContent`, no innerHTML.

## Trust model (don't "fix" these without understanding them)

- Buyers can verify the draw independently. That's the point.
- The organizer holds the BTCPay API key and can read every preimage, so the
  scheme proves *a buyer paid*; it cannot stop a dishonest organizer. The
  public commitment hash + published formula are what keep the organizer honest.
- Block timestamps are miner-set and can drift; a fixed block height would be
  stricter. Timestamp rule was chosen for usability ("first block after close").
- `BLOCK_API` defaults to mempool.space (a trusted third party). Point it at
  your own node for real sovereignty.

## Conventions

- Configuration only via environment variables (`.env`), never in code.
- Keep it one file, one process, one JSON state file. Don't add a database
  unless there's a real reason.
- Every admin endpoint: `hmac.compare_digest` + `_rate_limited`.
- Never put a preimage in `/api/status` or in anything rendered publicly.
- Any change to the draw formula is a **breaking change for verifiability**:
  update the docstring in `draw()`, the footer text in the page, README, and
  this file together.
- Tests so far are ad-hoc (monkeypatched calls to `app.draw`, `app.ingest_invoice`,
  Flask test client). If you add a test suite, cover: draw replay from the
  frozen list, pool shrinking, verify per prize, buy outside the window,
  ticket count from amount.

## Known unknowns / to verify before an event

- Exact JSON path of the Lightning preimage in
  `GET /api/v1/stores/{store}/invoices/{id}/payment-methods` for the deployed
  BTCPay version (`fetch_invoice_preimage`).
- Whether BTCPay's public receipt page exposes the preimage.
- `{InvoiceId}` placeholder substitution in `checkout.redirectURL`.
- Legal: lotteries may need a permit locally.

## Ideas not built yet

- Webhooks instead of polling (BTCPay `InvoiceSettled` with signature check).
- Fixed block height as an alternative rule (`DRAW_BLOCK_HEIGHT`).
- Use the organizer's own node for block data.
- Publish the commitment to Nostr automatically.
- Per-buyer prize cap (currently a buyer with many tickets can win more than once).
- Printable ticket / QR for POS sales.
- A proper test suite.
