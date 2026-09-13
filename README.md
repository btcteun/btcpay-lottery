# Lightning Lottery

A provably fair lottery for local events, powered by BTCPay Server and Lightning.
No names, no email, no KYC — the participant's wallet is the proof.

## How it works

1. People pick a number of tickets on the page and pay a BTCPay invoice.
   After payment BTCPay redirects them back and the page shows their ticket
   numbers. Sales at a BTCPay POS on the same store are picked up as well.
2. A public page shows the tickets sold in real time. Ticket numbers are the
   BTCPay invoice IDs by default; set `TICKET_MODE=salted` to publish a salted
   hash instead.
3. At closing time the ticket list is frozen and its SHA-256 is published
   before the drawing block exists.
4. The first Bitcoin block mined after closing time picks the winners.
   For prize *n*: `SHA256(blockhash + "," + sorted ticket list + "," + n) mod remaining tickets`.
   The winning ticket leaves the pool, the buyer's other tickets stay in.
   `PRIZE_COUNT` sets how many prizes are drawn. Anyone can verify this with any node.
5. The winner claims the prize in person by showing the payment **preimage**
   from their wallet. The organizer types it in and the server answers
   match / no match. The preimage is never published.

## Run it

```bash
cp .env.example .env                        # fill in BTCPay creds, times, secrets
mkdir -p data && chown 10001:10001 data     # container runs as uid 10001
docker compose up -d --build
docker compose logs -f
```

The page is on `http://127.0.0.1:5000`. Put Caddy or nginx with HTTPS in front
before exposing it to the public.

State is written to `./data/<DATA_FILENAME>`. Change the filename in `.env`
for each event; old files stay as an audit trail.

## Before going live

- Confirm where your BTCPay version puts the Lightning preimage in the
  `payment-methods` API response and adjust `fetch_invoice_preimage()` in
  `app.py` if needed.
- Confirm BTCPay's public receipt page does not expose the preimage.
- Set `PUBLIC_URL` to the HTTPS address of this page (used for the redirect).
- Give the API key `canviewinvoices` and `cancreateinvoice` permissions.
- Set `TICKET_PRICE_SATS` to exactly what your POS charges. Tickets must be
  priced in SATS or BTC.
- Generate `ADMIN_TOKEN` (and `TICKET_SALT` if using salted mode) with
  `python3 -c 'import secrets;print(secrets.token_hex(32))'`.
- Check whether a lottery needs a permit in your jurisdiction.

## Trust model

- Buyers can verify the draw independently.
- The organizer holds the BTCPay API key and can read every preimage, so the
  scheme proves a buyer paid; it does not stop a dishonest organizer.
  Publishing the commitment hash somewhere immutable (print, Nostr) keeps you honest.
- Block timestamps are set by miners and can drift. For stricter fairness,
  announce a fixed block height instead of a closing time.
- Point `BLOCK_API` at your own node to remove the mempool.space dependency.

## License

MIT — see [LICENSE](LICENSE).
