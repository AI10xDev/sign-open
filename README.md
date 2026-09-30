# Sign Open

Python live wallet-gate verification.

From the repository root (Python 3.10+):

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python verify.py --origin https://00z.ai
```

The correct endpoint spelling is `/api/wallet-gate/challenge`.

This is an **opt-in live test**, not a load test. Each invocation makes eight
requests and creates a random, disposable Ethereum EOA in memory:

1. Confirm unauthenticated data returns 401, a wrong origin returns 403, and
   Ethereum mainnet (`chain_id: 1`) is rejected with 401.
2. POST `{address, chain_id: 11155111}` to `/challenge`.
3. Validate the exact domain, URI, wallet, Sepolia chain ID, nonce, five-minute
   lifetime, and expiry **before** signing the original message with EIP-191.
4. Confirm a malformed signature is rejected without consuming the challenge.
5. POST `{nonce, message, signature}` to `/verify`; expect a ten-minute Bearer token.
6. POST to `/data` with `Authorization: Bearer <token>` and check wallet/chain.
7. Submit the same proof again and confirm replay rejection (401).

TLS verification remains enabled; redirects are rejected. Requests have a
20-second socket timeout and response bodies are limited to 16 KiB. There are no
automatic retries. Exit status is **0** on success and **1** on verification failure.
HTTP 404 usually means the gate is disabled, 429 means rate-limited, and 503 means
the gate or its storage/configuration is unavailable. Check the failing endpoint
and expected status: some 401/403 responses are intentional success conditions.

No private key input, funded wallet, RPC, gas, or transaction is needed. Private
keys, signatures, and tokens are never printed or saved. The token remains valid
server-side until expiry even after the script exits. This grants **demo API
access only**, not account/subscription access, and does not test a browser wallet
extension or ERC-1271 contract wallet.

Offline tests (no live requests):

```bash
.venv/bin/python -m unittest discover -s . -p 'test_*.py' -v
```
