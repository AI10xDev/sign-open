# Sign Open

**Web3-gated signing for open-source package management.**

Sign Open explores using wallet signatures to authenticate contributors and gate
privileged package-management operations without making open-source code private.
The intended workflow lets maintainers prove control of a wallet before requesting
permission to publish a package, approve a release, or manage a package namespace.
Public source and package downloads can remain open while write operations require
authentication and explicit authorization.

## Project scope

This repository currently provides a **Python wallet-gate verification client and
offline tests**, not a package registry or a complete package manager. It checks a
challenge/sign/verify flow against an existing wallet-gated demo API, including
short-lived access tokens and rejection of replayed proofs.

Package publishing, maintainer roles, registry integrations, and artifact-signing
or provenance verification are **proposed integrations, not implemented features**.
The demo authenticates a disposable wallet; it does not establish a maintainer's
identity or permission to modify a package.

## Proposed package-management workflow

1. **Request a challenge.** A client supplies its wallet address and supported
   chain ID to a registry's authentication service.
2. **Review and sign.** The client checks the domain, URI, wallet, chain, nonce,
   and expiration before signing the challenge. This proves wallet control without
   sending an on-chain transaction.
3. **Verify and create a session.** The service verifies the signature, consumes
   the one-time challenge, and issues a short-lived access token.
4. **Authorize a package operation.** The registry separately checks whether the
   authenticated wallet is allowed to publish, approve releases, or administer the
   requested namespace. A valid signature alone must not grant these permissions.
5. **Record the result.** A registry integration could audit the wallet, package,
   version, and authorized action while keeping credentials out of logs.

An authentication signature is **not a signature over a package artifact**. Release
integrity and provenance need a separate mechanism binding the package name,
version, and content digest to an authorized signer. Wallet authentication also
does not require token ownership, payment, or gas; no token-based entitlement check
is implemented here.

## Run the current verifier

You need Python 3.10+ and an existing compatible wallet-gate API. This repository
does not include the API server. The origin below is an example target; run live
checks only against a service you are authorized to test.

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

## Offline tests

Run the protocol and transport tests without making live requests:

```bash
.venv/bin/python -m unittest discover -s . -p 'test_*.py' -v
```
