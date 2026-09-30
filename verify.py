#!/usr/bin/env python3
"""Opt-in live wallet-gate verification; no funded wallet, RPC, or transaction."""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from eth_account import Account
from eth_account.messages import encode_defunct

CHAIN_ID = 11155111
CHALLENGE_TTL = 300
TOKEN_TTL = 600
MAX_RESPONSE = 16_384


class VerificationError(Exception):
    """Only safe, locally constructed messages may be printed to the terminal."""


def validate_origin(origin):
    try:
        url = urlsplit(origin)
        port = url.port
    except ValueError:
        raise VerificationError("Invalid origin.") from None
    if (url.scheme != "https" or not url.hostname or url.username is not None
            or url.password is not None or url.path or url.query or url.fragment
            or origin != f"https://{url.netloc}" or port == 443
            or any(c.isspace() for c in origin)):
        raise VerificationError("Use an exact HTTPS origin without credentials, path, or trailing slash.")
    return origin


def parse_time(value):
    if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value):
        raise VerificationError("Invalid challenge timestamp.")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise VerificationError("Invalid challenge timestamp.") from None


def validate_challenge(challenge, origin, address, now=None):
    """Check every field before signing; return the ORIGINAL server message."""
    if not isinstance(challenge, dict):
        raise VerificationError("Invalid challenge response.")
    nonce = challenge.get("nonce")
    message = challenge.get("message")
    if (type(challenge.get("chain_id")) is not int or challenge["chain_id"] != CHAIN_ID
            or not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce)
            or not isinstance(message, str)):
        raise VerificationError("Invalid challenge fields.")
    issued_match = re.search(r"\nIssued At: ([^\n]+)\n", message)
    if not issued_match:
        raise VerificationError("Missing challenge issue time.")
    issued_text = issued_match.group(1)
    issued = parse_time(issued_text)
    expires_text = challenge.get("expires_at")
    expires = parse_time(expires_text)
    now = now or datetime.now(timezone.utc)
    if ((expires - issued).total_seconds() != CHALLENGE_TTL
            or expires <= now or (issued - now).total_seconds() > 30):
        raise VerificationError("Challenge expired or has an invalid lifetime.")
    expected = (
        f"{urlsplit(origin).netloc} wants you to sign in with your Ethereum account:\n{address}\n\n"
        "Sign in to the wallet-gated demo API. This does not send a transaction.\n\n"
        f"URI: {origin}\nVersion: 1\nChain ID: {CHAIN_ID}\nNonce: {nonce}\n"
        f"Issued At: {issued_text}\nExpiration Time: {expires_text}"
    )
    if message != expected:
        raise VerificationError("Challenge message does not match the expected signing context.")
    return message


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward a signature or Bearer token to a redirected destination.
        return None


class Api:
    def __init__(self, origin):
        self.origin = validate_origin(origin)
        self.opener = build_opener(NoRedirects())

    def post(self, endpoint, expected, body=None, headers=None):
        request = Request(
            f"{self.origin}/api/wallet-gate/{endpoint}",
            data=json.dumps(body).encode() if body is not None else b"",
            headers={"Origin": self.origin, "Content-Type": "application/json",
                     "User-Agent": "wallet-gate-python-check/1.0", **(headers or {})},
            method="POST",
        )
        try:
            try:
                response = self.opener.open(request, timeout=20)
            except HTTPError as error:
                response = error
            with response:
                if response.status != expected:
                    raise VerificationError(
                        f"{endpoint}: expected HTTP {expected}, received {response.status}.")
                if response.headers.get("Cache-Control") != "no-store":
                    raise VerificationError(f"{endpoint}: missing no-store policy.")
                raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise VerificationError(f"{endpoint}: response too large.")
                try:
                    result = json.loads(raw)
                except (ValueError, UnicodeError):
                    raise VerificationError(f"{endpoint}: invalid JSON response.") from None
                if not isinstance(result, dict):
                    raise VerificationError(f"{endpoint}: expected a JSON object.")
        except (URLError, OSError):
            raise VerificationError(f"{endpoint}: network/TLS request failed.") from None
        print(f"PASS POST /api/wallet-gate/{endpoint}: HTTP {expected}")
        return result


def verify_flow(api):
    # New random EOA on every run; never accept an operator key or persist this key.
    wallet = Account.create()
    request = {"address": wallet.address, "chain_id": CHAIN_ID}
    api.post("data", 401)
    api.post("challenge", 403, request, {"Origin": "https://example.invalid"})
    api.post("challenge", 401, {**request, "chain_id": 1})
    challenge = api.post("challenge", 200, request)
    message = validate_challenge(challenge, api.origin, wallet.address)
    signed = wallet.sign_message(encode_defunct(text=message))
    proof = {"nonce": challenge["nonce"], "message": message,
             "signature": "0x" + bytes(signed.signature).hex()}
    api.post("verify", 401, {**proof, "signature": "0x00"})
    verified = api.post("verify", 200, proof)
    token = verified.get("access_token")
    if (verified.get("token_type") != "Bearer" or type(verified.get("expires_in")) is not int
            or verified["expires_in"] != TOKEN_TTL or not isinstance(token, str)
            or len(token) > 2048
            or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token)):
        raise VerificationError("Unexpected token response.")
    # Authorization is proven by the protected API, not by decoding JWT claims locally.
    data = api.post("data", 200, headers={"Authorization": f"Bearer {token}"})
    if (data.get("wallet") != wallet.address or data.get("chain_id") != CHAIN_ID
            or not isinstance(data.get("data"), list)):
        raise VerificationError("Protected data does not match the authenticated wallet.")
    api.post("verify", 401, proof)
    print(f"Wallet gate OK at {api.origin}: sign/verify/data and rejection checks passed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True, help="Exact HTTPS origin, e.g. https://00z.ai")
    args = parser.parse_args()
    try:
        verify_flow(Api(args.origin))
    except VerificationError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    except Exception:
        # Library exceptions may contain sensitive request or signing payloads.
        print("FAIL: wallet-gate verification failed (details withheld).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
