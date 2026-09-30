import io
import json
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from eth_account import Account
from eth_account.messages import encode_defunct

import verify

ORIGIN = "https://00z.ai"


def fixture(address, now=None):
    now = now or datetime.now(timezone.utc)
    stamp = lambda date: date.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    issued, expires = stamp(now), stamp(now + timedelta(seconds=300))
    nonce = "ab" * 16
    return {
        "nonce": nonce, "chain_id": 11155111, "expires_at": expires,
        "message": (
            f"00z.ai wants you to sign in with your Ethereum account:\n{address}\n\n"
            "Sign in to the wallet-gated demo API. This does not send a transaction.\n\n"
            f"URI: {ORIGIN}\nVersion: 1\nChain ID: 11155111\nNonce: {nonce}\n"
            f"Issued At: {issued}\nExpiration Time: {expires}"
        ),
    }


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.address = Account.create().address
        self.now = datetime.now(timezone.utc)
        self.challenge = fixture(self.address, self.now)

    def test_valid_message_is_returned_unchanged(self):
        self.assertEqual(verify.validate_challenge(self.challenge, ORIGIN, self.address, self.now),
                         self.challenge["message"])

    def test_context_tampering_is_rejected(self):
        c = self.challenge
        for bad in [None, [], {**c, "chain_id": "11155111"}, {**c, "nonce": "x"},
                    {**c, "message": c["message"] + " "},
                    {**c, "message": c["message"].replace("00z.ai", "example.invalid")},
                    {**c, "message": c["message"].replace(self.address, Account.create().address)},
                    {**c, "message": c["message"].replace("11155111", "1")},
                    {**c, "expires_at": "invalid"}]:
            with self.subTest(value=type(bad).__name__), self.assertRaises(verify.VerificationError):
                verify.validate_challenge(bad, ORIGIN, self.address, self.now)

    def test_expiry_future_and_lifetime(self):
        for offset in [-301, 31]:
            with self.subTest(offset=offset), self.assertRaises(verify.VerificationError):
                verify.validate_challenge(fixture(self.address, self.now + timedelta(seconds=offset)),
                                          ORIGIN, self.address, self.now)
        bad = {**self.challenge, "expires_at": self.challenge["message"].split("Issued At: ")[1].split("\n")[0]}
        with self.assertRaises(verify.VerificationError):
            verify.validate_challenge(bad, ORIGIN, self.address, self.now)

    def test_origin_validation(self):
        self.assertEqual(verify.validate_origin(ORIGIN), ORIGIN)
        self.assertEqual(verify.validate_origin("https://localhost:3198"), "https://localhost:3198")
        for bad in ["http://00z.ai", "https://00z.ai/", "https://00z.ai/path", "https://user:pw@00z.ai",
                    "https://00z.ai?query", "https://00z.ai#fragment", "https://00z.ai:443", "https://"]:
            with self.subTest(origin=bad), self.assertRaises(verify.VerificationError):
                verify.validate_origin(bad)

    def test_complete_flow_signs_original_message_and_does_not_log_secrets(self):
        api = Mock(origin=ORIGIN)
        wallet = Account.create()
        challenge = fixture(wallet.address)
        api.post.side_effect = [{}, {}, {}, challenge, {},
                                {"token_type": "Bearer", "expires_in": 600, "access_token": "secret.jwt.token"},
                                {"wallet": wallet.address, "chain_id": 11155111, "data": []}, {}]
        output = io.StringIO()
        with patch.object(verify.Account, "create", return_value=wallet), redirect_stdout(output):
            verify.verify_flow(api)
        self.assertEqual(api.post.call_count, 8)
        proof = api.post.call_args_list[5].args[2]
        recovered = Account.recover_message(encode_defunct(text=challenge["message"]), signature=proof["signature"])
        self.assertEqual(recovered, wallet.address)
        self.assertEqual(api.post.call_args_list[7].args, ("verify", 401, proof))
        self.assertEqual(api.post.call_args_list[6].kwargs["headers"], {"Authorization": "Bearer secret.jwt.token"})
        for secret in ["secret.jwt.token", proof["signature"], wallet.key.hex()]:
            self.assertNotIn(secret, output.getvalue())

    def test_bad_context_is_never_signed(self):
        wallet = Mock(address=self.address)
        api = Mock(origin=ORIGIN)
        api.post.side_effect = [{}, {}, {}, {**self.challenge, "message": "Sign something else"}]
        with patch.object(verify.Account, "create", return_value=wallet):
            with self.assertRaises(verify.VerificationError):
                verify.verify_flow(api)
        wallet.sign_message.assert_not_called()


class TransportTests(unittest.TestCase):
    def response(self, status=200, raw=b"{}", headers=None):
        response = io.BytesIO(raw)
        response.status = status
        response.headers = headers if headers is not None else {"Cache-Control": "no-store"}
        return response

    def test_request_and_success(self):
        api = verify.Api(ORIGIN)
        api.opener = Mock()
        api.opener.open.return_value = self.response()
        with redirect_stdout(io.StringIO()):
            self.assertEqual(api.post("challenge", 200, {"chain_id": 11155111}), {})
        request = api.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, ORIGIN + "/api/wallet-gate/challenge")
        self.assertEqual(request.get_header("Origin"), ORIGIN)
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(json.loads(request.data), {"chain_id": 11155111})
        self.assertEqual(api.opener.open.call_args.kwargs["timeout"], 20)

    def test_expected_http_error_is_a_success_condition(self):
        api = verify.Api(ORIGIN)
        api.opener = Mock()
        api.opener.open.side_effect = HTTPError(ORIGIN, 401, "Unauthorized",
                                               {"Cache-Control": "no-store"}, io.BytesIO(b"{}"))
        with redirect_stdout(io.StringIO()):
            self.assertEqual(api.post("data", 401), {})

    def test_bad_responses_fail_without_echoing_response_content(self):
        for response in [self.response(status=404), self.response(headers={}),
                         self.response(raw=b"sensitive-body"), self.response(raw=b"[]"),
                         self.response(raw=b"x" * (verify.MAX_RESPONSE + 1))]:
            api = verify.Api(ORIGIN)
            api.opener = Mock()
            api.opener.open.return_value = response
            with self.assertRaises(verify.VerificationError) as caught:
                api.post("challenge", 200)
            self.assertNotIn("sensitive-body", str(caught.exception))

    def test_network_errors_are_sanitized(self):
        api = verify.Api(ORIGIN)
        api.opener = Mock()
        api.opener.open.side_effect = URLError("sensitive-details")
        with self.assertRaises(verify.VerificationError) as caught:
            api.post("challenge", 200)
        self.assertNotIn("sensitive-details", str(caught.exception))

    def test_redirects_are_not_followed(self):
        self.assertIsNone(verify.NoRedirects().redirect_request(None, None, 307, "", {}, "https://example.invalid"))


if __name__ == "__main__":
    unittest.main()
