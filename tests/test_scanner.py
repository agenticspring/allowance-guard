"""Scanner tests with a fake RPC client. No network."""

import unittest

from allowance_guard import abi
from allowance_guard.scanner import analyze, human_amount, scan_approvals


OWNER = "0x" + "aa" * 20
TOKEN1 = "0x" + "b1" * 20  # -> spender S1 (contract), UNLIMITED
TOKEN2 = "0x" + "b2" * 20  # -> spender S2 (EOA), 1000 tokens
S1 = "0x" + "c1" * 20
S2 = "0x" + "c2" * 20


def abi_encode_string(s):
    raw = s.encode()
    return (
        "0x"
        + "0" * 63
        + "1"
        + "%064x" % len(raw)
        + raw.hex().ljust(((len(raw) + 31) // 31) * 64, "0")
    )


class FakeRpc:
    def call(self, method, params):
        if method == "eth_blockNumber":
            return hex(20_000_000)
        if method == "eth_getLogs":
            filt = params[0]
            assert filt["topics"][0] == abi.APPROVAL_TOPIC
            assert filt["topics"][1] == abi.topic_for_owner(OWNER)
            return [
                {
                    "address": TOKEN1,
                    "topics": [
                        abi.APPROVAL_TOPIC,
                        abi.topic_for_owner(OWNER),
                        "0x" + "0" * 24 + S1[2:],
                    ],
                },
                {
                    "address": TOKEN2,
                    "topics": [
                        abi.APPROVAL_TOPIC,
                        abi.topic_for_owner(OWNER),
                        "0x" + "0" * 24 + S2[2:],
                    ],
                },
            ]
        if method == "eth_call":
            to, data = params[0]["to"], params[0]["data"]
            if data.startswith("0x" + abi.SELECTORS["allowance"]):
                if to == TOKEN1:
                    return "0x" + abi.encode_uint(abi.UINT_MAX)
                return "0x" + abi.encode_uint(1000 * 10**18)
            if data.startswith("0x" + abi.SELECTORS["symbol"]):
                return abi_encode_string("TKN1" if to == TOKEN1 else "TKN2")
            if data.startswith("0x" + abi.SELECTORS["decimals"]):
                return "0x" + abi.encode_uint(18)
            raise AssertionError("unexpected eth_call " + data[:10])
        if method == "eth_getCode":
            return "0x60806040" if params[0] == S1 else "0x"
        raise AssertionError("unexpected method " + method)


class TestScanner(unittest.TestCase):
    def test_scan_finds_pairs(self):
        pairs = scan_approvals(FakeRpc(), OWNER, 19_900_000, 20_000_000, chunk=5000)
        self.assertEqual(pairs, {(TOKEN1, S1): True, (TOKEN2, S2): True})

    def test_scan_chunking_single_block(self):
        pairs = scan_approvals(FakeRpc(), OWNER, 5, 5, chunk=5000)
        self.assertEqual(len(pairs), 2)

    def test_scan_skips_malformed_logs(self):
        class MalformedRpc(FakeRpc):
            def call(self, method, params):
                if method == "eth_getLogs":
                    good = {
                        "address": TOKEN1,
                        "topics": [
                            abi.APPROVAL_TOPIC,
                            abi.topic_for_owner(OWNER),
                            "0x" + "0" * 24 + S1[2:],
                        ],
                    }
                    return [
                        good,
                        {"topics": []},  # no topics
                        {"address": TOKEN1},  # missing topics key
                        {"topics": [abi.APPROVAL_TOPIC]},  # < 3 topics
                        {"address": "not-an-address", "topics": good["topics"]},
                        {"address": TOKEN1, "topics": [abi.APPROVAL_TOPIC,
                                                       abi.topic_for_owner(OWNER),
                                                       "0x1234"]},  # short topic
                        "not-a-dict",
                    ]
                return super().call(method, params)

        pairs = scan_approvals(MalformedRpc(), OWNER, 5, 5, chunk=5000)
        self.assertEqual(pairs, {(TOKEN1, S1): True})

    def test_analyze_flags(self):
        findings = analyze(FakeRpc(), OWNER, {(TOKEN1, S1): True, (TOKEN2, S2): True})
        self.assertEqual(len(findings), 2)
        by_token = {f["token"]: f for f in findings}
        f1 = by_token[TOKEN1]
        self.assertIn("UNLIMITED", f1["risks"])
        self.assertTrue(f1["unlimited"])
        self.assertEqual(f1["allowance_human"], "unlimited")
        self.assertFalse(f1["spender_is_eoa"])
        f2 = by_token[TOKEN2]
        self.assertIn("SPENDER_IS_EOA", f2["risks"])
        self.assertEqual(f2["allowance_human"], "1.00K")
        # revoke calldata is unsigned approve(spender, 0)
        self.assertTrue(f2["revoke_calldata"].startswith("0x095ea7b3"))
        self.assertTrue(f2["revoke_calldata"].endswith("0" * 64))
        self.assertIn(S2[2:], f2["revoke_calldata"])
        # riskiest first
        self.assertEqual(findings[0]["token"], TOKEN1)

    def test_analyze_skips_zero_allowance(self):
        class ZeroRpc(FakeRpc):
            def call(self, method, params):
                if method == "eth_call" and params[0]["data"].startswith(
                    "0x" + abi.SELECTORS["allowance"]
                ):
                    return "0x" + abi.encode_uint(0)
                return super().call(method, params)

        findings = analyze(ZeroRpc(), OWNER, {(TOKEN1, S1): True})
        self.assertEqual(findings, [])

    def test_human_amount(self):
        self.assertEqual(human_amount(abi.UINT_MAX, 18, True), "unlimited")
        self.assertEqual(human_amount(1500 * 10**18, 18, False), "1.50K")
        self.assertEqual(human_amount(2_500_000 * 10**6, 6, False), "2.50M")
        self.assertEqual(human_amount(5 * 10**17, 18, False), "0.5")


if __name__ == "__main__":
    unittest.main()
