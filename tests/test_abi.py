"""Unit tests for ABI helpers. No network."""

import unittest

from allowance_guard import abi


def abi_encode_string(s):
    raw = s.encode()
    return (
        "0x"
        + "0" * 63
        + "1"  # offset = 0x20
        + "%064x" % len(raw)
        + raw.hex().ljust(((len(raw) + 31) // 31) * 64, "0")
    )


class TestAbi(unittest.TestCase):
    def test_is_address(self):
        self.assertTrue(abi.is_address("0x" + "ab" * 20))
        self.assertTrue(abi.is_address("0x" + "AB" * 20))
        self.assertFalse(abi.is_address("0x123"))
        self.assertFalse(abi.is_address("ab" * 20))
        self.assertFalse(abi.is_address("0x" + "zz" * 20))
        self.assertFalse(abi.is_address(None))

    def test_normalize(self):
        self.assertEqual(
            abi.normalize_address("0x" + "AB" * 20), "0x" + "ab" * 20
        )
        with self.assertRaises(ValueError):
            abi.normalize_address("0x123")

    def test_pad_address(self):
        padded = abi.pad_address("0x" + "ab" * 20)
        self.assertEqual(len(padded), 64)
        self.assertTrue(padded.endswith("ab" * 20))
        self.assertTrue(padded.startswith("0" * 24))

    def test_allowance_calldata(self):
        owner = "0x" + "11" * 20
        spender = "0x" + "22" * 20
        data = abi.allowance_calldata(owner, spender)
        self.assertTrue(data.startswith("0xdd62ed3e"))
        self.assertEqual(len(data), 2 + 8 + 64 + 64)
        self.assertTrue(data.endswith("22" * 20))

    def test_approve_calldata_revoke(self):
        spender = "0x" + "22" * 20
        data = abi.approve_calldata(spender, 0)
        self.assertTrue(data.startswith("0x095ea7b3"))
        self.assertTrue(data.endswith("0" * 64))

    def test_decode_uint(self):
        self.assertEqual(abi.decode_uint("0x" + "0" * 63 + "1"), 1)
        self.assertEqual(abi.decode_uint("0x" + "f" * 64), abi.UINT_MAX)

    def test_decode_string(self):
        self.assertEqual(abi.decode_string(abi_encode_string("TKN1")), "TKN1")

    def test_decode_string_or_bytes32_fallback(self):
        # old tokens (e.g. MKR) return bytes32 instead of string
        raw = "0x" + "USDC".encode().hex().ljust(64, "0")
        self.assertEqual(abi.decode_string_or_bytes32(raw), "USDC")

    def test_approval_topic_shape(self):
        self.assertTrue(abi.APPROVAL_TOPIC.startswith("0x"))
        self.assertEqual(len(abi.APPROVAL_TOPIC), 66)


if __name__ == "__main__":
    unittest.main()
