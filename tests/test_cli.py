"""CLI tests. No network (invalid address exits before any RPC call)."""

import io
import unittest
from contextlib import redirect_stdout

from allowance_guard import cli


class TestCli(unittest.TestCase):
    def test_invalid_address_exits_2(self):
        self.assertEqual(cli.main(["not-an-address"]), 2)

    def test_parse_defaults(self):
        args = cli.parse_args(["0x" + "aa" * 20])
        self.assertTrue(args.rpc.startswith("https://"))
        self.assertIsNone(args.from_block)
        self.assertFalse(args.json)

    def test_format_table(self):
        findings = [
            {
                "token": "0x" + "b1" * 20,
                "symbol": "TKN1",
                "decimals": 18,
                "spender": "0x" + "c1" * 20,
                "allowance_raw": str(2**256 - 1),
                "allowance_human": "unlimited",
                "unlimited": True,
                "spender_is_eoa": False,
                "risks": ["UNLIMITED"],
                "revoke_calldata": "0x095ea7b3" + "00" * 64,
            }
        ]
        out = cli.format_table(findings, show_all=False)
        self.assertIn("TOKEN", out)
        self.assertIn("UNLIMITED", out)
        self.assertIn("0x" + "b1" * 20, out)

    def test_format_table_empty(self):
        out = cli.format_table([], show_all=False)
        self.assertIn("No risky approvals", out)


if __name__ == "__main__":
    unittest.main()
