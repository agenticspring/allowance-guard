"""CLI for allowance-guard. Read-only: scans approvals, never signs."""

import argparse
import json
import os
import sys

from . import abi
from .rpc import RpcClient, RpcError
from .scanner import analyze, scan_approvals

DEFAULT_RPC = "https://eth.llamarpc.com"
DEFAULT_LOOKBACK_BLOCKS = 100_000  # ~2 weeks of Ethereum mainnet history


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="allowance-guard",
        description=(
            "Scan an Ethereum address for risky ERC-20 token approvals "
            "(read-only; never signs or broadcasts)."
        ),
    )
    p.add_argument("address", help="wallet address to audit (0x...)")
    p.add_argument(
        "--rpc",
        default=os.environ.get("ALLOWANCE_GUARD_RPC", DEFAULT_RPC),
        help="JSON-RPC endpoint (default: %(default)s or $ALLOWANCE_GUARD_RPC)",
    )
    p.add_argument(
        "--from-block",
        default=None,
        help="start scan at block N (default: latest - %d)" % DEFAULT_LOOKBACK_BLOCKS,
    )
    p.add_argument(
        "--to-block", default="latest", help="stop scan at block N or 'latest'"
    )
    p.add_argument(
        "--chunk-size", type=int, default=5000, help="blocks per eth_getLogs call"
    )
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument(
        "--include-safe",
        action="store_true",
        help="also show approvals with no risk flags",
    )
    p.add_argument("--timeout", type=int, default=20, help="RPC timeout in seconds")
    p.add_argument("--quiet", action="store_true", help="only print findings")
    return p.parse_args(argv)


def resolve_blocks(rpc, args):
    latest = int(rpc.call("eth_blockNumber", []), 16)
    if args.to_block == "latest":
        to_block = latest
    else:
        to_block = int(args.to_block)
    if args.from_block is None:
        from_block = max(0, latest - DEFAULT_LOOKBACK_BLOCKS)
    else:
        from_block = int(args.from_block)
    if from_block > to_block:
        raise ValueError("--from-block is after --to-block")
    return from_block, to_block


def format_table(findings, show_all):
    rows = [f for f in findings if show_all or f["risks"]]
    lines = []
    lines.append(
        "%-42s %-8s %-42s %-12s %s"
        % ("TOKEN", "SYMBOL", "SPENDER", "ALLOWANCE", "RISKS")
    )
    lines.append("-" * 140)
    for f in rows:
        lines.append(
            "%-42s %-8s %-42s %-12s %s"
            % (
                f["token"],
                f["symbol"][:8],
                f["spender"],
                f["allowance_human"][:12],
                ",".join(f["risks"]) or "-",
            )
        )
    if not rows:
        lines.append("No risky approvals found. Nice.")
    return "\n".join(lines)


def main(argv=None):
    args = parse_args(argv)
    try:
        owner = abi.normalize_address(args.address)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    rpc = RpcClient(args.rpc, timeout=args.timeout)
    try:
        from_block, to_block = resolve_blocks(rpc, args)
    except (RpcError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    if not args.quiet and not args.json:
        print(
            "Scanning approvals for %s from block %d to %d ..."
            % (owner, from_block, to_block),
            file=sys.stderr,
        )

    def progress(start, end, total):
        if not args.quiet and not args.json:
            print(
                "  ... blocks %d-%d of %d" % (start, end, total),
                file=sys.stderr,
                end="\r",
            )

    try:
        pairs = scan_approvals(
            rpc, owner, from_block, to_block, chunk=args.chunk_size, progress=progress
        )
        findings = analyze(rpc, owner, pairs)
    except RpcError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    if not args.quiet and not args.json:
        print(file=sys.stderr)

    risky = [f for f in findings if f["risks"]]
    if args.json:
        print(json.dumps({"address": owner, "findings": findings}, indent=2))
    else:
        print(format_table(findings, args.include_safe))
        if risky and not args.quiet:
            print(
                "\nTo revoke, paste the finding's revoke_calldata as transaction data "
                "in your own wallet (this tool never signs or sends anything)."
            )
    return 1 if risky else 0


if __name__ == "__main__":
    sys.exit(main())
