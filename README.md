# allowance-guard

**Read-only ERC-20 approval risk scanner.** Point it at any Ethereum wallet and it
lists token approvals that are still active, flagging the risky ones — unlimited
allowances and approvals granted to EOAs (externally owned accounts) instead of
contracts. For each finding it prints unsigned `approve(spender, 0)` calldata you
can paste into your own wallet to revoke.

**This tool never signs, never broadcasts, never touches private keys.**
It only reads public on-chain data via JSON-RPC (`eth_getLogs`, `eth_call`,
`eth_getCode`, `eth_blockNumber`).

## Why

Approval phishing and malicious dApps trick users into granting unlimited token
allowances, then drain wallets months later. Most people have no idea which
approvals are still live on their address. `allowance-guard` answers that in one
command — no browser extension, no connecting your wallet to a website.

## Features

- Scans `Approval` events for any address over a configurable block range
  (chunked `eth_getLogs`, public-RPC friendly)
- Checks the **current** allowance on-chain — already-revoked approvals are skipped
- Risk flags: `UNLIMITED` (allowance == 2²⁵⁶−1), `SPENDER_IS_EOA`
  (spender has no contract code — EOAs can't be audited like contracts)
- Token symbol/decimals lookup for human-readable amounts
- Prints unsigned revoke calldata per finding (`approve(spender, 0)`)
- Text table or `--json` output; exit code `1` when risks are found (CI-friendly)
- Zero dependencies — Python 3.9+ stdlib only

## Installation

```bash
pip install .
# then run:
allowance-guard 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
```

Or without installing:

```bash
python3 -m allowance_guard.cli 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
```

## Usage

```bash
# scan the last ~100k blocks (default, ~2 weeks) of an address
allowance-guard 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045

# full history scan (slower; be kind to public RPCs)
allowance-guard 0xABC... --from-block 0 --chunk-size 2000

# custom RPC endpoint
allowance-guard 0xABC... --rpc https://cloudflare-eth.com
# or via env: ALLOWANCE_GUARD_RPC=https://cloudflare-eth.com allowance-guard 0xABC...

# machine-readable output, include non-risky approvals too
allowance-guard 0xABC... --json --include-safe
```

Exit codes: `0` = no risky approvals, `1` = risks found, `2` = error.

Example output:

```
TOKEN                                      SYMBOL   SPENDER                                    ALLOWANCE    RISKS
--------------------------------------------------------------------------------------------------------------------------------------------
0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 USDC     0x1111111111111111111111111111111111111111 unlimited    UNLIMITED
```

## Configuration

| Flag / env | Default | Description |
|---|---|---|
| `--rpc` / `ALLOWANCE_GUARD_RPC` | `https://eth.llamarpc.com` | JSON-RPC endpoint (no key needed) |
| `--from-block` | `latest − 100000` | First block to scan |
| `--to-block` | `latest` | Last block to scan |
| `--chunk-size` | `5000` | Blocks per `eth_getLogs` request |
| `--timeout` | `20` | RPC timeout (seconds) |

## Limitations & safety notes

- **Read-only by design.** The tool cannot sign or broadcast transactions; it has
  no wallet code path at all. Revoking is a manual step in your own wallet using
  the printed calldata.
- Needs an RPC endpoint that supports `eth_getLogs`. Some free endpoints disable
  it or rate-limit aggressively — if you see errors, try another public endpoint
  or run your own node.
- The default scan window covers ~2 weeks. Very old approvals need
  `--from-block 0` (takes a while on public RPCs).
- `symbol()`/`decimals()` fall back to `?`/`18` when a token doesn't implement
  them cleanly.
- No EIP-55 checksum validation (keccak intentionally avoided to stay
  dependency-free); addresses are validated for format and normalized to
  lowercase.
- No concurrency: the analyze phase makes up to 4 sequential RPC calls per
  (token, spender) pair (`allowance`, `symbol`, `decimals`, `eth_getCode`), so
  wallets with hundreds of live approvals take a while on high-latency RPCs.
- Only standard ERC-20 `Approval` events are detected; tokens emitting
  non-standard approval events are missed.
- Example addresses in docs/tests are well-known public addresses
  (e.g. `vitalik.eth`) or synthetic — never real user wallets.

## Development

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).
