"""Approval scanning and risk analysis. Everything here is read-only:
no signing, no broadcasting, no private keys involved at any point."""

from . import abi
from .rpc import RpcError


def scan_approvals(rpc, owner, from_block, to_block, chunk=5000, progress=None):
    """Find every (token, spender) pair the owner ever approved via logs.

    Returns a dict {(token, spender): True}. Chunked so public RPCs stay happy.
    """
    topic0 = abi.APPROVAL_TOPIC
    topic1 = abi.topic_for_owner(owner)
    pairs = {}
    start = from_block
    while start <= to_block:
        end = min(start + chunk - 1, to_block)
        logs = rpc.call(
            "eth_getLogs",
            [
                {
                    "fromBlock": hex(start),
                    "toBlock": hex(end),
                    "topics": [topic0, topic1],
                }
            ],
        )
        for log in logs or []:
            topics = log.get("topics", [])
            if len(topics) < 3:
                continue
            token = "0x" + log["address"][2:].lower()
            spender = "0x" + topics[2][-40:].lower()
            pairs[(token, spender)] = True
        if progress:
            progress(start, end, to_block)
        start = end + 1
    return pairs


def _safe_call(rpc, to, data, fallback=None):
    try:
        return rpc.call("eth_call", [{"to": to, "data": data}, "latest"])
    except RpcError:
        return fallback


def analyze(rpc, owner, pairs):
    """Check current allowance for each pair and flag risks.

    Returns a list of finding dicts sorted with riskiest first.
    """
    findings = []
    for token, spender in sorted(pairs):
        raw = _safe_call(rpc, token, abi.allowance_calldata(owner, spender))
        if raw is None:
            continue
        try:
            amount = abi.decode_uint(raw)
        except Exception:
            continue
        if amount == 0:
            continue  # already revoked / spent; not interesting

        symbol = _safe_call(
            rpc, token, "0x" + abi.SELECTORS["symbol"], fallback=None
        )
        symbol = (
            abi.decode_string_or_bytes32(symbol) if symbol is not None else "?"
        )
        decimals_raw = _safe_call(
            rpc, token, "0x" + abi.SELECTORS["decimals"], fallback=None
        )
        try:
            decimals = (
                abi.decode_uint(decimals_raw) if decimals_raw is not None else 18
            )
        except Exception:
            decimals = 18

        try:
            code = rpc.call("eth_getCode", [spender, "latest"])
            is_eoa = code in ("0x", "")
        except RpcError:
            is_eoa = None

        unlimited = amount == abi.UINT_MAX
        risks = []
        if unlimited:
            risks.append("UNLIMITED")
        if is_eoa:
            risks.append("SPENDER_IS_EOA")
        elif is_eoa is None:
            risks.append("SPENDER_UNKNOWN")

        findings.append(
            {
                "token": token,
                "symbol": symbol,
                "decimals": decimals,
                "spender": spender,
                "allowance_raw": str(amount),
                "allowance_human": human_amount(amount, decimals, unlimited),
                "unlimited": unlimited,
                "spender_is_eoa": bool(is_eoa),
                "risks": risks,
                # Unsigned calldata the user may paste into their own wallet
                # to revoke. This tool never signs or sends it.
                "revoke_calldata": abi.approve_calldata(spender, 0),
            }
        )
    findings.sort(key=lambda f: (len(f["risks"]), f["unlimited"]), reverse=True)
    return findings


def human_amount(amount, decimals, unlimited):
    if unlimited:
        return "unlimited"
    try:
        value = amount / (10**decimals)
    except Exception:
        return str(amount)
    if value >= 1_000_000:
        return "%.2fM" % (value / 1_000_000)
    if value >= 1_000:
        return "%.2fK" % (value / 1_000)
    text = "%.6f" % value
    return text.rstrip("0").rstrip(".") or "0"
