"""Minimal ABI helpers (stdlib only).

Function selectors and the Approval event topic below are well-known public
constants of the ERC-20 standard; they are hardcoded so the tool needs no
keccak implementation and zero dependencies.
"""

# keccak256("Approval(address,address,uint256)")
APPROVAL_TOPIC = (
    "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
)

SELECTORS = {
    "allowance": "dd62ed3e",  # allowance(address,address)
    "decimals": "313ce567",  # decimals()
    "symbol": "95d89b41",  # symbol()
    "approve": "095ea7b3",  # approve(address,uint256)
}

UINT_MAX = 2**256 - 1

_HEX = set("0123456789abcdefABCDEF")


def is_address(value):
    return (
        isinstance(value, str)
        and len(value) == 42
        and value.startswith("0x")
        and all(c in _HEX for c in value[2:])
    )


def normalize_address(value):
    if not is_address(value):
        raise ValueError("not a valid 0x address: %r" % (value,))
    return "0x" + value[2:].lower()


def pad_address(addr):
    """ABI-encode an address as a 32-byte word (hex, no 0x)."""
    return normalize_address(addr)[2:].lower().rjust(64, "0")


def encode_uint(value):
    return "%064x" % int(value)


def _strip_0x(data):
    return data[2:] if data.startswith("0x") else data


def decode_uint(hexdata):
    return int(_strip_0x(hexdata)[:64], 16)


def decode_string(hexdata):
    """Decode an ABI-encoded string return value."""
    h = _strip_0x(hexdata)
    if len(h) < 128:
        raise ValueError("too short for ABI string")
    length = int(h[64:128], 16)
    raw = h[128 : 128 + length * 2]
    return bytes.fromhex(raw).decode("utf-8", errors="replace")


def decode_bytes32(hexdata):
    h = _strip_0x(hexdata)[:64].ljust(64, "0")
    return bytes.fromhex(h).rstrip(b"\x00").decode("utf-8", errors="replace")


def decode_string_or_bytes32(hexdata):
    """symbol() may return string or bytes32 depending on the token."""
    try:
        return decode_string(hexdata)
    except Exception:
        return decode_bytes32(hexdata)


def allowance_calldata(owner, spender):
    return "0x" + SELECTORS["allowance"] + pad_address(owner) + pad_address(spender)


def approve_calldata(spender, amount=0):
    """Unsigned approve(spender, amount) calldata.

    Returned as data only — this tool NEVER signs or broadcasts it.
    Paste it into your own wallet to revoke.
    """
    return "0x" + SELECTORS["approve"] + pad_address(spender) + encode_uint(amount)


def topic_for_owner(owner):
    return "0x" + pad_address(owner)
