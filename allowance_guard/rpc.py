"""Minimal Ethereum JSON-RPC client built on urllib (stdlib only)."""

import json
import time
import urllib.error
import urllib.request


class RpcError(Exception):
    """Raised when the RPC endpoint returns an error or is unreachable."""


class RpcClient:
    def __init__(self, url, timeout=20, retries=2):
        self.url = url
        self.timeout = timeout
        self.retries = retries
        self._id = 0

    def call(self, method, params):
        """Perform one JSON-RPC call, retrying transient network failures."""
        self._id += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        ).encode()
        last_err = None
        for attempt in range(self.retries + 1):
            try:
                req = urllib.request.Request(
                    self.url,
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "allowance-guard/1.0",
                    },
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = json.loads(resp.read().decode())
                if "error" in body:
                    raise RpcError("RPC error: %s" % (body["error"],))
                return body.get("result")
            except RpcError:
                raise
            except Exception as exc:  # transient: retry with backoff
                last_err = exc
                time.sleep(0.5 * (attempt + 1))
        raise RpcError(
            "RPC call %s failed after %d attempts: %s"
            % (method, self.retries + 1, last_err)
        )
