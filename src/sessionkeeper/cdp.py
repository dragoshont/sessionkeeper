"""Minimal Chrome DevTools Protocol (CDP) client — zero third-party deps.

The harvester reads a warm browser's session **in-pod** over CDP bound to
loopback (``127.0.0.1:9222``); it never exposes the debugger off-pod (spec §5,
§11). httpOnly cookies (e.g. Regina Maria's ``RefreshTokenSSO``) are invisible to
page JavaScript, so they can only be read via CDP ``Storage.getCookies`` — which
is exactly what this client does.

Python's stdlib has no WebSocket client, and CDP commands ride a WebSocket, so a
tiny RFC 6455 client is hand-rolled here (text frames, client masking, the
126/127 extended lengths). The command layer is injectable (``command=``) so the
harvester logic is unit-tested offline with canned cookies and no real browser.
"""
from __future__ import annotations

import json
import os
import socket
import struct
import time
from typing import Any, Callable, Optional
from urllib.request import urlopen

# A command seam: (method, params) -> result dict. The real one talks CDP/WS; a
# fake one returns canned results in tests.
CommandFn = Callable[[str, dict], dict]


class CdpError(RuntimeError):
    pass


# -- RFC 6455 frame codec (just enough for CDP) ------------------------------

def encode_frame(payload: bytes, opcode: int = 0x1) -> bytes:
    """Encode one *masked* client frame (clients MUST mask; servers MUST NOT)."""
    n = len(payload)
    header = bytearray([0x80 | opcode])  # FIN + opcode
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header += struct.pack(">H", n)
    else:
        header.append(0x80 | 127)
        header += struct.pack(">Q", n)
    key = os.urandom(4)
    header += key
    masked = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return bytes(header) + masked


def read_message(recv_exactly: Callable[[int], bytes]) -> str:
    """Read frames via ``recv_exactly(n)`` until FIN; return the text payload.

    Control frames (ping/pong/close) are skipped. ``recv_exactly`` must return
    exactly ``n`` bytes or raise.
    """
    chunks: list[bytes] = []
    while True:
        b0, b1 = recv_exactly(2)
        fin = b0 & 0x80
        opcode = b0 & 0x0F
        masked = b1 & 0x80
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack(">H", recv_exactly(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", recv_exactly(8))[0]
        key = recv_exactly(4) if masked else b""
        data = recv_exactly(length) if length else b""
        if masked:
            data = bytes(b ^ key[i % 4] for i, b in enumerate(data))
        if opcode == 0x8:  # close
            raise CdpError("websocket closed by peer")
        if opcode in (0x9, 0xA):  # ping/pong — ignore
            continue
        chunks.append(data)
        if fin:
            break
    return b"".join(chunks).decode("utf-8", "replace")


def _recv_exactly_from(sock: socket.socket) -> Callable[[int], bytes]:
    def recv(n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            part = sock.recv(n - len(buf))
            if not part:
                raise CdpError("connection closed mid-frame")
            buf += part
        return bytes(buf)
    return recv


# -- the client --------------------------------------------------------------

class CdpClient:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:9222",
        *,
        command: Optional[CommandFn] = None,
        timeout: float = 15.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._command = command or self._ws_command

    def get_cookies(self, domains: Optional[list[str]] = None) -> list[dict]:
        """Return all cookies (incl. httpOnly), optionally filtered by domain.

        Uses the browser-level ``Storage.getCookies`` so no page target needs to
        be attached. A domain filter matches by suffix (``.example.com`` matches
        ``api.example.com``).
        """
        result = self._command("Storage.getCookies", {})
        cookies = result.get("cookies", []) if isinstance(result, dict) else []
        if not domains:
            return cookies
        wanted = tuple(d.lstrip(".").lower() for d in domains)
        out = []
        for c in cookies:
            dom = str(c.get("domain", "")).lstrip(".").lower()
            if any(dom == w or dom.endswith("." + w) for w in wanted):
                out.append(c)
        return out

    def eval_js(self, expression: str) -> object:
        """Evaluate JavaScript in the warm page and return the value.

        Used by the cold-login form-drive to fill credentials + click submit. The
        expression is NEVER logged (it may carry a password) — see the harvester.
        Page-domain command, so ``_ws_command`` routes it to the page target.
        """
        result = self._command(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True, "awaitPromise": True},
        )
        if isinstance(result, dict) and result.get("exceptionDetails"):
            raise CdpError(f"Runtime.evaluate threw: {result['exceptionDetails']}")
        inner = result.get("result", {}) if isinstance(result, dict) else {}
        return inner.get("value")

    def navigate(self, url: str) -> None:
        """Navigate the warm page to ``url`` and best-effort wait for load.

        Driven via ``window.location`` + a ``document.readyState`` poll so only
        the Runtime domain is needed (no Page-domain event subscription).
        """
        self.eval_js(f"window.location.href = {json.dumps(url)}; true")
        for _ in range(40):  # ~ up to timeout, polled
            try:
                state = self.eval_js("document.readyState")
            except CdpError:
                state = None
            if state == "complete":
                return
            time.sleep(0.25)

    def current_url(self) -> str:
        try:
            return str(self.eval_js("location.href") or "")
        except CdpError:
            return ""

    # -- real CDP-over-WebSocket transport -----------------------------------
    def _browser_ws_url(self) -> str:
        with urlopen(f"{self._base}/json/version", timeout=self._timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        url = data.get("webSocketDebuggerUrl")
        if not url:
            raise CdpError("no webSocketDebuggerUrl from /json/version")
        return url

    def _page_ws_url(self) -> str:
        """webSocketDebuggerUrl of the first ``page`` target (create one if none).

        Page/Runtime/DOM/Input commands must target a page, not the browser.
        """
        with urlopen(f"{self._base}/json", timeout=self._timeout) as resp:
            targets = json.loads(resp.read().decode("utf-8", "replace"))
        for t in targets if isinstance(targets, list) else []:
            if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                return t["webSocketDebuggerUrl"]
        with urlopen(f"{self._base}/json/new", timeout=self._timeout) as resp:
            t = json.loads(resp.read().decode("utf-8", "replace"))
        url = t.get("webSocketDebuggerUrl")
        if not url:
            raise CdpError("no page target available and /json/new returned none")
        return url

    def _ws_command(self, method: str, params: dict) -> dict:
        import base64
        from urllib.parse import urlparse

        # Page/Runtime/DOM/Input act on a page target; everything else (Storage,
        # Target, Browser) on the browser endpoint.
        page_domain = method.split(".", 1)[0] in ("Runtime", "Page", "DOM", "Input")
        ws_url = self._page_ws_url() if page_domain else self._browser_ws_url()
        parsed = urlparse(ws_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 9222
        path = parsed.path or "/"

        sock = socket.create_connection((host, port), timeout=self._timeout)
        try:
            sock.settimeout(self._timeout)
            key = base64.b64encode(os.urandom(16)).decode()
            handshake = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            )
            sock.sendall(handshake.encode())
            recv = _recv_exactly_from(sock)
            # Read response headers up to the blank line.
            header = bytearray()
            while b"\r\n\r\n" not in header:
                header += recv(1)
            if b"101" not in header.split(b"\r\n", 1)[0]:
                raise CdpError(f"websocket upgrade failed: {header[:80]!r}")

            sock.sendall(encode_frame(json.dumps({"id": 1, "method": method, "params": params}).encode()))
            while True:
                msg = json.loads(read_message(recv))
                if msg.get("id") == 1:
                    if "error" in msg:
                        raise CdpError(f"CDP {method} error: {msg['error']}")
                    return msg.get("result", {})
        finally:
            try:
                sock.close()
            except OSError:
                pass
