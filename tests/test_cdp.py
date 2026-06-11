"""CDP client: WebSocket frame codec round-trip + cookie filtering (offline)."""
import io

import pytest

from sessionkeeper.cdp import CdpClient, CdpError, encode_frame, read_message


def _reader(data: bytes):
    buf = io.BytesIO(data)

    def recv(n: int) -> bytes:
        b = buf.read(n)
        if len(b) != n:
            raise CdpError("short read")
        return b

    return recv


def test_frame_round_trip_small():
    payload = b'{"id":1,"method":"Storage.getCookies"}'
    assert read_message(_reader(encode_frame(payload))) == payload.decode()


def test_frame_round_trip_extended_length_126():
    payload = ("x" * 300).encode()  # >125 -> exercises the 2-byte length path
    assert read_message(_reader(encode_frame(payload))) == payload.decode()


def test_read_message_skips_ping_then_returns_text():
    ping = encode_frame(b"", opcode=0x9)
    text = encode_frame(b"hello", opcode=0x1)
    assert read_message(_reader(ping + text)) == "hello"


def test_read_message_raises_on_close():
    with pytest.raises(CdpError, match="closed"):
        read_message(_reader(encode_frame(b"", opcode=0x8)))


def test_get_cookies_returns_all_when_no_filter():
    cookies = [
        {"name": "A", "value": "1", "domain": "api.example.com"},
        {"name": "B", "value": "2", "domain": "other.org"},
    ]
    client = CdpClient(command=lambda m, p: {"cookies": cookies})
    assert client.get_cookies() == cookies


def test_get_cookies_filters_by_domain_suffix():
    cookies = [
        {"name": "A", "value": "1", "domain": "api.example.com"},
        {"name": "B", "value": "2", "domain": ".example.com"},
        {"name": "C", "value": "3", "domain": "evil.org"},
    ]
    client = CdpClient(command=lambda m, p: {"cookies": cookies})
    got = {c["name"] for c in client.get_cookies(["example.com"])}
    assert got == {"A", "B"}


def test_get_cookies_passes_correct_method():
    seen = {}

    def fake(method, params):
        seen["method"] = method
        return {"cookies": []}

    CdpClient(command=fake).get_cookies()
    assert seen["method"] == "Storage.getCookies"


def test_eval_js_returns_value():
    client = CdpClient(command=lambda m, p: {"result": {"type": "string", "value": "complete"}})
    assert client.eval_js("document.readyState") == "complete"


def test_eval_js_sends_runtime_evaluate_with_expression():
    seen = {}

    def fake(method, params):
        seen["method"] = method
        seen["expr"] = params.get("expression")
        return {"result": {"value": True}}

    CdpClient(command=fake).eval_js("1+1")
    assert seen["method"] == "Runtime.evaluate"
    assert seen["expr"] == "1+1"


def test_eval_js_raises_on_exception_details():
    client = CdpClient(command=lambda m, p: {"exceptionDetails": {"text": "ReferenceError"}})
    with pytest.raises(CdpError, match="threw"):
        client.eval_js("boom()")


def test_type_text_focuses_then_sends_input_insert_text_raw():
    seen = []

    def fake(method, params):
        seen.append((method, params))
        if method == "Runtime.evaluate":
            return {"result": {"value": True}}  # focus() / clear / events succeed
        return {}

    ok = CdpClient(command=fake).type_text("#email", 'p@ss"\\x')
    assert ok is True
    inserts = [p["text"] for m, p in seen if m == "Input.insertText"]
    assert inserts == ['p@ss"\\x']  # raw value, no JS escaping


def test_type_text_returns_false_when_element_absent():
    # focus() returns False (element not present) -> no insertText attempted.
    calls = []

    def fake(method, params):
        calls.append(method)
        if method == "Runtime.evaluate":
            return {"result": {"value": False}}
        return {}

    assert CdpClient(command=fake).type_text("#missing", "x") is False
    assert "Input.insertText" not in calls


def test_click_returns_true_when_present():
    assert CdpClient(command=lambda m, p: {"result": {"value": True}}).click("#go") is True


def test_navigate_sets_location_and_polls_ready():
    calls = []

    def fake(method, params):
        calls.append(params.get("expression", ""))
        # readyState polls return 'complete' immediately.
        return {"result": {"value": "complete"}}

    CdpClient(command=fake).navigate("https://example.com/login")
    assert any("location.href" in c for c in calls)


def test_navigate_polls_through_not_complete_then_complete():
    # Forces the time.sleep() poll branch (regression: cdp.py once missed
    # `import time`, which only blows up when readyState != 'complete' first).
    states = iter(["", "loading", "complete"])  # set href, then two polls

    def fake(method, params):
        expr = params.get("expression", "")
        if "readyState" in expr:
            return {"result": {"value": next(states, "complete")}}
        return {"result": {"value": True}}

    # Should return without raising (NameError would surface if time unimported).
    CdpClient(command=fake, timeout=1.0).navigate("https://example.com/login")

