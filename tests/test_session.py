import base64
import json
import time

from sessionkeeper.session import Session, jwt_expiry, seconds_until


def _make_jwt(exp: float) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"exp": int(exp)}).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.signature"


def test_session_roundtrip_json():
    s = Session(access_token="a", refresh_token="r", cookies={"k": "v"}, extra={"n": 1})
    out = Session.from_json(s.to_json())
    assert out == s


def test_session_from_empty_json():
    assert Session.from_json("") == Session()
    assert Session.from_json("{}") == Session()


def test_cookie_header_renders_named_tokens_and_cookies():
    s = Session(access_token="AT", refresh_token="RT", cookies={"sid": "9"})
    h = s.cookie_header(access_name="Access", refresh_name="Refresh")
    assert "Access=AT" in h and "Refresh=RT" in h and "sid=9" in h


def test_jwt_expiry_reads_exp():
    exp = time.time() + 3600
    assert abs(jwt_expiry(_make_jwt(exp)) - int(exp)) < 1


def test_jwt_expiry_none_for_non_jwt():
    assert jwt_expiry("not-a-jwt") is None
    assert jwt_expiry("") is None
    assert jwt_expiry("a.b") is None  # only two segments


def test_seconds_until():
    assert seconds_until(None) is None
    assert abs(seconds_until(100.0, now=40.0) - 60.0) < 1e-9
