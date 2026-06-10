import json

import pytest

from sessionkeeper.session import Session
from sessionkeeper.vault import VaultClient, VaultError, VaultItemNotFound
from conftest import FakeHTTP


def _list_resp(name, item_id="abc", notes=None, password="pw"):
    item = {"object": "item", "id": item_id, "name": name,
            "login": {"username": "u", "password": password}}
    if notes is not None:
        item["notes"] = notes
    return {"success": True, "data": {"object": "list", "data": [item]}}


def test_get_session_parses_notes_json():
    sess = Session(access_token="AT", refresh_token="RT")
    http = FakeHTTP({("GET", "/list/object/items?search=itm"): (200, {}, _list_resp("itm", notes=sess.to_json()))})
    vc = VaultClient("http://vault.test:8087", transport=http)
    got = vc.get_session("itm")
    assert got.access_token == "AT" and got.refresh_token == "RT"


def test_get_session_falls_back_to_login_password():
    http = FakeHTTP({("GET", "search=itm"): (200, {}, _list_resp("itm", notes=None, password="just-a-pw"))})
    vc = VaultClient("http://vault.test:8087", transport=http)
    assert vc.get_session("itm").access_token == "just-a-pw"


def test_get_session_missing_item_raises():
    http = FakeHTTP({("GET", "search=nope"): (200, {}, {"success": True, "data": {"data": []}})})
    vc = VaultClient("http://vault.test:8087", transport=http)
    with pytest.raises(VaultItemNotFound):
        vc.get_session("nope")


def test_put_session_does_read_modify_write_and_mirrors_password():
    sess = Session(access_token="NEW_AT", refresh_token="NEW_RT")
    http = FakeHTTP({
        ("GET", "search=itm"): (200, {}, _list_resp("itm", item_id="id-1", notes="{}", password="old")),
        ("PUT", "/object/item/id-1"): (200, {}, {"success": True, "data": {}}),
    })
    vc = VaultClient("http://vault.test:8087", transport=http)
    vc.put_session("itm", sess)
    put_call = [c for c in http.calls if c[0] == "PUT"][0]
    body = json.loads(put_call[3].decode())
    assert json.loads(body["notes"])["access_token"] == "NEW_AT"
    assert body["login"]["password"] == "NEW_AT"  # mirrored for simple readers


def test_api_key_sends_bearer():
    http = FakeHTTP({("GET", "search=itm"): (200, {}, _list_resp("itm", notes="{}"))})
    vc = VaultClient("http://vault.test:8087", api_key="secret", transport=http)
    vc.get_session("itm")
    assert http.calls[-1][2].get("Authorization") == "Bearer secret"


def test_http_error_raises_vault_error():
    http = FakeHTTP({("GET", "search=itm"): (500, {}, "boom")})
    vc = VaultClient("http://vault.test:8087", transport=http)
    with pytest.raises(VaultError):
        vc.get_session("itm")


def test_success_false_raises():
    http = FakeHTTP({("GET", "search=itm"): (200, {}, {"success": False, "message": "locked"})})
    vc = VaultClient("http://vault.test:8087", transport=http)
    with pytest.raises(VaultError):
        vc.get_session("itm")
