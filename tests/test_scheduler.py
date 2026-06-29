"""Scheduler integration tests with fake vault + fake providers."""

from sessionkeeper.metrics import Metrics
from sessionkeeper.provider import HEALTHY, NEEDS_HUMAN, NeedsLogin, ProviderConfig, SessionError, STALE
from sessionkeeper.scheduler import Scheduler
from sessionkeeper.session import Session


class FakeVault:
    def __init__(self, sessions):
        self.sessions = dict(sessions)
        self.writes = []
        self.fail_write = False

    def get_session(self, item):
        return self.sessions[item]

    def put_session(self, item, session):
        if self.fail_write:
            from sessionkeeper.vault import VaultError
            raise VaultError("write blocked")
        self.sessions[item] = session
        self.writes.append((item, session))


class FakeProvider:
    def __init__(self, pid, state, expiry, *, refreshed=None, raises=None, margin=2700):
        self.id = pid
        self.config = ProviderConfig(id=pid, vault_item=f"item/{pid}", refresh_margin_seconds=margin)
        self._state = state
        self._expiry = expiry
        self._refreshed = refreshed
        self._raises = raises
        self.refresh_called = 0

    def probe(self, session):
        return self._state, self._expiry

    def refresh(self, session):
        self.refresh_called += 1
        if self._raises:
            raise self._raises
        return self._refreshed or Session(access_token="rotated", refresh_token="rotated-r")

    def login(self, assist=None):
        raise NeedsLogin("no")


def _sched(provider, vault, metrics, alert=None):
    return Scheduler([provider], vault, metrics, clock=lambda: 1000.0, sleep=lambda s: None, alert=alert)


def test_healthy_not_due_does_not_refresh():
    # expiry far in the future (well beyond the 2700s margin)
    p = FakeProvider("p", HEALTHY, 1000.0 + 100000)
    vault = FakeVault({"item/p": Session(access_token="a", refresh_token="r")})
    m = Metrics()
    _sched(p, vault, m).tick()
    assert p.refresh_called == 0
    assert 'state="healthy"' in m.render()


def test_due_triggers_refresh_and_persists_back_to_vault():
    p = FakeProvider("p", HEALTHY, 1000.0 + 60, refreshed=Session(access_token="NEW", refresh_token="NEWR"))
    vault = FakeVault({"item/p": Session(access_token="old", refresh_token="oldr")})
    m = Metrics()
    _sched(p, vault, m).tick()
    assert p.refresh_called == 1
    assert vault.sessions["item/p"].access_token == "NEW"  # written back
    assert len(vault.writes) == 1
    assert 'result="success"' in m.render()


def test_stale_refreshes_even_if_not_within_margin():
    # access already expired -> STALE -> refresh attempted regardless of margin
    p = FakeProvider("p", STALE, 1000.0 - 5)
    vault = FakeVault({"item/p": Session(access_token="x", refresh_token="r")})
    m = Metrics()
    _sched(p, vault, m).tick()
    assert p.refresh_called == 1


def test_needs_login_marks_needs_human_and_alerts():
    p = FakeProvider("p", HEALTHY, 1000.0 + 60, raises=NeedsLogin("dead"))
    vault = FakeVault({"item/p": Session(access_token="a", refresh_token="r")})
    m = Metrics()
    alerts = []
    _sched(p, vault, m, alert=lambda pid, reason: alerts.append((pid, reason))).tick()
    assert 'state="needs-human"' in m.render()
    assert alerts and alerts[0][0] == "p"
    assert not vault.writes  # nothing persisted on a dead session


def test_probe_needs_human_short_circuits_no_refresh():
    p = FakeProvider("p", NEEDS_HUMAN, None)
    vault = FakeVault({"item/p": Session()})
    m = Metrics()
    _sched(p, vault, m).tick()
    assert p.refresh_called == 0
    assert 'state="needs-human"' in m.render()


def test_technical_error_marks_stale_not_needs_human():
    p = FakeProvider("p", HEALTHY, 1000.0 + 60, raises=SessionError("503"))
    vault = FakeVault({"item/p": Session(access_token="a", refresh_token="r")})
    m = Metrics()
    _sched(p, vault, m).tick()
    out = m.render()
    assert 'state="stale"' in out and 'result="error"' in out
    assert 'state="needs-human"' not in out


def test_refresh_ok_but_vault_write_fails_not_marked_healthy():
    p = FakeProvider("p", HEALTHY, 1000.0 + 60)
    vault = FakeVault({"item/p": Session(access_token="a", refresh_token="r")})
    vault.fail_write = True
    m = Metrics()
    _sched(p, vault, m).tick()
    out = m.render()
    assert 'result="write_error"' in out
    assert 'state="stale"' in out  # rotated token wasn't durably persisted


def test_run_forever_stops():
    p = FakeProvider("p", HEALTHY, 1000.0 + 100000)
    vault = FakeVault({"item/p": Session(access_token="a", refresh_token="r")})
    s = Scheduler([p], vault, Metrics(), interval_seconds=0.0,
                  clock=lambda: 1000.0, sleep=lambda x: None)
    s.stop()  # pre-stop: run_forever should do one tick then exit promptly
    s.run_forever()
