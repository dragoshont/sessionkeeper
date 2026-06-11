"""Scheduler escalation: refresh dead -> harvester login(), guarded by breaker."""
from sessionkeeper.metrics import Metrics
from sessionkeeper.provider import HEALTHY, NeedsLogin, ProviderConfig
from sessionkeeper.scheduler import Scheduler
from sessionkeeper.session import Session


class FakeVault:
    def __init__(self, sessions):
        self.sessions = dict(sessions)
        self.writes = []

    def get_session(self, item):
        return self.sessions[item]

    def put_session(self, item, session):
        self.sessions[item] = session
        self.writes.append((item, session))


class EscalatingProvider:
    """refresh() always raises NeedsLogin; login() is configurable."""

    def __init__(self, pid, *, login_result=None, login_raises=None, min_gap=300, max_day=24):
        self.id = pid
        self.config = ProviderConfig(
            id=pid, vault_item=f"item-{pid}",
            min_seconds_between_logins=min_gap, max_logins_per_day=max_day,
        )
        self._login_result = login_result
        self._login_raises = login_raises
        self.login_called = 0

    def probe(self, session):
        return HEALTHY, 1000.0 + 60  # within margin -> due -> refresh attempted

    def refresh(self, session):
        raise NeedsLogin("refresh token lapsed")

    def login(self, assist=None):
        self.login_called += 1
        if self._login_raises:
            raise self._login_raises
        return self._login_result or Session(access_token="RELOGGED")


def _sched(provider, vault, metrics, alert=None):
    return Scheduler([provider], vault, metrics, clock=lambda: 1000.0, sleep=lambda s: None, alert=alert)


def test_refresh_dead_escalates_to_login_and_persists():
    p = EscalatingProvider("p")
    vault = FakeVault({"item-p": Session(refresh_token="r")})
    m = Metrics()
    _sched(p, vault, m).tick()
    assert p.login_called == 1
    assert vault.sessions["item-p"].access_token == "RELOGGED"
    out = m.render()
    assert 'sessionkeeper_login_total{provider="p",result="success"}' in out
    assert 'state="healthy"' in out


def test_login_needs_login_marks_needs_human_and_alerts():
    p = EscalatingProvider("p", login_raises=NeedsLogin("one-time human login required"))
    vault = FakeVault({"item-p": Session(refresh_token="r")})
    m = Metrics()
    alerts = []
    _sched(p, vault, m, alert=lambda pid, reason: alerts.append((pid, reason))).tick()
    assert p.login_called == 1
    assert 'state="needs-human"' in m.render()
    assert alerts and alerts[0][0] == "p"
    assert not vault.writes


def test_circuit_breaker_blocks_login_when_cap_zero():
    # max_logins_per_day=0 -> breaker never allows a login -> straight to needs-human.
    p = EscalatingProvider("p", max_day=0)
    vault = FakeVault({"item-p": Session(refresh_token="r")})
    m = Metrics()
    alerts = []
    _sched(p, vault, m, alert=lambda pid, reason: alerts.append((pid, reason))).tick()
    assert p.login_called == 0  # suppressed by the breaker
    out = m.render()
    assert 'state="needs-human"' in out
    assert alerts and "suppressed" in alerts[0][1]


def test_breaker_min_gap_blocks_second_login_in_window():
    p = EscalatingProvider("p", min_gap=600, max_day=24)
    vault = FakeVault({"item-p": Session(refresh_token="r")})
    m = Metrics()
    s = _sched(p, vault, m)
    s.tick()  # first login allowed + recorded
    assert p.login_called == 1
    s.tick()  # same clock (1000.0) -> within min_gap -> suppressed
    assert p.login_called == 1
    assert 'state="needs-human"' in m.render()
