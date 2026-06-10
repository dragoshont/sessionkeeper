from sessionkeeper.metrics import Metrics
from sessionkeeper.provider import HEALTHY, NEEDS_HUMAN


def test_render_includes_all_three_metrics():
    m = Metrics()
    m.set_state("p1", HEALTHY)
    m.set_expiry("p1", 1234.6)
    m.inc_refresh("p1", "success")
    out = m.render()
    assert 'sessionkeeper_session_state{provider="p1",state="healthy"} 0' in out
    assert 'sessionkeeper_session_expiry_seconds{provider="p1"} 1235' in out
    assert 'sessionkeeper_refresh_total{provider="p1",result="success"} 1' in out
    # exposition hygiene: HELP/TYPE present
    assert "# TYPE sessionkeeper_session_state gauge" in out
    assert "# TYPE sessionkeeper_refresh_total counter" in out


def test_state_label_reflects_code():
    m = Metrics()
    m.set_state("p", NEEDS_HUMAN)
    assert 'state="needs-human"} 3' in m.render()


def test_refresh_total_accumulates():
    m = Metrics()
    m.inc_refresh("p", "success")
    m.inc_refresh("p", "success")
    m.inc_refresh("p", "error")
    out = m.render()
    assert 'result="success"} 2' in out
    assert 'result="error"} 1' in out


def test_set_expiry_none_removes():
    m = Metrics()
    m.set_expiry("p", 10.0)
    m.set_expiry("p", None)
    assert "sessionkeeper_session_expiry_seconds{" not in m.render()
