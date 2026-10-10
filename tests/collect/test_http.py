"""HttpClient 단위 테스트(태스크 3.2)."""

import pytest

from oss_vuln_fix_finder.collect.http import CollectError, HttpClient
from oss_vuln_fix_finder.constants import BACKOFF_BASE_SEC, MAX_RETRIES, USER_AGENT
from tests.collect.fakes import CONNECTION_ERROR, FakeClock, FakeResponse, FakeSession

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _client(responses, clock=None):
    clock = clock or FakeClock()
    session = FakeSession(responses)
    return HttpClient(session=session, clock=clock, sleep=clock.sleep), session, clock


def test_sets_user_agent_and_counts() -> None:
    """User-Agent를 붙이고 호스트별 요청 수를 센다."""
    client, session, _ = _client([FakeResponse(200, "ok")])
    assert client.get_text(NVD, {"a": 1}) == "ok"
    assert session.headers["User-Agent"] == USER_AGENT
    assert client.request_counts["services.nvd.nist.gov"] == 1


def test_nvd_requests_are_six_seconds_apart() -> None:
    """NVD 요청 사이에는 6초 간격을 둔다."""
    client, _, clock = _client(
        [FakeResponse(200, "1"), FakeResponse(200, "2"), FakeResponse(200, "3")]
    )
    client.get_text(NVD)
    clock.now += 1.5  # 첫 요청 후 1.5초가 지남
    client.get_text(NVD)
    client.get_text(NVD)
    assert clock.sleeps == [pytest.approx(4.5), pytest.approx(6.0)]


def test_retries_transient_errors_with_backoff() -> None:
    """429와 연결 오류는 지수 백오프로 다시 시도한다."""
    client, _, clock = _client([FakeResponse(429), CONNECTION_ERROR, FakeResponse(200, "ok")])
    assert client.get_text("https://api.osv.dev/v1/query") == "ok"
    backoffs = [s for s in clock.sleeps if s in (BACKOFF_BASE_SEC, BACKOFF_BASE_SEC * 2)]
    assert backoffs == [BACKOFF_BASE_SEC, BACKOFF_BASE_SEC * 2]
    assert client.request_counts["api.osv.dev"] == 3


def test_gives_up_after_max_retries() -> None:
    """MAX_RETRIES번 재시도 후에도 실패하면 CollectError."""
    client, session, _ = _client([FakeResponse(503)] * (MAX_RETRIES + 1))
    with pytest.raises(CollectError, match="HTTP 503"):
        client.get_text(NVD)
    assert len(session.calls) == MAX_RETRIES + 1


def test_permanent_error_is_not_retried() -> None:
    """404 같은 영구 오류는 바로 실패한다."""
    client, session, _ = _client([FakeResponse(404)])
    with pytest.raises(CollectError, match="HTTP 404"):
        client.get_text("https://repo1.maven.org/x")
    assert len(session.calls) == 1


def test_post_json_sends_payload() -> None:
    """post_json은 json 인자로 본문을 보낸다."""
    client, session, _ = _client([FakeResponse(200, "{}")])
    client.post_json("https://api.osv.dev/v1/query", {"package": {"name": "g:a"}})
    method, _, kwargs = session.calls[0]
    assert method == "POST" and kwargs["json"] == {"package": {"name": "g:a"}}
