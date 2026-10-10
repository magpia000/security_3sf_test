"""수집기 테스트용 가짜 HTTP 세션과 시계."""

from dataclasses import dataclass, field

import requests


@dataclass
class FakeResponse:
    """requests.Response 대역."""

    status_code: int
    text: str = ""


@dataclass
class FakeClock:
    """sleep이 호출되면 시간이 그만큼 흐르는 가짜 시계."""

    now: float = 1000.0
    sleeps: list[float] = field(default_factory=list)

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class FakeSession:
    """미리 정한 응답을 순서대로 돌려주고 호출 내용을 기록한다.

    응답 대신 함수(handler)를 주면 (method, url, kwargs)로 응답을 만든다.
    """

    def __init__(self, responses=None, handler=None) -> None:
        self.headers: dict[str, str] = {}
        self.calls: list[tuple[str, str, dict]] = []
        self._responses = list(responses or [])
        self._handler = handler

    def request(self, method: str, url: str, **kwargs):
        self.calls.append((method, url, kwargs))
        if self._handler:
            return self._handler(method, url, kwargs)
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


CONNECTION_ERROR = requests.ConnectionError("boom")
