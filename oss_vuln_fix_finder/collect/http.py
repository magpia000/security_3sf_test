"""요청 간격 제한과 재시도를 갖춘 HTTP 클라이언트(PRD 4.2-8).

NVD는 API 키 없이 30초에 5회까지만 받으므로 호스트별로 최소 요청 간격을 지킨다.
일시 오류(403/429/5xx, 연결 오류)는 지수 백오프로 다시 시도한다.
"""

import logging
import time
from collections import Counter
from collections.abc import Callable
from urllib.parse import urlparse

import requests

from oss_vuln_fix_finder.constants import (
    BACKOFF_BASE_SEC,
    DEFAULT_MIN_INTERVAL_SEC,
    HTTP_TIMEOUT_SEC,
    MAX_RETRIES,
    NVD_CVE_URL,
    NVD_MIN_INTERVAL_SEC,
    RETRY_STATUS_CODES,
    USER_AGENT,
)

logger = logging.getLogger(__name__)
HTTP_OK = 200


class CollectError(RuntimeError):
    """재시도 후에도 요청이 실패했을 때 발생한다."""


def default_intervals() -> dict[str, float]:
    """호스트별 기본 최소 요청 간격."""
    return {urlparse(NVD_CVE_URL).netloc: NVD_MIN_INTERVAL_SEC}


class HttpClient:
    """요청 간격·재시도·요청 수 집계를 담당한다.

    시계와 대기 함수를 주입받아 테스트에서 실제로 기다리지 않게 한다.
    """

    def __init__(
        self,
        session: requests.Session | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        min_intervals: dict[str, float] | None = None,
    ) -> None:
        self._session = session or requests.Session()
        self._session.headers.update({"User-Agent": USER_AGENT})
        self._clock = clock
        self._sleep = sleep
        self._min_intervals = default_intervals() if min_intervals is None else min_intervals
        self._last_request_at: dict[str, float] = {}
        self.request_counts: Counter[str] = Counter()

    def get_text(self, url: str, params: dict | None = None) -> str:
        """GET 요청 본문을 문자열로 돌려준다."""
        return self._request("GET", url, params=params)

    def post_json(self, url: str, payload: dict) -> str:
        """JSON 본문으로 POST하고 응답 본문을 문자열로 돌려준다."""
        return self._request("POST", url, json=payload)

    def _request(self, method: str, url: str, **kwargs: object) -> str:
        """간격을 지키며 요청하고, 일시 오류는 최대 MAX_RETRIES번 다시 시도한다."""
        host = urlparse(url).netloc
        last_problem = ""
        for attempt in range(MAX_RETRIES + 1):
            if attempt:
                delay = BACKOFF_BASE_SEC * 2 ** (attempt - 1)
                logger.warning(
                    "%s 재시도 %d/%d (%.0f초 대기): %s",
                    host,
                    attempt,
                    MAX_RETRIES,
                    delay,
                    last_problem,
                )
                self._sleep(delay)
            self._wait_turn(host)
            try:
                response = self._session.request(method, url, timeout=HTTP_TIMEOUT_SEC, **kwargs)
            except requests.RequestException as error:
                last_problem = f"연결 오류 {error.__class__.__name__}"
                continue
            finally:
                self.request_counts[host] += 1
            if response.status_code == HTTP_OK:
                return response.text
            last_problem = f"HTTP {response.status_code}"
            if response.status_code not in RETRY_STATUS_CODES:
                break  # 4xx 같은 영구 오류는 다시 시도해도 같다
        raise CollectError(f"{method} {url} 실패: {last_problem}")

    def _wait_turn(self, host: str) -> None:
        """같은 호스트에 대한 직전 요청과 최소 간격만큼 떨어지도록 기다린다."""
        interval = self._min_intervals.get(host, DEFAULT_MIN_INTERVAL_SEC)
        last = self._last_request_at.get(host)
        if last is not None:
            remaining = interval - (self._clock() - last)
            if remaining > 0:
                self._sleep(remaining)
        self._last_request_at[host] = self._clock()
