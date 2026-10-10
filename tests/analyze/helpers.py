"""분석 엔진 테스트용 도우미."""

import json

from oss_vuln_fix_finder.models import AffectedRange, Vulnerability
from tests.conftest import FIXTURES


def load_fixture(name: str) -> dict:
    """fixture JSON을 읽는다."""
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def vuln(
    vuln_id: str, *ranges: AffectedRange, exact: tuple[str, ...] = (), **kwargs
) -> Vulnerability:
    """테스트용 취약점을 짧게 만든다."""
    return Vulnerability(vuln_id=vuln_id, ranges=ranges, exact_versions=frozenset(exact), **kwargs)


def below(end: str, start: str | None = None) -> AffectedRange:
    """[start, end) 범위."""
    return AffectedRange(start=start, end=end)
