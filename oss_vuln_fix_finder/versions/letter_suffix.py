"""숫자 + 한 글자 접미사 버전 규칙(libjpeg: `6b`, `8`, `8a`, `9e`).

접미사가 없는 버전이 가장 앞선다(`8` < `8a`). 브랜치는 숫자부(`8`)다.
"""

import re
from functools import cache

from oss_vuln_fix_finder.versions.base import InvalidVersionError, VersionRule

_PATTERN = re.compile(r"^(\d+)([a-z]?)$", re.IGNORECASE)


@cache
def _parse(version: str) -> tuple[int, str]:
    """버전을 (숫자, 접미사)로 나눈다."""
    match = _PATTERN.match(version.strip())
    if not match:
        raise InvalidVersionError(f"숫자+문자 접미사 버전으로 해석할 수 없다: {version}")
    return int(match.group(1)), match.group(2).lower()


class LetterSuffixRule(VersionRule):
    """libjpeg 계열 규칙. 사전배포판 개념이 없다."""

    name = "letter_suffix"

    def sort_key(self, version: str) -> tuple:
        return _parse(version)

    def branch(self, version: str, depth: int | None = None) -> str:
        return str(_parse(version)[0])

    def is_prerelease(self, version: str) -> bool:
        _parse(version)  # 해석할 수 없는 버전이면 여기서 오류를 낸다
        return False


RULE = LetterSuffixRule()
