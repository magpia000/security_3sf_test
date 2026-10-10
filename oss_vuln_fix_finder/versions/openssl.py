"""OpenSSL 버전 규칙.

3.0 미만은 `0.9.8h`, `1.0.2u`처럼 숫자 뒤에 문자 접미사를 붙여 패치를 표시한다.
접미사는 a~z 다음에 za~zz로 이어지므로 길이를 먼저 비교하고 같은 길이끼리 문자열을 비교한다
(`z` < `za` < `zh`). 3.0 이상은 `3.0.8`처럼 숫자만 쓴다.
"""

import re
from functools import cache

from oss_vuln_fix_finder.versions.base import InvalidVersionError, VersionRule

_PATTERN = re.compile(r"^(\d+)\.(\d+)\.(\d+)([a-z]*)(?:-(alpha|beta|pre)(\d*))?$", re.IGNORECASE)
_PRERELEASE_ORDER = {"alpha": 0, "beta": 1, "pre": 2}
_RELEASE_FLAG = 1
_LETTER_BRANCH_LIMIT = 3  # 이 메이저 버전 미만은 접미사 앞 숫자부 전체가 브랜치다


@cache
def _parse(version: str) -> tuple[int, int, int, str, str, int]:
    """버전을 (메이저, 마이너, 패치, 문자 접미사, 사전배포 표시, 번호)로 나눈다."""
    match = _PATTERN.match(version.strip())
    if not match:
        raise InvalidVersionError(f"OpenSSL 버전으로 해석할 수 없다: {version}")
    major, minor, patch, letters, label, number = match.groups()
    return (
        int(major),
        int(minor),
        int(patch),
        letters.lower(),
        (label or "").lower(),
        int(number or 0),
    )


class OpenSslRule(VersionRule):
    """OpenSSL 규칙. 브랜치: 3.0 미만은 `0.9.8`·`1.0.2`, 3.0 이상은 `3.0`·`3.5`."""

    name = "openssl"

    def sort_key(self, version: str) -> tuple:
        major, minor, patch, letters, label, number = _parse(version)
        if label:
            release = (0, _PRERELEASE_ORDER[label], number)
        else:
            release = (_RELEASE_FLAG, 0, 0)
        return major, minor, patch, len(letters), letters, release

    def branch(self, version: str, depth: int | None = None) -> str:
        major, minor, patch, *_ = _parse(version)
        if major < _LETTER_BRANCH_LIMIT:
            return f"{major}.{minor}.{patch}"
        return f"{major}.{minor}"

    def is_prerelease(self, version: str) -> bool:
        return bool(_parse(version)[4])


RULE = OpenSslRule()
