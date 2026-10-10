"""점으로 구분한 숫자 + 선택적 꼬리표 버전 규칙(GCC, LLVM, SQLite, zlib).

예: `4.8.0`, `1.2.5.1`, `9.0.1-rc3`. 꼬리표가 dev·alpha·beta·pre·rc이면 사전배포판으로 보고
같은 숫자의 정식 버전보다 낮게 둔다(`9.0.1-rc3` < `9.0.1`). 그 밖의 꼬리표(예: `p1`)는
정식 버전보다 높은 사후 패치로 본다. 브랜치 깊이는 매핑 파일의 `branch_depth`를 따른다.
"""

import re
from functools import cache

from oss_vuln_fix_finder.versions.base import (
    InvalidVersionError,
    VersionRule,
    branch_from_numbers,
    pad_numbers,
)

_PATTERN = re.compile(r"^(\d+(?:\.\d+)*)(?:[-._]?([A-Za-z]+)[-._]?(\d*))?$")
_NUMBER_WIDTH = 6
_PRERELEASE_ORDER = {
    "dev": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "pre": 3,
    "preview": 3,
    "rc": 4,
}
_PRERELEASE_FLAG, _RELEASE_FLAG, _POST_RELEASE_FLAG = 0, 1, 2


@cache
def _parse(version: str) -> tuple[tuple[int, ...], str, int]:
    """버전을 (숫자 튜플, 꼬리표, 꼬리표 번호)로 나눈다."""
    match = _PATTERN.match(version.strip())
    if not match:
        raise InvalidVersionError(f"점 구분 숫자 버전으로 해석할 수 없다: {version}")
    numbers = tuple(int(part) for part in match.group(1).split("."))
    return numbers, (match.group(2) or "").lower(), int(match.group(3) or 0)


class SemverLikeRule(VersionRule):
    """GCC·LLVM·SQLite·zlib 공용 규칙."""

    name = "semver_like"

    def sort_key(self, version: str) -> tuple:
        numbers, label, number = _parse(version)
        if not label:
            tail = (_RELEASE_FLAG, 0, "", 0)
        elif label in _PRERELEASE_ORDER:
            tail = (_PRERELEASE_FLAG, _PRERELEASE_ORDER[label], "", number)
        else:
            tail = (_POST_RELEASE_FLAG, 0, label, number)
        return pad_numbers(numbers, _NUMBER_WIDTH), tail

    def branch(self, version: str, depth: int | None = None) -> str:
        return branch_from_numbers(_parse(version)[0], depth)

    def is_prerelease(self, version: str) -> bool:
        return _parse(version)[1] in _PRERELEASE_ORDER


RULE = SemverLikeRule()
