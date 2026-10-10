"""Maven 버전 규칙.

Maven ComparableVersion을 이 프로젝트에 필요한 만큼 단순화했다.
숫자 부분을 먼저 비교하고, 한정어는 alpha < beta < milestone < rc < snapshot < (정식) < sp 순이다.
"""

import re
from functools import cache

from oss_vuln_fix_finder.versions.base import (
    InvalidVersionError,
    VersionRule,
    branch_from_numbers,
    pad_numbers,
)

_TOKEN = re.compile(r"\d+|[A-Za-z]+")
_NUMBER_WIDTH = 6
_RELEASE_RANK = 5
_UNKNOWN_RANK = 7
# 한정어 → 순위. `a`, `b`, `m`은 Maven에서 alpha, beta, milestone의 약어다.
_QUALIFIER_RANK = {
    "alpha": 0,
    "a": 0,
    "beta": 1,
    "b": 1,
    "milestone": 2,
    "m": 2,
    "rc": 3,
    "cr": 3,
    "snapshot": 4,
    "": _RELEASE_RANK,
    "ga": _RELEASE_RANK,
    "final": _RELEASE_RANK,
    "release": _RELEASE_RANK,
    "sp": 6,
}


@cache
def _parse(version: str) -> tuple[tuple[int, ...], str, int]:
    """버전을 (숫자 부분, 한정어, 한정어 번호)로 나눈다."""
    tokens = _TOKEN.findall(version)
    if not tokens or not tokens[0].isdigit():
        raise InvalidVersionError(f"Maven 버전으로 해석할 수 없다: {version}")
    numbers: list[int] = []
    index = 0
    while index < len(tokens) and tokens[index].isdigit():
        numbers.append(int(tokens[index]))
        index += 1
    qualifier = tokens[index].lower() if index < len(tokens) else ""
    qualifier_number = (
        int(tokens[index + 1]) if index + 1 < len(tokens) and tokens[index + 1].isdigit() else 0
    )
    return tuple(numbers), qualifier, qualifier_number


class MavenRule(VersionRule):
    """Maven 컴포넌트용 규칙. 브랜치는 앞 두 자리(`1.4`)다."""

    name = "maven"

    def sort_key(self, version: str) -> tuple:
        numbers, qualifier, qualifier_number = _parse(version)
        rank = _QUALIFIER_RANK.get(qualifier, _UNKNOWN_RANK)
        # 알 수 없는 한정어끼리는 문자열 순으로 비교한다.
        text = qualifier if rank == _UNKNOWN_RANK else ""
        return pad_numbers(numbers, _NUMBER_WIDTH), rank, qualifier_number, text

    def branch(self, version: str, depth: int | None = None) -> str:
        return branch_from_numbers(_parse(version)[0], depth)

    def is_prerelease(self, version: str) -> bool:
        return _QUALIFIER_RANK.get(_parse(version)[1], _UNKNOWN_RANK) < _RELEASE_RANK


RULE = MavenRule()
