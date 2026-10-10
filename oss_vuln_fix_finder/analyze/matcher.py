"""버전이 취약점의 영향 범위에 드는지 판정한다(PRD 4.3-15).

비교는 반드시 버전 규칙의 정렬 키로 한다. 문자열 비교는 쓰지 않는다(rules.md 4.3).
"""

import logging

from oss_vuln_fix_finder.models import AffectedRange, Vulnerability
from oss_vuln_fix_finder.versions.base import InvalidVersionError, VersionRule

logger = logging.getLogger(__name__)


def is_affected(vulnerability: Vulnerability, version: str, rule: VersionRule) -> bool:
    """version이 취약점의 정확 버전 목록이나 범위 중 하나에 들면 True."""
    return bool(matching_ranges(vulnerability, version, rule))


def matching_ranges(vulnerability: Vulnerability, version: str, rule: VersionRule) -> list[str]:
    """version을 포함하는 범위의 설명 목록(출력 8열용). 없으면 빈 목록."""
    key = rule.sort_key(version)
    matched = [
        f"={exact}"
        for exact in sorted(vulnerability.exact_versions)
        if _same_version(exact, key, rule)
    ]
    matched += [r.describe() for r in vulnerability.ranges if _in_range(r, key, rule)]
    return matched


def _same_version(candidate: str, key: tuple, rule: VersionRule) -> bool:
    """정확 버전이 같은 버전인지 확인한다. 해석할 수 없는 값은 같지 않은 것으로 본다."""
    try:
        return rule.sort_key(candidate) == key
    except InvalidVersionError:
        return False


def _in_range(affected: AffectedRange, key: tuple, rule: VersionRule) -> bool:
    """정렬 키가 범위 안에 있는지 확인한다.

    경계 버전을 규칙으로 해석할 수 없으면 판정할 수 없으므로 그 범위는 건너뛴다.
    """
    try:
        if affected.start is not None:
            start = rule.sort_key(affected.start)
            if key < start or (key == start and not affected.start_inclusive):
                return False
        if affected.end is not None:
            end = rule.sort_key(affected.end)
            if key > end or (key == end and not affected.end_inclusive):
                return False
    except InvalidVersionError as error:
        logger.debug("범위 경계를 해석할 수 없어 건너뛴다: %s", error)
        return False
    return True
