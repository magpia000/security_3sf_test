"""버전 규칙 공통 인터페이스와 규칙 레지스트리(PRD 4.4).

각 규칙은 버전 문자열을 정렬 키로 바꾸고, 브랜치와 사전배포판 여부를 판정한다.
정렬 키끼리 비교하면 버전 순서가 된다. 서로 다른 규칙의 키는 비교하지 않는다.
"""

import logging
from abc import ABC, abstractmethod
from collections.abc import Iterable

from oss_vuln_fix_finder.constants import DEFAULT_BRANCH_DEPTH

logger = logging.getLogger(__name__)


class InvalidVersionError(ValueError):
    """규칙으로 해석할 수 없는 버전 문자열."""


class VersionRule(ABC):
    """버전 규칙의 공통 인터페이스."""

    name: str = ""

    def normalize(self, raw: str, prefix: str = "") -> str:
        """입력 버전에서 공백과 매핑 파일의 접두사(예: `llvmorg-`)를 뗀다."""
        version = raw.strip()
        if prefix and version.lower().startswith(prefix.lower()):
            version = version[len(prefix) :]
        return version

    @abstractmethod
    def sort_key(self, version: str) -> tuple:
        """정렬 키를 만든다. 해석할 수 없으면 InvalidVersionError."""

    @abstractmethod
    def branch(self, version: str, depth: int | None = None) -> str:
        """버전이 속한 릴리스 브랜치 이름을 돌려준다(예: `0.9.8`, `1.2`)."""

    @abstractmethod
    def is_prerelease(self, version: str) -> bool:
        """rc·alpha·beta·SNAPSHOT 같은 사전배포판이면 True."""

    def is_valid(self, version: str) -> bool:
        """규칙으로 해석할 수 있는 버전이면 True."""
        try:
            self.sort_key(version)
        except InvalidVersionError:
            return False
        return True

    def compare(self, left: str, right: str) -> int:
        """left가 작으면 -1, 같으면 0, 크면 1."""
        left_key, right_key = self.sort_key(left), self.sort_key(right)
        return (left_key > right_key) - (left_key < right_key)


def branch_from_numbers(numbers: tuple[int, ...], depth: int | None) -> str:
    """숫자 부분의 앞 `depth`자리로 브랜치 이름을 만든다. 자리가 모자라면 0으로 채운다."""
    size = depth or DEFAULT_BRANCH_DEPTH
    padded = list(numbers[:size]) + [0] * (size - len(numbers[:size]))
    return ".".join(str(number) for number in padded)


def pad_numbers(numbers: tuple[int, ...], width: int) -> tuple[int, ...]:
    """`1.7`과 `1.7.0`이 같은 키가 되도록 숫자 튜플 뒤를 0으로 채운다."""
    return numbers + (0,) * (width - len(numbers))


def unique_sorted(versions: Iterable[str], rule: VersionRule) -> list[str]:
    """해석 가능한 버전만 남겨 중복(같은 키)을 없애고 오름차순으로 정렬한다.

    해석할 수 없는 버전은 경고 로그를 남기고 버린다.
    """
    by_key: dict[tuple, str] = {}
    for version in versions:
        try:
            key = rule.sort_key(version)
        except InvalidVersionError:
            logger.debug("%s 규칙으로 해석할 수 없는 버전을 건너뛴다: %s", rule.name, version)
            continue
        by_key.setdefault(key, version)
    return [by_key[key] for key in sorted(by_key)]


def get_rule(name: str) -> VersionRule:
    """규칙 이름으로 규칙 객체를 찾는다.

    Raises:
        KeyError: 등록되지 않은 규칙 이름.
    """
    # 순환 import를 피하려고 레지스트리를 처음 쓸 때 규칙 모듈을 불러온다.
    from oss_vuln_fix_finder.versions import letter_suffix, maven, openssl, semver_like

    rules = {
        rule.name: rule for rule in (maven.RULE, openssl.RULE, letter_suffix.RULE, semver_like.RULE)
    }
    return rules[name]
