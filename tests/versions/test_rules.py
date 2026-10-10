"""버전 규칙 단위 테스트(태스크 2.1~2.5). PRD 4.4 표의 순서 예를 모두 포함한다."""

import pytest

from oss_vuln_fix_finder.versions.base import InvalidVersionError, get_rule, unique_sorted

ORDER_CASES = [
    # 2.2 maven
    ("maven", ["1.4.1", "1.10", "1.21"]),
    ("maven", ["2.0.0-M1", "2.0.0-RC1", "2.0.0-SNAPSHOT", "2.0.0", "2.0.0-sp1"]),
    ("maven", ["3.0.0-alpha-1", "3.0.0-beta-1", "3.0.0"]),
    # 2.3 openssl
    ("openssl", ["0.9.8h", "0.9.8za", "0.9.8zh", "1.0.0", "1.0.2u", "1.1.1w", "3.0.8"]),
    ("openssl", ["0.9.8", "0.9.8a", "0.9.8y", "0.9.8z", "0.9.8za"]),
    ("openssl", ["1.1.1-pre9", "1.1.1", "3.0.0-alpha1", "3.0.0-beta2", "3.0.0"]),
    # 2.4 letter_suffix
    ("letter_suffix", ["8", "8a", "8b", "8d", "9", "9a"]),
    # 2.5 semver_like
    ("semver_like", ["9.0.1-rc3", "9.0.1", "10.0.0"]),
    ("semver_like", ["1.2.5", "1.2.11", "1.2.13"]),
    ("semver_like", ["1.2.5", "1.2.5.1", "1.2.6"]),
    ("semver_like", ["4.8.0", "4.8.1", "4.9.0", "10.1.0"]),
]


@pytest.mark.parametrize("rule_name, ordered", ORDER_CASES)
def test_ordering(rule_name: str, ordered: list[str]) -> None:
    """각 목록은 오름차순이어야 한다."""
    rule = get_rule(rule_name)
    for lower, higher in zip(ordered, ordered[1:], strict=False):
        assert rule.compare(lower, higher) == -1, f"{lower} < {higher}"


@pytest.mark.parametrize(
    "rule_name, version, depth, expected",
    [
        ("maven", "1.4.1", None, "1.4"),
        ("maven", "2", None, "2.0"),
        ("openssl", "0.9.8h", None, "0.9.8"),
        ("openssl", "1.0.2u", None, "1.0.2"),
        ("openssl", "1.1.1w", None, "1.1.1"),
        ("openssl", "3.0.8", None, "3.0"),
        ("openssl", "3.5.1", None, "3.5"),
        ("letter_suffix", "8b", None, "8"),
        ("semver_like", "4.8.0", 1, "4"),
        ("semver_like", "9.0.1-rc3", 1, "9"),
        ("semver_like", "3.7.9", 2, "3.7"),
        ("semver_like", "1.2.5", 2, "1.2"),
    ],
)
def test_branch(rule_name: str, version: str, depth: int | None, expected: str) -> None:
    """브랜치 정의는 PRD 4.4 표를 따른다."""
    assert get_rule(rule_name).branch(version, depth) == expected


@pytest.mark.parametrize(
    "rule_name, version, expected",
    [
        ("maven", "2.0.0-M1", True),
        ("maven", "1.0-SNAPSHOT", True),
        ("maven", "4.28.0-RC1", True),
        ("maven", "1.0.Final", False),
        ("maven", "1.4.1", False),
        ("openssl", "3.0.0-beta1", True),
        ("openssl", "0.9.8zh", False),
        ("letter_suffix", "8b", False),
        ("semver_like", "9.0.1-rc3", True),
        ("semver_like", "1.2.5", False),
        ("semver_like", "1.0p1", False),
    ],
)
def test_prerelease(rule_name: str, version: str, expected: bool) -> None:
    """사전배포판 판정."""
    assert get_rule(rule_name).is_prerelease(version) is expected


def test_normalize_strips_prefix() -> None:
    """매핑 파일의 접두사를 떼고 공백을 정리한다."""
    rule = get_rule("semver_like")
    assert rule.normalize(" llvmorg-9.0.1-rc3 ", "llvmorg-") == "9.0.1-rc3"
    assert rule.normalize("9.0.1", "llvmorg-") == "9.0.1"


def test_equal_versions_share_key() -> None:
    """`1.7`과 `1.7.0`은 같은 버전으로 본다."""
    assert get_rule("maven").compare("1.7", "1.7.0") == 0


@pytest.mark.parametrize(
    "rule_name, version",
    [("openssl", "1.0.1-fips"), ("letter_suffix", "8bb"), ("semver_like", "abc"), ("maven", "r09")],
)
def test_invalid_versions(rule_name: str, version: str) -> None:
    """해석할 수 없는 버전은 InvalidVersionError이고 is_valid는 False다."""
    rule = get_rule(rule_name)
    assert rule.is_valid(version) is False
    with pytest.raises(InvalidVersionError):
        rule.sort_key(version)


def test_unique_sorted_drops_invalid_and_duplicates() -> None:
    """정렬 도우미는 잘못된 버전과 중복을 버린다."""
    rule = get_rule("openssl")
    assert unique_sorted(["1.0.2u", "x", "0.9.8h", "1.0.2u", "0.9.8zh"], rule) == [
        "0.9.8h",
        "0.9.8zh",
        "1.0.2u",
    ]


def test_unknown_rule_name() -> None:
    """등록되지 않은 규칙 이름은 KeyError."""
    with pytest.raises(KeyError):
        get_rule("nope")
