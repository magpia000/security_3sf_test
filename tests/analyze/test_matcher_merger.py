"""matcher·merger 단위 테스트(태스크 4.2, 4.3)."""

import pytest

from oss_vuln_fix_finder.analyze.matcher import is_affected, matching_ranges
from oss_vuln_fix_finder.analyze.merger import canonical_id, merge_vulnerabilities
from oss_vuln_fix_finder.models import AffectedRange, Vulnerability
from oss_vuln_fix_finder.versions.base import get_rule
from tests.analyze.helpers import vuln

OPENSSL = get_rule("openssl")


@pytest.mark.parametrize(
    "affected_range, version, expected",
    [
        (AffectedRange("0.9.8", True, "0.9.8za", False), "0.9.8h", True),
        (AffectedRange("0.9.8", True, "0.9.8za", False), "0.9.8za", False),  # 끝 미포함
        (AffectedRange("0.9.8", True, "0.9.8zh", True), "0.9.8zh", True),  # 끝 포함
        (AffectedRange("0.9.8h", False, None, False), "0.9.8h", False),  # 시작 미포함
        (AffectedRange(None, True, "1.0.1s", False), "0.9.8zh", True),  # 시작 없음
        (AffectedRange(), "3.6.0", True),  # 모든 버전
        (AffectedRange("x.y", True, "1.0.0", False), "0.9.8h", False),  # 해석 불가 경계는 건너뜀
    ],
)
def test_range_membership(affected_range, version, expected) -> None:
    """범위 경계 포함·미포함 규칙."""
    assert is_affected(vuln("V", affected_range), version, OPENSSL) is expected


def test_exact_versions_and_descriptions() -> None:
    """정확 버전은 같은 키로 비교하고 출력용 설명을 만든다."""
    item = vuln("V", AffectedRange(None, True, "0.9.8i", False), exact=("0.9.8h", "bad"))
    assert matching_ranges(item, "0.9.8h", OPENSSL) == ["=0.9.8h", "<0.9.8i"]
    assert matching_ranges(item, "0.9.8i", OPENSSL) == []


def test_canonical_id() -> None:
    """GHSA는 CVE 별칭으로, 별칭이 없으면 원래 ID로."""
    assert canonical_id(vuln("GHSA-1", aliases=("CVE-2022-1",))) == "CVE-2022-1"
    assert canonical_id(vuln("GHSA-2")) == "GHSA-2"


def test_merge_combines_sources_and_enriches() -> None:
    """NVD와 OSV의 같은 CVE를 합치고, OSV 전용 CVE는 단건 조회로 점수를 보완한다."""
    nvd = vuln(
        "CVE-1",
        AffectedRange(None, True, "2.0", False),
        sources=frozenset({"NVD"}),
        description="nvd",
        cvss_score=5.0,
    )
    osv = vuln(
        "GHSA-1",
        AffectedRange(None, True, "2.1", False),
        aliases=("CVE-1",),
        sources=frozenset({"OSV"}),
        description="osv",
    )
    osv_only = vuln("GHSA-2", aliases=("CVE-2",), sources=frozenset({"OSV"}), description="osv2")
    enrich = {
        "CVE-2": Vulnerability("CVE-2", description="nvd2", cvss_score=9.8, severity="CRITICAL")
    }
    merged = {v.vuln_id: v for v in merge_vulnerabilities([nvd, osv, osv_only], enrich)}
    assert merged["CVE-1"].sources == {"NVD", "OSV"}
    assert merged["CVE-1"].description == "nvd"
    assert len(merged["CVE-1"].ranges) == 2
    assert merged["CVE-1"].aliases == ("GHSA-1",)
    assert (merged["CVE-2"].cvss_score, merged["CVE-2"].description) == (9.8, "osv2")


def test_merge_excludes_rejected_and_optional_disputed() -> None:
    """Rejected는 항상, disputed는 옵션이 없을 때만 뺀다."""
    items = [vuln("CVE-R", is_rejected=True), vuln("CVE-D", is_disputed=True), vuln("CVE-OK")]
    assert [v.vuln_id for v in merge_vulnerabilities(items, {})] == ["CVE-OK"]
    assert [v.vuln_id for v in merge_vulnerabilities(items, {}, include_disputed=True)] == [
        "CVE-D",
        "CVE-OK",
    ]


def test_enrichment_can_mark_rejected() -> None:
    """OSV에만 있던 CVE도 NVD 단건 조회에서 Rejected면 뺀다."""
    osv = vuln("GHSA-3", aliases=("CVE-3",))
    assert merge_vulnerabilities([osv], {"CVE-3": vuln("CVE-3", is_rejected=True)}) == []
