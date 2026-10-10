"""remediation 단위 테스트(태스크 4.4, 4.5)."""

from oss_vuln_fix_finder.analyze.merger import merge_vulnerabilities
from oss_vuln_fix_finder.analyze.parsers import parse_cpe_versions, parse_nvd_page
from oss_vuln_fix_finder.analyze.remediation import (
    NO_FIX,
    RemediationInput,
    choose_remediation,
    current_vulnerabilities,
    format_ids,
)
from oss_vuln_fix_finder.models import AffectedRange
from oss_vuln_fix_finder.versions.base import get_rule
from tests.analyze.helpers import below, load_fixture, vuln

SEMVER = get_rule("semver_like")


def run(current, versions, all_cves, rule=SEMVER, depth=2, lts=()):
    """C를 계산해 판정을 실행한다."""
    current_cves = current_vulnerabilities(all_cves, current, rule)
    return choose_remediation(
        RemediationInput(current, versions, all_cves, current_cves, rule, depth, lts)
    )


def test_step1_same_branch_resolution() -> None:
    """1단계: 같은 브랜치의 가장 낮은 C-해결 버전."""
    cves = [vuln("CVE-A", below("1.2.9")), vuln("CVE-B", below("1.2.12"))]
    result = run("1.2.5", ["1.2.5", "1.2.6", "1.2.11", "1.2.12", "1.3.1"], cves)
    assert (result.nearest, result.latest, result.notes) == ("1.2.12", "1.3.1", ())


def test_step1_reports_new_vulnerabilities() -> None:
    """1단계에서 고른 버전에 새 취약점이 있으면 비고에 적는다."""
    cves = [
        vuln("CVE-A", below("1.2.6")),
        vuln("CVE-N", AffectedRange("1.2.6", True, "1.2.7", False)),
    ]
    result = run("1.2.5", ["1.2.6", "1.2.7"], cves)
    assert result.nearest == "1.2.6"
    assert "신규 취약점: CVE-N" in result.notes


def test_step2_branch_final_with_alternative() -> None:
    """2단계: 같은 브랜치로 해결 불가 → 브랜치 최종 버전 + 미해결 + 브랜치 변경 권장."""
    cves = [vuln("CVE-A", below("2.0.0"))]
    result = run("1.2.5", ["1.2.6", "1.2.9", "2.0.0", "2.1.0"], cves)
    assert result.nearest == "1.2.9"
    assert result.notes[:2] == ("동일 브랜치 최종 버전, 미해결: CVE-A", "브랜치 변경 시: 2.0.0")


def test_step3_branch_change() -> None:
    """3단계: 현재가 브랜치 최종 버전이면 다른 브랜치의 무취약 버전."""
    cves = [
        vuln("CVE-A", below("1.2.9")),
        vuln("CVE-B", AffectedRange("1.2.0", True, "1.2.10", False)),
    ]
    result = run("1.1.3", ["1.1.3", "1.2.5", "1.2.10"], cves)
    assert result.nearest == "1.2.10"
    assert "브랜치 변경" in result.notes


def test_step4_no_fix_and_latest_still_vulnerable() -> None:
    """4단계: 해결 버전이 없으면 표시하고, 최신 버전의 미해결도 적는다."""
    cves = [vuln("CVE-A", AffectedRange())]
    result = run("1.0.0", ["1.0.0", "1.1.0", "2.0.0"], cves, depth=1)
    assert result.nearest == "1.1.0"  # 같은 브랜치 최종(2단계)
    result = run("2.0.0", ["1.0.0", "2.0.0"], cves, depth=1)
    assert result.nearest == NO_FIX
    assert result.latest == "2.0.0"
    assert "최신 버전에도 미해결: CVE-A" in result.notes


def test_no_current_vulnerability() -> None:
    """C가 비면 가까운 버전은 `-`, 최신 버전은 그대로 계산한다(PRD 4.3-21)."""
    result = run("1.3.1", ["1.2.5", "1.3.1"], [vuln("CVE-A", below("1.2.9"))])
    assert (result.nearest, result.latest) == ("-", "1.3.1")


def test_prerelease_never_recommended() -> None:
    """사전배포판은 후보에서 뺀다."""
    result = run(
        "9.0.1-rc3", ["9.0.1-rc3", "9.0.1", "10.0.0-rc1"], [vuln("CVE-A", below("9.0.1"))], depth=1
    )
    assert (result.nearest, result.latest) == ("9.0.1", "9.0.1")


def test_format_ids_truncates() -> None:
    """ID가 많으면 앞의 5개만 적는다."""
    assert format_ids({f"CVE-{i}" for i in range(7)}).endswith("외 2건")


def test_openssl_098h_regression() -> None:
    """PRD 4.3-21-1: OpenSSL 0.9.8h → 0.9.8zh(미해결 비고), 브랜치 변경 권장, 최신 + LTS 비고."""
    rule = get_rule("openssl")
    found = parse_nvd_page(load_fixture("nvd_cve_openssl.json"), ("cpe:2.3:a:openssl:openssl",))
    all_cves = merge_vulnerabilities(found, {})
    versions = parse_cpe_versions(load_fixture("nvd_cpe_openssl.json"))
    current_cves = current_vulnerabilities(all_cves, "0.9.8h", rule)
    assert [v.vuln_id for v in current_cves] == ["CVE-2009-0001", "CVE-2014-0224", "CVE-2016-0800"]

    result = choose_remediation(
        RemediationInput("0.9.8h", versions, all_cves, current_cves, rule, None, ("3.0", "3.5"))
    )
    assert result.nearest == "0.9.8zh"
    assert result.latest == "3.6.0"
    assert result.notes == (
        "동일 브랜치 최종 버전, 미해결: CVE-2016-0800",
        "브랜치 변경 시: 1.0.1u",
        "LTS: 3.5.4",
    )
