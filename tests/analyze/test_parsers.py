"""parsers 단위 테스트(태스크 4.1)."""

from oss_vuln_fix_finder.analyze.parsers import (
    parse_cpe_versions,
    parse_maven_versions,
    parse_nvd_cve,
    parse_nvd_page,
    parse_osv_page,
)
from oss_vuln_fix_finder.models import AffectedRange
from tests.analyze.helpers import load_fixture
from tests.conftest import FIXTURES

OPENSSL_CPE = ("cpe:2.3:a:openssl:openssl",)


def _by_id(vulns):
    return {v.vuln_id: v for v in vulns}


def test_nvd_ranges_and_exact_versions() -> None:
    """범위 키는 AffectedRange로, 범위 없는 CPE 버전은 정확 버전으로 바꾼다."""
    vulns = _by_id(parse_nvd_page(load_fixture("nvd_cve_openssl.json"), OPENSSL_CPE))
    assert vulns["CVE-2009-0001"].exact_versions == {"0.9.8g", "0.9.8h"}
    assert vulns["CVE-2014-0224"].ranges == (
        AffectedRange("0.9.8", True, "0.9.8za", False),
        AffectedRange("1.0.1", True, "1.0.1h", False),
    )
    assert vulns["CVE-2010-5298"].ranges == (AffectedRange("0.9.8", True, "0.9.8zh", True),)


def test_nvd_ignores_other_products() -> None:
    """다른 제품(debian_linux) CPE는 범위로 쓰지 않는다."""
    drown = _by_id(parse_nvd_page(load_fixture("nvd_cve_openssl.json"), OPENSSL_CPE))[
        "CVE-2016-0800"
    ]
    assert all(r.end in ("1.0.1s", "1.0.2g") for r in drown.ranges)


def test_nvd_cvss_priority_and_flags() -> None:
    """CVSS 우선순위(v3.1 → v3.0 → v4.0 → v2)와 Rejected·disputed 표시."""
    vulns = _by_id(parse_nvd_page(load_fixture("nvd_cve_openssl.json"), OPENSSL_CPE))
    assert (vulns["CVE-2014-0224"].cvss_score, vulns["CVE-2014-0224"].severity) == (7.4, "HIGH")
    assert (vulns["CVE-2009-0001"].cvss_score, vulns["CVE-2009-0001"].severity) == (
        5.0,
        "MEDIUM",
    )  # v2
    assert vulns["CVE-2025-0001"].severity == "CRITICAL"  # v4.0
    assert vulns["CVE-2015-9999"].is_rejected
    assert vulns["CVE-2010-5298"].is_disputed


def test_nvd_cve_without_prefixes_has_metadata_only() -> None:
    """단건 보완 조회는 범위 없이 메타데이터만 담는다."""
    item = load_fixture("nvd_cve_by_id_CVE-2022-25647.json")["vulnerabilities"][0]["cve"]
    vulnerability = parse_nvd_cve(item)
    assert vulnerability.cvss_score == 7.5 and not vulnerability.ranges


def test_osv_events_and_versions() -> None:
    """OSV events는 범위로, versions는 정확 버전으로, GIT 범위는 무시한다."""
    vulns = _by_id(parse_osv_page(load_fixture("osv_gson.json"), "com.google.code.gson:gson"))
    gson = vulns["GHSA-4jrv-ppp4-jm57"]
    assert gson.ranges == (AffectedRange(None, True, "2.8.9", False),)
    assert gson.aliases == ("CVE-2022-25647",)
    assert "1.7" in gson.exact_versions
    advisory = vulns["GHSA-0000-0000-0000"]
    assert advisory.ranges == (AffectedRange("1.7", True, "1.7.1", True),)
    assert advisory.severity == "MEDIUM"  # MODERATE → MEDIUM


def test_version_lists() -> None:
    """CPE 버전(update 포함)과 Maven 메타데이터 버전 목록."""
    versions = parse_cpe_versions(load_fixture("nvd_cpe_openssl.json"))
    assert "0.9.8zh" in versions and "3.6.0-beta1" in versions and "1.0.1-fips" in versions
    xml = (FIXTURES / "maven-metadata-gson.xml").read_text(encoding="utf-8")
    assert parse_maven_versions(xml)[:2] == ["1.7", "1.7.1"]
