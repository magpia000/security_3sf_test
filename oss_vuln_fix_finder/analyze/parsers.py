"""묶음 원본(NVD·OSV·Maven) → 도메인 객체 변환(PRD 4.3-15·17, 4.5-24).

모두 순수 함수다. 파일·네트워크를 다루지 않고, 이미 읽은 dict·문자열만 받는다.
"""

import logging
import xml.etree.ElementTree as ElementTree

from oss_vuln_fix_finder.constants import SOURCE_NVD, SOURCE_OSV
from oss_vuln_fix_finder.models import AffectedRange, Vulnerability

logger = logging.getLogger(__name__)

# CVSS는 v3.1 → v3.0 → v4.0 → v2 순서로 처음 있는 것을 쓴다(PRD 4.5-24 6열).
CVSS_METRIC_ORDER = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")
NVD_STATUS_REJECTED = "Rejected"
DISPUTED_TAG = "disputed"
DISPUTED_PREFIX = "** DISPUTED"
OSV_RANGE_TYPES = frozenset({"ECOSYSTEM", "SEMVER"})
OSV_ZERO_VERSION = "0"  # OSV에서 "처음부터"를 뜻하는 introduced 값
# GitHub Advisory의 심각도 표기를 CVSS 표기에 맞춘다.
SEVERITY_ALIASES = {"MODERATE": "MEDIUM"}
CPE_EMPTY_VALUES = frozenset({"*", "-", ""})


# ---------- NVD ----------


def parse_nvd_page(data: dict, cpe_prefixes: tuple[str, ...]) -> list[Vulnerability]:
    """NVD CVE 응답 한 페이지를 Vulnerability 목록으로 바꾼다.

    컴포넌트의 CPE에 해당하는 영향 범위가 하나도 없는 CVE는 버린다.
    """
    result = []
    for item in data.get("vulnerabilities", []):
        vulnerability = parse_nvd_cve(item["cve"], cpe_prefixes)
        if vulnerability.ranges or vulnerability.exact_versions:
            result.append(vulnerability)
    return result


def parse_nvd_cve(cve: dict, cpe_prefixes: tuple[str, ...] = ()) -> Vulnerability:
    """NVD `cve` 객체 하나를 바꾼다. cpe_prefixes가 비면 범위 없이 메타데이터만 담는다."""
    description = _english_description(cve)
    score, severity = _nvd_cvss(cve.get("metrics", {}))
    ranges, exact = (
        _nvd_ranges(cve.get("configurations", []), cpe_prefixes)
        if cpe_prefixes
        else ((), frozenset())
    )
    tags = {tag for entry in cve.get("cveTags", []) for tag in entry.get("tags", [])}
    return Vulnerability(
        vuln_id=cve["id"],
        description=description,
        cvss_score=score,
        severity=severity,
        ranges=ranges,
        exact_versions=exact,
        sources=frozenset({SOURCE_NVD}),
        is_rejected=cve.get("vulnStatus") == NVD_STATUS_REJECTED,
        is_disputed=DISPUTED_TAG in tags or description.startswith(DISPUTED_PREFIX),
    )


def _english_description(cve: dict) -> str:
    """영문 설명을 꺼낸다."""
    for entry in cve.get("descriptions", []):
        if entry.get("lang") == "en":
            return entry.get("value", "").strip()
    return ""


def _nvd_cvss(metrics: dict) -> tuple[float | None, str | None]:
    """우선순위가 가장 높은 CVSS의 (점수, 심각도). 같은 버전 안에서는 NVD의 Primary를 먼저 쓴다."""
    for key in CVSS_METRIC_ORDER:
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        # v2는 심각도가 cvssData 밖에 있다.
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return data.get("baseScore"), severity
    return None, None


def _nvd_ranges(
    configurations: list, cpe_prefixes: tuple[str, ...]
) -> tuple[tuple[AffectedRange, ...], frozenset[str]]:
    """configurations에서 컴포넌트 CPE의 `vulnerable: true` 항목만 범위·정확 버전으로 모은다."""
    ranges: list[AffectedRange] = []
    exact: set[str] = set()
    prefixes = {prefix.lower() for prefix in cpe_prefixes}
    for configuration in configurations:
        for node in configuration.get("nodes", []):
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                parts = match["criteria"].split(":")
                if ":".join(parts[:5]).lower() not in prefixes:
                    continue  # 운영체제 등 다른 제품의 CPE
                _collect_match(match, parts, ranges, exact)
    return tuple(dict.fromkeys(ranges)), frozenset(exact)


def _collect_match(
    match: dict, parts: list[str], ranges: list[AffectedRange], exact: set[str]
) -> None:
    """cpeMatch 하나를 범위 또는 정확 버전으로 바꿔 담는다."""
    start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
    end = match.get("versionEndIncluding") or match.get("versionEndExcluding")
    version = _unescape(parts[5]) if len(parts) > 5 else "*"
    if start or end:
        ranges.append(
            AffectedRange(
                start=start,
                start_inclusive="versionStartExcluding" not in match,
                end=end,
                end_inclusive="versionEndIncluding" in match,
            )
        )
    elif version == "*":
        ranges.append(AffectedRange())  # 버전 제한 없이 모든 버전이 취약
    elif version != "-":
        exact.add(_cpe_version(parts))


def _unescape(value: str) -> str:
    """CPE의 역슬래시 이스케이프(`1\\.0`)를 푼다."""
    return value.replace("\\", "")


def _cpe_version(parts: list[str]) -> str:
    """CPE 버전 필드와 update 필드를 합친다(`1.0.1` + `beta1` → `1.0.1-beta1`)."""
    version = _unescape(parts[5])
    update = _unescape(parts[6]) if len(parts) > 6 else "*"
    return version if update in CPE_EMPTY_VALUES else f"{version}-{update}"


def parse_cpe_versions(data: dict) -> list[str]:
    """NVD CPE 응답에서 버전 문자열 목록을 꺼낸다."""
    versions = []
    for product in data.get("products", []):
        parts = product["cpe"]["cpeName"].split(":")
        if len(parts) > 5 and _unescape(parts[5]) not in CPE_EMPTY_VALUES:
            versions.append(_cpe_version(parts))
    return versions


# ---------- OSV ----------


def parse_osv_page(data: dict, package_name: str) -> list[Vulnerability]:
    """OSV 응답 한 페이지를 Vulnerability 목록으로 바꾼다."""
    return [parse_osv_vuln(vuln, package_name) for vuln in data.get("vulns", [])]


def parse_osv_vuln(vuln: dict, package_name: str) -> Vulnerability:
    """OSV 취약점 하나를 바꾼다. 해당 패키지의 affected 항목만 본다."""
    ranges: list[AffectedRange] = []
    exact: set[str] = set()
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name") != package_name:
            continue
        for osv_range in affected.get("ranges", []):
            if osv_range.get("type") in OSV_RANGE_TYPES:
                ranges.extend(_osv_events_to_ranges(osv_range.get("events", [])))
        exact.update(affected.get("versions", []))
    severity = vuln.get("database_specific", {}).get("severity")
    return Vulnerability(
        vuln_id=vuln["id"],
        aliases=tuple(vuln.get("aliases", [])),
        description=(vuln.get("details") or vuln.get("summary") or "").strip(),
        severity=SEVERITY_ALIASES.get(severity, severity),
        ranges=tuple(dict.fromkeys(ranges)),
        exact_versions=frozenset(exact),
        sources=frozenset({SOURCE_OSV}),
        is_rejected="withdrawn" in vuln,
    )


def _osv_events_to_ranges(events: list[dict]) -> list[AffectedRange]:
    """OSV events(introduced/fixed/last_affected)를 범위 목록으로 바꾼다.

    introduced로 범위를 열고 fixed(미포함)나 last_affected(포함)로 닫는다.
    끝까지 닫히지 않으면 위쪽으로 열린 범위다.
    """
    ranges: list[AffectedRange] = []
    start: str | None = None
    is_open = False
    for event in events:
        if "introduced" in event:
            start = None if event["introduced"] == OSV_ZERO_VERSION else event["introduced"]
            is_open = True
        elif is_open and ("fixed" in event or "last_affected" in event):
            inclusive = "last_affected" in event
            ranges.append(
                AffectedRange(
                    start=start,
                    end=event.get("last_affected") or event["fixed"],
                    end_inclusive=inclusive,
                )
            )
            is_open = False
    if is_open:
        ranges.append(AffectedRange(start=start))
    return ranges


# ---------- Maven ----------


def parse_maven_versions(xml_text: str) -> list[str]:
    """maven-metadata.xml에서 버전 목록을 꺼낸다."""
    root = ElementTree.fromstring(xml_text)
    return [node.text.strip() for node in root.iter("version") if node.text and node.text.strip()]
