"""scan 전체 흐름(PRD 4.3, 4.5).

묶음 로드 → 입력 행별 분석 → 보고서 엑셀·JSONL 로그 저장 → 요약.
네트워크 모듈(collect)을 import하지 않는다(PRD 4.3-13, rules.md 5장).
"""

import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from oss_vuln_fix_finder.analyze.matcher import matching_ranges
from oss_vuln_fix_finder.analyze.merger import canonical_id, merge_vulnerabilities
from oss_vuln_fix_finder.analyze.parsers import (
    parse_cpe_versions,
    parse_maven_versions,
    parse_nvd_cve,
    parse_nvd_page,
    parse_osv_page,
)
from oss_vuln_fix_finder.analyze.remediation import (
    RemediationInput,
    choose_remediation,
    current_vulnerabilities,
)
from oss_vuln_fix_finder.bundle import (
    STATUS_OK,
    BundleReader,
    component_dir,
    cve_by_id_path,
    file_sha256,
)
from oss_vuln_fix_finder.constants import BUNDLE_STALE_DAYS, KST, NOTE_SEPARATOR
from oss_vuln_fix_finder.io_excel import read_components, write_report
from oss_vuln_fix_finder.mapping import ComponentMapping
from oss_vuln_fix_finder.models import (
    ComponentResult,
    ComponentSpec,
    ComponentType,
    InputRow,
    RowStatus,
    Vulnerability,
)
from oss_vuln_fix_finder.versions.base import VersionRule, get_rule

logger = logging.getLogger(__name__)
NATIVE_VERSION_SOURCE_NOTE = "버전 목록 출처: NVD CPE"  # PRD 7장 NVD CPE 한계 표시
STATUS_ROWS = (RowStatus.INVALID_INPUT, RowStatus.UNMAPPED, RowStatus.UNCOLLECTED)


@dataclass
class ScanSummary:
    """콘솔 요약용 집계(PRD 4.5-27)."""

    input_rows: int = 0
    vulnerable_rows: int = 0
    cve_rows: int = 0
    severity_counts: Counter = field(default_factory=Counter)
    status_counts: Counter = field(default_factory=Counter)
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ScanResult:
    """scan 결과 파일 경로와 요약."""

    report_path: Path
    log_path: Path
    summary: ScanSummary


@dataclass(frozen=True)
class ComponentData:
    """묶음에서 읽은 컴포넌트 단위 데이터(같은 컴포넌트의 여러 행이 공유한다)."""

    rule: VersionRule
    all_cves: list[Vulnerability]
    versions: list[str]


def run_scan(
    input_path: Path,
    bundle_path: Path,
    output_dir: Path,
    mapping: ComponentMapping,
    include_disputed: bool = False,
    log_dir: Path = Path("logs"),
    now: datetime | None = None,
) -> ScanResult:
    """묶음만으로 입력 목록을 분석해 보고서를 만든다."""
    now = now or datetime.now(KST)
    reader = BundleReader(bundle_path)
    warnings = check_bundle(reader, input_path, now)
    for warning in warnings:
        logger.warning(warning)

    cache: dict[str, ComponentData] = {}
    rows = read_components(input_path)
    results = [analyze_row(row, mapping, reader, include_disputed, cache) for row in rows]

    report_path = write_report(
        build_report_rows(results, reader.manifest["created_at"]), output_dir, now
    )
    summary = summarize(results, warnings)
    log_path = write_log(log_dir, now, results, summary)
    return ScanResult(report_path, log_path, summary)


def check_bundle(reader: BundleReader, input_path: Path, now: datetime) -> list[str]:
    """입력 파일 해시(PRD 4.3-14)와 묶음 수집일(OQ-5 가정: 30일)을 확인해 경고 목록을 만든다."""
    warnings = []
    if reader.manifest.get("input_sha256") != file_sha256(input_path):
        warnings.append(
            f"입력 파일이 수집 때와 다르다(수집 입력: {reader.manifest.get('input_file')}). "
            "수집하지 않은 컴포넌트는 UNCOLLECTED로 표시된다."
        )
    age = now - reader.created_at
    if age > timedelta(days=BUNDLE_STALE_DAYS):
        warnings.append(
            f"묶음이 {age.days}일 전에 수집되었다. 최신 취약점을 반영하려면 다시 수집하라."
        )
    return warnings


def analyze_row(
    row: InputRow,
    mapping: ComponentMapping,
    reader: BundleReader,
    include_disputed: bool,
    cache: dict[str, ComponentData],
) -> ComponentResult:
    """입력 행 하나를 분석한다. 분석할 수 없는 행은 상태(status)와 사유를 담아 돌려준다."""
    if not row.is_valid:
        return ComponentResult(
            row, RowStatus.INVALID_INPUT, extra_notes=("컴포넌트명 또는 버전이 비어 있다",)
        )
    spec = mapping.get(row.name)
    if spec is None:
        return ComponentResult(
            row, RowStatus.UNMAPPED, extra_notes=("config/component_map.yaml에 없는 컴포넌트",)
        )
    collected = reader.component_status(row.name)
    if collected != STATUS_OK:
        error = (
            reader.manifest.get("components", {})
            .get(row.name, {})
            .get("error", "묶음에 수집 데이터가 없다")
        )
        return ComponentResult(row, RowStatus.UNCOLLECTED, extra_notes=(f"수집 실패: {error}",))

    if spec.name not in cache:
        cache[spec.name] = load_component_data(spec, reader, include_disputed)
    data = cache[spec.name]
    current = data.rule.normalize(row.version, spec.version_prefix)
    if not data.rule.is_valid(current):
        return ComponentResult(
            row, RowStatus.INVALID_INPUT, extra_notes=(f"버전을 해석할 수 없다: {row.version}",)
        )
    return _assess(row, spec, data, current)


def _assess(
    row: InputRow, spec: ComponentSpec, data: ComponentData, current: str
) -> ComponentResult:
    """집합 C를 구하고 조치 버전을 판정한다."""
    current_cves = current_vulnerabilities(data.all_cves, current, data.rule)
    remediation = choose_remediation(
        RemediationInput(
            current=current,
            versions=data.versions,
            all_cves=data.all_cves,
            current_cves=current_cves,
            rule=data.rule,
            branch_depth=spec.branch_depth,
            lts_branches=spec.lts_branches,
        )
    )
    matched = {
        v.vuln_id: NOTE_SEPARATOR.join(matching_ranges(v, current, data.rule)) for v in current_cves
    }
    extra = (NATIVE_VERSION_SOURCE_NOTE,) if spec.component_type is ComponentType.NATIVE else ()
    return ComponentResult(
        row=row,
        status=None if current_cves else RowStatus.NO_VULNERABILITY,
        vulnerabilities=current_cves,
        matched_ranges=matched,
        remediation=remediation,
        extra_notes=extra,
    )


def load_component_data(
    spec: ComponentSpec, reader: BundleReader, include_disputed: bool
) -> ComponentData:
    """묶음에서 컴포넌트의 전체 취약점(집합 K)과 버전 목록을 만든다.

    데이터 폴더는 collect와 같이 매핑 파일의 컴포넌트명(spec.name)을 기준으로 찾는다.
    """
    base = component_dir(spec.name)
    found: list[Vulnerability] = []
    for folder in reader.list_dirs(f"{base}/nvd_cve"):
        for page in reader.read_pages(f"{base}/nvd_cve/{folder}"):
            found.extend(parse_nvd_page(page, spec.cpes))
    if spec.maven:
        for page in reader.read_pages(f"{base}/osv"):
            found.extend(parse_osv_page(page, spec.maven))

    enrichment = {}
    for vulnerability in found:
        cve_id = canonical_id(vulnerability)
        if reader.exists(cve_by_id_path(cve_id)):
            items = reader.read_json(cve_by_id_path(cve_id)).get("vulnerabilities", [])
            if items:
                enrichment[cve_id] = parse_nvd_cve(items[0]["cve"])

    if spec.component_type is ComponentType.MAVEN:
        versions = parse_maven_versions(reader.read_text(f"{base}/maven/maven-metadata.xml"))
    else:
        versions = [
            version
            for folder in reader.list_dirs(f"{base}/nvd_cpe")
            for page in reader.read_pages(f"{base}/nvd_cpe/{folder}")
            for version in parse_cpe_versions(page)
        ]
    return ComponentData(
        get_rule(spec.version_rule),
        merge_vulnerabilities(found, enrichment, include_disputed),
        versions,
    )


def build_report_rows(results: list[ComponentResult], collected_at: str) -> list[tuple]:
    """출력 행을 만든다. CVE 1건당 1행, No 오름차순 → CVSS 내림차순(PRD 4.5-25·26)."""
    ordered = sorted(
        enumerate(results), key=lambda item: (_row_no_key(item[1].row.row_no), item[0])
    )
    rows: list[tuple] = []
    for _, result in ordered:
        rows.extend(_rows_for(result, collected_at))
    return rows


def _rows_for(result: ComponentResult, collected_at: str) -> list[tuple]:
    """입력 행 하나에 대한 출력 행들."""
    row = result.row
    head = (row.row_no, row.name, row.version)
    remediation = result.remediation
    notes = NOTE_SEPARATOR.join((*(remediation.notes if remediation else ()), *result.extra_notes))
    if result.status in STATUS_ROWS:
        return [(*head, result.status.value, "", None, "", "", "", "", notes, "", collected_at)]
    fix = (remediation.nearest, remediation.latest, notes)
    if result.status is RowStatus.NO_VULNERABILITY:
        return [(*head, result.status.value, "", None, "", "", *fix, "", collected_at)]
    vulns = sorted(
        result.vulnerabilities,
        key=lambda v: (v.cvss_score is None, -(v.cvss_score or 0), v.vuln_id),
    )
    return [
        (
            *head,
            v.vuln_id,
            v.description,
            v.cvss_score,
            v.severity or "",
            result.matched_ranges.get(v.vuln_id, ""),
            *fix,
            "; ".join(sorted(v.sources)),
            collected_at,
        )
        for v in vulns
    ]


def _row_no_key(row_no: str) -> tuple:
    """No 정렬 키: 숫자는 숫자 순, 숫자가 아니면 뒤로."""
    return (0, int(row_no), "") if row_no.isdigit() else (1, 0, row_no)


def summarize(results: list[ComponentResult], warnings: list[str]) -> ScanSummary:
    """실행 요약을 집계한다."""
    summary = ScanSummary(input_rows=len(results), warnings=list(warnings))
    for result in results:
        if result.status is not None:
            summary.status_counts[result.status.value] += 1
        if result.vulnerabilities:
            summary.vulnerable_rows += 1
            summary.cve_rows += len(result.vulnerabilities)
            summary.severity_counts.update(
                (v.severity or "UNKNOWN") for v in result.vulnerabilities
            )
    return summary


def write_log(
    log_dir: Path, now: datetime, results: list[ComponentResult], summary: ScanSummary
) -> Path:
    """행별 판정 결과와 요약을 JSONL로 남긴다(PRD 4.5-28)."""
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / f"scan_{now.strftime('%Y%m%d_%H%M%S')}.jsonl"
    with path.open("w", encoding="utf-8") as file:
        for result in results:
            remediation = result.remediation
            record = {
                "type": "row",
                "no": result.row.row_no,
                "component": result.row.name,
                "version": result.row.version,
                "status": result.status.value if result.status else "VULNERABLE",
                "cve_count": len(result.vulnerabilities),
                "nearest": remediation.nearest if remediation else None,
                "latest": remediation.latest if remediation else None,
                "notes": [*(remediation.notes if remediation else ()), *result.extra_notes],
            }
            file.write(json.dumps(record, ensure_ascii=False) + "\n")
        file.write(
            json.dumps(
                {
                    "type": "summary",
                    "input_rows": summary.input_rows,
                    "vulnerable_rows": summary.vulnerable_rows,
                    "cve_rows": summary.cve_rows,
                    "severity_counts": dict(summary.severity_counts),
                    "status_counts": dict(summary.status_counts),
                    "warnings": summary.warnings,
                },
                ensure_ascii=False,
            )
            + "\n"
        )
    return path
