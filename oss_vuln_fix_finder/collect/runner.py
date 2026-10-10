"""collect 전체 흐름(PRD 4.2).

입력 읽기 → 매핑 → 컴포넌트별 수집(실패해도 다음 컴포넌트 계속) → CVE 보완 조회 → 묶음 저장.
진행 상황은 콜백으로 넘기고 직접 출력하지 않는다(rules.md 4.1).
"""

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from oss_vuln_fix_finder.bundle import STATUS_FAILED, STATUS_OK, STATUS_UNMAPPED, BundleWriter
from oss_vuln_fix_finder.collect.http import CollectError, HttpClient
from oss_vuln_fix_finder.collect.maven import collect_maven_metadata
from oss_vuln_fix_finder.collect.nvd import (
    collect_cves_by_id,
    collect_nvd_cpe_versions,
    collect_nvd_cves,
)
from oss_vuln_fix_finder.collect.osv import collect_osv
from oss_vuln_fix_finder.constants import KST
from oss_vuln_fix_finder.io_excel import read_components
from oss_vuln_fix_finder.mapping import ComponentMapping
from oss_vuln_fix_finder.models import ComponentSpec, ComponentType

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Progress:
    """진행 상황 한 건.

    Attributes:
        index: 현재 컴포넌트 순번(1부터).
        total: 전체 컴포넌트 수.
        name: 컴포넌트명.
        eta_seconds: 남은 예상 시간(첫 컴포넌트 전에는 None).
    """

    index: int
    total: int
    name: str
    eta_seconds: float | None


@dataclass(frozen=True)
class CollectResult:
    """collect 결과: 묶음 경로와 manifest."""

    bundle_path: Path
    manifest: dict


def run_collect(
    input_path: Path,
    bundle_dir: Path,
    mapping: ComponentMapping,
    client: HttpClient | None = None,
    progress: Callable[[Progress], None] | None = None,
    now: datetime | None = None,
) -> CollectResult:
    """입력 목록의 컴포넌트 데이터를 수집해 묶음 파일을 만든다."""
    client = client or HttpClient()
    writer = BundleWriter(now or datetime.now(KST), input_path)
    names = _unique_component_names(input_path)
    nvd_ids: set[str] = set()
    osv_cve_ids: set[str] = set()
    started = time.monotonic()

    for index, name in enumerate(names, start=1):
        if progress:
            progress(Progress(index, len(names), name, _eta(started, index - 1, len(names))))
        spec = mapping.get(name)
        if spec is None:
            writer.set_component_status(name, STATUS_UNMAPPED)
            continue
        try:
            found_nvd, found_osv = _collect_component(client, writer, spec)
        except (CollectError, ValueError, KeyError) as error:
            # 한 컴포넌트가 실패해도 나머지는 계속 수집한다(PRD 4.2-11).
            logger.error("%s 수집 실패: %s", name, error)
            writer.set_component_status(name, STATUS_FAILED, str(error), data_name=spec.name)
            continue
        nvd_ids |= found_nvd
        osv_cve_ids |= found_osv
        writer.set_component_status(name, STATUS_OK, data_name=spec.name)

    failed_cves = collect_cves_by_id(client, writer, osv_cve_ids - nvd_ids)
    writer.manifest["enrichment_failures"] = failed_cves
    writer.set_request_counts(dict(client.request_counts))
    return CollectResult(writer.write(bundle_dir), writer.manifest)


def _collect_component(
    client: HttpClient, writer: BundleWriter, spec: ComponentSpec
) -> tuple[set[str], set[str]]:
    """유형에 맞는 소스에서 수집하고 (NVD에서 받은 CVE, OSV 별칭 CVE)를 돌려준다."""
    nvd_ids: set[str] = set()
    osv_cve_ids: set[str] = set()
    if spec.component_type is ComponentType.MAVEN:
        osv_cve_ids = collect_osv(client, writer, spec)
        collect_maven_metadata(client, writer, spec)
        if spec.cpes:  # Maven 컴포넌트도 CPE가 있으면 NVD로 교차 확인한다
            nvd_ids = collect_nvd_cves(client, writer, spec)
    else:
        nvd_ids = collect_nvd_cves(client, writer, spec)
        collect_nvd_cpe_versions(client, writer, spec)
    return nvd_ids, osv_cve_ids


def _unique_component_names(input_path: Path) -> list[str]:
    """유효한 입력 행의 컴포넌트명을 처음 나온 순서대로 중복 없이 모은다."""
    names: dict[str, None] = {}
    for row in read_components(input_path):
        if row.is_valid:
            names.setdefault(row.name, None)
    return list(names)


def _eta(started: float, done: int, total: int) -> float | None:
    """지금까지의 컴포넌트당 평균 시간으로 남은 시간을 추정한다."""
    if done == 0:
        return None
    return (time.monotonic() - started) / done * (total - done)
