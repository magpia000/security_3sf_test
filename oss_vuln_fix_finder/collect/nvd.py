"""NVD CVE·CPE 조회(PRD 4.2-7·8·9).

- CVE: 버전 없는 CPE 접두어를 `virtualMatchString`에 넣어 제품의 전체 CVE를 받는다.
- CPE: `cpeMatchString`으로 제품의 등록 버전 목록을 받는다(네이티브 버전 목록의 출처).
- CVE 단건: OSV 별칭 CVE의 CVSS·설명을 보완한다. 이미 받은 CVE는 다시 조회하지 않는다.
"""

import json
import logging
from collections.abc import Iterable

from oss_vuln_fix_finder.bundle import (
    BundleWriter,
    component_dir,
    cpe_slug,
    cve_by_id_path,
    page_name,
)
from oss_vuln_fix_finder.collect.http import CollectError, HttpClient
from oss_vuln_fix_finder.constants import (
    NVD_CPE_PAGE_SIZE,
    NVD_CPE_URL,
    NVD_CVE_PAGE_SIZE,
    NVD_CVE_URL,
)
from oss_vuln_fix_finder.models import ComponentSpec

logger = logging.getLogger(__name__)


def collect_nvd_cves(client: HttpClient, writer: BundleWriter, spec: ComponentSpec) -> set[str]:
    """컴포넌트의 모든 CPE 접두어에 대해 CVE 페이지를 담고, 받은 CVE ID 집합을 돌려준다."""
    received: set[str] = set()
    for cpe in spec.cpes:
        folder = f"{component_dir(spec.name)}/nvd_cve/{cpe_slug(cpe)}"
        for data in _fetch_pages(
            client, writer, NVD_CVE_URL, {"virtualMatchString": cpe}, NVD_CVE_PAGE_SIZE, folder
        ):
            received.update(item["cve"]["id"] for item in data.get("vulnerabilities", []))
    return received


def collect_nvd_cpe_versions(client: HttpClient, writer: BundleWriter, spec: ComponentSpec) -> None:
    """컴포넌트의 모든 CPE 접두어에 대해 CPE 사전 페이지를 담는다."""
    for cpe in spec.cpes:
        folder = f"{component_dir(spec.name)}/nvd_cpe/{cpe_slug(cpe)}"
        for _ in _fetch_pages(
            client, writer, NVD_CPE_URL, {"cpeMatchString": cpe}, NVD_CPE_PAGE_SIZE, folder
        ):
            pass


def collect_cves_by_id(
    client: HttpClient, writer: BundleWriter, cve_ids: Iterable[str]
) -> list[str]:
    """CVE를 한 건씩 조회해 담는다. 실패한 CVE ID 목록을 돌려준다(수집 전체는 멈추지 않는다)."""
    failed: list[str] = []
    for cve_id in sorted(set(cve_ids)):
        path = cve_by_id_path(cve_id)
        if writer.has(path):
            continue
        try:
            writer.add_text(path, client.get_text(NVD_CVE_URL, {"cveId": cve_id}))
        except CollectError as error:
            logger.warning("CVE 단건 조회 실패 %s: %s", cve_id, error)
            failed.append(cve_id)
    return failed


def _fetch_pages(
    client: HttpClient, writer: BundleWriter, url: str, params: dict, page_size: int, folder: str
) -> Iterable[dict]:
    """`startIndex`를 늘려 가며 모든 페이지를 받아 담고, 페이지 JSON을 차례로 내준다(PRD 4.2-9)."""
    start, page = 0, 1
    while True:
        text = client.get_text(url, {**params, "resultsPerPage": page_size, "startIndex": start})
        writer.add_text(f"{folder}/{page_name(page)}", text)
        data = json.loads(text)
        yield data
        received = int(data.get("resultsPerPage", 0))
        start += received
        if received == 0 or start >= int(data.get("totalResults", 0)):
            return
        page += 1
