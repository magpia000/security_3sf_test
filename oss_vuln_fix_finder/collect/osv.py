"""OSV.dev 조회(PRD 4.2-7).

Maven 패키지의 **전체** 취약점을 받기 위해 버전 없이 패키지명으로만 조회한다.
GitHub Advisory(GHSA) 데이터가 OSV에 포함되어 있으므로 GitHub는 따로 조회하지 않는다.
"""

import json

from oss_vuln_fix_finder.bundle import BundleWriter, component_dir, page_name
from oss_vuln_fix_finder.collect.http import HttpClient
from oss_vuln_fix_finder.constants import OSV_QUERY_URL
from oss_vuln_fix_finder.models import ComponentSpec

OSV_ECOSYSTEM_MAVEN = "Maven"


def collect_osv(client: HttpClient, writer: BundleWriter, spec: ComponentSpec) -> set[str]:
    """OSV 응답 페이지를 묶음에 담고, 별칭에 나온 CVE ID 집합을 돌려준다.

    돌려준 CVE ID는 NVD 단건 조회로 CVSS·설명을 보완하는 데 쓴다.
    """
    payload: dict = {"package": {"name": spec.maven, "ecosystem": OSV_ECOSYSTEM_MAVEN}}
    cve_ids: set[str] = set()
    page = 1
    while True:
        text = client.post_json(OSV_QUERY_URL, payload)
        writer.add_text(f"{component_dir(spec.name)}/osv/{page_name(page)}", text)
        data = json.loads(text)
        for vuln in data.get("vulns", []):
            cve_ids.update(alias for alias in vuln.get("aliases", []) if alias.startswith("CVE-"))
        token = data.get("next_page_token")
        if not token:
            return cve_ids
        payload = {**payload, "page_token": token}
        page += 1
