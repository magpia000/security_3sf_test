"""Maven Central 버전 목록 조회(PRD 4.2-7)."""

from oss_vuln_fix_finder.bundle import BundleWriter, component_dir
from oss_vuln_fix_finder.collect.http import HttpClient
from oss_vuln_fix_finder.constants import MAVEN_METADATA_URL
from oss_vuln_fix_finder.models import ComponentSpec

MAVEN_METADATA_FILE = "maven/maven-metadata.xml"


def maven_metadata_url(coordinate: str) -> str:
    """`group:artifact` 좌표로 maven-metadata.xml 주소를 만든다."""
    group, artifact = coordinate.split(":")[:2]
    return MAVEN_METADATA_URL.format(group_path=group.replace(".", "/"), artifact=artifact)


def collect_maven_metadata(client: HttpClient, writer: BundleWriter, spec: ComponentSpec) -> None:
    """maven-metadata.xml을 그대로 묶음에 담는다."""
    text = client.get_text(maven_metadata_url(spec.maven))
    writer.add_text(f"{component_dir(spec.name)}/{MAVEN_METADATA_FILE}", text)
