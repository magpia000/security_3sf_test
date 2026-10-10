"""수집기 단위 테스트(태스크 3.3~3.6). 실제 네트워크 대신 fixture 응답을 쓴다."""

import json
from datetime import datetime

import pytest

from oss_vuln_fix_finder.bundle import BundleReader, BundleWriter, component_dir
from oss_vuln_fix_finder.collect.http import HttpClient
from oss_vuln_fix_finder.collect.maven import maven_metadata_url
from oss_vuln_fix_finder.collect.nvd import collect_cves_by_id, collect_nvd_cves
from oss_vuln_fix_finder.collect.osv import collect_osv
from oss_vuln_fix_finder.collect.runner import run_collect
from oss_vuln_fix_finder.constants import KST
from oss_vuln_fix_finder.mapping import load_mapping
from oss_vuln_fix_finder.models import ComponentSpec, ComponentType
from tests.collect.fakes import FakeClock, FakeResponse, FakeSession
from tests.conftest import FIXTURES, PROJECT_ROOT

NOW = datetime(2026, 10, 10, 15, 0, tzinfo=KST)


def fixture_text(name: str) -> str:
    """fixture 파일 내용."""
    return (FIXTURES / name).read_text(encoding="utf-8")


def fixture_router(method: str, url: str, kwargs: dict) -> FakeResponse:
    """요청 주소·인자에 맞는 fixture 응답을 고른다."""
    params = kwargs.get("params") or {}
    if "api.osv.dev" in url:
        name = "osv_gson.json" if kwargs["json"]["package"]["name"].endswith(":gson") else None
        return FakeResponse(200, fixture_text(name) if name else '{"vulns": []}')
    if "repo1.maven.org" in url:
        return FakeResponse(200, fixture_text("maven-metadata-gson.xml"))
    if "cveId" in params:
        return FakeResponse(200, fixture_text(f"nvd_cve_by_id_{params['cveId']}.json"))
    if url.endswith("/cves/2.0"):
        target = params["virtualMatchString"]
        name = {
            "cpe:2.3:a:openssl:openssl": "nvd_cve_openssl.json",
            "cpe:2.3:a:zlib:zlib": "nvd_cve_zlib.json",
        }
        return FakeResponse(200, fixture_text(name.get(target, "nvd_cve_empty.json")))
    if url.endswith("/cpes/2.0"):
        target = params["cpeMatchString"]
        name = {
            "cpe:2.3:a:openssl:openssl": "nvd_cpe_openssl.json",
            "cpe:2.3:a:zlib:zlib": "nvd_cpe_zlib.json",
        }
        return FakeResponse(200, fixture_text(name.get(target, "nvd_cpe_empty.json")))
    return FakeResponse(404)


def make_client(handler=fixture_router) -> tuple[HttpClient, FakeSession]:
    """가짜 세션·시계를 쓰는 클라이언트."""
    clock = FakeClock()
    session = FakeSession(handler=handler)
    return HttpClient(session=session, clock=clock, sleep=clock.sleep), session


@pytest.fixture
def writer(tmp_path) -> BundleWriter:
    source = tmp_path / "in.xlsx"
    source.write_bytes(b"x")
    return BundleWriter(NOW, source)


GSON = ComponentSpec("googlegson", ComponentType.MAVEN, "maven", maven="com.google.code.gson:gson")
OPENSSL = ComponentSpec(
    "OpenSSL", ComponentType.NATIVE, "openssl", cpes=("cpe:2.3:a:openssl:openssl",)
)


def test_osv_queries_without_version(writer) -> None:
    """OSV는 버전 없이 패키지명으로 조회하고 별칭 CVE를 돌려준다."""
    client, session = make_client()
    assert collect_osv(client, writer, GSON) == {"CVE-2022-25647"}
    payload = session.calls[0][2]["json"]
    assert payload == {"package": {"name": "com.google.code.gson:gson", "ecosystem": "Maven"}}
    assert writer.has(f"{component_dir('googlegson')}/osv/page_001.json")


def test_osv_follows_page_token(writer) -> None:
    """next_page_token이 있으면 다음 페이지를 요청한다."""
    pages = [{"vulns": [], "next_page_token": "t1"}, {"vulns": [{"id": "X", "aliases": ["CVE-1"]}]}]
    client, session = make_client(lambda *_: FakeResponse(200, json.dumps(pages.pop(0))))
    assert collect_osv(client, writer, GSON) == {"CVE-1"}
    assert session.calls[1][2]["json"]["page_token"] == "t1"


def test_nvd_paging(writer) -> None:
    """totalResults가 페이지 크기보다 크면 startIndex를 늘려 모두 받는다."""

    def handler(method, url, kwargs):
        start = kwargs["params"]["startIndex"]
        item = {"cve": {"id": f"CVE-0000-{start}"}}
        return FakeResponse(
            200,
            json.dumps(
                {
                    "resultsPerPage": 1,
                    "startIndex": start,
                    "totalResults": 3,
                    "vulnerabilities": [item],
                }
            ),
        )

    client, session = make_client(handler)
    assert collect_nvd_cves(client, writer, OPENSSL) == {"CVE-0000-0", "CVE-0000-1", "CVE-0000-2"}
    assert [c[2]["params"]["startIndex"] for c in session.calls] == [0, 1, 2]
    assert session.calls[0][2]["params"]["virtualMatchString"] == "cpe:2.3:a:openssl:openssl"


def test_cve_by_id_skips_already_collected(writer) -> None:
    """이미 담긴 CVE는 다시 조회하지 않는다."""
    client, session = make_client()
    collect_cves_by_id(client, writer, ["CVE-2022-25647"])
    collect_cves_by_id(client, writer, ["CVE-2022-25647"])
    assert len(session.calls) == 1


def test_maven_metadata_url() -> None:
    """Maven 좌표로 메타데이터 주소를 만든다."""
    assert maven_metadata_url("com.google.code.gson:gson") == (
        "https://repo1.maven.org/maven2/com/google/code/gson/gson/maven-metadata.xml"
    )


def test_run_collect_end_to_end(tmp_path, make_input_xlsx) -> None:
    """입력 → 수집 → 묶음 저장. 실패·미매핑 컴포넌트가 있어도 나머지는 수집한다."""
    path = make_input_xlsx(
        [
            (1, "OpenSSL", "0.9.8h"),
            (2, "zlib", "1.2.5"),
            (3, "zlib", "1.1.3"),
            (4, "googlegson", "1.7"),
            (5, "unknown-lib", "1.0"),
            (6, "SQLite", "3.7.9"),
        ]
    )

    def handler(method, url, kwargs):
        if (kwargs.get("params") or {}).get("virtualMatchString") == "cpe:2.3:a:sqlite:sqlite":
            return FakeResponse(400)
        return fixture_router(method, url, kwargs)

    client, session = make_client(handler)
    events = []
    result = run_collect(
        path,
        tmp_path / "bundles",
        load_mapping(PROJECT_ROOT / "config" / "component_map.yaml"),
        client=client,
        progress=events.append,
        now=NOW,
    )

    reader = BundleReader(result.bundle_path)
    statuses = {name: entry["status"] for name, entry in reader.manifest["components"].items()}
    assert statuses == {
        "OpenSSL": "ok",
        "zlib": "ok",
        "googlegson": "ok",
        "unknown-lib": "unmapped",
        "SQLite": "failed",
    }
    assert [e.name for e in events] == ["OpenSSL", "zlib", "googlegson", "unknown-lib", "SQLite"]
    assert reader.exists("nvd_cve_by_id/CVE-2022-25647.json")
    assert reader.list_dirs(f"{component_dir('zlib')}/nvd_cve") == ["gnu_zlib", "zlib_zlib"]
    assert reader.manifest["request_counts"]["services.nvd.nist.gov"] >= 5
