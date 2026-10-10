"""bundle 단위 테스트(태스크 3.1)."""

import json
from datetime import datetime

import pytest

from oss_vuln_fix_finder.bundle import (
    BundleError,
    BundleReader,
    BundleWriter,
    component_dir,
    cpe_slug,
    file_sha256,
)
from oss_vuln_fix_finder.constants import KST

CREATED = datetime(2026, 10, 10, 15, 30, tzinfo=KST)


def _writer(tmp_path):
    source = tmp_path / "in.xlsx"
    source.write_bytes(b"input")
    return BundleWriter(CREATED, source), source


def test_paths() -> None:
    """경로 규칙."""
    assert component_dir("GNU Compiler Collection") == "components/gnu_compiler_collection"
    assert cpe_slug("cpe:2.3:a:zlib:zlib") == "zlib_zlib"


def test_round_trip(tmp_path) -> None:
    """쓴 내용을 그대로 다시 읽는다."""
    writer, source = _writer(tmp_path)
    base = component_dir("OpenSSL")
    writer.add_text(f"{base}/nvd_cve/openssl_openssl/page_002.json", json.dumps({"page": 2}))
    writer.add_text(f"{base}/nvd_cve/openssl_openssl/page_001.json", json.dumps({"page": 1}))
    writer.set_component_status("OpenSSL", "ok")
    writer.set_component_status("Foo", "failed", "timeout")
    writer.set_request_counts({"services.nvd.nist.gov": 3})
    path = writer.write(tmp_path / "bundles")
    assert path.name == "bundle_20261010_1530.zip"

    reader = BundleReader(path)
    assert reader.created_at == CREATED
    assert reader.manifest["input_sha256"] == file_sha256(source)
    assert reader.component_status("OpenSSL") == "ok"
    assert reader.component_status("Foo") == "failed"
    assert reader.component_status("Bar") is None
    assert [p["page"] for p in reader.read_pages(f"{base}/nvd_cve/openssl_openssl")] == [1, 2]
    assert reader.list_dirs(f"{base}/nvd_cve") == ["openssl_openssl"]


def test_same_minute_gets_new_name(tmp_path) -> None:
    """같은 분에 두 번 저장해도 덮어쓰지 않는다."""
    writer, _ = _writer(tmp_path)
    first = writer.write(tmp_path)
    second = writer.write(tmp_path)
    assert first != second and second.name == "bundle_20261010_1530_2.zip"


def test_invalid_bundle(tmp_path) -> None:
    """없는 파일, zip이 아닌 파일은 BundleError."""
    with pytest.raises(BundleError):
        BundleReader(tmp_path / "none.zip")
    bad = tmp_path / "bad.zip"
    bad.write_text("x", encoding="utf-8")
    with pytest.raises(BundleError):
        BundleReader(bad)
