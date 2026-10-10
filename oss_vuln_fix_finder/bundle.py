"""수집 묶음(zip) 쓰기·읽기(PRD 4.2-10, 4.3-13·14).

collect가 받은 원본 응답을 가공하지 않고 묶음 하나에 담고, scan은 이 묶음만 읽는다.
scan도 이 모듈을 쓰므로 네트워크 모듈을 import하지 않는다(rules.md 4.1).

묶음 안의 경로 규칙:
    manifest.json
    components/<컴포넌트>/osv/page_001.json
    components/<컴포넌트>/nvd_cve/<vendor_product>/page_001.json
    components/<컴포넌트>/nvd_cpe/<vendor_product>/page_001.json
    components/<컴포넌트>/maven/maven-metadata.xml
    nvd_cve_by_id/<CVE-ID>.json
"""

import hashlib
import json
import re
import zipfile
from datetime import datetime
from pathlib import Path

from oss_vuln_fix_finder import __version__
from oss_vuln_fix_finder.constants import BUNDLE_SCHEMA_VERSION, KST

MANIFEST_NAME = "manifest.json"
STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_UNMAPPED = "unmapped"


class BundleError(ValueError):
    """묶음 파일이 없거나 형식이 맞지 않을 때 발생한다."""


def slugify(text: str) -> str:
    """경로에 쓸 수 있는 소문자 영숫자·밑줄 이름을 만든다."""
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "unnamed"


def component_dir(name: str) -> str:
    """컴포넌트 데이터가 들어갈 묶음 안 폴더."""
    return f"components/{slugify(name)}"


def cpe_slug(cpe: str) -> str:
    """`cpe:2.3:a:zlib:zlib` → `zlib_zlib`."""
    _, _, _, vendor, product = cpe.split(":")[:5]
    return slugify(f"{vendor}_{product}")


def page_name(index: int) -> str:
    """페이지 파일 이름(1부터 시작)."""
    return f"page_{index:03d}.json"


def cve_by_id_path(cve_id: str) -> str:
    """CVE 단건 조회 결과 경로."""
    return f"nvd_cve_by_id/{cve_id}.json"


def file_sha256(path: Path) -> str:
    """파일의 SHA-256 해시(16진수)."""
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


class BundleWriter:
    """수집 결과를 메모리에 모았다가 zip 파일 하나로 쓴다."""

    def __init__(self, created_at: datetime, input_path: Path) -> None:
        self._files: dict[str, str] = {}
        self._manifest: dict = {
            "schema_version": BUNDLE_SCHEMA_VERSION,
            "tool_version": __version__,
            "created_at": created_at.astimezone(KST).isoformat(timespec="seconds"),
            "input_file": input_path.name,
            "input_sha256": file_sha256(input_path),
            "components": {},
            "request_counts": {},
        }

    def add_text(self, path: str, text: str) -> None:
        """원본 응답 본문을 그대로 담는다."""
        self._files[path] = text

    def has(self, path: str) -> bool:
        """이미 담긴 경로인지 확인한다(같은 CVE 재조회 방지에 쓴다)."""
        return path in self._files

    def set_component_status(
        self, name: str, status: str, error: str | None = None, data_name: str | None = None
    ) -> None:
        """컴포넌트별 수집 결과(ok/failed/unmapped)를 입력 컴포넌트명으로 기록한다.

        data_name은 데이터 폴더 이름의 기준이 되는 매핑 파일의 컴포넌트명이다.
        """
        entry: dict = {"status": status, "dir": component_dir(data_name or name)}
        if error:
            entry["error"] = error
        self._manifest["components"][name] = entry

    def set_request_counts(self, counts: dict[str, int]) -> None:
        """호스트별 요청 수를 기록한다."""
        self._manifest["request_counts"] = dict(sorted(counts.items()))

    @property
    def manifest(self) -> dict:
        """작성 중인 manifest(읽기용)."""
        return self._manifest

    def write(self, directory: Path) -> Path:
        """`bundle_YYYYMMDD_HHMM.zip`으로 저장하고 경로를 돌려준다. 이름이 겹치면 번호를 붙인다."""
        directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.fromisoformat(self._manifest["created_at"]).strftime("%Y%m%d_%H%M")
        path = directory / f"bundle_{stamp}.zip"
        counter = 2
        while path.exists():
            path = directory / f"bundle_{stamp}_{counter}.zip"
            counter += 1
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                MANIFEST_NAME, json.dumps(self._manifest, ensure_ascii=False, indent=2)
            )
            for name in sorted(self._files):
                archive.writestr(name, self._files[name])
        return path


class BundleReader:
    """묶음 zip을 읽는다. 파일 내용은 처음 읽을 때 메모리에 올린다."""

    def __init__(self, path: Path) -> None:
        if not path.is_file():
            raise BundleError(f"묶음 파일이 없다: {path}")
        try:
            with zipfile.ZipFile(path) as archive:
                self._files = {
                    name: archive.read(name).decode("utf-8") for name in archive.namelist()
                }
        except zipfile.BadZipFile as error:
            raise BundleError(f"묶음 파일이 zip 형식이 아니다: {path}") from error
        if MANIFEST_NAME not in self._files:
            raise BundleError(f"묶음에 {MANIFEST_NAME}이 없다: {path}")
        self.manifest: dict = json.loads(self._files[MANIFEST_NAME])

    @property
    def created_at(self) -> datetime:
        """수집일시(KST)."""
        return datetime.fromisoformat(self.manifest["created_at"])

    def component_status(self, name: str) -> str | None:
        """컴포넌트 수집 상태. 묶음에 없으면 None."""
        entry = self.manifest.get("components", {}).get(name)
        return entry["status"] if entry else None

    def exists(self, path: str) -> bool:
        """묶음 안에 경로가 있는지 확인한다."""
        return path in self._files

    def read_text(self, path: str) -> str:
        """파일 내용을 문자열로 읽는다."""
        return self._files[path]

    def read_json(self, path: str) -> dict:
        """JSON 파일을 읽는다."""
        return json.loads(self._files[path])

    def read_pages(self, prefix: str) -> list[dict]:
        """`prefix/page_001.json`, `page_002.json`… 을 순서대로 읽는다."""
        names = sorted(
            name for name in self._files if name.startswith(prefix + "/") and name.endswith(".json")
        )
        return [self.read_json(name) for name in names]

    def list_dirs(self, prefix: str) -> list[str]:
        """prefix 바로 아래 폴더 이름 목록."""
        depth = prefix.count("/") + 1
        dirs = {
            name.split("/")[depth]
            for name in self._files
            if name.startswith(prefix + "/") and name.count("/") > depth
        }
        return sorted(dirs)
