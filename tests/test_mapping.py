"""mapping 단위 테스트(태스크 1.3)."""

from pathlib import Path

import pytest

from oss_vuln_fix_finder.mapping import MappingError, load_mapping
from oss_vuln_fix_finder.models import ComponentType

PROJECT_MAPPING = Path(__file__).resolve().parents[1] / "config" / "component_map.yaml"
INPUT_COMPONENTS = [
    "Apache Commons Compress",
    "Apache MINA",
    "GNU Compiler Collection",
    "googlegson",
    "libjpeg",
    "LLVM - Low Level Virtual Machine",
    "OpenSSL",
    "protobuf-java",
    "SQLite",
    "zip4j",
    "zlib",
]


def test_project_mapping_covers_all_input_components() -> None:
    """초기 매핑은 현재 입력의 11개 컴포넌트를 모두 포함해야 한다(PRD 4.1-5)."""
    mapping = load_mapping(PROJECT_MAPPING)
    assert len(mapping) == 11
    for name in INPUT_COMPONENTS:
        assert mapping.get(name) is not None, name


def test_lookup_ignores_case_and_spaces() -> None:
    """이름 조회는 대소문자와 앞뒤 공백을 무시한다."""
    mapping = load_mapping(PROJECT_MAPPING)
    spec = mapping.get("  openssl ")
    assert spec is not None
    assert spec.component_type is ComponentType.NATIVE
    assert spec.lts_branches == ("3.0", "3.5")


def test_llvm_prefix_and_branch_depth() -> None:
    """LLVM은 llvmorg- 접두사를 떼고 첫 자리로 브랜치를 본다."""
    spec = load_mapping(PROJECT_MAPPING).get("LLVM - Low Level Virtual Machine")
    assert spec.version_prefix == "llvmorg-"
    assert spec.branch_depth == 1


def test_unknown_component_returns_none() -> None:
    """매핑에 없는 컴포넌트는 None(UNMAPPED)이다."""
    assert load_mapping(PROJECT_MAPPING).get("unknown-lib") is None


@pytest.mark.parametrize(
    "body, message",
    [
        ("components: {}", "components 목록"),
        ("components:\n  - name: a\n    type: other\n    version_rule: maven", "type은"),
        (
            "components:\n  - name: a\n    type: maven\n    version_rule: x\n    maven: g:a",
            "version_rule",
        ),
        ("components:\n  - name: a\n    type: maven\n    version_rule: maven", "group:artifact"),
        ("components:\n  - name: a\n    type: native\n    version_rule: openssl", "cpe 목록"),
        (
            "components:\n  - name: a\n    type: native\n    version_rule: openssl\n"
            "    cpe: ['cpe:2.3:a:x']",
            "cpe는",
        ),
    ],
)
def test_invalid_mapping_raises(tmp_path: Path, body: str, message: str) -> None:
    """형식 오류는 원인을 담은 MappingError로 알린다."""
    path = tmp_path / "map.yaml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(MappingError, match=message):
        load_mapping(path)


def test_duplicate_component_raises(tmp_path: Path) -> None:
    """같은 컴포넌트가 두 번 있으면 오류다."""
    entry = "  - name: A\n    type: maven\n    version_rule: maven\n    maven: g:a\n"
    path = tmp_path / "map.yaml"
    path.write_text("components:\n" + entry + entry.replace("A", "a"), encoding="utf-8")
    with pytest.raises(MappingError, match="두 번"):
        load_mapping(path)
