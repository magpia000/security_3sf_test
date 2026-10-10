"""io_excel 입력 읽기 단위 테스트(태스크 1.4)."""

import pytest

from oss_vuln_fix_finder.io_excel import InputFormatError, read_components, to_text
from tests.conftest import PROJECT_ROOT


def test_reads_versions_as_text(make_input_xlsx) -> None:
    """숫자처럼 보이는 버전도 문자열로 읽는다(`1.7`, `8b`)."""
    path = make_input_xlsx(
        [(37, "googlegson", "1.7"), (38, "libjpeg", "8b"), (52, "OpenSSL", "0.9.8h")]
    )
    rows = read_components(path)
    assert [(r.row_no, r.name, r.version) for r in rows] == [
        ("37", "googlegson", "1.7"),
        ("38", "libjpeg", "8b"),
        ("52", "OpenSSL", "0.9.8h"),
    ]
    assert all(r.is_valid for r in rows)


def test_blank_name_or_version_is_invalid(make_input_xlsx) -> None:
    """컴포넌트명이나 버전이 빈 행은 INVALID로 남기고 완전히 빈 행은 건너뛴다."""
    path = make_input_xlsx(
        [(1, "zlib", None), (2, None, "1.0"), (None, None, None), (3, "zlib", "1.2.5")]
    )
    rows = read_components(path)
    assert [r.is_valid for r in rows] == [False, False, True]


def test_missing_required_column_raises(make_input_xlsx) -> None:
    """필수 열이 없으면 InputFormatError."""
    path = make_input_xlsx([(1, "zlib")], header=("No", "오픈소스 컴포넌트명"))
    with pytest.raises(InputFormatError, match="컴포넌트 버전"):
        read_components(path)


def test_falls_back_to_first_sheet(make_input_xlsx) -> None:
    """Sheet1이 없으면 첫 시트를 읽는다."""
    path = make_input_xlsx([(1, "zlib", "1.2.5")], sheet="목록")
    assert read_components(path)[0].name == "zlib"


def test_reads_project_input_file() -> None:
    """실제 입력 파일 13행을 모두 유효하게 읽는다."""
    rows = read_components(PROJECT_ROOT / "data" / "오픈소스_컴포넌트목록.xlsx")
    assert len(rows) == 13
    assert all(r.is_valid for r in rows)
    assert rows[6].version == "llvmorg-9.0.1-rc3"


@pytest.mark.parametrize(
    "value, expected", [(None, ""), (13.0, "13"), (1.7, "1.7"), (" 8b ", "8b")]
)
def test_to_text(value, expected) -> None:
    """셀 값 문자열 변환 규칙."""
    assert to_text(value) == expected
