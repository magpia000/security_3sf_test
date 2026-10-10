"""models·constants 단위 테스트(태스크 1.2)."""

from oss_vuln_fix_finder import constants
from oss_vuln_fix_finder.models import AffectedRange, RowStatus


def test_row_status_values_match_prd() -> None:
    """상태 문자열은 PRD 4.5-24의 표기와 같아야 한다."""
    assert [s.value for s in RowStatus] == [
        "취약점 없음",
        "UNMAPPED",
        "UNCOLLECTED",
        "INVALID_INPUT",
    ]


def test_output_columns_keep_template_prefix() -> None:
    """출력 앞 5열은 템플릿과 같은 이름·순서여야 한다."""
    assert len(constants.OUTPUT_COLUMNS) == 13
    assert constants.OUTPUT_COLUMNS[0] == "No"
    assert constants.OUTPUT_COLUMNS[3].startswith("보안취약점 ID")


def test_nvd_interval_respects_public_limit() -> None:
    """키 없는 NVD 제한(30초 5회)을 지키는 간격이어야 한다."""
    assert constants.NVD_MIN_INTERVAL_SEC * 5 >= 30


def test_affected_range_describe() -> None:
    """범위 설명 문자열 형식을 확인한다."""
    assert AffectedRange("0.9.8", True, "0.9.8za", False).describe() == ">=0.9.8, <0.9.8za"
    assert AffectedRange(None, True, "1.2.12", True).describe() == "<=1.2.12"
    assert AffectedRange().describe() == "모든 버전"
