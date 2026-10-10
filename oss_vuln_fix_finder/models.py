"""도메인 데이터 구조.

모듈 사이에 딕셔너리 대신 이 데이터클래스를 주고받는다(rules.md 4.2).
"""

from dataclasses import dataclass, field
from enum import StrEnum


class RowStatus(StrEnum):
    """취약점 행이 없는 입력 행의 상태. 출력의 `보안취약점 ID` 열에 그대로 적는다."""

    NO_VULNERABILITY = "취약점 없음"
    UNMAPPED = "UNMAPPED"
    UNCOLLECTED = "UNCOLLECTED"
    INVALID_INPUT = "INVALID_INPUT"


class ComponentType(StrEnum):
    """컴포넌트 유형(PRD 4.1-3)."""

    MAVEN = "maven"
    NATIVE = "native"


@dataclass(frozen=True)
class InputRow:
    """입력 엑셀의 한 행. 모든 값은 문자열이다.

    Attributes:
        row_no: `No` 열 값.
        name: 컴포넌트명.
        version: 컴포넌트 버전(입력 그대로).
        is_valid: 컴포넌트명과 버전이 모두 있으면 True.
    """

    row_no: str
    name: str
    version: str
    is_valid: bool = True


@dataclass(frozen=True)
class ComponentSpec:
    """매핑 파일의 컴포넌트 항목(PRD 4.1-3)."""

    name: str
    component_type: ComponentType
    version_rule: str
    maven: str | None = None
    cpes: tuple[str, ...] = ()
    version_prefix: str = ""
    branch_depth: int | None = None
    lts_branches: tuple[str, ...] = ()


@dataclass(frozen=True)
class AffectedRange:
    """영향 버전 범위. 경계가 None이면 그쪽으로 열린 범위다."""

    start: str | None = None
    start_inclusive: bool = True
    end: str | None = None
    end_inclusive: bool = False

    def describe(self) -> str:
        """`>=0.9.8, <0.9.8za` 형태의 사람이 읽을 문자열을 만든다."""
        parts = []
        if self.start is not None:
            parts.append(f"{'>=' if self.start_inclusive else '>'}{self.start}")
        if self.end is not None:
            parts.append(f"{'<=' if self.end_inclusive else '<'}{self.end}")
        return ", ".join(parts) if parts else "모든 버전"


@dataclass(frozen=True)
class Vulnerability:
    """한 소스(또는 병합 결과)에서 얻은 취약점 하나."""

    vuln_id: str
    aliases: tuple[str, ...] = ()
    description: str = ""
    cvss_score: float | None = None
    severity: str | None = None
    ranges: tuple[AffectedRange, ...] = ()
    exact_versions: frozenset[str] = frozenset()
    sources: frozenset[str] = frozenset()
    is_rejected: bool = False
    is_disputed: bool = False


@dataclass(frozen=True)
class Remediation:
    """조치 버전 판정 결과(PRD 4.3-19~21)."""

    nearest: str
    latest: str
    notes: tuple[str, ...] = ()


@dataclass
class ComponentResult:
    """입력 행 하나의 분석 결과.

    Attributes:
        row: 입력 행.
        status: 취약점 행 대신 상태 행을 낼 때의 상태. 취약점이 있으면 None.
        vulnerabilities: 현재 버전에 영향을 주는 취약점(집합 C).
        matched_ranges: 취약점 ID별로 현재 버전을 포함한 범위 설명.
        remediation: 조치 버전 판정 결과.
        extra_notes: 상태 행에 붙일 비고(예: 오류 원인).
    """

    row: InputRow
    status: RowStatus | None = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    matched_ranges: dict[str, str] = field(default_factory=dict)
    remediation: Remediation | None = None
    extra_notes: tuple[str, ...] = ()
