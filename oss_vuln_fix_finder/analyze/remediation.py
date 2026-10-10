"""조치 버전 판정(PRD 4.3-18~21, A안).

용어(rules.md 4.4):
    all_cves (K)        컴포넌트의 전체 취약점
    current_cves (C)    현재 버전에 영향을 주는 취약점
    resolves_current    C의 어떤 취약점에도 영향받지 않음(C-해결)
    is_clean            K의 어떤 취약점에도 영향받지 않음(무취약)
"""

from dataclasses import dataclass

from oss_vuln_fix_finder.analyze.matcher import is_affected
from oss_vuln_fix_finder.constants import MAX_IDS_IN_NOTE, NOT_APPLICABLE
from oss_vuln_fix_finder.models import Remediation, Vulnerability
from oss_vuln_fix_finder.versions.base import VersionRule, unique_sorted

NO_FIX = "해결 버전 없음"


@dataclass(frozen=True)
class RemediationInput:
    """판정에 필요한 값 묶음.

    Attributes:
        current: 정규화한 현재 버전.
        versions: 컴포넌트의 전체 릴리스 버전(정렬·중복 제거 전).
        all_cves: 집합 K.
        current_cves: 집합 C.
        rule: 버전 규칙.
        branch_depth: 매핑 파일의 브랜치 깊이.
        lts_branches: 매핑 파일의 LTS 브랜치.
    """

    current: str
    versions: list[str]
    all_cves: list[Vulnerability]
    current_cves: list[Vulnerability]
    rule: VersionRule
    branch_depth: int | None = None
    lts_branches: tuple[str, ...] = ()


def current_vulnerabilities(
    all_cves: list[Vulnerability], current: str, rule: VersionRule
) -> list[Vulnerability]:
    """집합 K에서 현재 버전에 영향을 주는 취약점(집합 C)을 고른다(PRD 4.3-15)."""
    return [
        vulnerability for vulnerability in all_cves if is_affected(vulnerability, current, rule)
    ]


def format_ids(ids: set[str]) -> str:
    """CVE ID를 정렬해 앞의 몇 개만 적고 나머지는 `외 N건`으로 줄인다."""
    ordered = sorted(ids)
    shown = ", ".join(ordered[:MAX_IDS_IN_NOTE])
    hidden = len(ordered) - MAX_IDS_IN_NOTE
    return f"{shown} 외 {hidden}건" if hidden > 0 else shown


class _Judge:
    """버전별 영향 CVE를 한 번만 계산해 두고 판정에 재사용한다."""

    def __init__(self, data: RemediationInput) -> None:
        self.data = data
        rule = data.rule
        self.stable = [v for v in unique_sorted(data.versions, rule) if not rule.is_prerelease(v)]
        self.current_ids = {v.vuln_id for v in data.current_cves}
        self._affected = {
            v: {c.vuln_id for c in data.all_cves if is_affected(c, v, rule)} for v in self.stable
        }
        current_key = rule.sort_key(data.current)
        self.candidates = [v for v in self.stable if rule.sort_key(v) > current_key]
        self.at_or_above = [v for v in self.stable if rule.sort_key(v) >= current_key]

    def affected(self, version: str) -> set[str]:
        return self._affected[version]

    def resolves_current(self, version: str) -> bool:
        return not (self._affected[version] & self.current_ids)

    def is_clean(self, version: str) -> bool:
        return not self._affected[version]

    def branch(self, version: str) -> str:
        return self.data.rule.branch(version, self.data.branch_depth)


def choose_remediation(data: RemediationInput) -> Remediation:
    """해결 가까운 버전과 최신 버전을 고르고 비고를 만든다."""
    judge = _Judge(data)
    notes: list[str] = []
    nearest = _pick_nearest(judge, notes) if data.current_cves else NOT_APPLICABLE  # PRD 4.3-21
    latest = _pick_latest(judge, notes)
    return Remediation(nearest=nearest, latest=latest, notes=tuple(notes))


def _pick_nearest(judge: _Judge, notes: list[str]) -> str:
    """PRD 4.3-19의 1~4단계를 차례로 적용한다."""
    current_branch = judge.branch(judge.data.current)
    same_branch = [v for v in judge.candidates if judge.branch(v) == current_branch]
    other_branch = [v for v in judge.candidates if judge.branch(v) != current_branch]
    clean_elsewhere = next((v for v in other_branch if judge.is_clean(v)), None)

    # 1단계: 같은 브랜치에서 현재 취약점을 모두 해결한 가장 낮은 버전
    resolved = next((v for v in same_branch if judge.resolves_current(v)), None)
    if resolved:
        new_ids = judge.affected(resolved) - judge.current_ids
        if new_ids:
            notes.append(f"신규 취약점: {format_ids(new_ids)}")
        return resolved

    # 2단계: 같은 브랜치로는 해결할 수 없으면 브랜치 최종 버전 + 미해결 목록
    if same_branch:
        last = same_branch[-1]
        notes.append(
            f"동일 브랜치 최종 버전, 미해결: {format_ids(judge.affected(last) & judge.current_ids)}"
        )
        if clean_elsewhere:
            notes.append(f"브랜치 변경 시: {clean_elsewhere}")
        return last

    # 3단계: 현재 버전이 브랜치 최종 버전이면 다른 브랜치의 가장 낮은 무취약 버전
    if clean_elsewhere:
        notes.append("브랜치 변경")
        return clean_elsewhere

    # 4단계
    return NO_FIX


def _pick_latest(judge: _Judge, notes: list[str]) -> str:
    """PRD 4.3-20: 현재 이상 안정 버전 중 무취약인 가장 높은 버전과 LTS 비고."""
    if not judge.at_or_above:
        notes.append("버전 목록 없음")
        return NOT_APPLICABLE
    clean = [v for v in judge.at_or_above if judge.is_clean(v)]
    if clean:
        latest = clean[-1]
    else:
        latest = judge.at_or_above[-1]
        notes.append(f"최신 버전에도 미해결: {format_ids(judge.affected(latest))}")

    lts = judge.data.lts_branches
    if lts and judge.branch(latest) not in lts:
        lts_clean = [v for v in clean if judge.branch(v) in lts]
        if lts_clean:
            notes.append(f"LTS: {lts_clean[-1]}")
    return latest
