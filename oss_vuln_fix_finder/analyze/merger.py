"""소스별 취약점을 CVE ID 기준으로 합치고 제외 규칙을 적용한다(PRD 4.3-16·17)."""

from collections.abc import Iterable

from oss_vuln_fix_finder.constants import SOURCE_NVD
from oss_vuln_fix_finder.models import Vulnerability

CVE_PREFIX = "CVE-"


def canonical_id(vulnerability: Vulnerability) -> str:
    """대표 ID: CVE면 그대로, 아니면 별칭의 첫 CVE, 그것도 없으면 원래 ID."""
    if vulnerability.vuln_id.startswith(CVE_PREFIX):
        return vulnerability.vuln_id
    return next(
        (alias for alias in vulnerability.aliases if alias.startswith(CVE_PREFIX)),
        vulnerability.vuln_id,
    )


def merge_vulnerabilities(
    found: Iterable[Vulnerability],
    enrichment: dict[str, Vulnerability],
    include_disputed: bool = False,
) -> list[Vulnerability]:
    """같은 취약점을 하나로 합치고, Rejected는 항상·disputed는 기본으로 뺀다.

    Args:
        found: NVD·OSV에서 컴포넌트에 대해 찾은 취약점(범위 포함).
        enrichment: CVE ID → NVD 단건 조회 결과(CVSS·설명·상태 보완용, 범위 없음).
        include_disputed: True면 disputed CVE도 남긴다.

    Returns:
        ID 순으로 정렬한 병합 결과.
    """
    groups: dict[str, list[Vulnerability]] = {}
    for vulnerability in found:
        groups.setdefault(canonical_id(vulnerability), []).append(vulnerability)

    merged = [
        _merge_group(vuln_id, items, enrichment.get(vuln_id)) for vuln_id, items in groups.items()
    ]
    kept = [v for v in merged if not v.is_rejected and (include_disputed or not v.is_disputed)]
    return sorted(kept, key=lambda v: v.vuln_id)


def _merge_group(
    vuln_id: str, items: list[Vulnerability], extra: Vulnerability | None
) -> Vulnerability:
    """같은 ID의 취약점들을 하나로 합친다. 범위는 합집합(어느 소스든 취약하다면 취약)."""
    # 설명·점수는 NVD를 먼저, 다음은 단건 보완, 마지막으로 OSV 순으로 고른다.
    ordered = sorted(items, key=lambda v: SOURCE_NVD not in v.sources)
    metadata = ordered + ([extra] if extra else [])
    aliases = {alias for v in items for alias in (v.vuln_id, *v.aliases)} - {vuln_id}
    return Vulnerability(
        vuln_id=vuln_id,
        aliases=tuple(sorted(aliases)),
        description=_first(v.description for v in metadata) or "",
        cvss_score=_first(v.cvss_score for v in metadata),
        severity=_first(v.severity for v in metadata),
        ranges=tuple(dict.fromkeys(r for v in items for r in v.ranges)),
        exact_versions=frozenset().union(*(v.exact_versions for v in items)),
        sources=frozenset().union(*(v.sources for v in items)),
        is_rejected=any(v.is_rejected for v in metadata),
        is_disputed=any(v.is_disputed for v in metadata),
    )


def _first(values: Iterable) -> object:
    """None·빈 문자열이 아닌 첫 값."""
    return next((value for value in values if value not in (None, "")), None)
