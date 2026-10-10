"""컴포넌트 매핑 파일(`config/component_map.yaml`)을 읽고 검증한다(PRD 4.1-3)."""

from pathlib import Path

import yaml

from oss_vuln_fix_finder.constants import VERSION_RULE_NAMES
from oss_vuln_fix_finder.models import ComponentSpec, ComponentType

DEFAULT_MAPPING_PATH = Path("config") / "component_map.yaml"


class MappingError(ValueError):
    """매핑 파일 형식이 잘못되었을 때 발생한다."""


def normalize_name(name: str) -> str:
    """컴포넌트명 비교용 키를 만든다(앞뒤 공백 제거, 대소문자 무시)."""
    return " ".join(name.split()).casefold()


class ComponentMapping:
    """컴포넌트명으로 ComponentSpec을 찾는 조회 객체."""

    def __init__(self, specs: list[ComponentSpec]) -> None:
        self._by_name: dict[str, ComponentSpec] = {}
        for spec in specs:
            key = normalize_name(spec.name)
            if key in self._by_name:
                raise MappingError(f"매핑 파일에 같은 컴포넌트가 두 번 있다: {spec.name}")
            self._by_name[key] = spec

    def get(self, name: str) -> ComponentSpec | None:
        """컴포넌트명에 해당하는 항목을 돌려준다. 없으면 None(UNMAPPED)."""
        return self._by_name.get(normalize_name(name))

    def __len__(self) -> int:
        return len(self._by_name)


def load_mapping(path: Path = DEFAULT_MAPPING_PATH) -> ComponentMapping:
    """매핑 파일을 읽어 검증한 뒤 ComponentMapping을 만든다.

    Raises:
        MappingError: 필수 항목 누락, 알 수 없는 유형·버전 규칙 등 형식 오류.
    """
    with path.open(encoding="utf-8") as file:
        document = yaml.safe_load(file) or {}
    entries = document.get("components")
    if not isinstance(entries, list):
        raise MappingError(f"{path}: 최상위에 components 목록이 있어야 한다")
    return ComponentMapping([_parse_entry(entry, index) for index, entry in enumerate(entries)])


def _parse_entry(entry: dict, index: int) -> ComponentSpec:
    """매핑 항목 하나를 검증해 ComponentSpec으로 바꾼다."""
    where = f"components[{index}]"
    name = _require_text(entry, "name", where)
    where = f"{where}({name})"
    try:
        component_type = ComponentType(_require_text(entry, "type", where))
    except ValueError as error:
        raise MappingError(f"{where}: type은 maven 또는 native여야 한다") from error

    version_rule = _require_text(entry, "version_rule", where)
    if version_rule not in VERSION_RULE_NAMES:
        raise MappingError(f"{where}: 알 수 없는 version_rule '{version_rule}'")

    maven = entry.get("maven")
    cpes = tuple(entry.get("cpe") or ())
    if component_type is ComponentType.MAVEN and (not maven or ":" not in maven):
        raise MappingError(f"{where}: maven 유형은 group:artifact 형식의 maven 값이 필요하다")
    if component_type is ComponentType.NATIVE and not cpes:
        raise MappingError(f"{where}: native 유형은 cpe 목록이 필요하다")
    for cpe in cpes:
        if not cpe.startswith("cpe:2.3:") or len(cpe.split(":")) != 5:
            raise MappingError(f"{where}: cpe는 cpe:2.3:part:vendor:product 형식이어야 한다: {cpe}")

    branch_depth = entry.get("branch_depth")
    if branch_depth is not None and (not isinstance(branch_depth, int) or branch_depth < 1):
        raise MappingError(f"{where}: branch_depth는 1 이상의 정수여야 한다")

    return ComponentSpec(
        name=name,
        component_type=component_type,
        version_rule=version_rule,
        maven=maven,
        cpes=cpes,
        version_prefix=str(entry.get("version_prefix") or ""),
        branch_depth=branch_depth,
        lts_branches=tuple(str(branch) for branch in entry.get("lts_branches") or ()),
    )


def _require_text(entry: dict, key: str, where: str) -> str:
    """필수 문자열 항목을 꺼낸다. 없거나 비어 있으면 MappingError."""
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise MappingError(f"{where}: '{key}' 항목이 필요하다")
    return value.strip()
