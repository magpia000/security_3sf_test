"""패키지 골격이 올바르게 구성되었는지 확인하는 테스트(태스크 1.1)."""

import importlib

import pytest

import oss_vuln_fix_finder

SUBPACKAGES = [
    "oss_vuln_fix_finder.collect",
    "oss_vuln_fix_finder.versions",
    "oss_vuln_fix_finder.analyze",
]


def test_package_has_version() -> None:
    """패키지에 버전 문자열이 정의되어 있어야 한다."""
    assert oss_vuln_fix_finder.__version__ == "0.1.0"


@pytest.mark.parametrize("module_name", SUBPACKAGES)
def test_subpackage_importable(module_name: str) -> None:
    """하위 패키지를 import할 수 있어야 한다."""
    module = importlib.import_module(module_name)
    assert module.__doc__, f"{module_name}에 모듈 docstring이 없다"


@pytest.mark.parametrize("dependency", ["openpyxl", "requests", "yaml", "pandas"])
def test_runtime_dependency_installed(dependency: str) -> None:
    """PRD 7장의 실행 의존성이 설치되어 있어야 한다."""
    importlib.import_module(dependency)
