"""공통 테스트 픽스처."""

import socket
from collections.abc import Callable, Iterable
from pathlib import Path

import pytest
from openpyxl import Workbook

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"

DEFAULT_HEADER = (
    "No",
    "오픈소스 컴포넌트명\n(Component name)",
    "컴포넌트 버전\n(Component version name)",
)


@pytest.fixture
def make_input_xlsx(tmp_path: Path) -> Callable[..., Path]:
    """입력 엑셀을 임시 폴더에 만드는 함수를 돌려준다."""

    def _make(rows: Iterable[tuple], header: tuple = DEFAULT_HEADER, sheet: str = "Sheet1") -> Path:
        workbook = Workbook()
        worksheet = workbook.active
        worksheet.title = sheet
        worksheet.append(list(header))
        for row in rows:
            worksheet.append(list(row))
        path = tmp_path / "input.xlsx"
        workbook.save(path)
        return path

    return _make


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """소켓 연결을 막아 네트워크 요청이 일어나면 테스트가 실패하게 한다(PRD 4.3-13)."""

    def _blocked(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("scan 중 네트워크 연결이 시도되었다")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
