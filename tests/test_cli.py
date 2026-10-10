"""CLI 인자 처리 단위 테스트(태스크 1.5)."""

import pytest

from oss_vuln_fix_finder.__main__ import build_parser


def test_scan_arguments() -> None:
    """scan은 입력·묶음·출력 경로와 disputed 옵션을 받는다."""
    args = build_parser().parse_args(
        ["scan", "--input", "in.xlsx", "--bundle", "b.zip", "--output", "out", "--include-disputed"]
    )
    assert args.command == "scan"
    assert str(args.bundle) == "b.zip"
    assert args.include_disputed is True


def test_collect_arguments() -> None:
    """collect는 입력과 묶음 폴더를 받는다."""
    args = build_parser().parse_args(["collect", "--input", "in.xlsx", "--bundle", "bundles"])
    assert args.command == "collect"
    assert str(args.mapping).endswith("component_map.yaml")


def test_command_is_required() -> None:
    """명령 없이 실행하면 사용법 오류로 끝난다."""
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_collect_command_reports_bundle(tmp_path, make_input_xlsx, monkeypatch, capsys) -> None:
    """collect 명령은 수집기를 실행하고 묶음 경로를 출력한다."""
    from oss_vuln_fix_finder.__main__ import main
    from oss_vuln_fix_finder.collect import runner
    from tests.collect.test_collectors import make_client

    client, _ = make_client()
    original = runner.run_collect
    monkeypatch.setattr(runner, "run_collect", lambda *a, **k: original(*a, **k, client=client))
    path = make_input_xlsx([(52, "OpenSSL", "0.9.8h")])
    code = main(["collect", "--input", str(path), "--bundle", str(tmp_path / "b")])
    output = capsys.readouterr().out
    assert code == 0
    assert "묶음 파일:" in output and "[1/1] OpenSSL" in output


def test_missing_input_file_is_error(tmp_path, capsys) -> None:
    """없는 입력 파일은 오류 메시지와 종료 코드 1."""
    from oss_vuln_fix_finder.__main__ import main

    code = main(["collect", "--input", str(tmp_path / "none.xlsx"), "--bundle", str(tmp_path)])
    assert code == 1
    assert "[오류]" in capsys.readouterr().out
