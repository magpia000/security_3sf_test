"""CLI 진입점(PRD 4.1-1).

    uv run python -m oss_vuln_fix_finder collect --input <입력.xlsx> --bundle <폴더>
    uv run python -m oss_vuln_fix_finder scan --input <입력.xlsx> --bundle <묶음.zip> \
        --output <폴더>

콘솔 출력은 이 모듈에서만 한다(rules.md 4.2). collect와 scan 모듈은 명령을 실행할 때
불러온다. scan이 collect 패키지(네트워크)를 불러오지 않게 하기 위해서다(rules.md 5장).
"""

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from oss_vuln_fix_finder import __version__
from oss_vuln_fix_finder.mapping import DEFAULT_MAPPING_PATH, MappingError, load_mapping

EXIT_OK = 0
EXIT_ERROR = 1


def build_parser() -> argparse.ArgumentParser:
    """명령행 인자 파서를 만든다."""
    parser = argparse.ArgumentParser(
        prog="oss_vuln_fix_finder",
        description="오픈소스 컴포넌트 취약점 식별 및 조치 버전 추천 도구",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--verbose", action="store_true", help="상세 로그를 출력한다")
    commands = parser.add_subparsers(dest="command", required=True)

    collect = commands.add_parser(
        "collect", help="인터넷 PC에서 취약점 데이터를 수집해 묶음 파일을 만든다"
    )
    collect.add_argument("--input", required=True, type=Path, help="입력 컴포넌트 목록 엑셀")
    collect.add_argument("--bundle", required=True, type=Path, help="묶음 파일을 저장할 폴더")
    collect.add_argument("--mapping", type=Path, default=DEFAULT_MAPPING_PATH, help="매핑 파일")

    scan = commands.add_parser(
        "scan", help="묶음 파일만으로 취약점 보고서를 만든다(네트워크 사용 안 함)"
    )
    scan.add_argument("--input", required=True, type=Path, help="입력 컴포넌트 목록 엑셀")
    scan.add_argument("--bundle", required=True, type=Path, help="collect가 만든 묶음 zip 파일")
    scan.add_argument("--output", required=True, type=Path, help="보고서를 저장할 폴더")
    scan.add_argument("--mapping", type=Path, default=DEFAULT_MAPPING_PATH, help="매핑 파일")
    scan.add_argument("--log-dir", type=Path, default=Path("logs"), help="JSONL 로그 폴더")
    scan.add_argument(
        "--include-disputed", action="store_true", help="분쟁(disputed) CVE도 포함한다"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI를 실행하고 종료 코드를 돌려준다."""
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    handlers = {"collect": _run_collect, "scan": _run_scan}
    try:
        return handlers[args.command](args)
    except (MappingError, ValueError, FileNotFoundError) as error:
        # 입력·매핑·묶음 형식 오류는 원인만 알리고 종료한다.
        print(f"[오류] {error}")
        return EXIT_ERROR


def _run_collect(args: argparse.Namespace) -> int:
    """collect 명령을 실행하고 진행 상황과 결과를 출력한다."""
    from oss_vuln_fix_finder.collect.runner import Progress, run_collect

    def show(progress: Progress) -> None:
        eta = f", 남은 예상 {progress.eta_seconds / 60:.1f}분" if progress.eta_seconds else ""
        print(f"[{progress.index}/{progress.total}] {progress.name} 수집 중{eta}", flush=True)

    print("수집을 시작한다. NVD는 키 없이 요청 간격 6초를 지키므로 수 분이 걸린다.")
    result = run_collect(args.input, args.bundle, load_mapping(args.mapping), progress=show)
    components = result.manifest["components"]
    failed = {
        name: entry.get("error", "")
        for name, entry in components.items()
        if entry["status"] == "failed"
    }
    unmapped = [name for name, entry in components.items() if entry["status"] == "unmapped"]
    print(f"묶음 파일: {result.bundle_path}")
    print(
        f"컴포넌트 {len(components)}개 — 성공 {len(components) - len(failed) - len(unmapped)}, "
        f"실패 {len(failed)}, 매핑 없음 {len(unmapped)}"
    )
    for name, error in failed.items():
        print(f"  실패: {name} — {error}")
    for name in unmapped:
        print(f"  매핑 없음: {name} (config/component_map.yaml에 추가 필요)")
    print(f"요청 수: {result.manifest['request_counts']}")
    return EXIT_OK


def _run_scan(args: argparse.Namespace) -> int:
    """scan 명령을 실행하고 요약을 출력한다(PRD 4.5-27)."""
    from oss_vuln_fix_finder.scan import run_scan

    result = run_scan(
        args.input,
        args.bundle,
        args.output,
        load_mapping(args.mapping),
        include_disputed=args.include_disputed,
        log_dir=args.log_dir,
    )
    summary = result.summary
    for warning in summary.warnings:
        print(f"[경고] {warning}")
    print(f"보고서: {result.report_path}")
    print(f"로그: {result.log_path}")
    print(
        f"입력 {summary.input_rows}행 — 취약점 발견 {summary.vulnerable_rows}행, "
        f"CVE {summary.cve_rows}건"
    )
    severities = ", ".join(
        f"{name} {count}" for name, count in sorted(summary.severity_counts.items())
    )
    print(f"심각도: {severities or '없음'}")
    statuses = ", ".join(f"{name} {count}" for name, count in sorted(summary.status_counts.items()))
    print(f"상태: {statuses or '없음'}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
