# Tasks: oss-vuln-fix-finder

- 입력 PRD: `분석_설계/prd-oss-vuln-fix-finder.md` (v1.1)
- 개발 규칙: `분석_설계/rules.md`
- 작성 규칙: `ai-dev-tasks/generate-tasks.md`
- 상태: Phase 2 완료 (하위 태스크·Relevant Files 포함)

## Relevant Files

- `pyproject.toml` - 의존성(openpyxl, requests, PyYAML, pytest), pytest·ruff(줄 길이 100) 설정.
- `config/component_map.yaml` - 컴포넌트명 → Maven 좌표/CPE, 버전 규칙, 브랜치 깊이, LTS 브랜치 매핑.
- `oss_vuln_fix_finder/__init__.py` - 패키지 버전 정의.
- `oss_vuln_fix_finder/__main__.py` - CLI 진입점(`collect`, `scan`), 콘솔 출력·로깅 설정.
- `oss_vuln_fix_finder/models.py` - 도메인 데이터클래스(Component, Vulnerability, AffectedRange, Remediation)와 상태 Enum.
- `oss_vuln_fix_finder/constants.py` - 요청 간격·재시도 횟수·시트명·열 이름 등 상수.
- `oss_vuln_fix_finder/mapping.py` - 매핑 파일 로드·검증.
- `oss_vuln_fix_finder/io_excel.py` - 입력 엑셀 읽기·검증, 출력 엑셀 쓰기·서식.
- `oss_vuln_fix_finder/bundle.py` - 묶음 zip 쓰기·읽기, manifest 처리(네트워크 없음).
- `oss_vuln_fix_finder/collect/http.py` - 요청 간격 제한·재시도·User-Agent를 갖춘 HTTP 클라이언트.
- `oss_vuln_fix_finder/collect/osv.py` - OSV.dev 조회.
- `oss_vuln_fix_finder/collect/nvd.py` - NVD CVE·CPE 조회(페이지 처리, CVE 중복 조회 방지).
- `oss_vuln_fix_finder/collect/maven.py` - Maven Central 버전 목록 조회.
- `oss_vuln_fix_finder/collect/runner.py` - collect 전체 흐름(컴포넌트별 실패 격리, 진행 콜백, manifest 작성).
- `oss_vuln_fix_finder/versions/base.py` - 버전 규칙 공통 인터페이스와 규칙 레지스트리.
- `oss_vuln_fix_finder/versions/maven.py` - Maven 버전 규칙.
- `oss_vuln_fix_finder/versions/openssl.py` - OpenSSL 버전 규칙.
- `oss_vuln_fix_finder/versions/letter_suffix.py` - 숫자+문자 접미사 규칙(libjpeg).
- `oss_vuln_fix_finder/versions/semver_like.py` - 점 구분 숫자+사전배포판 규칙(GCC, LLVM, SQLite, zlib).
- `oss_vuln_fix_finder/analyze/parsers.py` - 묶음 원본(NVD/OSV JSON)을 Vulnerability로 정규화.
- `oss_vuln_fix_finder/analyze/matcher.py` - 버전이 영향 범위에 드는지 판정.
- `oss_vuln_fix_finder/analyze/merger.py` - CVE 병합, 별칭 치환, Rejected·disputed 처리.
- `oss_vuln_fix_finder/analyze/remediation.py` - 집합 C·K 구성, C-해결/무취약 판정, 조치 버전 선택.
- `oss_vuln_fix_finder/scan.py` - scan 전체 흐름(묶음 로드, 분석, 출력, 요약, 로그).
- `tests/test_skeleton.py` - 패키지 골격·의존성 설치 확인 테스트(1.1).
- `tests/conftest.py` - 공통 픽스처, 네트워크 차단 픽스처.
- `tests/fixtures/` - NVD(CVE·CPE·단건)·OSV·Maven 응답 샘플(실제 API 구조를 따른 가상 데이터).
- `tests/test_mapping.py`, `tests/test_io_excel.py`, `tests/test_cli.py`, `tests/test_bundle.py` - 각 모듈 단위 테스트.
- `tests/versions/test_rules.py` - 4개 버전 규칙의 순서·브랜치·사전배포판 단위 테스트(규칙별 케이스를 한 파일에서 표로 관리).
- `tests/collect/fakes.py` - 가짜 HTTP 세션·시계.
- `tests/collect/test_http.py`, `tests/collect/test_collectors.py` - HTTP 클라이언트·수집기·collect 흐름 단위 테스트(fixture 응답 사용).
- `tests/analyze/helpers.py` - 분석 테스트 도우미.
- `tests/analyze/test_parsers.py`, `test_matcher_merger.py`, `test_remediation.py` - 분석 엔진 단위 테스트(OpenSSL 0.9.8h 회귀 포함).
- `tests/test_scan_integration.py` - 네트워크 차단 상태 scan 통합 테스트, 재실행 동일성, 수행 시간, 13열 형식, scan의 collect 미import 확인.
- `tests/test_models.py`, `tests/test_skeleton.py` - 상수·모델, 골격 테스트.
- `README.md` - 설치, collect/scan 사용법, 폐쇄망 반입 절차.

### Notes

- 테스트는 `tests/` 아래에 모듈 구조를 따라 둔다(`rules.md` 6장).
- 실행: `uv run pytest -q` (특정 파일: `uv run pytest tests/versions/test_openssl.py -q`).
- 단위 테스트는 실제 네트워크를 호출하지 않는다. 응답은 `tests/fixtures/`의 샘플을 쓴다.

## Instructions for Completing Tasks

**IMPORTANT:** As you complete each task, you must check it off in this markdown file by changing `- [ ]` to `- [x]`. This helps track progress and ensures you don't skip any steps.

Example:
- `- [ ] 1.1 Read file` → `- [x] 1.1 Read file` (after completing)

Update the file after completing each sub-task, not just after completing an entire parent task. 진행 절차·완료 기록 형식은 `분석_설계/rules.md` 2장을 따른다.

## Tasks

- [x] 1.0 프로젝트 기반과 입력 처리 (PRD 4.1, 7장)
  - [x] 1.1 의존성 추가(`openpyxl`, `requests`, `PyYAML`, 개발용 `pytest`)와 패키지 골격 생성(`oss_vuln_fix_finder/` 및 `collect/`·`versions/`·`analyze/` 하위 패키지, `tests/`, `config/`), pytest 설정, 골격 import 테스트
  - [x] 1.2 `constants.py`(상수)와 `models.py`(데이터클래스, `RowStatus` Enum: `취약점 없음`/`UNMAPPED`/`UNCOLLECTED`/`INVALID_INPUT`) 정의와 테스트
  - [x] 1.3 `mapping.py` 매핑 로더·검증과 `config/component_map.yaml` 초안(11개 컴포넌트, `version_prefix`, `branch_depth`, OpenSSL LTS `["3.0", "3.5"]`) 및 테스트
  - [x] 1.4 `io_excel.read_components`: 문자열로 읽기, 헤더 앞부분 한글명으로 열 찾기, 필수 열 누락 시 오류, 빈 값 행은 `INVALID_INPUT` (PRD 4.1-2, 4-1) 및 테스트
  - [x] 1.5 `__main__.py` CLI 골격: `collect`/`scan` 하위 명령, 인자(`--input`, `--bundle`, `--output`, `--include-disputed`), 로깅 설정, 아직 구현 안 된 명령은 안내 메시지 후 종료 코드 반환 및 테스트
  > 완료 2026-10-10 14:51 — 패키지 골격, 상수·모델, 매핑 로더와 초기 매핑(11개), 입력 엑셀 읽기·검증, CLI 골격 — 파일: constants.py, models.py, mapping.py, io_excel.py, __main__.py, config/component_map.yaml — 테스트: 35/35

- [x] 2.0 버전 비교 규칙 (PRD 4.4)
  - [x] 2.1 `versions/base.py`: 규칙 인터페이스(정규화, 정렬 키, 브랜치, 사전배포판 여부)와 이름 → 규칙 레지스트리, 테스트
  - [x] 2.2 `maven` 규칙(숫자·한정어 비교, `-SNAPSHOT`·`-M1`·`-RC1`·`-alpha`·`-beta` 사전배포판 판정, 브랜치 = 앞 두 자리) 및 PRD 표 순서 예 테스트
  - [x] 2.3 `openssl` 규칙(`0.9.8h` < `0.9.8za` < `0.9.8zh` < `1.0.0` < `1.0.2u` < `1.1.1w` < `3.0.8`, 3.0 미만/이상 브랜치 정의, `-beta`·`-alpha`·`-pre` 판정) 및 테스트
  - [x] 2.4 `letter_suffix` 규칙(`8` < `8a` < `8b` < `8d` < `9` < `9a`, 브랜치 = 숫자부) 및 테스트
  - [x] 2.5 `semver_like` 규칙(`9.0.1-rc3` < `9.0.1` < `10.0.0`, `1.2.5` < `1.2.11` < `1.2.13`, `llvmorg-` 접두사 제거는 매핑의 `version_prefix`로, 브랜치 깊이는 `branch_depth`로) 및 테스트
  > 완료 2026-10-10 14:52 — maven·openssl·letter_suffix·semver_like 규칙과 레지스트리, 정렬 도우미 — 파일: versions/base.py, maven.py, openssl.py, letter_suffix.py, semver_like.py — 테스트: 77/77

- [x] 3.0 collect 구현 (PRD 4.2)
  - [x] 3.1 `bundle.py`: 원본 응답 저장 경로 규칙, zip 쓰기·읽기, `manifest.json`(수집일시 KST, 도구 버전, 입력 파일명·SHA-256, 컴포넌트별 성공/실패, 소스별 요청 수) 및 테스트
  - [x] 3.2 `collect/http.py`: 호스트별 최소 요청 간격(NVD 6초), 403/429/5xx 지수 백오프 최대 5회, User-Agent, 요청 수 집계 및 테스트(가짜 세션·가짜 시계)
  - [x] 3.3 `collect/osv.py`: Maven 패키지 전체 취약점 조회(버전 없이), 페이지 토큰 처리 및 테스트
  - [x] 3.4 `collect/nvd.py` CVE 조회: `virtualMatchString`(버전 없는 CPE), `startIndex` 페이지 처리, `cveId` 단건 보완 조회, 이미 받은 CVE 재조회 방지 및 테스트
  - [x] 3.5 `collect/nvd.py` CPE 버전 목록 조회(`cpeMatchString`, 페이지 처리)와 `collect/maven.py`(`maven-metadata.xml`) 및 테스트
  - [x] 3.6 `collect/runner.py`: 입력 읽기 → 매핑 → 컴포넌트별 수집(실패 격리) → 묶음 저장, 진행 상황을 콜백으로 전달, CLI `collect` 연결 및 테스트
  > 완료 2026-10-10 14:56 — 묶음 쓰기·읽기, 요청 간격·재시도 HTTP 클라이언트, OSV·NVD(CVE/CPE/단건)·Maven 수집기, collect 흐름과 CLI 연결 — 파일: bundle.py, collect/http.py, osv.py, nvd.py, maven.py, runner.py, __main__.py — 테스트: 95/95

- [x] 4.0 scan 분석 엔진 (PRD 4.3)
  - [x] 4.1 `analyze/parsers.py`: NVD `configurations`(cpeMatch 범위·정확 버전, `vulnerable: true`만)와 OSV `affected`(ranges events, versions)를 `Vulnerability`로 정규화, CVSS 우선순위(v3.1 → v3.0 → v4.0 → v2), Rejected·disputed 표시 및 테스트
  - [x] 4.2 `analyze/matcher.py`: 버전 규칙을 써서 버전이 영향 범위에 드는지 판정(포함/제외 경계, 시작 없는 범위, 정확 버전 목록) 및 테스트
  - [x] 4.3 `analyze/merger.py`: 별칭으로 CVE ID 통일, 소스 간 병합(근거 소스 누적, CVSS·설명 보완), Rejected 제외, disputed 기본 제외/옵션 포함 및 테스트
  - [x] 4.4 `analyze/remediation.py`: 집합 K·C 구성, 후보(현재보다 높은 안정 버전), C-해결/무취약 판정, 해결 가까운 버전 19번 1~4단계, 최신 버전과 LTS 비고(20번), C가 빈 경우(21번), 비고 문구 생성 및 단계별 테스트
  - [x] 4.5 OpenSSL 0.9.8h 회귀 테스트(PRD 4.3-21-1)를 가상 데이터로 작성하고 통과 확인
  > 완료 2026-10-10 14:59 — NVD·OSV·Maven 파서, 범위 판정, CVE 병합·제외, A안 조치 버전 판정, OpenSSL 0.9.8h 회귀 — 파일: analyze/parsers.py, matcher.py, merger.py, remediation.py — 테스트: 122/122

- [x] 5.0 출력과 scan 통합 (PRD 4.3-13·14, 4.5, 6장)
  - [x] 5.1 `io_excel.write_report`: 13열(앞 5열 템플릿과 동일), CVE당 1행, 정렬(No 오름차순 → CVSS 내림차순), 서식(헤더 굵게·고정, 열 너비, 줄바꿈, 심각도 색) 및 테스트
  - [x] 5.2 `scan.py`: 묶음 로드, 입력 해시 비교 경고, 묶음 30일 경과 경고(OQ-5 가정), 행별 상태(`UNMAPPED`/`UNCOLLECTED`/`INVALID_INPUT`) 처리, 분석 엔진 호출, CLI `scan` 연결
  - [x] 5.3 콘솔 실행 요약(PRD 4.5-27)과 `logs/` JSONL 로그(PRD 4.5-28)
  - [x] 5.4 통합 테스트: 소켓 차단 상태에서 fixture 묶음으로 scan 성공, 두 번 실행 결과 동일(조회일시 제외), 수행 시간 30초 이내
  > 완료 2026-10-10 15:02 — 보고서 엑셀(13열·서식·정렬), scan 흐름(경고·상태 행·캐시), 콘솔 요약, JSONL 로그, 통합 테스트, ruff 포맷 적용 — 파일: io_excel.py, scan.py, __main__.py, tests/test_scan_integration.py — 테스트: 130/130

- [ ] 6.0 실데이터 검증과 문서화 (PRD 8장)
  - [ ] 6.1 (사용자 PC 실행 대기 — 작업 환경에서 NVD·OSV·Maven 접속이 차단됨) 인터넷 PC에서 실제 `collect` 실행: CPE vendor(OQ-1), LTS 목록(OQ-6), NVD 요청 수·소요 시간 확인 후 매핑 확정 — 사용자 PC에서 실행 필요
  - [ ] 6.2 실제 묶음으로 `scan` 실행: OpenSSL 0.9.8h 기대 결과, 표본 3개(OpenSSL 0.9.8h, zlib 1.2.5, gson 1.7) NVD/OSV 웹 수동 대조, 결과를 tasks 파일에 기록
  - [x] 6.3 `README.md`: 설치(uv), collect/scan 사용법, 출력 열 설명, 폐쇄망 반입(묶음 파일, 오프라인 wheel 준비)
