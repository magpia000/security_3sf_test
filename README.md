# oss-vuln-fix-finder

오픈소스 컴포넌트 목록(엑셀)을 받아 컴포넌트·버전별 보안취약점(CVE)을 찾고, 조치 버전 두 가지
(**해결 가까운 버전**, **최신 버전**)를 엑셀 보고서로 제시하는 CLI 도구다.

- 요구사항: `RFP/요구사항.md`
- 설계 문서(3-File System): `분석_설계/prd-oss-vuln-fix-finder.md`, `tasks-oss-vuln-fix-finder.md`, `rules.md`

실행은 두 단계로 나뉜다. 폐쇄망에서도 분석할 수 있게 하기 위해서다.

```
[인터넷 PC]  입력 엑셀 → collect → bundles/bundle_YYYYMMDD_HHMM.zip
                                              │ (USB 등으로 반입)
[폐쇄망 PC]  입력 엑셀 + 묶음 zip → scan → output/…xlsx, logs/…jsonl
```

## 1. 설치

Python 3.12와 [uv](https://docs.astral.sh/uv/)가 필요하다. 프로젝트 폴더에서 실행한다.

```powershell
uv sync
uv run pytest          # 단위·통합 테스트(네트워크 사용 안 함)
```

## 2. 사용법

### 2.1 collect — 인터넷 PC

```powershell
uv run python -m oss_vuln_fix_finder collect --input data\오픈소스_컴포넌트목록.xlsx --bundle bundles
```

- 데이터 출처: NVD(CVE·CPE), OSV.dev(Maven, GitHub Advisory 포함), Maven Central.
- NVD API 키 없이 동작한다. 공개 제한(30초 5회)을 지키려고 요청 사이를 6초씩 띄우므로
  현재 입력 기준 **약 6~12분**이 걸린다(추정값이며 첫 실행에서 확인이 필요하다).
- 일부 컴포넌트가 실패해도 나머지는 계속 수집한다. 실패한 컴포넌트는 scan에서 `UNCOLLECTED`로 나온다.

### 2.2 scan — 폐쇄망 PC (네트워크 사용 안 함)

```powershell
uv run python -m oss_vuln_fix_finder scan --input data\오픈소스_컴포넌트목록.xlsx --bundle bundles\bundle_20261010_1500.zip --output output
```

| 옵션 | 설명 |
|---|---|
| `--include-disputed` | 분쟁(disputed) CVE도 포함한다(기본 제외) |
| `--mapping` | 매핑 파일 경로(기본 `config/component_map.yaml`) |
| `--log-dir` | JSONL 로그 폴더(기본 `logs`) |
| `--verbose` | 상세 로그 |

경고가 나오는 경우: 입력 파일이 수집 때와 다를 때, 묶음이 30일보다 오래되었을 때.

## 3. 출력 보고서

`output/오픈소스_컴포넌트별 취약점목록_YYYYMMDD_HHMM.xlsx` — CVE 1건당 1행, `No` 오름차순 → CVSS 내림차순.

| 열 | 내용 |
|---|---|
| No / 컴포넌트명 / 컴포넌트 버전 | 입력 그대로 |
| 보안취약점 ID | CVE ID(없으면 GHSA 등). 취약점 행이 아니면 `취약점 없음`·`UNMAPPED`·`UNCOLLECTED`·`INVALID_INPUT` |
| 보안취약점 설명 | 영문 원문 |
| CVSS 점수 / 심각도 | v3.1 → v3.0 → v4.0 → v2 순으로 처음 있는 것 |
| 영향 버전 범위 | 현재 버전을 포함한 범위(예: `>=0.9.8, <0.9.8za`, `=0.9.8h`) |
| 해결 가까운 버전 / 최신 버전 | 아래 판정 규칙 |
| 비고 | `동일 브랜치 최종 버전, 미해결: …`, `브랜치 변경 시: …`, `LTS: …` 등 |
| 근거 소스 | `NVD`, `OSV` |
| 조회일시 | 묶음의 수집일시 |

### 판정 규칙 요약 (PRD 4.3, A안)

- **해결 가까운 버전**
  1. 같은 브랜치에서 현재 버전의 취약점을 모두 해결한 가장 낮은 버전
  2. 없으면 같은 브랜치의 최종 버전(미해결 CVE와 `브랜치 변경 시` 권장 버전을 비고에 표시)
  3. 현재 버전이 이미 브랜치 최종 버전이면 다른 브랜치의 가장 낮은 무취약 버전(`브랜치 변경`)
  4. 그래도 없으면 `해결 버전 없음`
- **최신 버전**: 알려진 취약점이 없는 가장 높은 안정 버전. LTS가 따로 있으면 비고에 `LTS: …`
- 사전배포판(rc, beta, SNAPSHOT 등)은 추천하지 않는다.
- 네이티브 라이브러리의 버전 목록은 NVD CPE 사전을 쓰므로 NVD에 없는 릴리스는 빠질 수 있다(비고에 표시).

## 4. 컴포넌트 추가

`config/component_map.yaml`에 항목을 추가한다. 형식은 파일 상단 주석을 따른다.
매핑에 없는 컴포넌트는 보고서에 `UNMAPPED`로 나온다.

```yaml
  - name: jackson-databind            # 입력 엑셀의 컴포넌트명
    type: maven
    maven: com.fasterxml.jackson.core:jackson-databind
    version_rule: maven
```

## 5. 폐쇄망 반입 절차

폐쇄망 PC로 옮길 것: ① 프로젝트 폴더, ② 묶음 zip, ③ Python 3.12 설치 파일과 uv 실행 파일,
④ 의존 패키지 wheel 묶음.

인터넷 PC에서 wheel 묶음을 준비한다.

```powershell
uv export --no-dev --no-hashes --format requirements-txt -o requirements.txt
uv run --with pip python -m pip download -r requirements.txt -d wheels --only-binary=:all: --platform win_amd64 --python-version 3.12
```

폐쇄망 PC에서 설치한다.

```powershell
uv venv --python 3.12
uv pip install --no-index --find-links wheels -r requirements.txt
.venv\Scripts\python -m oss_vuln_fix_finder scan --input ... --bundle ... --output output
```

폐쇄망에서는 `uv run` 대신 `.venv\Scripts\python`으로 실행한다(`uv run`은 의존성 동기화를 위해
인터넷을 찾을 수 있다).

## 6. 구조

```
oss_vuln_fix_finder/
  __main__.py      CLI (collect, scan)
  io_excel.py      입력 읽기·검증, 보고서 쓰기
  mapping.py       매핑 파일 로드
  bundle.py        묶음 zip 쓰기·읽기(네트워크 없음)
  scan.py          scan 흐름
  collect/         네트워크 수집(http, nvd, osv, maven, runner) — scan은 import하지 않는다
  analyze/         파서, 범위 판정, CVE 병합, 조치 버전 판정
  versions/        버전 규칙(maven, openssl, letter_suffix, semver_like)
config/component_map.yaml
tests/             pytest (fixtures/에 NVD·OSV·Maven 응답 샘플)
```
