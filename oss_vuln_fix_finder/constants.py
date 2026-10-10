"""프로젝트 전역 상수.

요청 간격, 재시도 횟수, 엑셀 열 이름처럼 여러 모듈이 함께 쓰는 값을 한곳에 모은다
(rules.md 4.4 매직 값 금지).
"""

from datetime import timedelta, timezone

from oss_vuln_fix_finder import __version__

# --- 공통 ---
TOOL_NAME = "oss-vuln-fix-finder"
USER_AGENT = f"{TOOL_NAME}/{__version__}"
KST = timezone(timedelta(hours=9), name="KST")

# --- 외부 API 주소 ---
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
MAVEN_METADATA_URL = "https://repo1.maven.org/maven2/{group_path}/{artifact}/maven-metadata.xml"

# --- 요청 제한 (PRD 4.2-8) ---
# NVD는 API 키가 없으면 30초에 5회까지만 허용하므로 요청 사이를 6초 이상 띄운다.
NVD_MIN_INTERVAL_SEC = 6.0
DEFAULT_MIN_INTERVAL_SEC = 0.5
MAX_RETRIES = 5
BACKOFF_BASE_SEC = 2.0
RETRY_STATUS_CODES = frozenset({403, 429, 500, 502, 503, 504})
HTTP_TIMEOUT_SEC = 60
NVD_CVE_PAGE_SIZE = 2000  # NVD CVE API 최대값
NVD_CPE_PAGE_SIZE = 10000  # NVD CPE API 최대값

# --- 입력 엑셀 (PRD 4.1-2) ---
INPUT_SHEET = "Sheet1"
INPUT_HEADER_NO = "No"
INPUT_HEADER_NAME = "오픈소스 컴포넌트명"
INPUT_HEADER_VERSION = "컴포넌트 버전"

# --- 출력 엑셀 (PRD 4.5-24) ---
OUTPUT_COLUMNS = (
    "No",
    "오픈소스 컴포넌트명\n(Component name)",
    "컴포넌트 버전\n(Component version name)",
    "보안취약점 ID\n(Vulnerability id)",
    "보안취약점 설명\n(Description)",
    "CVSS 점수",
    "심각도",
    "영향 버전 범위",
    "해결 가까운 버전",
    "최신 버전",
    "비고",
    "근거 소스",
    "조회일시",
)
OUTPUT_FILE_PREFIX = "오픈소스_컴포넌트별 취약점목록"
NOTE_SEPARATOR = "; "
NOT_APPLICABLE = "-"
MAX_IDS_IN_NOTE = 5  # 비고에 나열할 CVE ID 최대 개수(나머지는 "외 N건")

# --- 묶음 파일 ---
BUNDLE_SCHEMA_VERSION = 1
BUNDLE_STALE_DAYS = 30  # PRD OQ-5 가정: 30일이 지나면 경고

# --- 데이터 소스 이름 ---
SOURCE_NVD = "NVD"
SOURCE_OSV = "OSV"

# --- 버전 규칙 (PRD 4.4) ---
VERSION_RULE_NAMES = frozenset({"maven", "openssl", "letter_suffix", "semver_like"})
DEFAULT_BRANCH_DEPTH = 2
