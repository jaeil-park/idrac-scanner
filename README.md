# iDRAC Scanner

Dell iDRAC 장비를 네트워크에서 자동으로 스캔하고 일괄 설정을 적용하는 웹 애플리케이션입니다.

## 주요 기능

- **자동 스캔**: ARP + OUI 필터 → 포트 스캔 → Redfish 핑거프린팅
- **서비스 태그 조회**: Dell iDRAC Redfish API를 통한 시리얼 번호 / 모델 수집
- **일괄 설정**: Redfish PATCH / racadm CLI 프리셋을 여러 장비에 동시 적용
- **장비 관리**: 등록/미등록 구분, 카테고리 태그, 자격증명 저장
- **서브넷 계산기**: CIDR 범위 계산 및 스캔 범위 추가

## 문서

- [배포 가이드 (DEPLOY.md)](docs/DEPLOY.md) — Docker Compose / Portainer / 로컬 실행 등 전체 배포 방법

## 빠른 시작 (Docker Compose)

```bash
# 1. 저장소 클론
git clone https://github.com/YOUR_GITHUB_USER/idrac-scanner.git
cd idrac-scanner

# 2. 자격증명 설정 (.env 파일 생성)
cp .env.example .env
# .env 파일을 편집하여 IDRAC_FALLBACK_CREDS에 실제 iDRAC 패스워드 입력

# 3. 실행
docker compose up -d

# 웹 UI 접속: http://localhost:5010
```

## 환경 변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `PORT` | `5010` | 웹 서버 포트 |
| `DB_PATH` | `/data/known_devices.db` | 장비 DB 경로 (볼륨 마운트) |
| `IDRAC_FALLBACK_CREDS` | `[["root","calvin"]]` | iDRAC 폴백 자격증명 JSON 배열 |

### IDRAC_FALLBACK_CREDS 예시

```env
IDRAC_FALLBACK_CREDS=[["root","calvin"],["root","MyPassword1"],["admin","secret"]]
```

## Dell iDRAC Tools (racadm) 선택적 설치

racadm CLI 명령을 사용하려면 Dell iDRAC Tools tarball을 프로젝트 루트에 넣고 로컬 빌드합니다:

```bash
# Dell iDRAC Tools tarball을 프로젝트 폴더에 복사
cp /path/to/Dell-iDRACTools-Web-LX-*.tar.gz .

# 로컬 빌드
docker compose build
docker compose up -d
```

tarball이 없으면 Redfish API 전용 모드로 동작합니다 (racadm 명령 불가).

## 네트워크 요구사항

ARP 스캔을 위해 컨테이너가 호스트 네트워크 스택에 직접 접근해야 합니다.
`docker-compose.yml`의 `network_mode: host`와 `NET_RAW` / `NET_ADMIN` 권한이 필요합니다.

Linux 호스트에서만 `network_mode: host`가 정상 동작합니다.

## 개발 / 로컬 실행

```bash
pip install -r requirements.txt
export IDRAC_FALLBACK_CREDS='[["root","calvin"]]'
export DB_PATH=./known_devices.db
python scanner.py
```
