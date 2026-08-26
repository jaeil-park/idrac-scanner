# iDRAC Scanner — 배포 가이드

Dell iDRAC 스캐너를 다양한 환경에 배포하는 방법을 설명합니다.

---

## 목차

1. [사전 준비](#1-사전-준비)
2. [환경 변수 설정](#2-환경-변수-설정)
3. [방법 A — Docker Compose (권장)](#3-방법-a--docker-compose-권장)
4. [방법 B — Docker 단일 명령](#4-방법-b--docker-단일-명령)
5. [방법 C — Portainer 스택](#5-방법-c--portainer-스택)
6. [방법 D — 로컬 직접 실행 (개발용)](#6-방법-d--로컬-직접-실행-개발용)
7. [인증 설정 (선택)](#7-인증-설정-선택)
8. [HTTPS 설정 (선택)](#8-https-설정-선택)
9. [Dell iDRAC Tools (racadm) 선택적 설치](#9-dell-idrac-tools-racadm-선택적-설치)
10. [네트워크 요구사항](#10-네트워크-요구사항)
11. [데이터 영속성](#11-데이터-영속성)
12. [업데이트 방법](#12-업데이트-방법)
13. [문제 해결](#13-문제-해결)

---

## 1. 사전 준비

| 항목 | 최소 버전 | 비고 |
|------|-----------|------|
| OS | Linux (Ubuntu 20.04+, RHEL 8+, Rocky 8+) | ARP 스캔을 위해 Linux 필수 |
| Docker | 24.0 이상 | |
| Docker Compose | v2.20 이상 | `docker compose` (v2) 명령 사용 |
| 네트워크 권한 | `NET_RAW`, `NET_ADMIN` cap | ARP/ICMP 스캔에 필요 |

> **Windows/Mac**: `network_mode: host`가 지원되지 않아 ARP 스캔이 동작하지 않습니다.  
> 스캔 기능은 반드시 **Linux 호스트**에서 실행하세요.

---

## 2. 환경 변수 설정

배포 전 `.env` 파일을 생성합니다 (이 파일은 절대 Git에 커밋하지 마세요).

```bash
cat > .env << 'EOF'
# iDRAC 폴백 자격증명 — JSON 배열 형식
# 스캐너가 순서대로 시도하므로 가장 많이 사용하는 계정을 앞에 배치
IDRAC_FALLBACK_CREDS=[["root","calvin"],["root","패스워드1"],["admin","패스워드2"]]

# 웹 UI 포트 (기본값: 5010)
PORT=5010

# 장비 DB 저장 경로 (Docker 볼륨 권장)
DB_PATH=/data/known_devices.db
EOF
```

### IDRAC_FALLBACK_CREDS 형식 설명

```json
[
  ["root",  "calvin"],
  ["root",  "MyPassword1"],
  ["admin", "AdminPass2"]
]
```

- 배열 내 각 항목은 `["사용자명", "패스워드"]` 쌍
- 스캔 시 DB에 저장된 자격증명 → 목록 순서대로 인증 시도
- `root/calvin` 은 Dell 출하 기본값이므로 항상 포함 권장

---

## 3. 방법 A — Docker Compose (권장)

가장 간단한 배포 방법입니다. `docker-compose.yml`과 `.env` 파일만 있으면 됩니다.

### 3-1. 파일 준비

```bash
# 작업 디렉터리 생성
mkdir idrac-scanner && cd idrac-scanner

# docker-compose.yml 다운로드
curl -O https://raw.githubusercontent.com/jaeil-park/idrac-scanner/main/docker-compose.yml

# .env 파일 생성 (2번 항목 참고)
cat > .env << 'EOF'
IDRAC_FALLBACK_CREDS=[["root","calvin"]]
PORT=5010
DB_PATH=/data/known_devices.db
EOF
```

### 3-2. 실행

```bash
# 이미지 Pull 후 백그라운드 실행
docker compose up -d

# 로그 확인
docker compose logs -f
```

### 3-3. 접속

```
http://<호스트IP>:5010
```

### 3-4. 중지 / 재시작

```bash
docker compose down        # 중지 (데이터 볼륨 유지)
docker compose restart     # 재시작
docker compose down -v     # 중지 + 데이터 볼륨 삭제 (초기화)
```

---

## 4. 방법 B — Docker 단일 명령

`docker-compose.yml` 없이 단일 명령으로 실행합니다.

```bash
docker run -d \
  --name idrac-scanner \
  --restart unless-stopped \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  -e PYTHONUNBUFFERED=1 \
  -e PORT=5010 \
  -e DB_PATH=/data/known_devices.db \
  -e 'IDRAC_FALLBACK_CREDS=[["root","calvin"]]' \
  -v idrac_data:/data \
  ghcr.io/jaeil-park/idrac-scanner:latest
```

---

## 5. 방법 C — Portainer 스택

Portainer Web UI를 통해 배포하는 방법입니다.

### 5-1. Portainer 접속

`http://<Portainer서버IP>:9000` 접속 → Stacks → Add stack

### 5-2. 스택 이름 입력

```
idrac-scanner
```

### 5-3. Web editor에 아래 내용 입력

```yaml
services:
  idrac-scanner:
    image: ghcr.io/jaeil-park/idrac-scanner:latest
    container_name: idrac-scanner
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
    environment:
      - PYTHONUNBUFFERED=1
      - PORT=5010
      - DB_PATH=/data/known_devices.db
      - IDRAC_FALLBACK_CREDS=[["root","calvin"],["root","패스워드"]]
    volumes:
      - idrac_data:/data
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  idrac_data:
```

> `IDRAC_FALLBACK_CREDS` 값을 실제 환경에 맞게 수정하세요.

### 5-4. Deploy the stack 클릭

배포 완료 후 `http://<호스트IP>:5010` 접속

---

## 6. 방법 D — 로컬 직접 실행 (개발용)

Docker 없이 Python으로 직접 실행합니다. Windows에서도 동작하지만 ARP 스캔은 제한됩니다.

### 6-1. Python 환경 준비

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 6-2. 환경 변수 설정 및 실행

```bash
export IDRAC_FALLBACK_CREDS='[["root","calvin"]]'
export DB_PATH=./known_devices.db
export PORT=5010

python scanner.py
```

Windows PowerShell:

```powershell
$env:IDRAC_FALLBACK_CREDS = '[["root","calvin"]]'
$env:DB_PATH = './known_devices.db'
$env:PORT = '5010'
python scanner.py
```

---

## 7. 인증 설정 (선택)

웹 UI에 비밀번호 인증을 추가합니다. `AUTH_PASSWORD`가 비어 있으면 인증이 비활성화됩니다 (기존 방식 그대로).

### .env 설정

```bash
# 웹 UI 로그인 계정 (기본 사용자명: admin)
AUTH_USER=admin
AUTH_PASSWORD=MySecretPassword!

# Flask 세션 서명 키 — 임의의 긴 문자열 권장
SECRET_KEY=$(openssl rand -hex 32)
```

### 동작 방식

| 상태 | 동작 |
|------|------|
| `AUTH_PASSWORD` 미설정 | 인증 없음 (기존 동작) |
| `AUTH_PASSWORD` 설정됨 | 모든 페이지 로그인 필요, API는 401 반환 |

---

## 8. HTTPS 설정 (선택)

### 방법 1 — 기존 인증서 사용

```bash
SSL_CERTFILE=/data/certs/server.crt
SSL_KEYFILE=/data/certs/server.key
```

인증서 파일을 Docker 볼륨 또는 bind-mount로 컨테이너에 제공합니다.

```yaml
volumes:
  - ./certs:/data/certs:ro
  - idrac_data:/data
```

### 방법 2 — 자체 서명 인증서 자동 생성

```bash
SSL_SELF_SIGNED=1
```

컨테이너 시작 시 OpenSSL로 자체 서명 인증서를 자동 생성합니다.  
브라우저에서 보안 경고가 표시되지만 암호화는 작동합니다.

### HTTPS 활성화 시 접속 주소

```
https://<호스트IP>:5010
```

> `PORT` 변수를 `443`으로 변경하면 기본 HTTPS 포트로 접속 가능합니다.

---

## 9. Dell iDRAC Tools (racadm) 선택적 설치

racadm CLI 명령 프리셋을 사용하려면 Dell iDRAC Tools가 필요합니다.  
없으면 **Redfish API 전용 모드**로 동작합니다 (대부분의 기능 사용 가능).

### 설치 방법 (로컬 빌드)

```bash
# 1. Dell 공식 사이트에서 tarball 다운로드 후 프로젝트 루트에 복사
cp /path/to/Dell-iDRACTools-Web-LX-*.tar.gz .

# 2. 소스 코드 클론
git clone https://github.com/jaeil-park/idrac-scanner.git
cd idrac-scanner

# tarball을 해당 폴더에 복사
cp /path/to/Dell-iDRACTools-Web-LX-*.tar.gz .

# 3. 로컬 빌드 + 실행
docker compose build
docker compose up -d
```

> tarball이 없어도 `docker compose pull` 로 받은 ghcr.io 이미지는 정상 실행됩니다.  
> racadm 기능만 비활성화됩니다.

---

## 10. 네트워크 요구사항

| 항목 | 내용 |
|------|------|
| 네트워크 모드 | `host` 모드 필수 (Linux 전용) |
| 필요 포트 (인바운드) | `5010/tcp` — 웹 UI |
| iDRAC 접근 포트 | `443/tcp`, `80/tcp`, `623/udp` (IPMI) |
| ARP 스캔 | 같은 L2 브로드캐스트 도메인에 있어야 함 |
| 크로스 서브넷 | 포트 스캔 + Redfish 핑거프린팅으로 탐지 (ARP 불가) |
| 방화벽 | 호스트에서 iDRAC IP 대역의 443 포트 허용 필요 |

### 스캔 범위 기본값

- `192.168.0.0/23` (192.168.0.0 ~ 192.168.1.255)
- 웹 UI에서 CIDR 단위로 추가/삭제 가능

---

## 11. 데이터 영속성

장비 등록 정보, 자격증명, 프리셋 등은 SQLite DB에 저장됩니다.

| 항목 | 경로 |
|------|------|
| Docker 볼륨명 | `idrac_data` |
| 컨테이너 내부 경로 | `/data/known_devices.db` |

### 백업

```bash
# DB 파일 호스트로 복사
docker cp idrac-scanner:/data/known_devices.db ./backup_$(date +%Y%m%d).db
```

### 복원

```bash
docker cp ./backup_20260826.db idrac-scanner:/data/known_devices.db
docker restart idrac-scanner
```

---

## 12. 업데이트 방법

### Docker Compose

```bash
# 최신 이미지 Pull
docker compose pull

# 컨테이너 재생성
docker compose up -d
```

### Docker 단일 명령

```bash
docker pull ghcr.io/jaeil-park/idrac-scanner:latest
docker stop idrac-scanner && docker rm idrac-scanner
# 방법 B의 docker run 명령 재실행
```

---

## 13. 문제 해결

### 스캔 결과가 없음

```bash
# 컨테이너 내부에서 ping 테스트
docker exec idrac-scanner ping -c 1 192.168.0.1

# ARP 테이블 확인
docker exec idrac-scanner arp -a
```

- `network_mode: host` 설정 확인
- `NET_RAW`, `NET_ADMIN` cap 설정 확인
- 스캔 범위(CIDR)가 실제 iDRAC 대역과 일치하는지 확인

### 서비스 태그가 조회되지 않음

- iDRAC에 동시 접속 가능한 세션 수 제한 (보통 4~8개) 초과 가능
- 스캔 완료 후 자동으로 2초 대기 후 재시도 수행
- iDRAC 웹 UI에서 기존 세션 정리 후 재스캔

### 자격증명 오류

- `IDRAC_FALLBACK_CREDS` 환경변수가 올바른 JSON인지 확인:
  ```bash
  docker exec idrac-scanner env | grep IDRAC_FALLBACK_CREDS
  ```
- 웹 UI → 장비 클릭 → 자격증명 직접 입력 가능

### 로그 확인

```bash
docker logs idrac-scanner --tail 100 -f
```

### 컨테이너 상태 확인

```bash
docker ps -a | grep idrac-scanner
docker inspect idrac-scanner | grep -A5 '"Status"'
```
