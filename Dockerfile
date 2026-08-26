FROM python:3.11-slim

# 기본 도구 + ping/ARP/iproute2
RUN apt-get update && apt-get install -y --no-install-recommends \
        iputils-ping iproute2 net-tools tar \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 소스 전체 복사 (Dell tarball이 있으면 함께 복사됨)
COPY . .

# Dell iDRAC Tools — tarball이 있을 때만 설치 (선택 사항)
# 빌드 전 idrac_finder/ 폴더에 Dell-iDRACTools*.tar.gz 파일을 넣어두면 racadm이 설치됩니다.
RUN set -e; \
    TARBALL=$(ls Dell-iDRACTools*.tar.gz 2>/dev/null | head -1); \
    if [ -n "$TARBALL" ]; then \
        echo "[INFO] Dell iDRAC Tools tarball 발견: $TARBALL — 설치 시작"; \
        mkdir -p /tmp/idractools; \
        tar -xzf "$TARBALL" -C /tmp/idractools; \
        HAPI=$(find /tmp/idractools -name "srvadmin-hapi_*.deb" -path "*/UBUNTU22/x86_64/*" | head -1); \
        DEB=$(find /tmp/idractools -name "srvadmin-idracadm8_*.deb" -path "*/UBUNTU22/x86_64/*" | head -1); \
        if [ -n "$HAPI" ] && [ -n "$DEB" ]; then \
            IDRACADM7=$(find /tmp/idractools -name "srvadmin-idracadm7_*.deb" -path "*/UBUNTU22/x86_64/*" | head -1); \
            apt-get update; \
            apt-get install -y --no-install-recommends pciutils libargtable2-0 || apt-get install -y --no-install-recommends pciutils; \
            printf '#!/bin/sh\nexit 0\n' > /usr/bin/systemctl && chmod +x /usr/bin/systemctl; \
            printf '#!/bin/sh\nexit 0\n' > /sbin/chkconfig && chmod +x /sbin/chkconfig; \
            [ -n "$IDRACADM7" ] && dpkg --force-all -i "$IDRACADM7" || true; \
            dpkg --force-all -i "$HAPI" && dpkg --force-all -i "$DEB"; \
            RACADM_BIN=$(dpkg -L srvadmin-idracadm7 2>/dev/null | grep -E "racadm-wrapper|idracadm7" | grep -v "^/$" | head -1); \
            if [ -n "$RACADM_BIN" ] && [ -f "$RACADM_BIN" ]; then \
                ln -sf "$RACADM_BIN" /usr/local/bin/racadm; \
                echo "[OK] racadm → $RACADM_BIN"; \
                /usr/local/bin/racadm --version 2>&1 || true; \
            else \
                echo "[WARN] racadm 바이너리 없음"; \
            fi; \
        else \
            echo "[WARN] hapi 또는 racadm8 .deb 없음 — racadm 미설치"; \
            find /tmp/idractools -name "*.deb"; \
        fi; \
        rm -rf /tmp/idractools /var/lib/apt/lists/*; \
    else \
        echo "[INFO] Dell iDRAC Tools tarball 없음 — racadm 없이 빌드 (Redfish 전용 모드)"; \
    fi

EXPOSE 5001
CMD ["python", "scanner.py"]
