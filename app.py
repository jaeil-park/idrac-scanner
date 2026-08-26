import re
import json
from datetime import datetime

import requests
from bs4 import BeautifulSoup
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# ── 라우터 접속 설정 ─────────────────────────────────────────
ROUTER_URL  = "http://192.168.0.1"
ROUTER_USER = "admin"
ROUTER_PASS = "admin"          # 실제 비밀번호로 변경

# ── Dell / iDRAC MAC OUI 목록 (첫 3옥텟) ────────────────────
DELL_OUIS = {
    "00:0B:DB", "00:14:22", "00:1A:A0", "00:1E:C9", "00:21:9B",
    "00:22:19", "00:23:AE", "00:24:E8", "00:26:B9",
    "14:18:77", "18:66:DA", "24:6E:96", "34:17:EB", "3C:2C:54",
    "44:A8:42", "54:BF:64", "78:2B:CB", "84:8F:69", "B0:83:FE",
    "B8:CA:3A", "D0:94:66", "EC:F4:BB", "F0:1F:AF", "F4:8E:38",
    "F8:BC:12",
}


def normalize_mac(mac: str) -> str:
    """MAC 주소를 XX:XX:XX:XX:XX:XX 대문자 형식으로 정규화"""
    mac = mac.upper().replace("-", ":").replace(".", ":")
    parts = mac.split(":")
    return ":".join(p.zfill(2) for p in parts) if len(parts) == 6 else mac


def oui(mac: str) -> str:
    return ":".join(normalize_mac(mac).split(":")[:3])


def is_dell(mac: str) -> bool:
    return oui(mac) in DELL_OUIS


def router_session() -> requests.Session | None:
    """ipTIME 로그인 후 세션 반환"""
    s = requests.Session()
    s.headers["User-Agent"] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    )
    try:
        # 일부 펌웨어는 먼저 GET 으로 토큰을 받아야 함
        s.get(f"{ROUTER_URL}/", timeout=5)
        s.post(
            f"{ROUTER_URL}/sess-bin/login_handler.cgi",
            data={"username": ROUTER_USER, "passwd": ROUTER_PASS},
            timeout=8,
            allow_redirects=True,
        )
        return s
    except requests.RequestException as e:
        return None


def parse_hosts(html: str) -> list[dict]:
    """ipTIME DHCP 호스트 테이블 HTML 파싱"""
    soup = BeautifulSoup(html, "html.parser")
    hosts: list[dict] = []
    seen: set[str] = set()

    for table in soup.find_all("table"):
        for row in table.find_all("tr"):
            cells = [td.get_text(strip=True) for td in row.find_all("td")]
            if len(cells) < 2:
                continue
            # 첫 번째 셀이 IP 주소인 행만 처리
            if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", cells[0]):
                continue
            ip       = cells[0]
            mac_raw  = cells[1] if len(cells) > 1 else ""
            hostname = cells[2] if len(cells) > 2 else ""
            conn     = cells[3] if len(cells) > 3 else ""

            if ip in seen:
                continue
            seen.add(ip)

            mac = normalize_mac(mac_raw) if mac_raw else ""
            hosts.append(
                {
                    "ip":        ip,
                    "mac":       mac,
                    "hostname":  hostname,
                    "conn_type": conn,
                    "is_dell":   is_dell(mac) if mac else False,
                    "oui":       oui(mac) if mac else "",
                }
            )
    return hosts


def fetch_hosts(custom_url: str = "", custom_user: str = "", custom_pass: str = "") -> dict:
    """라우터에서 DHCP 호스트 목록 가져오기"""
    base    = custom_url  or ROUTER_URL
    user    = custom_user or ROUTER_USER
    passwd  = custom_pass or ROUTER_PASS

    s = requests.Session()
    s.headers["User-Agent"] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    )

    try:
        s.get(f"{base}/", timeout=5)
        s.post(
            f"{base}/sess-bin/login_handler.cgi",
            data={"username": user, "passwd": passwd},
            timeout=8,
            allow_redirects=True,
        )
    except requests.RequestException as e:
        return {"error": f"라우터 접속 실패: {e}", "hosts": []}

    # ipTIME 내부 네트워크 설정 페이지 (사용중인 IP 주소 정보 포함)
    urls_to_try = [
        f"{base}/sess-bin/timepro.cgi?tmenu=netconf&smenu=lanhosts",
        f"{base}/sess-bin/timepro.cgi?tmenu=netconf&smenu=lanhosts_status",
        f"{base}/sess-bin/timepro.cgi?tmenu=main_frame&smenu=lanhosts",
    ]

    html = ""
    for url in urls_to_try:
        try:
            r = s.get(url, timeout=8)
            if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", r.text):
                html = r.text
                break
        except requests.RequestException:
            continue

    if not html:
        return {"error": "호스트 페이지를 찾을 수 없습니다. 라우터 IP·계정을 확인하세요.", "hosts": []}

    hosts = parse_hosts(html)
    hosts.sort(key=lambda h: (not h["is_dell"], [int(x) for x in h["ip"].split(".")]))

    return {
        "hosts":      hosts,
        "total":      len(hosts),
        "dell_count": sum(1 for h in hosts if h["is_dell"]),
        "updated":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "error":      None,
    }


# ── Flask 라우트 ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html",
                           router_url=ROUTER_URL,
                           router_user=ROUTER_USER)


@app.route("/api/hosts")
def api_hosts():
    url  = request.args.get("url",  "")
    user = request.args.get("user", "")
    pwd  = request.args.get("pass", "")
    data = fetch_hosts(url, user, pwd)
    return jsonify(data)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
