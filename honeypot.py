import socket
import threading
import csv
import json
import os
import time
import requests
from datetime import datetime

LOG_FILE_CSV = "logs/attacks.csv"
LOG_FILE_JSON = "logs/attacks.json"
DASHBOARD_URL = "http://127.0.0.1:5000/api/report_attack"

# Fake service banners
BANNERS = {
    2121:  b"220 FTP server ready (vsftpd 2.0.1)\r\n",
    2222:  b"SSH-2.0-OpenSSH_4.3\r\n",
    2323:  b"\r\nWelcome to Cisco Router\r\nlogin: ",
    8080:  b"HTTP/1.1 200 OK\r\nServer: Apache/2.2.3\r\nContent-Length: 0\r\n\r\n",
    33060: b"5.0.51a-community\r\n",
    8081:  b"HTTP/1.1 200 OK\r\nServer: Tomcat/4.1\r\n\r\n",
}

PORT_NAMES = {
    2121: "FTP",
    2222: "SSH",
    2323: "Telnet",
    8080: "HTTP",
    33060: "MySQL",
    8081: "HTTP-ALT",
}

ATTACK_TYPES = {
    2121:  "FTP Probe",
    2222:  "SSH Brute Force / Scan",
    2323:  "Telnet Exploit Attempt",
    8080:  "Web Scan / HTTP Probe",
    33060: "Database Attack",
    8081:  "Web App Attack",
}

# Simple fake shell responses
FAKE_SHELL_RESPONSES = {
    "ls": "bin  boot  dev  etc  home  lib  media  mnt  opt  root  run  sbin  srv  sys  tmp  usr  var\n",
    "whoami": "root\n",
    "uname -a": "Linux debian 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2 (2019-08-28) x86_64 GNU/Linux\n",
    "pwd": "/root\n",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\n",
}

os.makedirs("logs", exist_ok=True)

geo_cache = {}

def get_geo(ip):
    if ip in geo_cache: return geo_cache[ip]
    if ip in ["127.0.0.1", "localhost"] or ip.startswith("192.168."):
        return "Local Network", "Internal"
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if response.get("status") == "success":
            geo = (response.get("country", "Unknown"), response.get("city", "Unknown"))
            geo_cache[ip] = geo
            return geo
    except: pass
    return "Unknown", "Unknown"

def init_logs():
    headers = ["timestamp", "attacker_ip", "attacker_port", "target_port",
               "service", "attack_type", "payload", "duration_ms", "country", "city"]
    if not os.path.exists(LOG_FILE_CSV):
        with open(LOG_FILE_CSV, "w", newline="") as f:
            csv.writer(f).writerow(headers)

init_logs()
log_lock = threading.Lock()

def notify_dashboard(attack_data):
    try: requests.post(DASHBOARD_URL, json=attack_data, timeout=1)
    except: pass

def log_attack(ip, attacker_port, target_port, payload, duration_ms):
    country, city = get_geo(ip)
    attack_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attacker_ip": ip, "attacker_port": attacker_port, "target_port": target_port,
        "service": PORT_NAMES.get(target_port, "Unknown"),
        "attack_type": ATTACK_TYPES.get(target_port, "Generic Probe"),
        "payload": payload.replace("\n", " ")[:200],
        "duration_ms": round(duration_ms, 2),
        "country": country, "city": city
    }

    with log_lock:
        # Log to CSV
        with open(LOG_FILE_CSV, "a", newline="") as f:
            csv.writer(f).writerow(list(attack_data.values()))
        # Log to JSON
        with open(LOG_FILE_JSON, "a") as f:
            f.write(json.dumps(attack_data) + "\n")

    print(f"[{attack_data['timestamp']}] {attack_data['service']} hit by {ip} ({country})")
    notify_dashboard(attack_data)

def handle_connection(conn, addr, port):
    start = time.time()
    attacker_ip, attacker_port = addr
    payload_parts = []

    try:
        banner = BANNERS.get(port, b"Connected.\r\n")
        conn.sendall(banner)
        conn.settimeout(10)

        if port in [2222, 2323]:
            # Simple interactive shell lure
            data = conn.recv(1024)
            if data:
                payload_parts.append(data.decode(errors="ignore").strip())
                conn.sendall(b"Username: ")
                user = conn.recv(1024)
                if user:
                    payload_parts.append(f"USER:{user.decode(errors='ignore').strip()}")
                    conn.sendall(b"Password: ")
                    pw = conn.recv(1024)
                    if pw:
                        payload_parts.append(f"PASS:{pw.decode(errors='ignore').strip()}")
                        conn.sendall(b"\r\nWelcome to the restricted shell. Type 'help' for commands.\r\n# ")

                        # Miniature fake shell loop (2 commands max to avoid hanging)
                        for _ in range(2):
                            cmd_data = conn.recv(1024)
                            if not cmd_data: break
                            cmd = cmd_data.decode(errors="ignore").strip().lower()
                            payload_parts.append(f"CMD:{cmd}")
                            if cmd in FAKE_SHELL_RESPONSES:
                                conn.sendall(FAKE_SHELL_RESPONSES[cmd].encode() + b"# ")
                            elif cmd == "exit":
                                break
                            else:
                                conn.sendall(f"sh: {cmd}: command not found\n# ".encode())
        else:
            data = conn.recv(1024)
            if data: payload_parts.append(data.decode(errors="ignore").strip())

    except Exception as e:
        payload_parts.append(f"[Error: {e}]")
    finally:
        duration_ms = (time.time() - start) * 1000
        log_attack(attacker_ip, attacker_port, port, " | ".join(payload_parts), duration_ms)
        try: conn.close()
        except: pass

def start_listener(port):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen(5)
        print(f"[*] Listening on port {port} ({PORT_NAMES.get(port)})")
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_connection, args=(conn, addr, port), daemon=True).start()
    except Exception as e:
        print(f"[!] Could not start listener on {port}: {e}")

def run():
    print("="*50 + "\n   HONEYTRAPX REAL-TIME ENGINE STARTING\n" + "="*50)
    for port in BANNERS.keys():
        threading.Thread(target=start_listener, args=(port,), daemon=True).start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping...")

if __name__ == "__main__":
    run()
