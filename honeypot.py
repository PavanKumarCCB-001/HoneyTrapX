import socket
import threading
import os
import time
import random
import requests
import uuid
from datetime import datetime
from session_engine import SessionManager
from fake_filesystem import read_file
from canary import trigger_canary

LOG_FILE = "logs/attacks.csv"
DASHBOARD_URL = "http://127.0.0.1:5000/api/report_attack"

BANNERS = {
    2121:  b"220 FTP server ready (vsftpd 3.0.3)\r\n",
    2222:  b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n",
    2323:  b"\r\nWelcome to Ubuntu 18.04.4 LTS\r\nlogin: ",
    8080:  b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Length: 0\r\n\r\n",
    8443:  b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Length: 0\r\n\r\n",
    33060: b"5.7.32-MySQL Community Server\r\n",
}

PORT_NAMES = {
    2121: "FTP",
    2222: "SSH",
    2323: "Telnet",
    8080: "HTTP",
    8443: "HTTPS",
    33060: "MySQL",
}

session_manager = SessionManager()

def get_geo(ip):
    if ip in ["127.0.0.1", "localhost"] or ip.startswith("192.168."):
        return "Local Network", "Internal", 0, 0
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if response.get("status") == "success":
            return (
                response.get("country", "Unknown"),
                response.get("city", "Unknown"),
                response.get("lat", 0),
                response.get("lon", 0)
            )
    except: pass
    return "Unknown", "Unknown", 0, 0

def notify_dashboard(attack_data):
    try: requests.post(DASHBOARD_URL, json=attack_data, timeout=1)
    except: pass

def handle_interactive_session(conn, session):
    """Manages the fake shell interaction."""
    conn.settimeout(30)
    try:
        # Initial prompts for telnet/ssh emulation
        if session.target_port == 2323:
            # Login loop
            for _ in range(3):
                data = conn.recv(1024)
                if not data: return
                session.history.append({"ts": time.time(), "in": data.decode(errors="ignore")})
                conn.sendall(b"Password: ")
                data = conn.recv(1024)
                if not data: return
                session.history.append({"ts": time.time(), "in": "****"})
                time.sleep(random.uniform(0.5, 1.5))
                conn.sendall(b"Login incorrect\r\n\r\nlogin: ")
            return

        # Simple Command Loop
        conn.sendall(f"{session.user}@{socket.gethostname()}:{session.cwd}$ ".encode())
        while True:
            data = conn.recv(1024)
            if not data: break

            cmd = data.decode(errors="ignore").strip()
            if not cmd:
                conn.sendall(f"{session.user}@{socket.gethostname()}:{session.cwd}$ ".encode())
                continue

            # Add jitter to mimic real system load
            time.sleep(random.uniform(0.05, 0.4))

            # Intercept cat to check for canaries
            if cmd.startswith("cat "):
                parts = cmd.split()
                if len(parts) > 1:
                    path = parts[1]
                    if not path.startswith("/"):
                        abs_path = os.path.normpath(os.path.join(session.cwd, path))
                    else:
                        abs_path = path

                    _, canary_token = read_file(abs_path)
                    if canary_token:
                        trigger_canary(canary_token, session.session_id, session.ip, session.target_port, abs_path)

            output = session.execute_command(cmd)
            conn.sendall(output.encode())

            if cmd == "exit":
                break

            conn.sendall(f"{session.user}@{socket.gethostname()}:{session.cwd}$ ".encode())

    except Exception as e:
        print(f"Session Error: {e}")
    finally:
        session_manager.end_session(session.session_id)

def handle_connection(conn, addr, port):
    attacker_ip, attacker_port = addr
    session_id = str(uuid.uuid4())
    session = session_manager.create_session(session_id, attacker_ip, port)

    country, city, lat, lon = get_geo(attacker_ip)

    try:
        banner = BANNERS.get(port, b"Connected.\r\n")
        conn.sendall(banner)

        # Log the initial connection for real-time dashboard
        attack_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attacker_ip": attacker_ip,
            "target_port": port,
            "service": PORT_NAMES.get(port, "Unknown"),
            "payload": "Connection established",
            "country": country,
            "city": city,
            "lat": lat,
            "lon": lon,
            "session_id": session_id
        }
        notify_dashboard(attack_data)

        # Interactive shell for SSH/Telnet
        if port in [2222, 2323]:
            handle_interactive_session(conn, session)
        elif port in [8080, 8443]:
            # Web lure: Interactive responses for common paths
            conn.settimeout(5)
            data = conn.recv(4096)
            payload = data.decode(errors="ignore") if data else ""
            session.history.append({"ts": time.time(), "in": payload})

            if payload:
                first_line = payload.splitlines()[0] if payload else ""
                attack_data["payload"] = first_line
                notify_dashboard(attack_data)

                if "GET / " in first_line or "GET /index" in first_line:
                    response = (
                        "HTTP/1.1 200 OK\r\n"
                        "Server: Apache/2.4.41 (Ubuntu)\r\n"
                        "Content-Type: text/html\r\n\r\n"
                        "<html><body><h1>It works!</h1><p>This is the default welcome page.</p>"
                        "<!-- TODO: Move the management console from /admin to a secure port --></body></html>"
                    )
                    conn.sendall(response.encode())
                elif "GET /admin" in first_line:
                    response = (
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/html\r\n\r\n"
                        "<html><body><h2>Admin Login</h2><form>User: <input type='text'><br>Pass: <input type='password'><br><input type='submit'></form></body></html>"
                    )
                    conn.sendall(response.encode())
                elif "GET /phpmyadmin" in first_line:
                    response = "HTTP/1.1 200 OK\r\n\r\nphpMyAdmin - Error: Access Denied"
                    conn.sendall(response.encode())
                elif "GET /.env" in first_line:
                    response = "HTTP/1.1 200 OK\r\n\r\nDB_PASSWORD=secret_pass\nAPI_KEY=sk_live_fake"
                    conn.sendall(response.encode())
                elif "GET /robots.txt" in first_line:
                    response = "HTTP/1.1 200 OK\r\n\r\nUser-agent: *\nDisallow: /admin\nDisallow: /phpmyadmin"
                    conn.sendall(response.encode())
        else:
            # Generic capture for other ports
            conn.settimeout(5)
            data = conn.recv(4096)
            payload = data.decode(errors="ignore") if data else ""
            session.history.append({"ts": time.time(), "in": payload})

            # Update dashboard with payload if any
            if payload:
                attack_data["payload"] = payload[:200]
                notify_dashboard(attack_data)

    except Exception as e:
        pass
    finally:
        try: conn.close()
        except: pass
        session_manager.end_session(session_id)

def start_listener(port):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen(10)
        print(f"[*] Honeypot listening on port {port} ({PORT_NAMES.get(port)})")
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_connection, args=(conn, addr, port), daemon=True).start()
    except Exception as e:
        print(f"[!] Bind error on {port}: {e}")

def run():
    os.makedirs("logs/sessions", exist_ok=True)
    for port in BANNERS.keys():
        threading.Thread(target=start_listener, args=(port,), daemon=True).start()

    print("\n[+] All honeypot services active.")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down.")

if __name__ == "__main__":
    run()
