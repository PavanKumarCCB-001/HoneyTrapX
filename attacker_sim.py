# Attacker Simulator for HoneyTrapX
# Uses various techniques to test the honeypot's detection and logging.

import socket
import requests
import time
import argparse

def scan_ports(host):
    print(f"[*] Scanning {host}...")
    ports = [2121, 2222, 2323, 8080, 8443, 33060]
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((host, port))
            print(f"  [+] Port {port} OPEN")
            s.close()
        except: pass

def brute_force(host, port):
    print(f"[*] Brute forcing {host}:{port}...")
    for i in range(10):
        try:
            s = socket.socket()
            s.connect((host, port))
            s.recv(1024)
            s.send(b"admin\n")
            s.recv(1024)
            s.send(f"pass{i}\n".encode())
            s.close()
            time.sleep(0.1)
        except: break

def web_attack(host, port):
    url = f"http://{host}:{port}"
    print(f"[*] Probing web server at {url}...")
    paths = ["/", "/admin", "/phpmyadmin", "/.env", "/config.php", "/robots.txt"]
    for path in paths:
        try:
            res = requests.get(url + path)
            print(f"  [+] GET {path} -> {res.status_code}")
        except: pass

    print("[*] Testing SQL Injection...")
    requests.get(url + "/?id=1' OR 1=1 --")

    print("[*] Testing Directory Traversal...")
    requests.get(url + "/?file=../../../../etc/passwd")

def shell_session(host, port):
    print(f"[*] Starting interactive shell session on {host}:{port}...")
    try:
        s = socket.socket()
        s.connect((host, port))
        print(s.recv(1024).decode()) # Banner

        commands = [
            "ls -la",
            "whoami",
            "pwd",
            "cd /home/admin/documents",
            "ls",
            "cat passwords.txt", # Canary!
            "cat backup.sql",     # Canary!
            "uname -a",
            "exit"
        ]

        for cmd in commands:
            time.sleep(1)
            print(f"  > {cmd}")
            s.send((cmd + "\n").encode())
            print(s.recv(4096).decode())

        s.close()
    except Exception as e:
        print(f"  [!] Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["scan", "brute", "web", "shell", "full"], default="full")
    args = parser.parse_args()

    host = "127.0.0.1"

    if args.mode in ["scan", "full"]: scan_ports(host)
    if args.mode in ["brute", "full"]: brute_force(host, 2222)
    if args.mode in ["web", "full"]: web_attack(host, 8080)
    if args.mode in ["shell", "full"]: shell_session(host, 2222)
