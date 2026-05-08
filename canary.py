# Canary Token System for HoneyTrapX

import requests
import time

DASHBOARD_ALERTS_URL = "http://127.0.0.1:5000/api/canary_alert"

def trigger_canary(token_id, session_id, ip, port, path):
    """Signals that a canary token has been accessed."""
    print(f"[!!!] CANARY TRIGGERED: {token_id} accessed by {ip} on port {port} (Path: {path})")

    alert_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "token_id": token_id,
        "session_id": session_id,
        "attacker_ip": ip,
        "target_port": port,
        "file_path": path,
        "message": f"CRITICAL: Attacker accessed sensitive file: {path}"
    }

    try:
        requests.post(DASHBOARD_ALERTS_URL, json=alert_data, timeout=1)
    except:
        # Dashboard might be down, ignore
        pass

    return alert_data
