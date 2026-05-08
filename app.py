from flask import Flask, render_template, jsonify, send_from_directory, request, abort
from flask_socketio import SocketIO, emit
from analyzer import analyze_payload, get_mitre_info, calculate_score, load_data
import os
import json
import csv
from datetime import datetime

app = Flask(__name__, static_folder=".")
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'honeypot-secret-123')
socketio = SocketIO(app, cors_allowed_origins="*")

LOG_FILE = "logs/attacks.csv"

def get_ip_score(ip):
    df = load_data()
    if df.empty: return 10
    ip_history = df[df['attacker_ip'] == ip]
    if ip_history.empty: return 10
    return calculate_score(ip_history)

@app.route('/')
def dashboard_redirect():
    return render_template('index.html')

@app.route('/dashboard')
def index():
    return render_template('index.html')

# --- Decoy Web Endpoints ---

@app.route('/admin')
def admin_login():
    log_http_attack("Access /admin - Fake Login Panel")
    return render_template('admin_login.html')

@app.route('/phpmyadmin')
def phpmyadmin():
    log_http_attack("Access /phpmyadmin - Fake Database Panel")
    return render_template('phpmyadmin.html')

@app.route('/.env')
def exposed_env():
    log_http_attack("Access /.env - Canary Token Triggered", 40)
    return "DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=prod_db\nDB_USERNAME=root\nDB_PASSWORD=root_secure_password\nAPI_KEY=sk_live_51M...fake"

@app.route('/config.php')
def exposed_config():
    log_http_attack("Access /config.php - Exposed Credentials")
    return "<?php\n$db_host = 'localhost';\n$db_user = 'db_admin';\n$db_pass = 'p@ssw0rd123';\n$db_name = 'intranet_db';\n?>"

@app.route('/robots.txt')
def robots():
    return "User-agent: *\nDisallow: /admin\nDisallow: /phpmyadmin\nDisallow: /.env\nDisallow: /backup\nDisallow: /config.php"

@app.route('/api/v1/users')
def api_users():
    return jsonify([
        {"id": 1, "username": "admin", "email": "admin@company.com"},
        {"id": 2, "username": "developer", "email": "dev@company.com"}
    ])

@app.route('/login', methods=['POST'])
def handle_login():
    user = request.form.get('username')
    pw = request.form.get('password')
    log_http_attack(f"Login Attempt: {user}:{pw}", 15)
    if user == 'admin' and pw == 'admin':
        return "<h1>Admin Dashboard</h1><p>Welcome back, Admin.</p>"
    return "Invalid credentials", 401

@app.route('/api/report_attack', methods=['POST'])
def report_attack():
    data = request.json
    ip = data.get('attacker_ip')
    payload = data.get('payload', '')

    tags, _ = analyze_payload(payload)
    mitre_tags = get_mitre_info(tags)

    data['mitre_tags'] = mitre_tags

    # Calculate score before saving to avoid double-logging or re-reading
    score = get_ip_score(ip)
    data['threat_score'] = score

    save_to_csv(data)
    socketio.emit('new_attack', data)
    return jsonify({"status": "ok"}), 200

@app.route('/api/canary_alert', methods=['POST'])
def canary_alert():
    data = request.json
    ip = data.get('attacker_ip')

    save_to_csv(data) # Log the canary event too
    score = get_ip_score(ip)
    data['threat_score'] = score

    socketio.emit('canary_triggered', data)
    return jsonify({"status": "ok"}), 200

# --- Helper Functions ---

def log_http_attack(payload, score_inc=10):
    ip = request.remote_addr
    tags, _ = analyze_payload(payload)
    mitre_tags = get_mitre_info(tags)

    data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attacker_ip": ip,
        "target_port": 5000, # Trap on the dashboard/web port
        "service": "HTTP-Trap",
        "payload": payload,
        "country": "Local",
        "city": "Local",
        "lat": 0,
        "lon": 0,
        "mitre_tags": mitre_tags
    }
    save_to_csv(data)

    score = get_ip_score(ip)
    data['threat_score'] = score

    socketio.emit('new_attack', data)

def save_to_csv(data):
    os.makedirs('logs', exist_ok=True)
    header = not os.path.exists(LOG_FILE)

    # Ensure all required fields exist to prevent CSV misalignment
    fieldnames = ["timestamp","attacker_ip","target_port","service","payload","country","city","lat","lon","threat_score","mitre_tags","session_id"]

    # Sanitize payload to remove newlines which break CSV
    if 'payload' in data and isinstance(data['payload'], str):
        data['payload'] = data['payload'].replace('\n', ' ').replace('\r', ' ')

    with open(LOG_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if header: writer.writeheader()
        row = {k: data.get(k, '') for k in fieldnames}
        writer.writerow(row)

if __name__ == '__main__':
    socketio.run(app, debug=False, port=5000, host='0.0.0.0')
