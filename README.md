# 🛡️ HoneyTrapX v2.0 - High-Interaction Real-Time Honeypot

HoneyTrapX has been evolved from a simple port listener into a **Stateful, High-Interaction Honeypot** designed to capture, analyze, and visualize attacker behavior in real-time.

---

## ✨ Key Features

- **🧠 Stateful Sessions**: Real-time tracking of attacker interactions across multiple protocols.
- **🐚 High-Interaction Lures**: Emulated shell environments for SSH and Telnet that provide a realistic "hacker experience."
- **📁 Decoy Filesystem**: A complete fake Linux directory structure with "Canary" files that trigger instant high-severity alerts.
- **📊 Real-Time Analytics Dashboard**:
    - **Global Threat Map**: Live visualization of attacker origins via Geo-IP enrichment.
    - **MITRE ATT&CK Mapping**: Automatic classification of attack patterns (e.g., Brute Force, Directory Traversal).
    - **Dynamic Threat Scoring**: AI-ready scoring system (0-100) based on the depth and danger of the interaction.
    - **Event Stream**: Live "Matrix-style" scroll of incoming telemetry.
- **🕸️ Multi-Protocol Support**: Dedicated listeners for FTP (2121), SSH (2222), Telnet (2323), HTTP (8080), HTTPS (8443), and MySQL (33060).
- **🐳 Dockerized Deployment**: One-command setup for rapid deployment.

---

## 🚀 Quick Start

### 1. Installation
Ensure you have Python 3.8+ installed.
```bash
pip install -r requirements.txt
```

### 2. Launching the Honeypot
#### Option A: Using Docker (Recommended)
```bash
docker-compose up --build
```

#### Option B: Manual Start (Linux/Mac)
```bash
./run.sh
```

### 3. Visualizing Attacks
Open your browser and navigate to:
👉 **[http://localhost:5000](http://localhost:5000)**

---

## 🧪 Testing the System (Simulation)
We've included a powerful **Attacker Simulator** to help you verify the detection capabilities.

In a new terminal, run:
```bash
python attacker_sim.py
```
Watch the dashboard update in real-time as the script performs:
- Network scanning & service discovery.
- SSH password brute-forcing.
- Web vulnerability probing (SQLi, Path Traversal).
- Interactive shell session & sensitive file exfiltration.

---

## 📁 File Structure & Architecture
- `honeypot.py`: The core engine handling multi-port connections.
- `app.py`: The Flask-SocketIO dashboard and API gateway.
- `session_engine.py`: Manages the state and history of individual attackers.
- `fake_filesystem.py`: Defines the decoy OS structure and file content.
- `analyzer.py`: Intelligence logic for MITRE mapping and threat scoring.
- `canary.py`: Alerting logic for unauthorized access to sensitive decoys.
- `attacker_sim.py`: Automated red-team simulation tool.

---

## ⚠️ Security Note
This project is for **Educational and Research Purposes**. It is configured to run on **High Ports** (e.g., 2222 instead of 22) to avoid requiring root privileges and to prevent accidental interference with host services. Always deploy in a controlled, isolated environment.
