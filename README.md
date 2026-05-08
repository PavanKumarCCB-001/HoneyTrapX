# HoneyTrapX v2.0 - High-Interaction Real-Time Honeypot

HoneyTrapX has been upgraded from a simple listener to a stateful, high-interaction honeypot with real-time analytics and MITRE ATT&CK mapping.

## New Features
- **Stateful Sessions**: Attackers interacting via SSH/Telnet-style lures are given a persistent decoy environment.
- **Decoy Filesystem**: A realistic Linux directory structure with "Canary" files that trigger instant alerts.
- **Real-Time Dashboard**: Powered by Flask-SocketIO, featuring:
    - **Global Threat Map**: Visualizes attacker locations using Geo-IP enrichment.
    - **Live Event Stream**: Matrix-style scroll of incoming attacks with threat scoring.
    - **MITRE ATT&CK Tagging**: Automatically classifies attacks (e.g., T1110 for Brute Force, T1190 for Exploit Public-Facing App).
    - **Threat Scoring**: Dynamic scoring based on interaction depth and suspiciousness.
- **Web Decoys**: Fake `/admin`, `/phpmyadmin`, and SQL injection traps.
- **Dockerized**: Easy deployment using Docker and Docker Compose.

## Installation & Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run with Docker (Recommended)
```bash
docker-compose up --build
```

### 3. Manual Execution
#### i. Run the Services
You can use the provided helper script:
```bash
./run.sh
```
Or run manually:
```bash
python honeypot.py &
python app.py
```

#### ii. Testing (Simulation)
Use the included attacker simulator to generate realistic traffic:
```bash
python attacker_sim.py
```

## Security Note
This is a honeypot designed for research and educational purposes. It is configured to run on high ports (2222, 2121, etc.) by default to avoid requiring root privileges and to prevent accidental exposure of host services.

## File Structure
- `honeypot.py`: Core multi-port listener and session handler.
- `app.py`: Web dashboard and SocketIO server.
- `analyzer.py`: Logic for MITRE mapping and threat scoring.
- `session_engine.py`: Manages stateful shell interactions.
- `fake_filesystem.py`: Defines the decoy directory structure.
- `canary.py`: Alerting logic for sensitive file access.
- `attacker_sim.py`: Penetration testing simulator.
