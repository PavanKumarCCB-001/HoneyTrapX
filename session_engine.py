# Session Engine for HoneyTrapX
# Manages stateful per-connection interactions (shell context).

import time
import os
import json
from fake_filesystem import get_node, list_dir, read_file

class Session:
    def __init__(self, session_id, ip, port):
        self.session_id = session_id
        self.ip = ip
        self.target_port = port
        self.start_time = time.time()
        self.cwd = "/home/admin"
        self.user = "admin"
        self.history = []
        self.is_authenticated = False
        self.env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": f"/home/{self.user}",
            "SHELL": "/bin/bash",
            "TERM": "xterm-256color"
        }

    def execute_command(self, cmd_line):
        """Processes a shell command and returns the output."""
        self.history.append({"timestamp": time.time(), "cmd": cmd_line})
        parts = cmd_line.strip().split()
        if not parts:
            return ""

        cmd = parts[0]
        args = parts[1:]

        if cmd == "pwd":
            return self.cwd + "\n"

        elif cmd == "whoami":
            return self.user + "\n"

        elif cmd == "ls":
            path = self.cwd
            if args:
                # Handle basic path resolution
                if args[0].startswith("/"):
                    path = args[0]
                else:
                    path = os.path.normpath(os.path.join(self.cwd, args[0]))

            items = list_dir(path)
            if items is not None:
                return "  ".join(items) + "\n"
            return f"ls: cannot access '{path}': No such file or directory\n"

        elif cmd == "cd":
            if not args:
                self.cwd = f"/home/{self.user}"
                return ""

            target = args[0]
            if target.startswith("/"):
                path = target
            else:
                path = os.path.normpath(os.path.join(self.cwd, target))

            node = get_node(path)
            if node and node["type"] == "dir":
                self.cwd = path
                return ""
            return f"-bash: cd: {target}: No such file or directory\n"

        elif cmd == "cat":
            if not args:
                return ""

            target = args[0]
            if target.startswith("/"):
                path = target
            else:
                path = os.path.normpath(os.path.join(self.cwd, target))

            content, canary = read_file(path)
            if content is not None:
                # Triggering canary would be handled by a callback or in the caller
                return content + "\n"
            return f"cat: {target}: No such file or directory\n"

        elif cmd == "uname":
            if "-a" in args:
                return "Linux debian 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2 (2019-08-28) x86_64 GNU/Linux\n"
            return "Linux\n"

        elif cmd == "id":
            if self.user == "root":
                return "uid=0(root) gid=0(root) groups=0(root)\n"
            return "uid=1000(admin) gid=1000(admin) groups=1000(admin),24(cdrom),27(sudo),30(dip),46(plugdev),116(lpadmin),126(sambashare)\n"

        elif cmd == "exit":
            return "logout\n"

        elif cmd in ["sudo", "su"]:
            return f"[sudo] password for {self.user}: \n" # Trap for password entry

        return f"-bash: {cmd}: command not found\n"

    def save_transcript(self, log_dir="logs/sessions"):
        os.makedirs(log_dir, exist_ok=True)
        filename = f"{self.ip}_{int(self.start_time)}.json"
        filepath = os.path.join(log_dir, filename)
        data = {
            "session_id": self.session_id,
            "ip": self.ip,
            "port": self.target_port,
            "start_time": self.start_time,
            "end_time": time.time(),
            "history": self.history
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)
        return filepath

class SessionManager:
    def __init__(self):
        self.sessions = {}

    def create_session(self, session_id, ip, port):
        session = Session(session_id, ip, port)
        self.sessions[session_id] = session
        return session

    def get_session(self, session_id):
        return self.sessions.get(session_id)

    def end_session(self, session_id):
        if session_id in self.sessions:
            filepath = self.sessions[session_id].save_transcript()
            del self.sessions[session_id]
            return filepath
        return None
