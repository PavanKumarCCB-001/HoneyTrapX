# Fake Filesystem Structure for HoneyTrapX
# Mimics a Linux environment with decoy files and canary tokens.

FS_TREE = {
    "/": {
        "type": "dir",
        "children": {
            "etc": {
                "type": "dir",
                "children": {
                    "passwd": {"type": "file", "content": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:105:110:MySQL Server,,,:/nonexistent:/bin/false\nubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash"},
                    "shadow": {"type": "file", "content": "root:$6$vG8$fakehash:18500:0:99999:7:::\nadmin:$6$fake$hash:18500:0:99999:7:::"},
                    "hosts": {"type": "file", "content": "127.0.0.1 localhost\n192.168.1.10 web-server\n192.168.1.20 db-server-internal\n10.0.0.5 backup-node"},
                    "crontab": {"type": "file", "content": "# /etc/crontab\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n30 2 * * * root /usr/local/bin/backup_db.sh > /dev/null 2>&1"},
                }
            },
            "home": {
                "type": "dir",
                "children": {
                    "admin": {
                        "type": "dir",
                        "children": {
                            ".bash_history": {"type": "file", "content": "ls -la\ncd /var/www/html\ncat .env\nssh admin@backup-node\nsudo su -"},
                            ".ssh": {
                                "type": "dir",
                                "children": {
                                    "authorized_keys": {"type": "file", "content": "ssh-rsa AAAAB3Nza... fake-key-admin@workstation"}
                                }
                            },
                            "documents": {
                                "type": "dir",
                                "children": {
                                    "passwords.txt": {"type": "file", "content": "Critical Passwords:\n- MySQL: root / db_p@ssw0rd_2024\n- Admin Panel: admin / SuperSecure789\n- AWS: AKIA... / secret...", "canary": "TOKEN_PASSWORDS_TXT"},
                                    "backup.sql": {"type": "file", "content": "-- MySQL dump 10.13\n-- Host: localhost    Database: prod_db\nINSERT INTO `users` VALUES (1,'admin','hash...','admin@example.com');", "canary": "TOKEN_BACKUP_SQL"},
                                    "notes.txt": {"type": "file", "content": "TODO: Change the credentials in .env file in the web root. It's currently exposed if someone finds it."}
                                }
                            }
                        }
                    },
                    "ubuntu": {"type": "dir", "children": {}}
                }
            },
            "var": {
                "type": "dir",
                "children": {
                    "www": {
                        "type": "dir",
                        "children": {
                            "html": {
                                "type": "dir",
                                "children": {
                                    "index.php": {"type": "file", "content": "<?php echo 'Welcome to Company Intranet'; ?>"},
                                    "config.php": {"type": "file", "content": "<?php\n$db_host = 'localhost';\n$db_user = 'db_admin';\n$db_pass = 'p@ssw0rd123';\n$db_name = 'intranet_db';\n?>"},
                                    ".env": {"type": "file", "content": "DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=prod_db\nDB_USERNAME=root\nDB_PASSWORD=root_secure_password\nAPI_KEY=sk_live_51M...fake", "canary": "TOKEN_ENV_FILE"}
                                }
                            }
                        }
                    }
                }
            },
            "tmp": {
                "type": "dir",
                "children": {}
            },
            "root": {
                "type": "dir",
                "children": {
                    ".bash_history": {"type": "file", "content": "apt update\napt upgrade\nrm -rf /tmp/*\nreboot"}
                }
            }
        }
    }
}

def get_node(path):
    """Retrieves a node (dir or file) from the FS_TREE based on an absolute path."""
    if not path.startswith("/"):
        return None
    if path == "/":
        return FS_TREE["/"]

    parts = [p for p in path.split("/") if p]
    current = FS_TREE["/"]

    for part in parts:
        if current["type"] != "dir" or part not in current["children"]:
            return None
        current = current["children"][part]

    return current

def list_dir(path):
    """Returns a list of items in a directory."""
    node = get_node(path)
    if node and node["type"] == "dir":
        return list(node["children"].keys())
    return None

def read_file(path):
    """Returns the content of a file and whether it's a canary."""
    node = get_node(path)
    if node and node["type"] == "file":
        return node["content"], node.get("canary")
    return None, None
