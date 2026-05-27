"""Upload _probe.py to the router and run it."""
import sys
import paramiko
from pathlib import Path

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("192.168.3.1", port=222, username="root", password="keenetic",
          allow_agent=False, look_for_keys=False, timeout=15)

# Upload via cat heredoc — works on any sh.
probe = Path(__file__).parent / "_probe.py"
content = probe.read_text(encoding="utf-8").replace("\r\n", "\n")
# Use base64 to avoid heredoc / quoting issues entirely.
import base64
b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")

upload = f"echo '{b64}' | base64 -d > /tmp/probe.py && echo uploaded"
stdin, stdout, stderr = c.exec_command(upload, timeout=20)
print(stdout.read().decode())
err = stderr.read().decode()
if err: print("err:", err)

# Run it.
print("--- running ---")
stdin, stdout, stderr = c.exec_command("/opt/bin/python3 /tmp/probe.py 2>&1", timeout=60)
print(stdout.read().decode())
print("(exit", stdout.channel.recv_exit_status(), ")")

c.close()
