import os
import platform
import getpass
import subprocess
from datetime import datetime
import sys

findings_count = 0
report_file = f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
print("========================================")
print("   Linux Privilege Escalation Auditor")
print("========================================")


# ----------------------------------------
# System Information
# ----------------------------------------

print("\n[+] System Information")

print("Operating System :", platform.system())
print("OS Release       :", platform.release())
print("Kernel Version   :", platform.version())
print("Architecture     :", platform.machine())


# ----------------------------------------
# User Information
# ----------------------------------------

print("\n[+] User Information")

print("Username         :", getpass.getuser())
print("User ID          :", os.getuid())


# ----------------------------------------
# Current Privileges
# ----------------------------------------

print("\n[+] Current Privileges")

result = subprocess.run(
    ["id"],
    capture_output=True,
    text=True
)

print(result.stdout.strip())


# ----------------------------------------
# Current Directory
# ----------------------------------------

print("\n[+] Current Directory")

print(os.getcwd())


print("\n========================================")
print("   Basic Audit Completed")
print("========================================")


# ----------------------------------------
# Sudo Privileges
# ----------------------------------------

print("\n[+] Sudo Privileges")

sudo_result = subprocess.run(
    ["sudo", "-l"],
    capture_output=True,
    text=True
)

print(sudo_result.stdout)

if sudo_result.returncode == 0:
    print("[!] Sudo configuration detected.")
else:
    print("[-] Unable to check sudo privileges.")


# ----------------------------------------
# SUID File Audit
# ----------------------------------------

print("\n[+] SUID File Audit")

suid_count = 0

result = subprocess.run(
    [
        "find",
        "/usr",
        "/bin",
        "/sbin",
        "/opt",
        "-perm",
        "-4000",
        "-type",
        "f"
    ],
    capture_output=True,
    text=True
)


if result.stdout:
    print(result.stdout)
    suid_count = len(result.stdout.strip().splitlines())
else:
    print("[-] No SUID files found.")




# ----------------------------------------
# Linux Capabilities Audit
# ----------------------------------------

print("\n[+] Linux Capabilities Audit")

capabilities_count = 0

result = subprocess.run(
    [
        "getcap",
        "-r",
        "/usr",
        "/bin",
        "/sbin",
        "/opt"
    ],
    capture_output=True,
    text=True
)

if result.stdout:
    print(result.stdout)
    capabilities_count = len(result.stdout.strip().splitlines())
else:
    print("[-] No file capabilities found.")

# ----------------------------------------
# Audit Completed
# ----------------------------------------

# ----------------------------------------
# Writable Directory Audit
# ----------------------------------------

print("\n[+] Writable Directory Audit")

result = subprocess.run(
    [
        "find",
        "/tmp",
        "/var/tmp",
        "/opt",
        "-type",
        "d",
        "-perm",
        "-0002"
    ],
    capture_output=True,
    text=True
)

if result.stdout:
    print(result.stdout)
else:
    print("[-] No world-writable directories found.")
# ----------------------------------------
# Cron Audit
# ----------------------------------------

print("\n[+] Cron Audit")

cron_paths = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly"
]

for path in cron_paths:
    if os.path.exists(path):
        print(f"\nChecking: {path}")

        if os.path.isfile(path):
            try:
                with open(path, "r") as file:
                    print(file.read())
            except PermissionError:
                print("[-] Permission denied.")
        elif os.path.isdir(path):
            try:
                for item in os.listdir(path):
                    print(item)
            except PermissionError:
                print("[-] Permission denied.")

print("\n[+] Systemd Service Audit")

systemd_path = "/etc/systemd/system"

if os.path.exists(systemd_path):
    for root, dirs, files in os.walk(systemd_path):
        for filename in files:
            if filename.endswith(".service"):
                service_file = os.path.join(root, filename)
                print(f"[+] Service file: {service_file}")
                if os.access(service_file, os.W_OK):
                    print("[!] Service file is writable by current user.")
                    findings_count += 1
else:
    print("[-] Systemd service directory not found.")

# ----------------------------------------
# SSH Configuration Audit
# ----------------------------------------

print("\n[+] SSH Configuration Audit")

ssh_config = "/etc/ssh/sshd_config"

if os.path.isfile(ssh_config):
    try:
        with open(ssh_config, "r") as file:
            for line in file:
                line = line.strip()

                if line and not line.startswith("#"):
                    if line.lower().startswith("permitrootlogin"):
                        print("[+] " + line)
                    elif line.lower().startswith("passwordauthentication"):
                        print("[+] " + line)
    except PermissionError:
        print("[-] Permission denied.")
else:
    print("[-] SSH server configuration not found.")

print("\n[+] Findings Summary")
print("Potential issues found:", findings_count)
print("SUID files found:", suid_count)
print("Files with capabilities:", capabilities_count)

print("\n========================================")
print("   Linux Privilege Escalation Audit")
print("   Completed")
print("========================================")

