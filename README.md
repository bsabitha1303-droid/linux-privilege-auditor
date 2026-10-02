# Linux Privilege Escalation Auditor

## About the Project

Linux Privilege Escalation Auditor is a Python-based, command-line tool designed to audit Linux system configurations and identify potential privilege-related security concerns.

It helps users review system information, permissions, and configurations for defensive security purposes.

## Features

- Collects Linux system information
- Displays current user and privilege details
- Audits sudo privileges
- Identifies SUID files
- Detects files with Linux capabilities
- Checks writable directories
- Reviews cron jobs
- Audits systemd service files
- Checks SSH server configuration
- Displays a findings summary
- Saves audit output to a text report

## Technologies Used

- Python 3
- Linux
- Ubuntu on WSL2
- Visual Studio Code
- Linux command-line utilities

## Requirements

- Python 3
- Linux or Ubuntu on WSL2
- `find` and `getcap` utilities

## How to Run

- Open the project directory in your terminal.

- Run the following command:

   ```bash
   python3 lpea.py
   ```

- To save the audit output to a text file, run:

   ```bash
   python3 lpea.py | tee audit_report.txt
   ```

## Project Structure

```text
linux-privilege-auditor/
├── lpea.py
├── lpea_backup.py
├── README.md
└── audit_report.txt
```

## Purpose

This project is intended for educational and defensive security auditing. It helps users understand Linux permissions and configuration areas that may require further review.

## Limitations

- The tool performs read-only checks.
- Detected SUID files and Linux capabilities are not automatically vulnerabilities.
- The findings summary only reflects conditions currently checked by the script.
- The tool is not a comprehensive vulnerability scanner.
- Results may vary across Linux distributions and environments.

## Disclaimer

Use this tool only on systems you own or have explicit permission to audit. This tool is intended for authorized security auditing and educational use.
