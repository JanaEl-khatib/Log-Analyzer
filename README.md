# Log File Analyzer – Detect Failed Logins & Suspicious Activity

This Python script analyzes system log files to identify:

- Repeated failed login attempts
- Potential brute-force IP addresses
- Suspicious log entries (e.g. "unauthorized", "denied", etc.)

It generates a clean, readable report and optionally saves it to a text file for further review.

---

## Features

- Uses regex to detect failed login attempts from system logs
- Flags IP addresses with repeated login failures (customizable threshold)
- Searches for general suspicious activity based on keywords
- Generates a summary report in the terminal and a `log_analysis_report.txt` file
- Includes a dummy log generator for testing

---

## How to Use

### 1. Clone this repo:
```bash
git clone https://github.com/your-username/log-analyzer.git
cd log-analyzer
python log_analyzer.py
