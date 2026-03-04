# Security Log Analyzer (Python)

A lightweight Python log parser that flags suspicious authentication activity such as brute-force attempts, password spraying, and successful logins after repeated failures.

This project is built as a SOC-style portfolio piece to demonstrate log analysis skills.

---

## What it Detects

- **Possible brute force**
  - Many failed logins from one IP within a short time window
- **Possible password spraying**
  - One IP failing across multiple different usernames
- **Suspicious success after failures**
  - A successful login from an IP that had multiple recent failures

---

## Supported Inputs

- **Linux auth logs** (auth.log / sshd style)
- **Windows Security logs** (CSV export; focuses on Event IDs 4624 and 4625)

---

## How to Run

### Linux sample
```bash
python log_analyzer.py --linux sample_logs_linux_auth.log
