# EduRankAI Security Log Analysis

**Task 6 — Security Log Analysis and Interpretation**

A small, dependency-free toolkit and worked investigation for analyzing security logs. The project includes synthetic sample logs, a parser that flags suspicious activity, written findings, and an incident report.

All data is synthetic.

## Project Files

| File | Purpose |
|---|---|
| `auth.log`, `apache_access.log`, `firewall.log`, `windows_security.csv` | Sample security logs |
| `analyze_logs.py` | Parses logs and detects suspicious activity |
| `generate_sample_logs.py` | Regenerates sample logs |
| `test_analyzer.py` | Unit tests |
| `analysis_output.txt` | Example analyzer output |
| `findings.md` | Investigation findings, timeline, and indicators of compromise |
| `incident_report.md` | Incident report with recommendations and MITRE ATT&CK mapping |
| `Makefile`, `.gitignore`, `LICENSE` | Project configuration and license |

## Detection Capabilities

- **Linux authentication logs:** SSH brute-force attempts, successful logins after failures, sudo commands, new users, and cron activity.
- **Apache access logs:** Potential SQL injection, path traversal, scanner user agents, and webshell requests.
- **Firewall logs:** Periodic outbound connections and internal SMB probing.
- **Windows Security logs:** RDP login failures (Event ID 462