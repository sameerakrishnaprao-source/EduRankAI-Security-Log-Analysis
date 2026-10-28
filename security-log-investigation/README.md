# Decode and Interpret Security Logs

A small, dependency-free toolkit and worked investigation for reading security logs: synthetic sample logs, a parser/decoder that flags attack activity, written findings, and an incident report. All data is synthetic (IPs are RFC 5737 / RFC 1918 addresses).

## Files (everything is in this one folder)

| File | Purpose |
|---|---|
| `auth.log`, `apache_access.log`, `firewall.log`, `windows_security.csv` | Sample logs |
| `analyze_logs.py` | Parser + decoder; prints and saves findings |
| `generate_sample_logs.py` | Regenerates the sample logs |
| `test_analyzer.py` | Unit tests |
| `analysis_output.txt` | Output of the analyzer on the sample logs |
| `findings.md` | Decoding guide, findings F1-F10, timeline, IOCs |
| `incident_report.md` | Incident report with recommendations and MITRE ATT&CK mapping |
| `Makefile`, `.gitignore`, `LICENSE` | Project helpers (MIT) |

## What it detects

| Log | Detections |
|---|---|
| Linux `auth.log` | SSH brute force, success-after-failures, sudo commands, new users, cron |
| Apache `access.log` | SQL injection, path traversal, scanner user-agents, webshell requests |
| Firewall | Fixed-interval C2 beaconing, internal SMB probing |
| Windows Security (CSV) | RDP guessing (4625), Office spawning PowerShell (4688), scheduled tasks (4698), decoding of `-enc` base64 commands |

## Run (Python 3.8+, standard library only)

```bash
python3 analyze_logs.py                          # analyse logs in this folder
python3 analyze_logs.py --logs /path/to/logs --out result.txt
python3 generate_sample_logs.py                  # regenerate sample logs
python3 -m unittest discover -s . -v             # run tests
```

Start with `incident_report.md`, then `findings.md`.

## Scenario

An attacker brute-forces SSH on `web01`, gains root, plants a hidden admin account and beacons to a C2 server every 60 s. Hours later a macro-laden Word document on `WS-014` runs encoded PowerShell that contacts the same C2 server.

## License

MIT
