#!/usr/bin/env python3
"""Parses the sample logs, decodes artefacts, and prints findings. Usage: python3 analyze_logs.py"""
import re, csv, base64, os, argparse, collections, urllib.parse
ROOT = os.path.dirname(os.path.abspath(__file__))
ap_ = argparse.ArgumentParser(description="Decode and interpret security logs")
ap_.add_argument("--logs", default=ROOT, help="directory containing the log files")
ap_.add_argument("--out", default=os.path.join(ROOT, "analysis_output.txt"), help="where to save the text output")
args = ap_.parse_args()
B = args.logs
out = []
def p(s=""): out.append(s); print(s)
def hdr(s): p(); p("="*70); p(s); p("="*70)

# ---- 1. SSH auth.log ----
hdr("1. SSH / AUTH LOG (web01)")
fails, accepts, sudo, other = collections.Counter(), [], [], []
first_fail = {}
fail_users = collections.defaultdict(set)
for line in open(f"{B}/auth.log"):
    t = line.split()[2]
    m = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+)", line)
    if m:
        u, ip = m.groups(); fails[ip] += 1; fail_users[ip].add(u); first_fail.setdefault(ip, t); continue
    m = re.search(r"Accepted (\S+) for (\S+) from (\S+)", line)
    if m: accepts.append((t, *m.groups())); continue
    m = re.search(r"sudo: (\S+) .*COMMAND=(.*)", line)
    if m: sudo.append((t, *m.groups())); continue
    if re.search(r"useradd|usermod|CRON", line): other.append(line.strip())
for ip, n in fails.most_common():
    p(f"Failed logins from {ip}: {n} (first {first_fail[ip]}), accounts tried: {sorted(fail_users[ip])}")
    if n >= 10: p(f"  -> BRUTE FORCE (>=10 failures)")
for t, meth, user, ip in accepts:
    if fails.get(ip, 0) >= 10:
        p(f"[!] {t} SUCCESSFUL login '{user}' via {meth} from {ip} AFTER {fails[ip]} failures -> probable credential compromise")
    else:
        p(f"    {t} normal login '{user}' via {meth} from {ip}")
p("Privileged commands:")
for t, u, c in sudo: p(f"   {t} {u}: {c}")
p("Persistence / account changes:")
for o in other: p("   " + o)

# ---- 2. Apache ----
hdr("2. WEB ACCESS LOG (Apache)")
rx = re.compile(r'(\S+) - - \[(.*?)\] "(\S+) (\S+) [^"]*" (\d+) (\d+) "[^"]*" "([^"]*)"')
sigs = {"SQL injection": r"(?i)(union%20select|union select|or%20'1'='1|drop%20table|sleep\()|id=1'$|' or ",
        "Path traversal": r"(\.\./|\.\.%2f|\.\.\.\.//)",
        "Scanner UA": r"(?i)(nikto|sqlmap|nmap|curl/)",
        "Webshell": r"(?i)(shell\.php|cmd=)"}
hits = collections.defaultdict(list)
for line in open(f"{B}/apache_access.log"):
    m = rx.match(line)
    if not m: continue
    ip, ts, meth, path, st, sz, ua = m.groups()
    dec = urllib.parse.unquote(path)
    for name, pat in sigs.items():
        if re.search(pat, path, re.I) or re.search(pat, dec, re.I) or (name == "Scanner UA" and re.search(pat, ua)):
            hits[(ip, name)].append((ts.split(":",1)[1].split()[0], meth, dec, st, sz))
for (ip, name), ev in sorted(hits.items()):
    p(f"{ip}  {name}: {len(ev)} request(s)")
    for t, meth, dec, st, sz in ev:
        flag = "  <-- 200 OK = may have SUCCEEDED" if st == "200" and name != "Scanner UA" else ""
        p(f"     {t} {meth} {dec[:75]} -> {st} ({sz}B){flag}")

# ---- 3. Firewall ----
hdr("3. FIREWALL LOG")
out_c = collections.defaultdict(list)
for line in open(f"{B}/firewall.log"):
    d = dict(re.findall(r"(\w+)=(\S+)", line)); ts, act, dr = line.split()[:3]
    if dr == "OUT" and d["DST"].startswith("198.51.100"): out_c[(d["SRC"], d["DST"], d["DPT"])].append(ts[11:19])
for (s, d, port), ts in out_c.items():
    gaps = [(int(b[3:5])*60+int(b[6:])) - (int(a[3:5])*60+int(a[6:])) for a, b in zip(ts, ts[1:])]
    tag = f"  -> BEACONING every ~{round(sum(gaps)/len(gaps))}s" if len(ts) > 5 and gaps and max(gaps)-min(gaps) <= 2 else ""
    p(f"{s} -> {d}:{port}  {len(ts)} conn(s) {ts[0]}..{ts[-1]}{tag}")
p("Lateral movement attempts (SMB/445 internal):")
for line in open(f"{B}/firewall.log"):
    if "DPT=445" in line: p("   " + line.strip())

# ---- 4. Windows ----
hdr("4. WINDOWS SECURITY EVENTS (WS-014)")
ev = {4624:"Logon success",4625:"Logon FAILED",4688:"Process created",4698:"Scheduled task created"}
c = collections.Counter(); 
for r in csv.DictReader(open(f"{B}/windows_security.csv")):
    eid = int(r["EventID"])
    if eid == 4625: c[(r["Account"], re.search(r"SourceIP=(\S+)", r["Details"]).group(1))] += 1
    elif eid in (4688, 4698):
        p(f"{r['TimeCreated']} [{eid} {ev[eid]}] {r['Account']}: {r['Details'][:110]}")
        m = re.search(r"-enc (\S+)", r["Details"])
        if m:
            p(f"   [!] Word spawned PowerShell with hidden window + encoded command")
            p(f"   DECODED (base64 UTF-16LE): {base64.b64decode(m.group(1)).decode('utf-16le')}")
for (acct, ip), n in c.items(): p(f"4625 failures: {n} x '{acct}' from {ip} (RDP, LogonType 10)")

os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
open(args.out, "w").write("\n".join(out)+"\n")
