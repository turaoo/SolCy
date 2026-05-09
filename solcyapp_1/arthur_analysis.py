#!/usr/bin/env python3
"""
Arthur Analysis — Full Threat Intelligence Platform
-----------------------------------------------------
- Single file or entire folder scanning
- VirusTotal hash lookup (70+ AV engines)
- MalwareBazaar hash lookup (free, no key needed)
- AlienVault OTX IOC lookup (free key at otx.alienvault.com)
- IOC extraction (IPs, URLs, domains, hashes)
- YARA-style pattern matching
- Hash watchlist alerting
- SQLite scan history database
- HTML threat dashboard
- CSV + plain text export
- PE section entropy analysis
- Obfuscation detection

Usage:
    python arthur_analysis.py <file>
    python arthur_analysis.py <folder> --scan-folder
    python arthur_analysis.py <file> --vt-key KEY --otx-key KEY
    python arthur_analysis.py <file> --html report.html --csv results.csv
    python arthur_analysis.py --dashboard                  (view past scans)
    python arthur_analysis.py --watchlist hashes.txt       (set hash watchlist)

Free API keys:
    VirusTotal : https://www.virustotal.com/gui/join-us
    OTX        : https://otx.alienvault.com
    MalwareBazaar: no key needed
"""

import sys, hashlib, argparse, json, csv, re, struct, os, sqlite3
import urllib.request, urllib.error, urllib.parse
from pathlib import Path
from datetime import datetime, timezone
from math import log2

# ── ANSI colors ───────────────────────────────────────────────────────────────
RESET="\033[0m"; BOLD="\033[1m"; RED="\033[91m"; YELLOW="\033[93m"
GREEN="\033[92m"; CYAN="\033[96m"; GRAY="\033[90m"; WHITE="\033[97m"
MAGENTA="\033[95m"

def colored(text, color):
    return f"{color}{text}{RESET}" if sys.stdout.isatty() else text

# ── Magic signatures ───────────────────────────────────────────────────────────
MAGIC_SIGNATURES = [
    (b"\x4D\x5A",                "PE Executable (Windows EXE/DLL)",  "HIGH"),
    (b"\x7F\x45\x4C\x46",        "ELF Executable (Linux/Unix)",       "HIGH"),
    (b"\xCA\xFE\xBA\xBE",        "Java Class / Mach-O (macOS)",       "HIGH"),
    (b"\xCE\xFA\xED\xFE",        "Mach-O Executable (macOS)",         "HIGH"),
    (b"\xCF\xFA\xED\xFE",        "Mach-O 64-bit (macOS)",             "HIGH"),
    (b"\x25\x50\x44\x46",        "PDF Document",                      "MEDIUM"),
    (b"\x50\x4B\x03\x04",        "ZIP Archive",                       "MEDIUM"),
    (b"\x52\x61\x72\x21\x1A",    "RAR Archive",                       "MEDIUM"),
    (b"\x37\x7A\xBC\xAF\x27\x1C","7-Zip Archive",                    "MEDIUM"),
    (b"\x1F\x8B",                "GZIP Archive",                      "MEDIUM"),
    (b"\xD0\xCF\x11\xE0",        "MS Office OLE (doc/xls/ppt)",       "MEDIUM"),
    (b"\x50\x4B",                "OOXML Office (docx/xlsx/pptx)",     "MEDIUM"),
    (b"\x89\x50\x4E\x47",        "PNG Image",                         "LOW"),
    (b"\xFF\xD8\xFF",            "JPEG Image",                        "LOW"),
    (b"\x47\x49\x46\x38",        "GIF Image",                         "LOW"),
    (b"\x42\x4D",                "BMP Image",                         "LOW"),
    (b"\x49\x44\x33",            "MP3 Audio",                         "LOW"),
    (b"\x66\x74\x79\x70",        "MP4/MOV Video",                     "LOW"),
    (b"\x52\x49\x46\x46",        "RIFF/WAV/AVI",                      "LOW"),
]

# ── Suspicious patterns ────────────────────────────────────────────────────────
SUSPICIOUS_PATTERNS = {
    "Process Injection":["CreateRemoteThread","VirtualAllocEx","WriteProcessMemory","NtUnmapViewOfSection","SetThreadContext","QueueUserAPC","RtlCreateUserThread","NtWriteVirtualMemory","ZwUnmapViewOfSection"],
    "Shell / Execution":["cmd.exe","powershell","WScript.Shell","CScript","ShellExecute","CreateProcess","/bin/sh","/bin/bash","system(","exec(","popen(","subprocess","os.system"],
    "Network / C2":["wget ","curl ","urllib","requests.get","socket.connect","InternetOpenUrl","HttpSendRequest","WinHttpOpen","nc -e","ncat","reverse shell","connect-back","beacon","C2","command and control","IRC","bot_id","checkip","gethostbyname","WSAStartup","send(","recv("],
    "Obfuscation / Encoding":["base64","eval(","fromCharCode","unescape(","atob(","btoa(","rot13","XOR","chr(","hex(","zlib","gzip.decompress","marshal.loads"],
    "Persistence":["HKEY_","autorun","startup","schtasks","crontab","Registry","Run\\","RunOnce","LaunchAgent","LaunchDaemon","rc.local","init.d","systemd",".bashrc",".profile"],
    "Ransomware":["ransom","encrypt","decrypt","AES","RSA","bitcoin","wallet","payment","your files",".locked",".encrypted","CryptEncrypt","CryptGenKey","BCryptEncrypt","pay","deadline","hours to pay","files have been encrypted"],
    "Infostealer":["password","passwd","credential","keylog","GetAsyncKeyState","SetWindowsHookEx","clipboard","GetClipboardData","browser","cookie","logindata","wallet.dat","seed phrase","screenshot","BitBlt","GetDC","keychain","lastpass","autofill","stored password","chrome","firefox","edge","telegram","discord token","steam","filezilla"],
    "Botnet / RAT":["bot","zombie","flood","ddos","spam","C&C","remote access","RAT","backdoor","bind shell","reverse_tcp","meterpreter","empire","cobalt strike","screen capture","webcam","microphone","keylogger","upload","download","execute","shell_exec"],
    "Worm / Propagation":["self-replication","spreads","worm","infect","NetShareEnum","WNetOpenEnum","CopyFile","propagat","removable","USB","network share","SMB","exploit","MS17-010","EternalBlue","BlueKeep","brute"],
    "Rootkit":["rootkit","SSDT","hook","IRP","MBR","bootkit","DKOM","hide process","hide file","NtQuerySystemInformation","ObRegisterCallbacks","driver",".sys","kernel"],
    "Spyware / Adware":["spyware","adware","track","monitor","surveillance","location","GPS","microphone","camera","spy","send_data","exfiltrate","upload_file"],
    "Dropper / Downloader":["URLDownloadToFile","DownloadFile","WinHttpReadData","drop","payload","stage","loader","inject","temp\\","%TEMP%","AppData","dropper"],
    "Privilege Escalation":["SeDebugPrivilege","token impersonation","bypassuac","runas","sudo ","setuid","AdjustTokenPrivileges","ImpersonateLoggedOnUser","SYSTEM","NT AUTHORITY"],
    "Web Exploit":["document.write","<iframe","<script","eval(unescape","onload=","onerror=","javascript:","XSS","SQLi","UNION SELECT","DROP TABLE","../","etc/passwd"],
    "Anti-Analysis":["IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess","GetTickCount","Sleep(","anti-vm","vmware","virtualbox","sandbox","wireshark","procmon","ollydbg","x64dbg","timing","cpuid","rdtsc"],
}

# ── Malware families ───────────────────────────────────────────────────────────
MALWARE_FAMILIES = [
    ("Ransomware","Encrypts victim files and demands payment for decryption. Drops a ransom note, disables backups, and may exfiltrate data before encrypting.",["Ransomware"],2,"HIGH"),
    ("Infostealer","Harvests saved passwords, browser cookies, cryptocurrency wallets, and clipboard contents, then silently exfiltrates them to an attacker-controlled server.",["Infostealer"],2,"HIGH"),
    ("Remote Access Trojan (RAT)","Provides an attacker with covert remote control including shell access, file management, keylogging, and screen/webcam capture.",["Botnet / RAT"],2,"HIGH"),
    ("Botnet Agent","Enrolls the host into a botnet for DDoS flooding, spam campaigns, or proxy services under remote command-and-control.",["Botnet / RAT","Network / C2"],3,"HIGH"),
    ("Worm","Self-propagating malware that spreads across networks or removable media, often exploiting unpatched vulnerabilities like EternalBlue.",["Worm / Propagation"],2,"HIGH"),
    ("Rootkit","Operates at kernel or boot level to hide from the OS and security tools. May hook system calls, manipulate the MBR, or use driver-based techniques.",["Rootkit"],2,"HIGH"),
    ("Dropper / Downloader","Fetches and installs a secondary payload from a remote server, bypassing static detection of the final malware stage.",["Dropper / Downloader"],2,"MEDIUM"),
    ("Spyware","Silently monitors keystrokes, location, microphone, and camera, then sends collected data to a remote attacker.",["Spyware / Adware","Infostealer"],2,"MEDIUM"),
    ("Trojan","Disguises itself as a legitimate program while opening backdoors, dropping payloads, or stealing data in the background.",["Shell / Execution","Persistence"],3,"MEDIUM"),
    ("Keylogger","Records keystrokes and captures screenshots or clipboard data to steal credentials typed by the user.",["Infostealer"],1,"MEDIUM"),
    ("Backdoor","Installs a hidden remote-access channel that persists across reboots, allowing re-entry without re-exploiting a vulnerability.",["Persistence","Network / C2"],3,"MEDIUM"),
    ("Cryptominer","Hijacks CPU/GPU resources to mine cryptocurrency for the attacker, degrading system performance.",["Network / C2"],1,"LOW"),
    ("Adware","Injects unwanted ads, redirects browser traffic, or installs extensions to generate revenue for the attacker.",["Spyware / Adware","Web Exploit"],2,"LOW"),
]

HIGH_RISK_EXTS={"exe","dll","bat","cmd","ps1","vbs","js","jar","msi","scr","com","pif","hta","wsf","reg","lnk","vbe","jse"}
MED_RISK_EXTS={"zip","rar","7z","gz","tar","pdf","doc","docm","xls","xlsm","xlsb","ppt","pptm","iso","img","dmg","apk"}

DB_PATH = Path.home() / ".arthur_analysis" / "scans.db"

# ── Database ───────────────────────────────────────────────────────────────────
def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analyzed_at TEXT, filename TEXT, filepath TEXT,
        size TEXT, extension TEXT, magic_type TEXT,
        entropy REAL, severity TEXT, families TEXT,
        total_indicators INTEGER, vt_malicious INTEGER,
        vt_total INTEGER, vt_names TEXT,
        mb_detected INTEGER, ioc_count INTEGER,
        md5 TEXT, sha1 TEXT, sha256 TEXT,
        verdict TEXT, watchlist_hit INTEGER DEFAULT 0
    )""")
    con.commit()
    return con

def save_scan(report):
    con = init_db()
    vt  = report.get("virustotal", {})
    mb  = report.get("malwarebazaar", {})
    ex  = report.get("executive_summary", {})
    iocs = report.get("iocs", {})
    ioc_count = sum(len(v) for v in iocs.values())
    families = "; ".join(f["family"] for f in report.get("malware_classification",[]))
    con.execute("""INSERT INTO scans
        (analyzed_at,filename,filepath,size,extension,magic_type,entropy,severity,
         families,total_indicators,vt_malicious,vt_total,vt_names,mb_detected,
         ioc_count,md5,sha1,sha256,verdict,watchlist_hit)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
        report["analyzed_at"], report["filename"], report["filepath"],
        report["size"], report["extension"], report["magic_type"],
        report["entropy"], report["severity"], families,
        sum(len(v) for v in report.get("suspicious_strings",{}).values()),
        vt.get("malicious",0), vt.get("total",0),
        ", ".join(vt.get("top_names",[])),
        1 if mb.get("found") else 0,
        ioc_count,
        report["hashes"]["md5"], report["hashes"]["sha1"], report["hashes"]["sha256"],
        ex.get("verdict",""), 1 if report.get("watchlist_hit") else 0
    ))
    con.commit(); con.close()

def load_history(limit=100):
    con = init_db()
    rows = con.execute(
        "SELECT * FROM scans ORDER BY analyzed_at DESC LIMIT ?", (limit,)
    ).fetchall()
    cols = [d[0] for d in con.execute("SELECT * FROM scans LIMIT 0").description]
    con.close()
    return [dict(zip(cols, r)) for r in rows]

# ── Core analysis ──────────────────────────────────────────────────────────────
def compute_hashes(data):
    return {"md5":hashlib.md5(data).hexdigest(),"sha1":hashlib.sha1(data).hexdigest(),"sha256":hashlib.sha256(data).hexdigest()}

def detect_magic(data):
    for sig,name,risk in MAGIC_SIGNATURES:
        if data[:len(sig)]==sig: return name,risk
    sample=data[:512]
    printable=sum(0x20<=b<0x7F or b in(9,10,13) for b in sample)
    if len(sample) and printable/len(sample)>0.85: return "Text / Script file","MEDIUM"
    return "Unknown binary","MEDIUM"

def calc_entropy(data):
    if not data: return 0.0
    freq=[0]*256
    for b in data: freq[b]+=1
    n=len(data)
    return -sum((f/n)*log2(f/n) for f in freq if f)

def section_entropy(data):
    results=[]
    if data[:2]!=b"MZ": return results
    try:
        pe_off=struct.unpack_from("<I",data,0x3C)[0]
        if data[pe_off:pe_off+4]!=b"PE\x00\x00": return results
        num_sec=struct.unpack_from("<H",data,pe_off+6)[0]
        opt_sz=struct.unpack_from("<H",data,pe_off+20)[0]
        sec_off=pe_off+24+opt_sz
        for i in range(num_sec):
            s=sec_off+i*40
            name=data[s:s+8].rstrip(b"\x00").decode("latin-1","replace")
            vsize=struct.unpack_from("<I",data,s+16)[0]
            raw_off=struct.unpack_from("<I",data,s+20)[0]
            raw_sz=struct.unpack_from("<I",data,s+16)[0]
            ent=calc_entropy(data[raw_off:raw_off+raw_sz])
            results.append({"name":name,"entropy":round(ent,4),"size":vsize})
    except: pass
    return results

def scan_strings(data):
    try: text=data[:200_000].decode("latin-1","replace")
    except: text=""
    hits={}
    for cat,pats in SUSPICIOUS_PATTERNS.items():
        found=[p for p in pats if p.lower() in text.lower()]
        if found: hits[cat]=found
    return hits

def extract_iocs(data):
    """Extract Indicators of Compromise from file content."""
    iocs={"ips":[],"urls":[],"domains":[],"emails":[],"hashes":[]}
    try:
        text=data[:500_000].decode("latin-1","replace")
        # IPs (exclude private)
        ips=re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',text)
        iocs["ips"]=list(set(ip for ip in ips if not re.match(r'^(127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|0\.)',ip)))[:20]
        # URLs
        urls=re.findall(r'https?://[^\s\'"<>{}\[\]]{8,}',text)
        iocs["urls"]=list(set(urls))[:20]
        # Domains (heuristic)
        domains=re.findall(r'\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|ru|cn|tk|top|xyz|info|biz|cc|pw)\b',text)
        iocs["domains"]=list(set(d for d in domains if len(d)>6))[:20]
        # Emails
        emails=re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',text)
        iocs["emails"]=list(set(emails))[:10]
        # MD5/SHA hashes embedded in file
        md5s=re.findall(r'\b[a-fA-F0-9]{32}\b',text)
        sha256s=re.findall(r'\b[a-fA-F0-9]{64}\b',text)
        iocs["hashes"]=list(set(md5s[:5]+sha256s[:5]))[:10]
    except: pass
    # Remove empties
    return {k:v for k,v in iocs.items() if v}

def detect_obfuscation(data):
    findings=[]
    try:
        text=data[:500_000].decode("latin-1","replace")
        b64=re.findall(r'[A-Za-z0-9+/]{100,}={0,2}',text)
        if b64: findings.append(f"Base64 blob(s) detected ({len(b64)} found, longest: {max(len(b) for b in b64)} chars)")
        hex_blobs=re.findall(r'(?:0x[0-9a-fA-F]{2},?\s*){16,}',text)
        if hex_blobs: findings.append(f"Hex-encoded data detected ({len(hex_blobs)} block(s))")
        if re.search(r'(?i)-enc(?:oded)?(?:command)?\s+[A-Za-z0-9+/=]{20,}',text):
            findings.append("PowerShell encoded command detected")
        cc=len(re.findall(r'["\']\s*\+\s*["\']',text))
        if cc>10: findings.append(f"Heavy string concatenation ({cc} instances — possible obfuscation)")
        chrc=len(re.findall(r'[Cc]hr\s*\(\s*\d+\s*\)',text))
        if chrc>5: findings.append(f"Chr() character obfuscation ({chrc} instances)")
        null_ratio=data.count(0)/max(len(data),1)
        if null_ratio>0.4: findings.append(f"High null-byte ratio ({null_ratio:.1%}) — file may be padded or packed")
        sample=data[1024:2048]
        if len(sample)>100:
            xor_score=sum(1 for i in range(0,len(sample)-1,2) if sample[i]==sample[i+1])/(len(sample)//2)
            if xor_score>0.3: findings.append("Repeating byte patterns — possible XOR encryption")
    except: pass
    return findings

def classify_malware(hits, magic_risk, ext_risk, ent):
    results=[]
    order={"HIGH":0,"MEDIUM":1,"LOW":2}
    for name,desc,req,min_h,base_conf in MALWARE_FAMILIES:
        matched=[c for c in req if c in hits]
        total=sum(len(hits[c]) for c in matched)
        if len(matched)>=1 and total>=min_h:
            conf=base_conf
            if magic_risk=="HIGH" and conf=="MEDIUM": conf="HIGH"
            if ent>7.2 and name in ("Ransomware","Dropper / Downloader","Rootkit"): conf="HIGH"
            results.append({"family":name,"confidence":conf,"description":desc,"matched_categories":matched,"indicator_count":total})
    results.sort(key=lambda x:(order[x["confidence"]],-x["indicator_count"]))
    return results

def severity_label(hits, magic_risk, ext_risk, vt=None, mb=None):
    if vt and vt.get("malicious",0)>0: return "HIGH"
    if mb and mb.get("found"): return "HIGH"
    if magic_risk=="HIGH" or ext_risk=="HIGH": return "HIGH"
    if sum(len(v) for v in hits.values())>0 or magic_risk=="MEDIUM": return "MEDIUM"
    return "LOW"

def fmt_size(n):
    for unit in ("B","KB","MB","GB"):
        if n<1024: return f"{n} B" if unit=="B" else f"{n:.1f} {unit}"
        n/=1024
    return f"{n:.2f} TB"

def risk_color(level):
    return {"HIGH":RED,"MEDIUM":YELLOW,"LOW":GREEN}.get(level.upper(),WHITE)

# ── Watchlist ──────────────────────────────────────────────────────────────────
def load_watchlist(path=None):
    wl_path=Path(path) if path else Path.home()/".arthur_analysis"/"watchlist.txt"
    if not wl_path.exists(): return set()
    hashes=set()
    for line in wl_path.read_text().splitlines():
        line=line.strip().lower()
        if line and not line.startswith("#"): hashes.add(line)
    return hashes

def check_watchlist(hashes, watchlist):
    for h in hashes.values():
        if h.lower() in watchlist: return True, h
    return False, None

# ── Threat intelligence APIs ───────────────────────────────────────────────────
def query_virustotal(sha256, api_key):
    url=f"https://www.virustotal.com/api/v3/files/{sha256}"
    req=urllib.request.Request(url,headers={"x-apikey":api_key})
    try:
        with urllib.request.urlopen(req,timeout=15) as resp:
            raw=json.loads(resp.read())
            attr=raw.get("data",{}).get("attributes",{})
            stats=attr.get("last_analysis_stats",{})
            results=attr.get("last_analysis_results",{})
            detections={}
            for eng,res in results.items():
                if res.get("category") in ("malicious","suspicious"):
                    detections[eng]={"category":res.get("category"),"result":res.get("result","")}
            names=[v["result"] for v in detections.values() if v["result"]]
            nc={}
            for n in names: nc[n]=nc.get(n,0)+1
            top_names=sorted(nc,key=nc.get,reverse=True)[:5]
            return {"found":True,"malicious":stats.get("malicious",0),"suspicious":stats.get("suspicious",0),
                    "undetected":stats.get("undetected",0),"total":sum(stats.values()),
                    "detections":detections,"top_names":top_names,
                    "tags":attr.get("tags",[]),"vt_link":f"https://www.virustotal.com/gui/file/{sha256}"}
    except urllib.error.HTTPError as e:
        msgs={404:"Hash not in VirusTotal database (file may be new or rare)",401:"Invalid VirusTotal API key",429:"Rate limit hit — free API: 4 requests/minute"}
        return {"found":False,"reason":msgs.get(e.code,f"HTTP error {e.code}")}
    except Exception as ex:
        return {"found":False,"reason":f"Connection error: {ex}"}

def query_malwarebazaar(sha256):
    """MalwareBazaar — free, no API key needed."""
    url="https://mb-api.abuse.ch/api/v1/"
    data=urllib.parse.urlencode({"query":"get_info","hash":sha256}).encode()
    req=urllib.request.Request(url,data=data,headers={"User-Agent":"ArthurAnalysis/1.0"})
    try:
        with urllib.request.urlopen(req,timeout=15) as resp:
            raw=json.loads(resp.read())
            if raw.get("query_status")=="hash_not_found":
                return {"found":False,"reason":"Hash not in MalwareBazaar database"}
            if raw.get("query_status")=="ok" and raw.get("data"):
                d=raw["data"][0]
                return {"found":True,"malware_name":d.get("signature","Unknown"),
                        "tags":d.get("tags",[]) or [],
                        "file_type":d.get("file_type",""),
                        "first_seen":d.get("first_seen",""),
                        "reporter":d.get("reporter",""),
                        "mb_link":f"https://bazaar.abuse.ch/sample/{sha256}"}
            return {"found":False,"reason":"Not found"}
    except Exception as ex:
        return {"found":False,"reason":f"MalwareBazaar error: {ex}"}

def query_otx(sha256, api_key):
    """AlienVault OTX threat intelligence."""
    url=f"https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general"
    req=urllib.request.Request(url,headers={"X-OTX-API-KEY":api_key,"User-Agent":"ArthurAnalysis/1.0"})
    try:
        with urllib.request.urlopen(req,timeout=15) as resp:
            raw=json.loads(resp.read())
            pulses=raw.get("pulse_info",{}).get("pulses",[])
            if not pulses:
                return {"found":False,"reason":"No OTX threat reports for this file"}
            return {"found":True,"pulse_count":len(pulses),
                    "pulse_names":[p.get("name","") for p in pulses[:5]],
                    "tags":list(set(t for p in pulses for t in p.get("tags",[])))[:10],
                    "otx_link":f"https://otx.alienvault.com/indicator/file/{sha256}"}
    except urllib.error.HTTPError as e:
        return {"found":False,"reason":f"OTX HTTP error {e.code}"}
    except Exception as ex:
        return {"found":False,"reason":f"OTX error: {ex}"}

# ── Executive summary ──────────────────────────────────────────────────────────
def build_executive_summary(report):
    severity=report["severity"]; families=report["malware_classification"]
    hits=report["suspicious_strings"]; ent=report["entropy"]; filename=report["filename"]
    vt=report.get("virustotal",{}); mb=report.get("malwarebazaar",{})
    otx=report.get("otx",{})

    if report.get("watchlist_hit"):
        verdict="⚠ WATCHLIST MATCH — KNOWN MALICIOUS HASH"
        action="This file matches your watchlist. Quarantine immediately."
        detail=f"{filename} matched a hash in your local watchlist."
    elif vt.get("found") and vt.get("malicious",0)>0:
        mal=vt["malicious"]; tot=vt["total"]
        verdict=f"CONFIRMED MALICIOUS — {mal}/{tot} ENGINES DETECTED"
        action="DO NOT open or execute. Quarantine immediately and escalate to your security team."
        names=vt.get("top_names",[])
        detail=f"{filename} flagged by {mal}/{tot} security engines on VirusTotal. {'Identified as: '+', '.join(names)+'. ' if names else ''}"
        if mb.get("found"): detail+=f"Also confirmed in MalwareBazaar as {mb.get('malware_name','Unknown')}. "
        if otx.get("found"): detail+=f"OTX: {otx.get('pulse_count',0)} threat intelligence report(s) found."
    elif mb.get("found"):
        verdict=f"CONFIRMED MALICIOUS — IN MALWAREBAZAAR DATABASE"
        action="DO NOT open or execute. This is a known malware sample. Quarantine immediately."
        detail=f"{filename} found in MalwareBazaar as '{mb.get('malware_name','Unknown')}'. First seen: {mb.get('first_seen','')}."
    elif not families and not hits:
        verdict="LIKELY CLEAN"
        action="No immediate action required. Continue routine monitoring."
        detail=f"{filename} shows no indicators of malicious behavior."
        if vt.get("found"): detail+=f" VirusTotal: 0/{vt['total']} engines detected a threat."
    else:
        primary=families[0]["family"] if families else "Unknown"
        others=[f["family"] for f in families[1:3]]
        if severity=="HIGH": verdict="HIGH RISK — IMMEDIATE ACTION REQUIRED"; action="Isolate the file. Do not open or execute. Escalate to your security team."
        elif severity=="MEDIUM": verdict="MEDIUM RISK — FURTHER INVESTIGATION NEEDED"; action="Do not open. Submit to a sandbox for dynamic analysis."
        else: verdict="LOW RISK — REVIEW RECOMMENDED"; action="Exercise caution. Review in a safe isolated environment."
        family_str=primary+(f" with traits of {', '.join(others)}" if others else "")
        detail=f"{filename} classified as {family_str}. {sum(len(v) for v in hits.values())} indicator(s) across {len(hits)} category(s). "
        if ent>7.2: detail+="High entropy — may be packed or encrypted. "
        if "Anti-Analysis" in hits: detail+="Anti-analysis techniques detected. "
        if vt.get("found"): detail+=f"VirusTotal: {vt.get('malicious',0)}/{vt.get('total',0)} engines flagged this file."

    return {"verdict":verdict,"action":action,"detail":detail}

def build_behavior_summary(families, hits):
    if not families and not hits:
        return "No behavioral indicators detected. The file appears benign based on static analysis."
    lines=[]
    if families:
        p=families[0]; others=[f["family"] for f in families[1:]]
        lines.append(f"This file exhibits characteristics consistent with {p['family']} (confidence: {p['confidence']}). {p['description']}")
        if others: lines.append(f"Additional malware traits detected: {', '.join(others)}.")
    bmap={"Process Injection":"It attempts to inject code into other running processes.","Shell / Execution":"It spawns shell commands or child processes.","Network / C2":"It communicates over the network, likely to a command-and-control server.","Obfuscation / Encoding":"It uses encoding or obfuscation techniques to hide its true intent.","Persistence":"It installs persistence mechanisms to survive reboots.","Ransomware":"It contains encryption routines and ransom-related strings.","Infostealer":"It targets stored credentials, cookies, or sensitive user data.","Botnet / RAT":"It contains remote-access or botnet coordination capabilities.","Worm / Propagation":"It attempts to replicate or spread to other systems.","Rootkit":"It uses rootkit techniques to conceal itself from the OS.","Spyware / Adware":"It monitors user activity or injects unwanted content.","Dropper / Downloader":"It downloads or drops additional payloads onto the system.","Privilege Escalation":"It attempts to escalate privileges beyond its initial access level.","Web Exploit":"It contains web-based exploit code.","Anti-Analysis":"It uses anti-debugging or anti-VM techniques to evade analysis."}
    for cat in hits:
        if cat in bmap: lines.append(bmap[cat])
    return " ".join(lines)

# ── CSV export ─────────────────────────────────────────────────────────────────
def export_csv(report, csv_path):
    path=Path(csv_path); exists=path.exists()
    vt=report.get("virustotal",{}); mb=report.get("malwarebazaar",{})
    ex=report["executive_summary"]; iocs=report.get("iocs",{})
    row={"analyzed_at":report["analyzed_at"],"filename":report["filename"],"filepath":report["filepath"],"size":report["size"],"extension":report["extension"],"file_type":report["magic_type"],"entropy":report["entropy"],"severity":report["severity"],"verdict":ex["verdict"],"action":ex["action"],"malware_families":"; ".join(f["family"] for f in report["malware_classification"]) or "None","suspicious_categories":"; ".join(report["suspicious_strings"].keys()) or "None","total_indicators":sum(len(v) for v in report["suspicious_strings"].values()),"obfuscation":"; ".join(report.get("obfuscation",[])[:2]) or "None","ioc_ips":"; ".join(iocs.get("ips",[])),"ioc_urls":"; ".join(iocs.get("urls",[])[:3]),"ioc_domains":"; ".join(iocs.get("domains",[])[:5]),"vt_malicious":vt.get("malicious","N/A"),"vt_total":vt.get("total","N/A"),"vt_names":", ".join(vt.get("top_names",[])) or "N/A","mb_found":mb.get("found",False),"mb_name":mb.get("malware_name","N/A"),"watchlist_hit":report.get("watchlist_hit",False),"md5":report["hashes"]["md5"],"sha1":report["hashes"]["sha1"],"sha256":report["hashes"]["sha256"]}
    with open(path,"a",newline="",encoding="utf-8") as f:
        writer=csv.DictWriter(f,fieldnames=list(row.keys()))
        if not exists: writer.writeheader()
        writer.writerow(row)

# ── PDF report ────────────────────────────────────────────────────────────────
def export_pdf(report, pdf_path):
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable)
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
    except ImportError:
        print(colored("  PDF export requires reportlab: pip install reportlab", YELLOW))
        return

    ex       = report["executive_summary"]
    severity = report["severity"]
    families = report["malware_classification"]
    hits     = report["suspicious_strings"]
    hashes   = report["hashes"]
    vt       = report.get("virustotal", {})
    mb       = report.get("malwarebazaar", {})
    obf      = report.get("obfuscation", [])
    iocs     = report.get("iocs", {})

    sev_rgb  = {"HIGH": colors.HexColor("#c0392b"),
                "MEDIUM": colors.HexColor("#e67e22"),
                "LOW": colors.HexColor("#27ae60")}.get(severity, colors.gray)

    doc  = SimpleDocTemplate(str(pdf_path), pagesize=letter,
                             leftMargin=0.75*inch, rightMargin=0.75*inch,
                             topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()

    # Custom styles
    title_style  = ParagraphStyle("title",  fontSize=18, fontName="Helvetica-Bold",
                                  textColor=colors.HexColor("#1a1d27"), spaceAfter=4)
    sub_style    = ParagraphStyle("sub",    fontSize=9,  fontName="Helvetica",
                                  textColor=colors.gray, spaceAfter=12)
    h2_style     = ParagraphStyle("h2",     fontSize=11, fontName="Helvetica-Bold",
                                  textColor=colors.HexColor("#2c3e50"), spaceBefore=14, spaceAfter=6)
    body_style   = ParagraphStyle("body",   fontSize=9,  fontName="Helvetica",
                                  textColor=colors.HexColor("#333333"), spaceAfter=4, leading=14)
    mono_style   = ParagraphStyle("mono",   fontSize=8,  fontName="Courier",
                                  textColor=colors.HexColor("#2c3e50"), spaceAfter=3)
    verdict_style= ParagraphStyle("verdict",fontSize=13, fontName="Helvetica-Bold",
                                  textColor=sev_rgb, spaceAfter=6)

    story = []

    # ── Header ────────────────────────────────────────────────────────────────
    story.append(Paragraph("ARTHUR ANALYSIS", title_style))
    story.append(Paragraph("Threat Intelligence Report", sub_style))
    story.append(HRFlowable(width="100%", thickness=2, color=sev_rgb, spaceAfter=12))

    # File + date info table
    info_data = [
        ["File", report["filename"]],
        ["Path", report["filepath"][:80]+"..." if len(report["filepath"])>80 else report["filepath"]],
        ["Analyzed", report["analyzed_at"]],
        ["Severity", severity],
    ]
    info_tbl = Table(info_data, colWidths=[1.2*inch, 5.5*inch])
    info_tbl.setStyle(TableStyle([
        ("FONTNAME",  (0,0),(-1,-1), "Helvetica"),
        ("FONTSIZE",  (0,0),(-1,-1), 9),
        ("FONTNAME",  (0,0),(0,-1),  "Helvetica-Bold"),
        ("TEXTCOLOR", (0,0),(0,-1),  colors.HexColor("#555555")),
        ("TEXTCOLOR", (1,3),(1,3),   sev_rgb),
        ("FONTNAME",  (1,3),(1,3),   "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0,0),(-1,-1), [colors.HexColor("#f8f9fa"), colors.white]),
        ("TOPPADDING",  (0,0),(-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1), 4),
        ("LEFTPADDING",  (0,0),(-1,-1), 6),
        ("GRID", (0,0),(-1,-1), 0.25, colors.HexColor("#dddddd")),
    ]))
    story.append(info_tbl)
    story.append(Spacer(1, 12))

    # ── Executive Summary ─────────────────────────────────────────────────────
    story.append(Paragraph("EXECUTIVE SUMMARY", h2_style))
    story.append(Paragraph(ex["verdict"], verdict_style))
    story.append(Paragraph(f"<b>Recommended Action:</b> {ex['action']}", body_style))
    story.append(Paragraph(ex["detail"], body_style))
    story.append(Spacer(1, 8))

    # ── Hashes ────────────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dddddd"), spaceAfter=8))
    story.append(Paragraph("FILE HASHES", h2_style))
    hash_data = [["Algorithm","Hash"],
                 ["MD5",    hashes["md5"]],
                 ["SHA-1",  hashes["sha1"]],
                 ["SHA-256",hashes["sha256"]]]
    hash_tbl = Table(hash_data, colWidths=[0.9*inch, 5.8*inch])
    hash_tbl.setStyle(TableStyle([
        ("FONTNAME",  (0,0),(-1,0),  "Helvetica-Bold"),
        ("FONTNAME",  (0,1),(-1,-1), "Courier"),
        ("FONTSIZE",  (0,0),(-1,-1), 8),
        ("BACKGROUND",(0,0),(-1,0),  colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0,0),(-1,0),  colors.white),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#f8f9fa"),colors.white]),
        ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#dddddd")),
        ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("LEFTPADDING",(0,0),(-1,-1),6),
    ]))
    story.append(hash_tbl)
    story.append(Spacer(1, 8))

    # ── VirusTotal ────────────────────────────────────────────────────────────
    if vt and vt.get("found"):
        story.append(HRFlowable(width="100%",thickness=0.5,color=colors.HexColor("#dddddd"),spaceAfter=8))
        story.append(Paragraph("VIRUSTOTAL RESULTS", h2_style))
        mal=vt["malicious"]; tot=vt["total"]
        vc=colors.HexColor("#c0392b") if mal>5 else colors.HexColor("#e67e22") if mal>0 else colors.HexColor("#27ae60")
        story.append(Paragraph(f"<b>Detections:</b> <font color='#{('c0392b' if mal>5 else 'e67e22' if mal>0 else '27ae60')}'>{mal}/{tot} engines</font>", body_style))
        if vt.get("top_names"): story.append(Paragraph(f"<b>Malware Names:</b> {', '.join(vt['top_names'])}", body_style))
        if vt.get("tags"):      story.append(Paragraph(f"<b>Tags:</b> {', '.join(vt['tags'])}", body_style))
        story.append(Paragraph(f"<b>Full Report:</b> {vt['vt_link']}", body_style))
        if vt.get("detections"):
            story.append(Spacer(1, 6))
            det_data = [["Engine","Category","Detection Name"]]
            for eng,res in list(vt["detections"].items())[:15]:
                det_data.append([eng, res["category"], res["result"][:40]])
            det_tbl = Table(det_data, colWidths=[2*inch, 1.2*inch, 3.5*inch])
            det_tbl.setStyle(TableStyle([
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
                ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#2c3e50")),
                ("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#fff5f5"),colors.white]),
                ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#dddddd")),
                ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
                ("LEFTPADDING",(0,0),(-1,-1),5),
            ]))
            story.append(det_tbl)
        story.append(Spacer(1,8))

    # ── MalwareBazaar ─────────────────────────────────────────────────────────
    if mb and mb.get("found"):
        story.append(HRFlowable(width="100%",thickness=0.5,color=colors.HexColor("#dddddd"),spaceAfter=8))
        story.append(Paragraph("MALWAREBAZAAR", h2_style))
        story.append(Paragraph(f"<b>Malware Name:</b> {mb.get('malware_name','Unknown')}", body_style))
        story.append(Paragraph(f"<b>First Seen:</b> {mb.get('first_seen','')}", body_style))
        if mb.get("tags"): story.append(Paragraph(f"<b>Tags:</b> {', '.join(mb['tags'])}", body_style))
        story.append(Spacer(1,8))

    # ── Malware Classification ────────────────────────────────────────────────
    story.append(HRFlowable(width="100%",thickness=0.5,color=colors.HexColor("#dddddd"),spaceAfter=8))
    story.append(Paragraph("MALWARE CLASSIFICATION", h2_style))
    if families:
        fam_data = [["Family","Confidence","Indicators","Matched Categories"]]
        for f in families:
            fam_data.append([f["family"], f["confidence"], str(f["indicator_count"]), ", ".join(f["matched_categories"])])
        fam_tbl = Table(fam_data, colWidths=[1.8*inch, 0.9*inch, 0.8*inch, 3.2*inch])
        conf_colors_map = {"HIGH":colors.HexColor("#c0392b"),"MEDIUM":colors.HexColor("#e67e22"),"LOW":colors.HexColor("#27ae60")}
        style_cmds = [
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#2c3e50")),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#f8f9fa"),colors.white]),
            ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#dddddd")),
            ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
            ("LEFTPADDING",(0,0),(-1,-1),5),
        ]
        for i,f in enumerate(families,1):
            cc = conf_colors_map.get(f["confidence"], colors.gray)
            style_cmds.append(("TEXTCOLOR",(1,i),(1,i),cc))
            style_cmds.append(("FONTNAME",(1,i),(1,i),"Helvetica-Bold"))
        fam_tbl.setStyle(TableStyle(style_cmds))
        story.append(fam_tbl)
    else:
        story.append(Paragraph("No known malware family matched.", body_style))
    story.append(Spacer(1,8))

    # ── Behavior Summary ──────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%",thickness=0.5,color=colors.HexColor("#dddddd"),spaceAfter=8))
    story.append(Paragraph("BEHAVIOR SUMMARY", h2_style))
    story.append(Paragraph(report["behavior_summary"], body_style))
    story.append(Spacer(1,8))

    # ── Obfuscation ───────────────────────────────────────────────────────────
    if obf:
        story.append(HRFlowable(width="100%",thickness=0.5,color=colors.HexColor("#dddddd"),spaceAfter=8))
        story.append(Paragraph("OBFUSCATION DETECTED", h2_style))
        for o in obf:
            story.append(Paragraph(f"• {o}", body_style))
        story.append(Spacer(1,8))

    # ── IOCs ──────────────────────────────────────────────────────────────────
    if iocs:
        story.append(HRFlowable(width="100%",thickness=0.5,color=colors.HexColor("#dddddd"),spaceAfter=8))
        story.append(Paragraph("EXTRACTED IOCs", h2_style))
        for kind, vals in iocs.items():
            story.append(Paragraph(f"<b>{kind.upper()}</b>", body_style))
            for v in vals[:10]:
                story.append(Paragraph(v, mono_style))
        story.append(Spacer(1,8))

    # ── Suspicious Strings Summary ────────────────────────────────────────────
    if hits:
        story.append(HRFlowable(width="100%",thickness=0.5,color=colors.HexColor("#dddddd"),spaceAfter=8))
        story.append(Paragraph("SUSPICIOUS STRING CATEGORIES", h2_style))
        str_data = [["Category","Count","Sample Indicators"]]
        for cat, pats in hits.items():
            str_data.append([cat, str(len(pats)), ", ".join(pats[:4])+("..." if len(pats)>4 else "")])
        str_tbl = Table(str_data, colWidths=[1.8*inch, 0.6*inch, 4.3*inch])
        str_tbl.setStyle(TableStyle([
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#2c3e50")),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.HexColor("#f8f9fa"),colors.white]),
            ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#dddddd")),
            ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
            ("LEFTPADDING",(0,0),(-1,-1),5),
        ]))
        story.append(str_tbl)

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1,20))
    story.append(HRFlowable(width="100%",thickness=1,color=colors.HexColor("#dddddd"),spaceAfter=6))
    story.append(Paragraph(f"Arthur Analysis — Generated {report['analyzed_at']} — For authorized security analysis only",
                           ParagraphStyle("footer",fontSize=7,fontName="Helvetica",
                                          textColor=colors.gray,alignment=TA_CENTER)))
    doc.build(story)

# ── HTML report ────────────────────────────────────────────────────────────────
def export_html(report, html_path):
    ex=report["executive_summary"]; severity=report["severity"]
    families=report["malware_classification"]; hits=report["suspicious_strings"]
    hashes=report["hashes"]; vt=report.get("virustotal"); mb=report.get("malwarebazaar")
    otx=report.get("otx"); obf=report.get("obfuscation",[]); sections=report.get("pe_sections",[])
    iocs=report.get("iocs",{})

    sev_color={"HIGH":"#c0392b","MEDIUM":"#e67e22","LOW":"#27ae60"}.get(severity,"#888")
    conf_color={"HIGH":"#c0392b","MEDIUM":"#e67e22","LOW":"#27ae60"}

    chart_labels=json.dumps(list(hits.keys()))
    chart_values=json.dumps([len(v) for v in hits.values()])
    chart_colors=json.dumps(["#c0392b" if k in("Ransomware","Rootkit","Process Injection","Botnet / RAT","Worm / Propagation") else "#e67e22" if k in("Infostealer","Network / C2","Persistence","Privilege Escalation","Anti-Analysis","Dropper / Downloader") else "#3498db" for k in hits.keys()])

    # VT card
    if vt and vt.get("found"):
        mal=vt["malicious"]; tot=vt["total"]; pct=int(mal/tot*100) if tot else 0
        vc={"HIGH":"#c0392b","MEDIUM":"#e67e22","LOW":"#27ae60"}.get(severity,"#27ae60")
        det_rows="".join(f'<tr><td>{e}</td><td><span class="badge" style="background:{"#c0392b" if r["category"]=="malicious" else "#e67e22"}">{r["category"]}</span></td><td style="font-family:monospace;font-size:12px">{r["result"]}</td></tr>' for e,r in list(vt.get("detections",{}).items())[:20])
        vt_card=f"""<div class="card"><h2>VirusTotal — {mal}/{tot} Engines Detected</h2>
        <div style="display:flex;align-items:center;gap:2rem;margin-bottom:1.5rem">
          <div style="text-align:center"><div style="font-size:2.5rem;font-weight:700;color:{vc}">{mal}<span style="font-size:1.2rem;color:#aaa">/{tot}</span></div><div style="font-size:.8rem;color:#aaa">engines</div></div>
          <div style="flex:1"><div style="background:#2a2d3a;border-radius:6px;height:12px"><div style="width:{pct}%;height:100%;background:{vc};border-radius:6px"></div></div>
          <div style="margin-top:.5rem;font-size:.85rem;color:#aaa">{pct}% detection rate</div>
          {'<div style="margin-top:.4rem;font-size:.85rem"><strong>Names: </strong>'+", ".join(vt["top_names"])+"</div>" if vt.get("top_names") else ""}
          {'<div style="margin-top:.4rem;font-size:.85rem"><strong>Tags: </strong>'+", ".join(vt.get("tags",[]))+"</div>" if vt.get("tags") else ""}
          </div><a href="{vt["vt_link"]}" target="_blank" style="padding:8px 16px;background:#2a2d3a;color:#a8d8ff;border-radius:6px;text-decoration:none;font-size:.85rem">View on VirusTotal ↗</a>
        </div>
        {'<table><thead><tr><th>Engine</th><th>Category</th><th>Name</th></tr></thead><tbody>'+det_rows+'</tbody></table>' if det_rows else '<p style="color:#27ae60">✓ No engines detected a threat</p>'}
        </div>"""
    elif vt:
        vt_card=f'<div class="card"><h2>VirusTotal</h2><p style="color:#aaa">{vt.get("reason","Not found")}</p></div>'
    else:
        vt_card='<div class="card"><h2>VirusTotal</h2><p style="color:#aaa">Run with <code>--vt-key YOUR_KEY</code> to enable. Free key at virustotal.com</p></div>'

    # MB card
    if mb and mb.get("found"):
        mb_card=f'<div class="card" style="border-color:#c0392b"><h2>MalwareBazaar — Confirmed Malware Sample</h2><div class="grid2" style="gap:.75rem"><div class="stat"><div class="label">Malware Name</div><div class="value" style="color:#c0392b">{mb.get("malware_name","Unknown")}</div></div><div class="stat"><div class="label">File Type</div><div class="value">{mb.get("file_type","")}</div></div><div class="stat"><div class="label">First Seen</div><div class="value">{mb.get("first_seen","")}</div></div><div class="stat"><div class="label">Reporter</div><div class="value">{mb.get("reporter","")}</div></div></div>{"<div style=\"margin-top:.75rem;font-size:.85rem\"><strong>Tags: </strong>"+", ".join(mb.get("tags",[]))+"</div>" if mb.get("tags") else ""}<a href="{mb.get("mb_link","")}" target="_blank" style="display:inline-block;margin-top:.75rem;padding:6px 14px;background:#2a2d3a;color:#a8d8ff;border-radius:6px;text-decoration:none;font-size:.85rem">View on MalwareBazaar ↗</a></div>'
    elif mb:
        mb_card=f'<div class="card"><h2>MalwareBazaar</h2><p style="color:#aaa">{mb.get("reason","Not found in database")}</p></div>'
    else:
        mb_card='<div class="card"><h2>MalwareBazaar</h2><p style="color:#aaa">MalwareBazaar check not run.</p></div>'

    # OTX card
    if otx and otx.get("found"):
        otx_card=f'<div class="card"><h2>AlienVault OTX — {otx["pulse_count"]} Threat Report(s)</h2><ul style="padding-left:1.5rem;font-size:.9rem">{"".join("<li>"+p+"</li>" for p in otx.get("pulse_names",[]))}</ul>{"<div style=\"margin-top:.75rem;font-size:.85rem\"><strong>Tags: </strong>"+", ".join(otx.get("tags",[]))+"</div>" if otx.get("tags") else ""}<a href="{otx.get("otx_link","")}" target="_blank" style="display:inline-block;margin-top:.75rem;padding:6px 14px;background:#2a2d3a;color:#a8d8ff;border-radius:6px;text-decoration:none;font-size:.85rem">View on OTX ↗</a></div>'
    elif otx:
        otx_card=f'<div class="card"><h2>AlienVault OTX</h2><p style="color:#aaa">{otx.get("reason","No reports found")}</p></div>'
    else:
        otx_card='<div class="card"><h2>AlienVault OTX</h2><p style="color:#aaa">Run with <code>--otx-key YOUR_KEY</code> to enable. Free key at otx.alienvault.com</p></div>'

    # IOC card
    ioc_html=""
    for kind,vals in iocs.items():
        tags="".join(f'<span class="tag">{v}</span>' for v in vals)
        ioc_html+=f'<div class="accordion"><div class="accordion-header" onclick="toggle(this)"><span>▶ {kind.upper()}</span><span class="badge-count">{len(vals)}</span></div><div class="accordion-body">{tags}</div></div>'
    ioc_card=f'<div class="card"><h2>Extracted IOCs ({sum(len(v) for v in iocs.values())} total)</h2>{ioc_html if ioc_html else "<p style=\"color:#27ae60\">✓ No IOCs extracted</p>"}</div>'

    family_rows="".join(f'<tr><td><strong>{f["family"]}</strong></td><td><span class="badge" style="background:{conf_color.get(f["confidence"],"#888")}">{f["confidence"]}</span></td><td>{f["indicator_count"]}</td><td>{", ".join(f["matched_categories"])}</td></tr>' for f in families) or '<tr><td colspan="4" style="color:#27ae60">✓ No known malware family matched</td></tr>'

    strings_html="".join(f'<div class="accordion"><div class="accordion-header" onclick="toggle(this)"><span>▶ {cat}</span><span class="badge-count">{len(pats)}</span></div><div class="accordion-body">{"".join(f"<span class=tag>{p}</span>" for p in pats)}</div></div>' for cat,pats in hits.items()) or '<p style="color:#27ae60;padding:1rem">✓ No suspicious strings detected.</p>'

    obf_html=f'<div class="card"><h2>Obfuscation & Deep Analysis</h2><ul style="padding-left:1.5rem;font-size:.9rem">{"".join("<li style=\"margin-bottom:6px;color:#e0c97f\">"+o+"</li>" for o in obf)}</ul></div>' if obf else '<div class="card"><h2>Obfuscation & Deep Analysis</h2><p style="color:#27ae60">✓ No obfuscation techniques detected</p></div>'

    sec_html=""
    if sections:
        rows="".join(f'<tr><td style="font-family:monospace">{s["name"]}</td><td>{fmt_size(s["size"])}</td><td style="color:{"#c0392b" if s["entropy"]>7.2 else "#e67e22" if s["entropy"]>6.5 else "#aaa"}">{s["entropy"]:.2f} {"⚠ packed?" if s["entropy"]>7.2 else ""}</td></tr>' for s in sections)
        sec_html=f'<div class="card"><h2>PE Section Analysis</h2><table><thead><tr><th>Section</th><th>Size</th><th>Entropy</th></tr></thead><tbody>{rows}</tbody></table></div>'

    html=f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Arthur Analysis — {report["filename"]}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e0e0e0;line-height:1.6}}.topbar{{background:#1a1d27;border-bottom:2px solid {sev_color};padding:1.2rem 2rem;display:flex;align-items:center;gap:1rem}}.topbar h1{{font-size:1.2rem;font-weight:600;color:#fff}}.filename{{font-size:.9rem;color:#aaa}}.sev-badge{{background:{sev_color};color:#fff;font-size:.8rem;font-weight:700;padding:4px 14px;border-radius:20px;letter-spacing:.05em}}.container{{max-width:1100px;margin:0 auto;padding:2rem 1.5rem;display:grid;gap:1.5rem}}.card{{background:#1a1d27;border:1px solid #2a2d3a;border-radius:10px;padding:1.5rem}}.card h2{{font-size:.75rem;text-transform:uppercase;letter-spacing:.1em;color:#7a8aaa;margin-bottom:1rem;border-bottom:1px solid #2a2d3a;padding-bottom:.5rem}}.exec-verdict{{font-size:1.1rem;font-weight:700;color:{sev_color};margin-bottom:.5rem}}.exec-action{{background:{sev_color}22;border-left:3px solid {sev_color};padding:.75rem 1rem;border-radius:0 6px 6px 0;margin:.75rem 0;font-size:.95rem}}.exec-detail{{font-size:.9rem;color:#bbb}}.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem}}.stat{{background:#12141c;border-radius:8px;padding:1rem}}.stat .label{{font-size:.75rem;color:#7a8aaa;margin-bottom:4px}}.stat .value{{font-size:1rem;font-weight:600;word-break:break-all}}table{{width:100%;border-collapse:collapse;font-size:.9rem}}th{{text-align:left;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:#7a8aaa;padding:.5rem .75rem;border-bottom:1px solid #2a2d3a}}td{{padding:.6rem .75rem;border-bottom:1px solid #1e2130;vertical-align:top}}tr:last-child td{{border-bottom:none}}.badge{{display:inline-block;font-size:.7rem;font-weight:700;padding:2px 10px;border-radius:20px;color:#fff;letter-spacing:.04em}}.badge-count{{background:#2a2d3a;color:#aaa;font-size:.75rem;padding:2px 8px;border-radius:20px}}.hash-row{{display:flex;gap:.75rem;align-items:center;margin-bottom:.5rem;font-size:.85rem}}.hash-label{{min-width:60px;color:#7a8aaa;font-size:.75rem}}.hash-val{{font-family:'Cascadia Code','Consolas',monospace;color:#a8d8ff;word-break:break-all}}.accordion{{border:1px solid #2a2d3a;border-radius:6px;margin-bottom:.5rem;overflow:hidden}}.accordion-header{{display:flex;justify-content:space-between;align-items:center;padding:.75rem 1rem;cursor:pointer;background:#12141c;font-size:.9rem}}.accordion-header:hover{{background:#1e2130}}.accordion-body{{padding:.75rem 1rem;display:none;flex-wrap:wrap;gap:6px}}.accordion-body.open{{display:flex}}.tag{{background:#2a2d3a;color:#e0c97f;font-family:monospace;font-size:.78rem;padding:3px 8px;border-radius:4px}}.behavior-text{{font-size:.92rem;color:#ccc;line-height:1.8}}canvas{{max-height:280px}}code{{background:#2a2d3a;padding:2px 6px;border-radius:4px;font-size:.85rem}}.footer{{text-align:center;font-size:.75rem;color:#555;padding:1rem 0 2rem}}@media(max-width:700px){{.grid2{{grid-template-columns:1fr}}}}</style></head><body>
<div class="topbar"><div style="flex:1"><div class="filename">{report["filepath"]}</div><h1>{report["filename"]}</h1></div><span class="sev-badge">{severity} RISK</span></div>
<div class="container">
<div class="card"><h2>Executive Summary</h2><div class="exec-verdict">{ex["verdict"]}</div><div class="exec-action">{ex["action"]}</div><div class="exec-detail">{ex["detail"]}</div></div>
{vt_card}{mb_card}{otx_card}
<div class="grid2"><div class="card"><h2>File Information</h2><div class="grid2" style="gap:.75rem"><div class="stat"><div class="label">Filename</div><div class="value">{report["filename"]}</div></div><div class="stat"><div class="label">Size</div><div class="value">{report["size"]}</div></div><div class="stat"><div class="label">Extension</div><div class="value">.{report["extension"]} <span class="badge" style="background:{conf_color.get(report["extension_risk"],"#888")}">{report["extension_risk"]}</span></div></div><div class="stat"><div class="label">File Type</div><div class="value" style="font-size:.85rem">{report["magic_type"]}</div></div><div class="stat"><div class="label">Entropy</div><div class="value">{report["entropy"]:.2f}/8.0{"  ⚠ high" if report["entropy"]>7.2 else ""}</div></div><div class="stat"><div class="label">Analyzed</div><div class="value" style="font-size:.8rem">{report["analyzed_at"]}</div></div></div></div>
<div class="card"><h2>File Hashes</h2><div class="hash-row"><span class="hash-label">MD5</span><span class="hash-val">{hashes["md5"]}</span></div><div class="hash-row"><span class="hash-label">SHA-1</span><span class="hash-val">{hashes["sha1"]}</span></div><div class="hash-row"><span class="hash-label">SHA-256</span><span class="hash-val">{hashes["sha256"]}</span></div><p style="margin-top:1rem;font-size:.8rem;color:#7a8aaa">Search hashes on <a href="https://virustotal.com" target="_blank" style="color:#a8d8ff">VirusTotal</a> or <a href="https://bazaar.abuse.ch" target="_blank" style="color:#a8d8ff">MalwareBazaar</a>.</p></div></div>
{ioc_card}{obf_html}{sec_html}
<div class="card"><h2>Malware Classification</h2><table><thead><tr><th>Family</th><th>Confidence</th><th>Indicators</th><th>Matched Categories</th></tr></thead><tbody>{family_rows}</tbody></table></div>
<div class="card"><h2>Behavior Summary</h2><p class="behavior-text">{report["behavior_summary"]}</p></div>
<div class="grid2"><div class="card"><h2>Indicator Distribution</h2>{"<canvas id='chart'></canvas>" if hits else "<p style='color:#27ae60;padding:2rem 0;text-align:center'>✓ No indicators</p>"}</div>
<div class="card"><h2>Suspicious Strings ({sum(len(v) for v in hits.values())} total)</h2>{strings_html}</div></div>
</div><div class="footer">Arthur Analysis &mdash; {report["analyzed_at"]}</div>
<script>function toggle(el){{el.nextElementSibling.classList.toggle("open")}}
{"var ctx=document.getElementById('chart');new Chart(ctx,{type:'bar',data:{labels:"+chart_labels+",datasets:[{data:"+chart_values+",backgroundColor:"+chart_colors+",borderRadius:4}]},options:{plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#aaa',font:{size:11}},grid:{color:'#2a2d3a'}},y:{ticks:{color:'#aaa',stepSize:1},grid:{color:'#2a2d3a'},beginAtZero:true}}}});" if hits else ""}
</script></body></html>"""
    Path(html_path).write_text(html,encoding="utf-8")

# ── Dashboard ──────────────────────────────────────────────────────────────────
def export_dashboard(out_path="arthur_dashboard.html"):
    rows=load_history(200)
    if not rows:
        print(colored("  No scan history found. Run some scans first.",YELLOW)); return

    total=len(rows)
    high=sum(1 for r in rows if r["severity"]=="HIGH")
    medium=sum(1 for r in rows if r["severity"]=="MEDIUM")
    low=sum(1 for r in rows if r["severity"]=="LOW")
    vt_confirmed=sum(1 for r in rows if r.get("vt_malicious",0) and int(r["vt_malicious"] or 0)>0)
    mb_confirmed=sum(1 for r in rows if r.get("mb_detected"))
    watchlist_hits=sum(1 for r in rows if r.get("watchlist_hit"))

    table_rows=""
    for r in rows:
        sev=r["severity"]
        sc={"HIGH":"#c0392b","MEDIUM":"#e67e22","LOW":"#27ae60"}.get(sev,"#888")
        vt_txt=f"{r['vt_malicious']}/{r['vt_total']}" if r.get("vt_total") else "—"
        wl="⚠" if r.get("watchlist_hit") else ""
        table_rows+=f'<tr><td style="font-size:.8rem;color:#aaa">{r["analyzed_at"][:16]}</td><td title="{r["filepath"]}">{r["filename"]} {wl}</td><td><span style="background:{sc};color:#fff;padding:2px 8px;border-radius:12px;font-size:.75rem;font-weight:700">{sev}</span></td><td style="font-size:.85rem">{r["families"] or "—"}</td><td style="font-size:.85rem">{vt_txt}</td><td style="font-family:monospace;font-size:.75rem;color:#a8d8ff">{r["sha256"][:16]}...</td></tr>'

    html=f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Arthur Analysis — Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>*{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e0e0e0;line-height:1.6}}.topbar{{background:#1a1d27;border-bottom:2px solid #7a8aaa;padding:1.2rem 2rem}}.topbar h1{{font-size:1.3rem;font-weight:700;color:#fff}}.topbar p{{font-size:.85rem;color:#aaa}}.container{{max-width:1200px;margin:0 auto;padding:2rem 1.5rem;display:grid;gap:1.5rem}}.card{{background:#1a1d27;border:1px solid #2a2d3a;border-radius:10px;padding:1.5rem}}.card h2{{font-size:.75rem;text-transform:uppercase;letter-spacing:.1em;color:#7a8aaa;margin-bottom:1rem;border-bottom:1px solid #2a2d3a;padding-bottom:.5rem}}.stats{{display:grid;grid-template-columns:repeat(6,1fr);gap:1rem}}.stat{{background:#12141c;border-radius:8px;padding:1rem;text-align:center}}.stat .n{{font-size:2rem;font-weight:700}}.stat .l{{font-size:.75rem;color:#7a8aaa;margin-top:4px}}table{{width:100%;border-collapse:collapse;font-size:.9rem}}th{{text-align:left;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:#7a8aaa;padding:.5rem .75rem;border-bottom:1px solid #2a2d3a}}td{{padding:.55rem .75rem;border-bottom:1px solid #1e2130;vertical-align:middle}}tr:hover td{{background:#1e2130}}canvas{{max-height:220px}}.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem}}.footer{{text-align:center;font-size:.75rem;color:#555;padding:1rem 0 2rem}}input{{background:#12141c;border:1px solid #2a2d3a;color:#e0e0e0;padding:6px 12px;border-radius:6px;font-size:.9rem;width:300px}}@media(max-width:900px){{.stats{{grid-template-columns:repeat(3,1fr)}}.grid2{{grid-template-columns:1fr}}}}</style></head><body>
<div class="topbar"><h1>Arthur Analysis — Threat Intelligence Dashboard</h1><p>Last updated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")} &nbsp;|&nbsp; {total} scans in history</p></div>
<div class="container">
<div class="stats">
  <div class="stat"><div class="n">{total}</div><div class="l">Total Scans</div></div>
  <div class="stat"><div class="n" style="color:#c0392b">{high}</div><div class="l">High Risk</div></div>
  <div class="stat"><div class="n" style="color:#e67e22">{medium}</div><div class="l">Medium Risk</div></div>
  <div class="stat"><div class="n" style="color:#27ae60">{low}</div><div class="l">Low Risk</div></div>
  <div class="stat"><div class="n" style="color:#c0392b">{vt_confirmed}</div><div class="l">VT Confirmed</div></div>
  <div class="stat"><div class="n" style="color:#c0392b">{mb_confirmed}</div><div class="l">MalwareBazaar</div></div>
</div>
<div class="grid2">
  <div class="card"><h2>Severity Distribution</h2><canvas id="sevChart"></canvas></div>
  <div class="card"><h2>Search Scan History</h2><input id="search" placeholder="Search filename, family, hash..." oninput="filterTable()"><br><br><p style="font-size:.85rem;color:#aaa">{watchlist_hits} watchlist hit(s) in history</p></div>
</div>
<div class="card"><h2>Scan History</h2><table id="histTable"><thead><tr><th>Date</th><th>File</th><th>Severity</th><th>Classification</th><th>VT</th><th>SHA-256</th></tr></thead><tbody>{table_rows}</tbody></table></div>
</div><div class="footer">Arthur Analysis Threat Dashboard &mdash; {datetime.now(timezone.utc).isoformat()}</div>
<script>
new Chart(document.getElementById("sevChart"),{{type:"doughnut",data:{{labels:["High","Medium","Low"],datasets:[{{data:[{high},{medium},{low}],backgroundColor:["#c0392b","#e67e22","#27ae60"],borderWidth:0}}]}},options:{{plugins:{{legend:{{labels:{{color:"#aaa"}}}}}}}}}});
function filterTable(){{var q=document.getElementById("search").value.toLowerCase();document.querySelectorAll("#histTable tbody tr").forEach(r=>{{r.style.display=r.textContent.toLowerCase().includes(q)?"":"none"}})}}
</script></body></html>"""
    Path(out_path).write_text(html,encoding="utf-8")
    print(colored(f"  Dashboard saved: {Path(out_path).resolve()}",CYAN))

# ── Main analysis ──────────────────────────────────────────────────────────────
def analyze(filepath, as_json=False, report_path=None, html_path=None,
            csv_path=None, pdf_path=None, vt_key=None, otx_key=None, watchlist_path=None, no_mb=False):
    path=Path(filepath)
    if not path.exists():
        print(colored(f"[ERROR] File not found: {filepath}",RED)); sys.exit(1)

    print(colored(f"  Scanning: {path.name}",GRAY))
    data=path.read_bytes()
    ext=path.suffix.lstrip(".").lower()
    ext_risk="HIGH" if ext in HIGH_RISK_EXTS else("MEDIUM" if ext in MED_RISK_EXTS else "LOW")
    magic_type,magic_risk=detect_magic(data)
    hashes=compute_hashes(data)
    hits=scan_strings(data)
    ent=calc_entropy(data)
    obf=detect_obfuscation(data)
    sections=section_entropy(data)
    iocs=extract_iocs(data)
    families=classify_malware(hits,magic_risk,ext_risk,ent)
    behavior=build_behavior_summary(families,hits)
    analyzed_at=datetime.now(timezone.utc).isoformat()

    # Watchlist check
    watchlist=load_watchlist(watchlist_path)
    wl_hit,wl_hash=check_watchlist(hashes,watchlist)

    # Threat intel lookups
    vt_result=None
    if vt_key:
        print(colored("  Querying VirusTotal...",GRAY))
        vt_result=query_virustotal(hashes["sha256"],vt_key)

    mb_result=None
    if not no_mb:
        print(colored("  Querying MalwareBazaar...",GRAY))
        mb_result=query_malwarebazaar(hashes["sha256"])

    otx_result=None
    if otx_key:
        print(colored("  Querying AlienVault OTX...",GRAY))
        otx_result=query_otx(hashes["sha256"],otx_key)

    severity=severity_label(hits,magic_risk,ext_risk,vt_result,mb_result)

    report={
        "filename":path.name,"filepath":str(path.resolve()),
        "size":fmt_size(len(data)),"size_bytes":len(data),
        "extension":ext or "(none)","extension_risk":ext_risk,
        "magic_type":magic_type,"magic_risk":magic_risk,
        "entropy":round(ent,4),"hashes":hashes,
        "suspicious_strings":hits,"obfuscation":obf,
        "pe_sections":sections,"iocs":iocs,
        "malware_classification":families,"behavior_summary":behavior,
        "severity":severity,"analyzed_at":analyzed_at,
        "watchlist_hit":wl_hit,
    }
    if vt_result: report["virustotal"]=vt_result
    if mb_result: report["malwarebazaar"]=mb_result
    if otx_result: report["otx"]=otx_result
    report["executive_summary"]=build_executive_summary(report)

    # Save to database
    try: save_scan(report)
    except: pass

    if as_json:
        print(json.dumps(report,indent=2)); return report

    # ── Console output ────────────────────────────────────────────────────────
    W=62; sep="─"*W; s2="═"*W
    ex=report["executive_summary"]; vt=report.get("virustotal"); mb=report.get("malwarebazaar"); otx=report.get("otx")

    def pr(text="",color=None): print(colored(text,color) if color else text)

    pr(); pr("  ARTHUR ANALYSIS — THREAT INTELLIGENCE REPORT",BOLD)
    pr(s2,GRAY); pr(f"  Analyzed : {analyzed_at}"); pr(f"  File     : {path.name}"); pr(sep,GRAY); pr()

    if wl_hit: pr(f"  ⚠ WATCHLIST MATCH: {wl_hash}",RED); pr()

    pr("  [EXECUTIVE SUMMARY]",CYAN)
    pr(f"  {ex['verdict']}",risk_color(severity))
    pr(f"  {ex['action']}"); pr(f"  {ex['detail']}"); pr()

    if vt:
        pr("  [VIRUSTOTAL]",CYAN)
        if vt.get("found"):
            mal=vt["malicious"]; tot=vt["total"]
            col=RED if mal>5 else YELLOW if mal>0 else GREEN
            pr(f"  Detections : {mal}/{tot} engines",col)
            if vt.get("top_names"): pr(f"  Names      : {', '.join(vt['top_names'])}")
            if vt.get("tags"): pr(f"  Tags       : {', '.join(vt['tags'])}")
            pr(f"  Full report: {vt['vt_link']}")
        else: pr(f"  {vt.get('reason','Not found')}",GRAY)
        pr()

    if mb:
        pr("  [MALWAREBAZAAR]",CYAN)
        if mb.get("found"):
            pr(f"  ⚠ KNOWN MALWARE: {mb.get('malware_name','Unknown')}",RED)
            pr(f"  First seen : {mb.get('first_seen','')}"); pr(f"  Link       : {mb.get('mb_link','')}")
        else: pr(f"  {mb.get('reason','Not found')}",GRAY)
        pr()

    if otx:
        pr("  [ALIENVAULT OTX]",CYAN)
        if otx.get("found"):
            pr(f"  {otx['pulse_count']} threat report(s) found",YELLOW)
            for p in otx.get("pulse_names",[]): pr(f"    • {p}")
        else: pr(f"  {otx.get('reason','No reports')}",GRAY)
        pr()

    pr("  [FILE INFO]",CYAN)
    pr(f"  Name      : {path.name}"); pr(f"  Size      : {fmt_size(len(data))}  ({len(data):,} bytes)")
    pr(f"  Extension : .{ext}  [risk: {ext_risk}]"); pr(f"  Type      : {magic_type}  [risk: {magic_risk}]")
    ent_note="  ← high: may be packed/encrypted" if ent>7.2 else ""
    pr(f"  Entropy   : {ent:.2f} / 8.0{ent_note}"); pr()

    pr("  [HASHES]",CYAN)
    pr(f"  MD5    : {hashes['md5']}"); pr(f"  SHA-1  : {hashes['sha1']}"); pr(f"  SHA-256: {hashes['sha256']}"); pr()

    if iocs:
        pr("  [EXTRACTED IOCs]",CYAN)
        for kind,vals in iocs.items():
            pr(f"  ▶ {kind.upper()}",YELLOW)
            for v in vals[:5]: pr(f"      {v}")
        pr()

    if obf:
        pr("  [OBFUSCATION DETECTED]",CYAN)
        for o in obf: pr(f"  ⚠ {o}",YELLOW)
        pr()

    if sections:
        pr("  [PE SECTION ENTROPY]",CYAN)
        for s in sections:
            col=RED if s["entropy"]>7.2 else YELLOW if s["entropy"]>6.5 else None
            pr(f"  {s['name']:<12} entropy:{s['entropy']:.2f}  size:{fmt_size(s['size'])}",col)
        pr()

    pr("  [MALWARE CLASSIFICATION]",CYAN)
    if families:
        for f in families:
            c={"HIGH":RED,"MEDIUM":YELLOW,"LOW":GREEN}.get(f["confidence"],WHITE)
            pr(f"  ► {f['family']}  [confidence: {f['confidence']}]",c)
            pr(f"    {f['indicator_count']} indicator(s) — {', '.join(f['matched_categories'])}")
    else: pr("  ✓ No known malware family matched",GREEN)
    pr()

    pr("  [BEHAVIOR SUMMARY]",CYAN)
    words,buf=behavior.split(),"  "
    for word in words:
        if len(buf)+len(word)+1>60: pr(buf); buf="  "+word
        else: buf+=(" " if buf.strip() else "")+word
    if buf.strip(): pr(buf)
    pr()

    pr("  [SUSPICIOUS STRINGS]",CYAN)
    if hits:
        for cat,pats in hits.items():
            pr(f"  ▶ {cat}",YELLOW)
            for p in pats: pr(f"      {p}")
    else: pr("  ✓ None detected",GREEN)
    pr()

    pr("  [OVERALL SEVERITY]",CYAN)
    pr(f"  ● {severity}",risk_color(severity)); pr(); pr(s2,GRAY); pr()

    if html_path:    export_html(report,html_path);   pr(f"  HTML report  : {Path(html_path).resolve()}",CYAN)
    if csv_path:     export_csv(report,csv_path);    pr(f"  CSV updated  : {Path(csv_path).resolve()}",CYAN)
    if pdf_path:     export_pdf(report,pdf_path);    pr(f"  PDF report   : {Path(pdf_path).resolve()}",CYAN)
    if report_path:
        Path(report_path).write_text(f"Arthur Analysis Report\n{'='*60}\nFile: {path.name}\nAnalyzed: {analyzed_at}\nSeverity: {severity}\nVerdict: {ex['verdict']}\n\nHASHES\nMD5:    {hashes['md5']}\nSHA-1:  {hashes['sha1']}\nSHA-256:{hashes['sha256']}\n\nMALWARE CLASSIFICATION\n"+"\n".join(f"► {f['family']} [{f['confidence']}]" for f in families)+f"\n\nBEHAVIOR\n{behavior}\n\nSEVERITY: {severity}\n{'='*60}\n",encoding="utf-8")
        pr(f"  Report saved : {Path(report_path).resolve()}",CYAN)
    if html_path or csv_path or report_path or pdf_path: pr()

    return report

def scan_folder(folder, **kwargs):
    path=Path(folder)
    if not path.is_dir(): print(colored(f"[ERROR] Not a folder: {folder}",RED)); sys.exit(1)
    files=list(path.rglob("*"))
    files=[f for f in files if f.is_file()]
    print(colored(f"\n  Found {len(files)} file(s) in {folder}\n",CYAN))
    results=[]
    for i,f in enumerate(files,1):
        print(colored(f"  [{i}/{len(files)}] ",GRAY),end="")
        try: r=analyze(str(f),**kwargs); results.append(r)
        except Exception as e: print(colored(f"  Error scanning {f.name}: {e}",RED))
    high=[r for r in results if r["severity"]=="HIGH"]
    print(colored(f"\n  Folder scan complete: {len(results)} files | {len(high)} HIGH risk",CYAN))
    return results

# ── Entry point ────────────────────────────────────────────────────────────────
def main():
    parser=argparse.ArgumentParser(description="Arthur Analysis — Full Threat Intelligence Platform")
    parser.add_argument("file",nargs="?",help="File or folder to analyze")
    parser.add_argument("--scan-folder",action="store_true",help="Scan all files in a folder")
    parser.add_argument("--vt-key",metavar="KEY",help="VirusTotal API key (virustotal.com)")
    parser.add_argument("--otx-key",metavar="KEY",help="AlienVault OTX API key (otx.alienvault.com)")
    parser.add_argument("--no-mb",action="store_true",help="Skip MalwareBazaar lookup")
    parser.add_argument("--watchlist",metavar="FILE",help="Path to hash watchlist .txt file")
    parser.add_argument("--json",action="store_true",help="Output as JSON")
    parser.add_argument("--report",metavar="FILE",help="Save plain-text report")
    parser.add_argument("--html",metavar="FILE",help="Save HTML report")
    parser.add_argument("--csv",     metavar="FILE", help="Append to CSV log")
    parser.add_argument("--pdf",     metavar="FILE", help="Save PDF report (e.g. report.pdf) — requires: pip install reportlab")
    parser.add_argument("--dashboard",metavar="FILE",nargs="?",const="arthur_dashboard.html",help="Generate scan history dashboard")
    args=parser.parse_args()

    if args.dashboard:
        export_dashboard(args.dashboard)
        return

    if not args.file:
        parser.print_help(); sys.exit(1)

    vt_key=args.vt_key or os.environ.get("VT_API_KEY")
    otx_key=args.otx_key or os.environ.get("OTX_API_KEY")

    kwargs=dict(as_json=args.json,report_path=args.report,html_path=args.html,
                csv_path=args.csv,pdf_path=args.pdf,vt_key=vt_key,otx_key=otx_key,
                watchlist_path=args.watchlist,no_mb=args.no_mb)

    if args.scan_folder:
        scan_folder(args.file,**kwargs)
    else:
        analyze(args.file,**kwargs)

if __name__=="__main__":
    main()
