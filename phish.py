#!/usr/bin/env python3
# GSPL Phish Analyzer — IMAP poller + URL intel (VT + GSB) + header checks + risky attachments + lookalikes
# Notes:
# - SPF/DKIM/DMARC shown from Authentication-Results but do NOT affect score.
# - Verdict comes from URL intelligence + header mismatches + risky attachments + lookalike domains.

import os, re, time, imaplib, email, hashlib, requests, smtplib, socket, traceback
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.utils import parseaddr
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

# deps
import dns.resolver
import tldextract

# ====== Config via ENV ======
IMAP_SERVER   = os.getenv("IMAP_SERVER")
IMAP_USER     = os.getenv("IMAP_USER")
IMAP_PASS     = os.getenv("IMAP_PASS")
SMTP_SERVER   = os.getenv("SMTP_SERVER")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "465"))
SMTP_USER     = os.getenv("SMTP_USER")
SMTP_PASS     = os.getenv("SMTP_PASS")
REPLY_FROM    = os.getenv("REPLY_FROM", IMAP_USER)
VT_API_KEY    = os.getenv("VT_API_KEY", "")
GSB_API_KEY   = os.getenv("GSB_API_KEY", "")
KUMA_URL      = os.getenv("KUMA_URL", "")

# Tuning
POLL_SECONDS         = int(os.getenv("POLL_SECONDS", "30"))
MAX_URL_THREADS      = int(os.getenv("MAX_URL_THREADS", "8"))
MAX_MSG_THREADS      = int(os.getenv("MAX_MSG_THREADS", "4"))

# Scoring (SPF/DKIM/DMARC intentionally NOT scored)
VT_MALICIOUS_POINTS      = int(os.getenv("VT_MALICIOUS_POINTS", "30"))
SB_HIT_POINTS            = int(os.getenv("SB_HIT_POINTS", "30"))
HEADER_MISMATCH_POINTS   = int(os.getenv("HEADER_MISMATCH_POINTS", "15"))
ATTACH_DANGEROUS_POINTS  = int(os.getenv("ATTACH_DANGEROUS_POINTS", "25"))
LOOKALIKE_POINTS         = int(os.getenv("LOOKALIKE_POINTS", "20"))

THRESHOLD_SUSPICIOUS = int(os.getenv("THRESHOLD_SUSPICIOUS", "35"))
THRESHOLD_MALICIOUS  = int(os.getenv("THRESHOLD_MALICIOUS", "70"))

SAVE_DIR = "samples"
os.makedirs(SAVE_DIR, exist_ok=True)

socket.setdefaulttimeout(45)

# Risky attachment extensions
RISKY_EXTS = {".exe",".scr",".js",".vbs",".jar",".msi",".cmd",".bat",".ps1",
              ".hta",".vbe",".jse",".apk",".pkg",".iso",".img",".lnk",
              ".docm",".xlsm",".xlam",".pptm",".rtf",".chm",".ace",".7z",".rar",".zip"}

# ===== Small helpers =====

def levenshtein(a: str, b: str) -> int:
    a, b = a.lower(), b.lower()
    if a == b: return 0
    if not a: return len(b)
    if not b: return len(a)
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            ins = prev[j] + 1
            dele = curr[j-1] + 1
            sub = prev[j-1] + (ca != cb)
            curr.append(min(ins, dele, sub))
        prev = curr
    return prev[-1]

def registrable_domain(host: str) -> str:
    if not host: return ""
    ext = tldextract.extract(host)
    return (ext.registered_domain or host).lower()

def extract_urls_from_msg(msg):
    urls = set()
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype in ("text/html", "text/plain"):
            try:
                body = part.get_payload(decode=True).decode(errors="ignore")
                urls.update(re.findall(r"https?://[^\s\"'>]+", body))
            except Exception:
                continue
    cleaned = []
    for u in urls:
        cleaned.append(u.rstrip(").,;:]"))
    return list(set(cleaned))

def vt_lookup_url(url):
    if not VT_API_KEY: return None
    try:
        r = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": VT_API_KEY},
            data={"url": url},
            timeout=20
        )
        if r.status_code != 200: return None
        j = r.json()
        data_id = j.get("data", {}).get("id")
        if not data_id: return None
        r2 = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{data_id}",
            headers={"x-apikey": VT_API_KEY},
            timeout=20
        )
        if r2.status_code != 200: return None
        return r2.json().get("data", {}).get("attributes", {}).get("stats", {})
    except Exception:
        return None

def vt_lookup_domain(domain):
    if not VT_API_KEY or not domain: return None
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VT_API_KEY},
            timeout=20
        )
        if r.status_code != 200: return None
        return r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    except Exception:
        return None

def gsb_lookup_url_details(url):
    if not GSB_API_KEY: return {"hit": False, "matches": []}
    payload = {
        "client": {"clientId": "phishbox", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
            json=payload, timeout=20
        )
        if r.status_code != 200: return {"hit": False, "matches": []}
        data = r.json()
        matches = data.get("matches", [])
        return {"hit": bool(matches), "matches": matches}
    except Exception:
        return {"hit": False, "matches": []}

def parse_authentication_results(msg):
    """Parse Authentication-Results for spf= / dkim= / dmarc= (informational only)"""
    ars = msg.get_all("Authentication-Results", [])
    res = {"spf": None, "dkim": None, "dmarc": None}
    if not ars: return res
    txt = " ".join(ars)
    m = re.search(r"\bspf=([a-zA-Z0-9_-]+)", txt)
    if m: res["spf"] = m.group(1).lower()
    m = re.search(r"\bdkim=([a-zA-Z0-9_-]+)", txt)
    if m: res["dkim"] = m.group(1).lower()
    m = re.search(r"\bdmarc=([a-zA-Z0-9_-]+)", txt)
    if m: res["dmarc"] = m.group(1).lower()
    return res

def header_consistency_checks(msg):
    """Compare From vs Return-Path vs Reply-To; return (reasons, mismatch_count, from_domain)"""
    reasons = []
    def dom_of(hname):
        v = msg.get(hname) or ""
        addr = parseaddr(v)[1]
        return addr.split("@")[-1].lower() if "@" in addr else ""
    fdom = dom_of("From")
    rdom = dom_of("Return-Path")
    repdom = dom_of("Reply-To")
    if fdom and rdom and fdom != rdom:
        reasons.append(f"Header mismatch: From domain {fdom} != Return-Path {rdom}")
    if fdom and repdom and fdom != repdom:
        reasons.append(f"Header mismatch: From domain {fdom} != Reply-To {repdom}")
    mismatch_count = len(reasons)
    return reasons, mismatch_count, fdom

def risky_attachment_checks(msg):
    """Return (reasons, risky_count, attachments_list)"""
    reasons = []
    attachments = []
    risky = 0
    for part in msg.walk():
        fname = part.get_filename()
        if not fname: continue
        try:
            content = part.get_payload(decode=True)
        except Exception:
            content = None
        sha256 = hashlib.sha256(content).hexdigest() if content else None
        attachments.append((fname, sha256))
        ext = os.path.splitext(fname)[1].lower()
        if ext in RISKY_EXTS:
            risky += 1
            reasons.append(f"Risky attachment: {fname}")
    return reasons, risky, attachments

def lookalike_domain_finds(sender_domain: str, urls: list):
    """Flag if any URL host looks like the sender domain (distance <= 2) but is different."""
    if not sender_domain: return [], 0
    sd = registrable_domain(sender_domain)
    if not sd: return [], 0
    reasons = []
    hits = 0
    seen = set()
    for u in urls:
        try:
            host = urlparse(u).hostname or ""
        except Exception:
            host = ""
        rd = registrable_domain(host)
        if not rd or rd == sd:
            continue
        key = (sd, rd)
        if key in seen:
            continue
        seen.add(key)
        dist = levenshtein(sd, rd)
        if dist <= 2:
            hits += 1
            reasons.append(f"Lookalike domain: '{rd}' ~ '{sd}'")
    return reasons, hits

def send_kuma_heartbeat():
    if not KUMA_URL: return
    try:
        r = requests.get(KUMA_URL, timeout=5)
        if r.status_code == 200:
            print("[♥] Uptime Kuma heartbeat sent")
        else:
            print(f"[!] Kuma heartbeat failed: {r.status_code}")
    except Exception as e:
        print(f"[!] Kuma heartbeat error: {e}")

# ===== Core analysis =====

def analyze_eml_file(path):
    with open(path, "rb") as f:
        raw = f.read()
        msg = email.message_from_bytes(raw, policy=policy.default)

    # ---- URL extraction + intel
    urls = extract_urls_from_msg(msg)
    url_findings = []
    vt_hits = 0
    sb_hits = 0
    reasons = []
    score = 0

    def check_one_url(u):
        vt_stats = vt_lookup_url(u) or {}
        mal = int(vt_stats.get("malicious", 0))
        gsb = gsb_lookup_url_details(u)
        gsb_hit = bool(gsb.get("hit"))
        local_reasons = []
        if mal > 0:
            local_reasons.append(f"VirusTotal flagged {mal} engines for {u}")
        if gsb_hit:
            ttypes = ", ".join({m.get("threatType","") for m in gsb.get("matches",[])})
            local_reasons.append(f"Google Safe Browsing match ({ttypes}) for {u}")
        return {
            "url": u,
            "vt": vt_stats,
            "gsb": gsb,
            "vt_malicious": mal,
            "gsb_hit": gsb_hit,
            "reasons": local_reasons
        }

    if urls:
        with ThreadPoolExecutor(max_workers=MAX_URL_THREADS) as pool:
            for finding in pool.map(check_one_url, urls):
                url_findings.append(finding)
                vt_hits += 1 if finding["vt_malicious"] > 0 else 0
                sb_hits += 1 if finding["gsb_hit"] else 0
                reasons.extend(finding["reasons"])

    score += vt_hits * VT_MALICIOUS_POINTS
    score += sb_hits * SB_HIT_POINTS

    # ---- Header consistency
    hdr_reasons, mismatches, from_domain = header_consistency_checks(msg)
    if mismatches:
        score += HEADER_MISMATCH_POINTS
        reasons.extend(hdr_reasons)

    # ---- Risky attachments
    attach_reasons, risky_count, attachments = risky_attachment_checks(msg)
    if risky_count:
        score += ATTACH_DANGEROUS_POINTS
        reasons.extend(attach_reasons)

    # ---- Lookalike domains (URLs vs sender domain)
    sender_addr = parseaddr(msg.get("From", ""))[1]
    sender_domain = sender_addr.split("@", 1)[1].lower() if "@" in sender_addr else None
    ll_reasons, ll_hits = lookalike_domain_finds(sender_domain, urls)
    if ll_hits:
        score += LOOKALIKE_POINTS
        reasons.extend(ll_reasons)

    # ---- Sender domain VT (informational)
    vt_domain_stats = vt_lookup_domain(registrable_domain(sender_domain)) if sender_domain else {}

    # ---- Authentication-Results (informational)
    auth = parse_authentication_results(msg)

    # ---- Verdict
    verdict = "Safe"
    if score >= THRESHOLD_MALICIOUS:
        verdict = "Malicious"
    elif score >= THRESHOLD_SUSPICIOUS:
        verdict = "Suspicious"
    if not reasons:
        reasons.append("No obvious red flags detected")

    return {
        "subject": msg.get("Subject", ""),
        "from": msg.get("From", ""),                 # the analyzed inner .eml sender (or outer if inline)
        "from_name_email": sender_addr,
        "sender_domain": sender_domain,
        "auth_results": auth,                        # {'spf':..., 'dkim':..., 'dmarc':...}
        "urls": urls,
        "url_findings": url_findings,                # per-URL VT/GSB details
        "attachments": attachments,                  # (filename, sha256)
        "vt_hits": vt_hits,
        "sb_hits": sb_hits,
        "header_mismatches": mismatches,
        "risky_attachments": risky_count,
        "lookalike_hits": ll_hits,
        "domain_result": {                           # informational
            "vt_malicious": int((vt_domain_stats or {}).get("malicious", 0)),
            "gsb_hit": False
        },
        "verdict": verdict,
        "score": score,
        "reasons": reasons
    }

# ===== Reporting =====

def send_report(report, reporter_email, source_type):
    import templates  # your templates.py must read the keys we return above

    # for the template:
    report["reporter"] = reporter_email
    report["source_type"] = source_type  # "attached-eml" | "inline"

    msg = EmailMessage()
    msg["Subject"] = f"Phish Analyzer Report — Verdict: {report['verdict']}"
    msg["From"] = REPLY_FROM
    msg["To"] = reporter_email

    html = templates.build_html(report)
    text = templates.build_text(report)

    msg.set_content(text)
    msg.add_alternative(html, subtype="html")

    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as s:
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)
        print(f"[+] Report sent to {reporter_email}")

# ===== IMAP intake =====

def fetch_unseen_with_eml():
    """
    Returns list of (saved_path, reporter_email, source_type)
    - If .eml attachment exists: save that and mark source as 'attached-eml'
    - Else: save the raw outer message (inline), mark as 'inline'
    """
    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(IMAP_USER, IMAP_PASS)
    mail.select("inbox")
    typ, data = mail.search(None, "UNSEEN")
    ids = data[0].split()
    results = []
    for num in ids:
        typ, msg_data = mail.fetch(num, "(RFC822)")
        if typ != "OK":
            continue
        raw_bytes = msg_data[0][1]
        outer_msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        reporter = outer_msg.get("From")

        found_eml = False
        for part in outer_msg.iter_attachments():
            ctype = part.get_content_type() or ""
            fname = part.get_filename() or ""
            # Accept .eml attachments and message/rfc822
            if ctype == "message/rfc822" or fname.lower().endswith(".eml"):
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                fname_out = f"{SAVE_DIR}/{datetime.now().timestamp()}.eml"
                with open(fname_out, "wb") as f:
                    f.write(payload)
                results.append((fname_out, reporter, "attached-eml"))
                print(f"[+] Saved {fname_out} from {reporter}")
                found_eml = True
            # Keep .msg (not parsed)
            elif fname.lower().endswith(".msg"):
                payload = part.get_payload(decode=True)
                if payload:
                    fname_out = f"{SAVE_DIR}/{datetime.now().timestamp()}.msg"
                    with open(fname_out, "wb") as f:
                        f.write(payload)
                    print(f"[~] Saved MSG attachment (not parsed): {fname_out}")

        if not found_eml:
            # Fallback: no .eml → save outer mail raw bytes
            fname_out = f"{SAVE_DIR}/{datetime.now().timestamp()}-inline.eml"
            with open(fname_out, "wb") as f:
                f.write(raw_bytes)
            results.append((fname_out, reporter, "inline"))
            print(f"[+] Saved inline {fname_out} from {reporter}")

    mail.logout()
    return results

def process_eml_batch(batch):
    path, reporter, source_type = batch
    print(f"[*] Analyzing {path} ...")
    try:
        report = analyze_eml_file(path)
        send_report(report, reporter, source_type)
    except Exception as e:
        print("[!] Error analyzing", path, e)
        traceback.print_exc()

# ===== Main =====

if __name__ == "__main__":
    print(f"[~] Starting poller. Checking every {POLL_SECONDS}s ...")
    while True:
        try:
            batches = fetch_unseen_with_eml()
            if batches:
                with ThreadPoolExecutor(max_workers=MAX_MSG_THREADS) as pool:
                    pool.map(process_eml_batch, batches)
            else:
                print("[~] Nothing to process this cycle")
        except Exception as e:
            print("[!] Unexpected error:", e)
            traceback.print_exc()
        # heartbeat
        if KUMA_URL:
            send_kuma_heartbeat()
        time.sleep(POLL_SECONDS)
