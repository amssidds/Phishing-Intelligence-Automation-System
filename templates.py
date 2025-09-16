# templates.py — shows all signals clearly, with Forwarded by vs Sender (Analyzed)

def _badge(ok: bool, good="✅ Safe", bad="❌ Flagged"):
    return good if ok else bad

def _yesno(n: int, label: str):
    n = int(n or 0)
    return f"✅ Safe (0 {label})" if n == 0 else f"❌ {n} {label}"

def _auth_cell(v):
    if v is None: return "—"
    v = str(v).lower()
    if v in ("pass","none","bestguesspass"): return f"✅ {v}"
    if v in ("fail","temperror","permerror","softfail","neutral"): return f"⚠️ {v}"
    return v

def build_html(report):
    verdict = report.get("verdict","Safe")
    score   = int(report.get("score",0))
    if verdict == "Malicious":
        color="#c62828"; icon="🛑"
    elif verdict == "Suspicious":
        color="#ef6c00"; icon="⚠️"
    else:
        color="#2e7d32"; icon="✅"

    # URL rows
    rows=[]
    for f in report.get("url_findings",[]) or []:
        mal = int(f.get("vt_malicious",0))
        gsb = f.get("gsb",{}) or {}
        gsb_hit = bool(f.get("gsb_hit"))
        # brief threat types if any
        ttypes = ", ".join({m.get("threatType","") for m in gsb.get("matches",[])}) if gsb_hit else ""
        rows.append(f"""
        <tr>
          <td style="border:1px solid #ddd;padding:8px;word-break:break-all;">{f.get('url','')}</td>
          <td style="border:1px solid #ddd;padding:8px;">{('❌ '+str(mal)+' engines') if mal>0 else '✅ Safe'}</td>
          <td style="border:1px solid #ddd;padding:8px;">{'❌ '+(ttypes or 'Flagged') if gsb_hit else '✅ Safe'}</td>
        </tr>""")
    url_table = "".join(rows) or '<tr><td colspan="3" style="border:1px solid #ddd;padding:8px;">None</td></tr>'

    # Sender domain info
    dom = report.get("domain_result") or {}
    dom_flag = (int(dom.get("vt_malicious",0))>0) or bool(dom.get("gsb_hit"))
    dom_line = "❌ Sender domain flagged" if dom_flag else "✅ Sender domain check"

    auth = report.get("auth_results") or {}
    spf_cell   = _auth_cell(auth.get("spf"))
    dkim_cell  = _auth_cell(auth.get("dkim"))
    dmarc_cell = _auth_cell(auth.get("dmarc"))

    # counts
    vt_count   = sum(1 for f in report.get("url_findings",[]) if int(f.get("vt_malicious",0))>0)
    gsb_count  = sum(1 for f in report.get("url_findings",[]) if f.get("gsb_hit"))
    hdr_mm     = int(report.get("header_mismatches",0))
    risky_ct   = int(report.get("risky_attachments",0))
    look_ct    = int(report.get("lookalike_hits",0))

    # attachment list
    attach_rows = []
    for name, sha in report.get("attachments",[]) or []:
        attach_rows.append(f"<li>{name}{(' (SHA256: '+sha[:16]+'...)' if sha else '')}</li>")
    attach_list = "".join(attach_rows) or "<li>None</li>"

    # source type label
    src = report.get("source_type") or "inline"
    src_label = "Attached .eml" if src == "attached-eml" else "Inline forward (original headers may be limited)"

    return f"""<html>
  <body style="background:#fff;font-family:Arial,sans-serif;line-height:1.6;color:#111;">
    <div style="max-width:900px;margin:0 auto;">
      <div style="background:{color};color:#fff;padding:14px 16px;font-size:18px;font-weight:700;">{icon} {verdict} ({score}/100)</div>
      <div style="padding:16px;border:1px solid #e6e6e6;border-top:none;">

        <p><b>Forwarded by:</b> {report.get('reporter','')}<br>
           <b>Sender (analyzed):</b> {report.get('from_name_email','') or report.get('from','')}<br>
           <b>Subject:</b> {report.get('subject','')}<br>
           <b>Source:</b> {src_label}</p>

        <hr style="border:none;height:1px;background:#eee;margin:14px 0;" />

        <p><b>Why this verdict</b></p>
        <ul style="margin-top:6px">{''.join(f'<li>{r}</li>' for r in (report.get('reasons') or []))}</ul>

        <hr style="border:none;height:1px;background:#eee;margin:14px 0;" />

        <table style="border-collapse:collapse;width:100%;margin-top:6px">
          <tr>
            <th style="text-align:left;border:1px solid #ddd;padding:8px;">Check</th>
            <th style="text-align:left;border:1px solid #ddd;padding:8px;">Result</th>
            <th style="text-align:left;border:1px solid #ddd;padding:8px;">Meaning</th>
          </tr>
          <tr>
            <td style="border:1px solid #ddd;padding:8px;">VirusTotal</td>
            <td style="border:1px solid #ddd;padding:8px;">{ _yesno(vt_count, 'URLs flagged') }</td>
            <td style="border:1px solid #ddd;padding:8px;">Any engines flagged the link(s)?</td>
          </tr>
          <tr>
            <td style="border:1px solid #ddd;padding:8px;">Safe Browsing</td>
            <td style="border:1px solid #ddd;padding:8px;">{ _yesno(gsb_count, 'URLs flagged') }</td>
            <td style="border:1px solid #ddd;padding:8px;">Google flagged any link(s)?</td>
          </tr>
          <tr>
            <td style="border:1px solid #ddd;padding:8px;">Header consistency</td>
            <td style="border:1px solid #ddd;padding:8px;">{ '✅ No mismatches' if hdr_mm==0 else f'❌ {hdr_mm} mismatch(es)' }</td>
            <td style="border:1px solid #ddd;padding:8px;">Compare From vs Return-Path vs Reply-To</td>
          </tr>
          <tr>
            <td style="border:1px solid #ddd;padding:8px;">Risky attachments</td>
            <td style="border:1px solid #ddd;padding:8px;">{ '✅ None' if risky_ct==0 else f'❌ {risky_ct} risky file(s)' }</td>
            <td style="border:1px solid #ddd;padding:8px;">Executable/macro or other dangerous types</td>
          </tr>
          <tr>
            <td style="border:1px solid #ddd;padding:8px;">Lookalike domains</td>
            <td style="border:1px solid #ddd;padding:8px;">{ '✅ None' if look_ct==0 else f'❌ {look_ct} suspicious host(s)' }</td>
            <td style="border:1px solid #ddd;padding:8px;">URL hosts visually similar to sender domain</td>
          </tr>
          <tr>
            <td style="border:1px solid #ddd;padding:8px;">Sender Domain</td>
            <td style="border:1px solid #ddd;padding:8px;">{dom_line}</td>
            <td style="border:1px solid #ddd;padding:8px;">Reputation of the visible From: domain</td>
          </tr>
          <tr>
            <td style="border:1px solid #ddd;padding:8px;">Auth results</td>
            <td style="border:1px solid #ddd;padding:8px;">SPF: {spf_cell} &nbsp; | &nbsp; DKIM: {dkim_cell} &nbsp; | &nbsp; DMARC: {dmarc_cell}</td>
            <td style="border:1px solid #ddd;padding:8px;">From Authentication-Results (informational)</td>
          </tr>
        </table>

        <hr style="border:none;height:1px;background:#eee;margin:14px 0;" />

        <p><b>URL analysis</b></p>
        <table style="border-collapse:collapse;width:100%;margin-top:6px">
          <tr>
            <th style="text-align:left;border:1px solid #ddd;padding:8px;">URL</th>
            <th style="text-align:left;border:1px solid #ddd;padding:8px;">VT</th>
            <th style="text-align:left;border:1px solid #ddd;padding:8px;">GSB</th>
          </tr>
          {url_table}
        </table>

        <hr style="border:none;height:1px;background:#eee;margin:14px 0;" />

        <p><b>Attachments</b></p>
        <ul style="margin:6px 0 0 18px">{attach_list}</ul>

        <div style="margin-top:18px;padding:12px 14px;background:#fff7ed;border:1px solid #ffd8b2;border-radius:8px;">
          <div style="font-weight:700;margin-bottom:6px">What should I do?</div>
          <div>If you didn’t expect this email: don’t click links, don’t reply, delete it.<br>
               If you did expect it but something looks off: contact IT.</div>
        </div>

        <p style="margin-top:14px;color:#666;font-size:12px;">Automated report from GSPL Phish Analyzer.</p>
      </div>
    </div>
  </body>
</html>"""

def build_text(report):
    vt_count = sum(1 for f in report.get("url_findings",[]) if int(f.get("vt_malicious",0))>0)
    gsb_count= sum(1 for f in report.get("url_findings",[]) if f.get("gsb_hit"))
    auth = report.get("auth_results") or {}
    lines = [
        f"Verdict: {report.get('verdict')} ({int(report.get('score',0))}/100)",
        f"Forwarded by: {report.get('reporter','')}",
        f"Sender (analyzed): {report.get('from_name_email') or report.get('from')}",
        f"Subject: {report.get('subject')}",
        f"Source: {'Attached .eml' if (report.get('source_type')=='attached-eml') else 'Inline forward'}",
        f"Auth: SPF={auth.get('spf')}, DKIM={auth.get('dkim')}, DMARC={auth.get('dmarc')}",
        f"Header mismatches: {int(report.get('header_mismatches',0))}",
        f"Risky attachments: {int(report.get('risky_attachments',0))}",
        f"Lookalike domains: {int(report.get('lookalike_hits',0))}",
        f"VT flagged URLs: {vt_count}",
        f"GSB flagged URLs: {gsb_count}",
    ]
    if report.get("url_findings"):
        lines.append("URL analysis:")
        for f in report["url_findings"]:
            lines.append(f" - {f['url']} | VT malicious: {int(f.get('vt_malicious',0))} | GSB: {'hit' if f.get('gsb_hit') else 'none'}")
    return "\n".join(lines) + "\n"
