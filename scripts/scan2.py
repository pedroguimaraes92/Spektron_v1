
"""
Spektron Scan (CLI) - enterprise-ready single-file version

Run:
  python scripts/scan2.py                 # interactive REPL
  python scripts/scan2.py scan <target>   # one-shot (pipeline friendly)
  python scripts/scan2.py <target>        # one-shot (shorthand)

Accepts:
  scan <url|host>
  scan -k <url|host>
  scan --insecure <url|host>
  <url|host> (treated as scan)
"""

from __future__ import annotations

import json
import os
import re
import socket
import ssl
import shutil
import sys
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from colorama import init

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "output" / "scan"
OUT_DIR.mkdir(parents=True, exist_ok=True)

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

UA = "spektron/scan2 (enterprise-cli)"

RESET = "\033[0m"

C_DIM  = "\033[2m"
C_BOLD = "\033[1m"
C_RED  = "\033[31m"
C_YEL  = "\033[33m"
C_GRN  = "\033[32m"
C_BLU  = "\033[34m"
C_MAG  = "\033[35m"
C_CYA  = "\033[96m"
C_WHT  = "\033[37m"
GREEN_NEON = "\033[92m"

C_C_DIM  = C_DIM
C_C_BOLD = C_BOLD
C_C_RED  = C_RED

try:
    from colorama import init as _colorama_init
    _colorama_init(convert=True, strip=False, wrap=True)
except Exception:
    pass

_BANNER_PRINTED = False

def print_banner() -> None:
    banner_path = ROOT / "assets" / "ascii" / "ascii-art.txt"
    if not banner_path.exists():
        return
    try:
        banner = banner_path.read_text(encoding="utf-8")
        sys.stdout.write(GREEN_NEON)
        sys.stdout.write(banner)
        sys.stdout.write(RESET)
        sys.stdout.flush()
    except Exception:
        pass

def print_banner_once() -> None:
    global _BANNER_PRINTED
    if _BANNER_PRINTED:
        return
    print_banner()
    _BANNER_PRINTED = True



def c(s: str, color: str) -> str:
    return f"{color}{s}{RESET}"

def term_width(default: int = 92) -> int:
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except Exception:
        return default


def parse_scan_command(s: str) -> Tuple[str, bool]:
    """
    Accepts:
      - "scan <url|host>"
      - "scan -k <url|host>"
      - "scan --insecure <url|host>"
      - "<url|host>"  (treated as scan)

    Returns: (target_str, insecure_bool)
    """
    raw = (s or "").strip()
    if not raw:
        raise ValueError("target vazio")

    parts = raw.split()
    insecure = False

    if parts[0].lower() == "scan":
        rest = parts[1:]
        flags: List[str] = []
        while rest and rest[0].startswith("-"):
            flags.append(rest.pop(0))
        for f in flags:
            if f in ("-k", "--insecure"):
                insecure = True
        if not rest:
            raise ValueError("target vazio")
        return (" ".join(rest).strip(), insecure)

    return (raw, insecure)


def normalize_target(target: str) -> Dict[str, Any]:
    raw = (target or "").strip()
    if not raw:
        raise ValueError("target vazio")

    if "://" not in raw:
        raw = "https://" + raw

    u = urllib.parse.urlsplit(raw)
    scheme = (u.scheme or "https").lower()
    host = u.hostname or ""
    if not host:
        raise ValueError("host inválido")

    path = u.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    normalized = urllib.parse.urlunsplit((scheme, host, path, u.query, u.fragment))

    port = u.port
    if port is None:
        port = 443 if scheme == "https" else 80

    return {
        "input": target,
        "parsed_target": target,
        "normalized": normalized,
        "scheme": scheme,
        "host": host,
        "port": port,
    }

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def safe_filename(s: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "_", s.strip())
    s = re.sub(r"_+", "_", s)
    return s.strip("_") or "target"

def req_session(insecure: bool) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "*/*"})
    s.verify = (not insecure)
    return s

def http_request(
    sess: requests.Session,
    method: str,
    url: str,
    timeout: float = 12.0,
    allow_redirects: bool = True,
) -> Dict[str, Any]:
    t0 = time.time()
    try:
        r = sess.request(method, url, timeout=timeout, allow_redirects=allow_redirects)
        elapsed = int((time.time() - t0) * 1000)
        headers = dict(r.headers)
        headers_raw = [[k, v] for k, v in r.headers.items()]
        body_sample = ""
        body_sample_bytes = 0
        body_sample_truncated = False
        encoding = r.encoding or "utf-8"

        if method.upper() != "HEAD":
            raw = r.content or b""
            body_sample_bytes = min(len(raw), 4096)
            sample = raw[:4096]
            try:
                body_sample = sample.decode(encoding, errors="replace")
            except Exception:
                body_sample = sample.decode("utf-8", errors="replace")
            body_sample_truncated = len(raw) > 4096

        return {
            "url": r.url,
            "status": r.status_code,
            "headers_raw": headers_raw,
            "headers": headers,
            "elapsed_ms": elapsed,
            "body_encoding": encoding,
            "body_sample_bytes": body_sample_bytes,
            "body_sample_truncated": body_sample_truncated,
            "body_sample": body_sample,
            "ok": True,
            "error": None,
        }
    except Exception as e:
        elapsed = int((time.time() - t0) * 1000)
        return {
            "url": url,
            "status": None,
            "headers_raw": [],
            "headers": {},
            "elapsed_ms": elapsed,
            "body_encoding": None,
            "body_sample_bytes": 0,
            "body_sample_truncated": False,
            "body_sample": "",
            "ok": False,
            "error": str(e),
        }

def extract_html_signals(html: str) -> Dict[str, Any]:
    h = html or ""
    signals = {}

    if "gtm.js" in h or "googletagmanager.com/gtm.js" in h:
        signals["google_tag_manager"] = True
    if "cloudflare" in h.lower():
        signals["mentions_cloudflare"] = True
    if "swagger-ui" in h.lower():
        signals["swagger_ui"] = True

    return signals


def probe_dns(host: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": True, "a": [], "aaaa": [], "cname": [], "mx": [], "txt": []}
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        a = set()
        aaaa = set()
        for fam, *_rest, sockaddr in infos:
            ip = sockaddr[0]
            if fam == socket.AF_INET:
                a.add(ip)
            elif fam == socket.AF_INET6:
                aaaa.add(ip)
        out["a"] = sorted(a)
        out["aaaa"] = sorted(aaaa)
    except Exception:
        out["ok"] = False

    return out

def probe_tls(host: str, port: int, insecure: bool) -> Dict[str, Any]:
    res: Dict[str, Any] = {
        "present": False,
        "ok": False,
        "verify": (not insecure),
        "tls_version": None,
        "cipher": None,
        "cert": None,
        "peer_cert_available": False,
        "peer_cert_der_len": None,
        "peer_cert_sha256": None,
        "verify_requested": True,
        "verify_effective": (not insecure),
        "fallback_used": False,
    }
    try:
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                res["present"] = True
                res["ok"] = True
                res["tls_version"] = ssock.version()
                ciph = ssock.cipher()
                if ciph:
                    res["cipher"] = {"name": ciph[0], "protocol": ciph[1], "bits": ciph[2]}
                cert = ssock.getpeercert()
                if cert:
                    res["peer_cert_available"] = True
                    res["cert"] = {
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter"),
                        "subjectAltName": cert.get("subjectAltName"),
                    }
    except Exception:
        res["present"] = (port == 443)
        res["ok"] = False
    return res

def probe_http_stack(sess: requests.Session, url: str) -> Dict[str, Any]:
    snap = http_request(sess, "GET", url, timeout=12.0, allow_redirects=True)
    getr = snap
    headr = http_request(sess, "HEAD", url, timeout=12.0, allow_redirects=True)

    chain = []
    for r in [getr]:
        if r["ok"]:
            chain.append({
                "url": r["url"],
                "status": r["status"],
                "headers_raw": r["headers_raw"],
                "headers": r["headers"],
                "elapsed_ms": r["elapsed_ms"],
            })

    return {
        "ok": getr["ok"],
        "tls_verify": bool(sess.verify),
        "method": "GET",
        "error": getr["error"],
        "final_url": getr["url"],
        "final_status": getr["status"],
        "redirects": 0,
        "timing_total_ms": getr["elapsed_ms"],
        "chain": chain,
        "body_encoding": getr["body_encoding"],
        "body_sample_bytes": getr["body_sample_bytes"],
        "body_sample_truncated": getr["body_sample_truncated"],
        "body_sample": getr["body_sample"],
        "head": {
            "ok": headr["ok"],
            "final_status": headr["status"],
            "headers": headr["headers"],
            "elapsed_ms": headr["elapsed_ms"],
        }
    }

def probe_methods(sess: requests.Session, url: str) -> Dict[str, Any]:
    items = []
    for m in ["OPTIONS", "TRACE"]:
        r = http_request(sess, m, url, timeout=12.0, allow_redirects=True)
        items.append({"method": m, "url": url, "ok": r["ok"], "status": r["status"]})
    return {"ok": True, "tls_verify": bool(sess.verify), "items": items}

def probe_cors(sess: requests.Session, url: str) -> Dict[str, Any]:
    """
    Passive CORS probe (multi-origin + preflight). Uses bundled probes if available.

    Enterprise schema contract (stable for renderers):
      - ok: bool
      - tls_verify: bool
      - url: str
      - origin/acao/acac/reflected/risk: headline fields (best candidate)
      - error: optional str
      - details: full probe payload (items + preflight)
    """
    tls_verify = bool(getattr(sess, "verify", True))
    try:
        from probes.cors import probe_cors as _probe
        details = _probe(url, verify=tls_verify)

        items = details.get("items") or []
        sev_rank = {"high": 3, "medium": 2, "low": 1, "info": 0}

        best: Optional[Dict[str, Any]] = None
        for it in items:
            if not isinstance(it, dict) or not it.get("ok"):
                continue
            if best is None or sev_rank.get(it.get("risk"), 0) > sev_rank.get(best.get("risk"), 0):
                best = it

        if best is None:
            for it in items:
                if isinstance(it, dict):
                    best = it
                    break

        origin = (best or {}).get("origin_test") or "https://example.com"
        acao = (best or {}).get("acao")
        acac = (best or {}).get("acac")
        reflected = bool((best or {}).get("reflected", False))
        risk = (best or {}).get("risk") or "info"

        return {
            "ok": True,
            "tls_verify": tls_verify,
            "url": url,
            "origin": origin,
            "acao": acao,
            "acac": acac,
            "reflected": reflected,
            "risk": risk,
            "details": details,
        }
    except Exception as e:
        origin = "https://example.com"
        try:
            r = sess.options(
                url,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "Authorization",
                },
                timeout=12,
                allow_redirects=True,
            )
            acao = r.headers.get("Access-Control-Allow-Origin")
            acac = r.headers.get("Access-Control-Allow-Credentials")
            reflected = (acao == origin)
            acac_true = (acac or "").strip().lower() == "true"
            risk = "high" if (reflected and acac_true) else ("medium" if reflected else ("low" if (acao or "").strip() == "*" else "info"))
            return {
                "ok": True,
                "tls_verify": tls_verify,
                "url": url,
                "origin": origin,
                "acao": acao,
                "acac": acac,
                "reflected": reflected,
                "risk": risk,
            }
        except Exception as e2:
            return {
                "ok": False,
                "tls_verify": tls_verify,
                "url": url,
                "origin": origin,
                "error": str(e2) or str(e) or "unknown",
                "risk": "info",
            }

def probe_oidc(sess: requests.Session, base_url: str) -> Dict[str, Any]:
    """
    Passive OIDC well-known probe. Uses bundled probe if available.
    """
    try:
        from probes.oidc import probe_oidc as _probe  # type: ignore
        r = _probe(base_url, verify=sess.verify if hasattr(sess, "verify") else True)
        return r
    except Exception:
        try:
            url = urllib.parse.urljoin(base_url, "/.well-known/openid-configuration")
            r = sess.get(url, timeout=12, allow_redirects=True)
            if r.status_code == 200:
                return {"ok": True, "url": url, "status": 200}
            return {"ok": False, "url": url, "status": r.status_code}
        except Exception as e:
            return {"ok": False, "error": str(e)}

def probe_exposure_files(sess: requests.Session, base_url: str) -> Dict[str, Any]:
    paths = ["/robots.txt", "/.well-known/security.txt", "/security.txt", "/humans.txt", "/sitemap.xml", "/ads.txt"]
    items = []
    for pth in paths:
        url = base_url.rstrip("/") + pth
        r = http_request(sess, "GET", url, timeout=12.0, allow_redirects=True)
        item = {
            "path": pth,
            "url": url,
            "ok": r["ok"],
            "status": r["status"],
            "final_url": r["url"],
        }
        if r["ok"] and r["status"] == 200:
            item["body_sample"] = r["body_sample"]
            item["body_sample_truncated"] = r["body_sample_truncated"]
            sig = {}
            if pth == "/robots.txt":
                sig["has_disallow"] = ("Disallow:" in r["body_sample"])
                sig["has_allow"] = ("Allow:" in r["body_sample"])
                sig["has_sitemap"] = ("Sitemap:" in r["body_sample"])
            if pth == "/sitemap.xml":
                sig["looks_xml"] = r["body_sample"].lstrip().startswith("<?xml")
            if sig:
                item["signals"] = sig
        items.append(item)
    return {"ok": True, "tls_verify": bool(sess.verify), "items": items}

def probe_openapi(sess: requests.Session, base_url: str) -> Dict[str, Any]:
    """
    Passive OpenAPI discovery. Uses bundled probe if available (supports larger fetch cap + YAML best-effort).
    """
    try:
        from probes.openapi import probe_openapi as _probe
        return _probe(base_url, verify=sess.verify if hasattr(sess, "verify") else True)
    except Exception:
        candidates = [
            "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
            "/api-docs", "/v2/api-docs", "/v3/api-docs",
        ]
        items = []
        for p in candidates:
            u = urllib.parse.urljoin(base_url, p)
            try:
                r = sess.get(u, timeout=12, allow_redirects=True)
                body = (r.text or "")[:4096] if r.status_code == 200 else ""
                item = {"path": p, "url": u, "status": r.status_code, "final_url": r.url}
                if body and ("openapi" in body.lower() or "swagger" in body.lower()):
                    item["signals"] = {"looks_openapi": True}
                items.append(item)
            except Exception as e:
                items.append({"path": p, "url": u, "error": str(e)})
        return {"ok": True, "items": items}

def derive_security_findings(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    hp = {k.lower(): v for k, v in (headers or {}).items()}
    findings = []

    def add(fid: str, sev: str, title: str, detail: str, evidence: Dict[str, Any]) -> None:
        findings.append({"id": fid, "severity": sev, "title": title, "detail": detail, "evidence": evidence})

    if "strict-transport-security" not in hp:
        add("SEC_HDR_HSTS_MISSING", "medium", "HSTS ausente em HTTPS",
            "Resposta HTTPS não inclui Strict-Transport-Security (HSTS).",
            {"header": "strict-transport-security"})
    if "content-security-policy" not in hp:
        add("SEC_HDR_CSP_MISSING", "low", "CSP ausente",
            "Resposta não inclui Content-Security-Policy (CSP).",
            {"header": "content-security-policy"})

    rl = ["ratelimit-limit", "ratelimit-remaining", "ratelimit-reset", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"]
    if not any(h in hp for h in rl):
        add("SEC_HDR_RATELIMIT_MISSING", "info", "Headers de rate limit ausentes",
            "Resposta não expõe headers comuns de rate limit (pode existir via outro endpoint).",
            {"headers_checked": rl})
    return findings

def derive_tech(headers: Dict[str, str], body_sample: str) -> List[Dict[str, Any]]:
    tech = []
    h = {k.lower(): v for k, v in (headers or {}).items()}
    body = body_sample or ""

    if "server" in h and "cloudflare" in (h["server"] or "").lower():
        tech.append({
            "name": "Cloudflare",
            "category": "CDN/WAF",
            "confidence": "high",
            "evidence": {
                "server": h.get("server"),
                "cf-ray": h.get("cf-ray"),
                "cf-cache-status": h.get("cf-cache-status"),
            }
        })
    via = h.get("via", "")
    if "heroku-router" in via.lower():
        tech.append({
            "name": "Heroku",
            "category": "PaaS",
            "confidence": "medium",
            "evidence": {"header": "via", "value": via}
        })
    if "gtm.js" in body or "googletagmanager.com/gtm.js" in body:
        tech.append({
            "name": "Google Tag Manager",
            "category": "Analytics",
            "confidence": "high",
            "evidence": {"html": "gtm.js"}
        })

    return tech


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s or "")

def visible_len(s: str) -> int:
    return len(strip_ansi(s))

def clip_ansi(s: str, max_visible: int) -> str:
    """
    Trunca string mantendo sequências ANSI intactas.
    Se passar do limite visível, adiciona '…' (sem quebrar ANSI).
    """
    if max_visible <= 0:
        return ""
    if visible_len(s) <= max_visible:
        return s

    out = []
    vis = 0
    i = 0
    n = len(s)
    while i < n and vis < max_visible:
        if s[i] == "\x1b":
            m = ANSI_RE.match(s, i)
            if m:
                out.append(m.group(0))
                i = m.end()
                continue
        ch = s[i]
        out.append(ch)
        vis += 1
        i += 1

    out.append("…")
    out.append(RESET)
    return "".join(out)

def status_label(code: Optional[int]) -> str:
    """
    Label humano para status HTTP (sem exibir o número).
    """
    if code is None:
        return "Unknown"
    try:
        c0 = int(code)
    except Exception:
        return "Unknown"

    if 200 <= c0 <= 299:
        return "Found"
    if 300 <= c0 <= 399:
        return "Redirect"
    if c0 in (401,):
        return "Unauthorized"
    if c0 in (403,):
        return "Forbidden"
    if c0 in (404,):
        return "Not Found"
    if 400 <= c0 <= 499:
        return "Client Error"
    if 500 <= c0 <= 599:
        return "Server Error"
    return "Error"

def status_color(code: Optional[int]) -> str:
    if code is None:
        return C_DIM
    try:
        c0 = int(code)
    except Exception:
        return C_DIM
    if 200 <= c0 <= 299:
        return C_GRN
    if c0 == 404:
        return C_DIM
    if 300 <= c0 <= 399:
        return C_YEL
    if c0 in (401, 403):
        return C_YEL
    if 400 <= c0 <= 599:
        return C_RED
    return C_DIM

def severity_color(sev: str) -> str:
    s = (sev or "").lower()
    if s in ("critical", "high"):
        return C_RED
    if s in ("medium",):
        return C_YEL
    if s in ("low",):
        return C_CYA
    return C_DIM

def pretty_severity(sev: Any) -> str:
    s = (sev or "info")
    if not isinstance(s, str):
        s = "info"
    s = s.strip().lower() or "info"
    return s[:1].upper() + s[1:]

def boxed_section(title: str, lines: List[str], width: Optional[int] = None) -> str:
    w = width or min(120, max(80, term_width(100)))
    inner = w - 2
    top = "┌" + "─" * inner + "┐"
    bot = "└" + "─" * inner + "┘"
    t = f" {title} "
    title_line = " " * max(0, (inner - len(t)) // 2) + t
    title_line = title_line + " " * max(0, inner - len(title_line))
    title_bar = "│" + title_line[:inner] + "│"

    body = []
    for ln in lines:
        ln = (ln or "").replace("\t", "    ")
        if visible_len(ln) > inner:
            ln = clip_ansi(ln, inner - 1)
        pad = inner - visible_len(ln)
        if pad < 0:
            pad = 0
        body.append("│" + ln + (" " * pad) + "│")

    if not body:
        body = ["│" + "(none)".ljust(inner) + "│"]
    return "\n".join([top, title_bar] + body + [bot])

def kv_lines(pairs: List[Tuple[str, str]], pad_key: int = 10) -> List[str]:
    lines = []
    for k, v in pairs:
        lines.append(f" {k:<{pad_key}}: {v}")
    return lines

def http_summary提醒(code: Optional[int]) -> str:
    return status_label(code)

def print_scan_tables(result: Dict[str, Any]) -> None:
    obs = result.get("observations") or {}
    target = result.get("target") or {}
    derived = result.get("derived") or {}
    tech = result.get("tech") or []
    sec = (obs.get("security") or {}).get("findings") or []

    w = min(120, max(86, term_width(100)))

    http = obs.get("http") or {}
    tls_verify_on = "ON" if (http.get("tls_verify") is True) else "OFF"
    final_status = http.get("final_status")
    scheme = (target.get("scheme") or "").lower()
    progress = derived.get("progress") or {"pct": 100.0}
    pct = progress.get("pct", 100.0)

    summary_lines = kv_lines([
        ("Target", str(target.get("normalized") or "")),
        ("Host", str(target.get("host") or "")),
        ("Scheme", scheme),
        ("TLS verify", tls_verify_on.lower()),
        ("HTTP", http_summary提醒(final_status)),
        ("Progress", f"{pct:.1f}%"),
    ], pad_key=10)
    print(boxed_section("SPEKTRON SCAN SUMMARY", summary_lines, width=w))

    # TRANSPORT & TLS
    tr = (obs.get("transport") or {})
    tls = (obs.get("tls") or {})
    tls_ver = tls.get("tls_version") or "-"
    cipher = (tls.get("cipher") or {}).get("name") or "-"
    not_after = ((tls.get("cert") or {}).get("notAfter")) or "-"
    tr_lines = kv_lines([
        ("Final URL", str(tr.get("final_url") or target.get("normalized") or "")),
        ("Redirects", str(tr.get("redirects") if tr.get("redirects") is not None else "-")),
        ("TLS", tls_ver),
        ("Cipher", cipher),
        ("Cert exp", str(not_after)),
    ], pad_key=10)
    print(boxed_section("TRANSPORT & TLS", tr_lines, width=w))

    # DNS
    dns = (obs.get("dns") or {})
    a = dns.get("a") or []
    aaaa = dns.get("aaaa") or []
    cname = dns.get("cname") or []
    mx = dns.get("mx") or []
    txt = dns.get("txt") or []

    dns_lines = []
    dns_lines.append(f" A     ({len(a)}): " + (", ".join(a[:3]) if a else "-"))
    dns_lines.append(f" AAAA  ({len(aaaa)}): " + (", ".join(aaaa[:2]) if aaaa else "-"))
    dns_lines.append(f" CNAME ({len(cname)}): " + (", ".join(cname[:2]) if cname else "-"))
    dns_lines.append(f" MX    ({len(mx)}): " + (", ".join([m.get('exchange','-') for m in mx[:2]]) if mx else "-"))
    dns_lines.append(f" TXT   ({len(txt)}): " + (", ".join([t[:40] + ('…' if len(t) > 40 else '') for t in txt[:2]]) if txt else "-"))
    print(boxed_section("DNS RECORDS (top)", dns_lines, width=w))

    # OPENAPI/API DOCS
    oa = (obs.get("openapi") or {})
    items = oa.get("items") or []
    oa_lines: List[str] = []

    if items:
        for it in items[:8]:
            pth = it.get("path", "-")
            st = it.get("status")
            lbl = status_label(st)
            col = status_color(st)
            sig = it.get("signals") or {}
            hint = []
            if sig.get("looks_openapi"):
                hint.append("openapi")
            if sig.get("swagger_ui"):
                hint.append("swagger-ui")
            summ = it.get("openapi_summary") or {}
            if summ.get("paths_count"):
                hint.append(f"paths:{summ.get('paths_count')}")
            extra = (", ".join(hint)) if hint else ""
            oa_lines.append(f" {pth:<16} {c(lbl, col)}" + (f"  {extra}" if extra else ""))
    print(boxed_section("OPENAPI / API DOCS", oa_lines, width=w))

    # EXPOSURE FILES
    exp = (obs.get("exposure_files") or {})
    exp_items = exp.get("items") or []
    exp_lines: List[str] = []
    if exp_items:
        for it in exp_items[:10]:
            pth = it.get("path", "-")
            st = it.get("status")
            lbl = status_label(st)
            col = status_color(st)
            exp_lines.append(f" {pth:<22} {c(lbl, col)}")
    print(boxed_section("EXPOSURE FILES", exp_lines, width=w))

    # CORS PROBE
    cors = (obs.get("cors_probe") or {})
    if cors.get("ok"):
        risk = cors.get("risk") or "-"
        risk_col = C_RED if str(risk).lower() == "high" else (C_YEL if str(risk).lower() == "medium" else (C_CYA if str(risk).lower() == "low" else C_DIM))
        cors_lines = kv_lines([
            ("Origin", str(cors.get("origin"))),
            ("ACAO", str(cors.get("acao"))),
            ("ACAC", str(cors.get("acac"))),
            ("Reflected", str(cors.get("reflected"))),
            ("Risk", c(str(risk).lower(), risk_col)),
        ], pad_key=10)
    else:
        cors_lines = [f" error: {cors.get('error', 'unknown')}"]
    print(boxed_section("CORS PROBE", cors_lines, width=w))

    # SECURITY FINDINGS
    sec_lines = []
    if sec:
        for f in sec[:12]:
            sev = f.get("severity", "info")
            disp = pretty_severity(sev)
            tag = c(disp, severity_color(str(sev)))
            sec_lines.append(f" - {tag}: {f.get('title')}  [{f.get('id')}]")
    print(boxed_section("SECURITY FINDINGS", sec_lines, width=w))

    # TECH FINGERPRINTS
    tech_lines = []
    for t in tech[:12]:
        name = t.get("name")
        cat = t.get("category")
        conf = t.get("confidence")
        tech_lines.append(f" - {name} ({cat}, conf-{conf})")
    print(boxed_section("TECH FINGERPRINTS", tech_lines, width=w))


@dataclass
class ProbeCounter:
    total: int
    done: int = 0

    def tick(self) -> None:
        self.done += 1

    def pct(self) -> float:
        if self.total <= 0:
            return 100.0
        return max(0.0, min(100.0, (self.done / self.total) * 100.0))

def run_scan(target_str: str, insecure: bool) -> Dict[str, Any]:
    target = normalize_target(target_str)
    base_url = target["normalized"]
    host = target["host"]
    scheme = target["scheme"]

    sess = req_session(insecure)

    probes = ProbeCounter(total=8)

    observations: Dict[str, Any] = {}

    observations["dns"] = probe_dns(host)
    probes.tick()

    observations["transport"] = {
        "input_url": base_url,
        "input_scheme": scheme,
        "final_url": base_url,
        "final_scheme": scheme,
        "redirects": 0,
        "redirect_chain": [base_url],
        "tls_in_play": (scheme == "https"),
        "redirect_kind": None,
        "redirect_permanent_hint": None,
        "input_host": host,
        "final_host": host,
    }
    probes.tick()

    if scheme == "https":
        observations["tls"] = probe_tls(host, 443, insecure)
    else:
        observations["tls"] = {"present": False, "ok": False, "verify": (not insecure)}
    probes.tick()

    http = probe_http_stack(sess, base_url)
    observations["http_input_snapshot"] = http
    observations["http"] = http
    probes.tick()

    observations["http_head"] = {
        "ok": http.get("head", {}).get("ok", False),
        "tls_verify": bool(sess.verify),
        "method": "HEAD",
        "error": None if http.get("head", {}).get("ok") else "head_failed",
        "final_url": base_url,
        "final_status": http.get("head", {}).get("final_status"),
        "redirects": 0,
        "timing_total_ms": http.get("head", {}).get("elapsed_ms"),
        "chain": [
            {
                "url": base_url,
                "status": http.get("head", {}).get("final_status"),
                "headers_raw": [],
                "headers": http.get("head", {}).get("headers", {}),
                "elapsed_ms": http.get("head", {}).get("elapsed_ms"),
            }
        ],
        "body_encoding": "utf-8",
        "body_sample_bytes": 0,
        "body_sample_truncated": False,
        "body_sample": "",
    }
    probes.tick()

    observations["method_probes"] = probe_methods(sess, base_url)
    probes.tick()

    observations["cors_probe"] = probe_cors(sess, base_url)
    probes.tick()

    observations["oidc_probe"] = probe_oidc(sess, base_url)
    probes.tick()

    observations["exposure_files"] = probe_exposure_files(sess, base_url)
    observations["openapi"] = probe_openapi(sess, base_url)
    observations["mixed_content"] = {"ok": True, "count": 0, "examples": []}
    observations["surface"] = {
        "ok": True,
        "forms_count": 0,
        "forms_sample": [],
        "has_password_field": False,
        "has_upload_field": False,
        "login_hints": True if ("login" in (http.get("body_sample") or "").lower()) else False,
        "api_hints": [],
    }

    headers = (http.get("chain") or [{}])[0].get("headers") if http.get("chain") else (http.get("head", {}).get("headers") or {})
    findings = derive_security_findings(headers or {})
    observations["security"] = {
        "headers_present": {
            "strict-transport-security": (headers or {}).get("Strict-Transport-Security"),
            "content-security-policy": (headers or {}).get("Content-Security-Policy"),
            "x-frame-options": (headers or {}).get("X-Frame-Options"),
            "x-content-type-options": (headers or {}).get("X-Content-Type-Options"),
            "referrer-policy": (headers or {}).get("Referrer-Policy"),
            "permissions-policy": (headers or {}).get("Permissions-Policy"),
            "cross-origin-opener-policy": (headers or {}).get("Cross-Origin-Opener-Policy"),
            "cross-origin-embedder-policy": (headers or {}).get("Cross-Origin-Embedder-Policy"),
            "cross-origin-resource-policy": (headers or {}).get("Cross-Origin-Resource-Policy"),
        },
        "rate_limit_headers_present": {
            "ratelimit-limit": (headers or {}).get("RateLimit-Limit"),
            "ratelimit-remaining": (headers or {}).get("RateLimit-Remaining"),
            "ratelimit-reset": (headers or {}).get("RateLimit-Reset"),
            "x-ratelimit-limit": (headers or {}).get("X-RateLimit-Limit"),
            "x-ratelimit-remaining": (headers or {}).get("X-RateLimit-Remaining"),
            "x-ratelimit-reset": (headers or {}).get("X-RateLimit-Reset"),
        },
        "cookies": {},
        "findings": findings,
        "tls_verify": bool(sess.verify),
    }

    tech = derive_tech(headers or {}, http.get("body_sample") or "")
    derived = {
        "transport": {
            "input_scheme": scheme,
            "final_scheme": scheme,
            "https_posture": "enforced_by_redirect" if scheme == "https" else "plain_http",
            "hsts": {"present": False, "value": None, "max_age": None, "include_subdomains": False, "preload": False},
            "redirects": 0,
            "final_url": base_url,
            "redirect_kind": None,
            "redirect_permanent_hint": None,
            "input_host": host,
            "final_host": host,
            "http_downgrade_probe": {"attempted": True, "ok": True, "status": 301} if scheme == "https" else {"attempted": False},
        },
        "stack": {
            "edge": {
                "provider": "Cloudflare" if any(t.get("name") == "Cloudflare" for t in tech) else None,
                "signals": [t.get("name") for t in tech if t.get("category") == "CDN/WAF"],
                "confidence": "high" if any(t.get("name") == "Cloudflare" for t in tech) else "low",
            },
            "origin_server_hint": {"name": None, "confidence": "low", "source": None},
            "legacy_html": {"present": False, "signals": [], "confidence": "low"},
        },
        "progress": {"done": probes.done, "total": probes.total, "pct": probes.pct()},
    }

    out = {
        "version": "v2.0.0",
        "generated_at": now_utc_iso(),
        "engine": {"name": "spektron", "module": "scan", "version": "v2.0.0"},
        "target": target,
        "observations": observations,
        "derived": derived,
        "risks": [],
        "tech": tech,
    }
    return out

def save_result(result: Dict[str, Any]) -> Path:
    host = (result.get("target") or {}).get("host") or "target"
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    fname = f"scan_{safe_filename(host)}_{ts}.json"
    path = OUT_DIR / fname
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def run_one(raw_cmd: str) -> int:
    try:
        target_str, insecure = parse_scan_command(raw_cmd)
        res = run_scan(target_str, insecure=insecure)

        tls_verify = "ON" if not insecure else "OFF"
        print(c(f"[+] target: {res['target']['normalized']}", C_GRN) + "  " + c(f"TLS verify: {tls_verify}", C_DIM))
        print_scan_tables(res)

        out_path = save_result(res)
        print(c(f"[+] saved: {out_path}", C_GRN))
        return 0
    except KeyboardInterrupt:
        print()
        return 130
    except Exception as e:
        print(c(f"[!] error: {e}", C_RED))
        return 2

def repl() -> int:
    print_banner_once()
    print(c("Commands:", C_DIM) + " " + c("scan <url>", C_WHT) + c("  |  ", C_DIM) + c("scan -k <url>", C_WHT) + c("  |  ", C_DIM) + c("exit/quit", C_WHT))
    print(c("Examples:", C_DIM) + " " + c("scan https://reqres.in/", C_WHT) + c("  |  ", C_DIM) + c("scan -k https://example.com/", C_WHT))
    while True:
        try:
            raw = input(f"{C_BOLD}{C_CYA}> {RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if not raw:
            continue
        if raw.lower() in ("exit", "quit", "q"):
            return 0

        rc = run_one(raw)
        if rc not in (0,):
            continue

def main(argv: List[str]) -> int:
    init(convert=True, strip=False, wrap=True)
    if len(argv) > 1:
        raw = " ".join(argv[1:])
        return run_one(raw)
    return repl()

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
