# scripts/scan.py
# SPEKTRON Scan v1.8.0 — CLI ONLY (CMD)
# Run from project root:
#   python scripts\scan.py
#
# Usage (interactive):
#   scan https://target.com
#   scan http://target.com
#   scan -k https://target.com        (insecure: TLS verify off)
#   scan --insecure https://target.com
#   exit | quit | q
#
# Does (passive recon):
#   - DNS (A/AAAA + best-effort CNAME/MX/TXT via nslookup)
#   - Transport map: input_scheme vs final_scheme (redirect chain + redirect intel)
#   - TLS handshake (if final is https) with verify (fallback only with -k/--insecure)
#   - HTTP fetch (manual redirects, keeps chain) + correct tls_verify semantics across redirects
#   - HTTP input snapshot (no redirects) to capture 30x behavior cleanly
#   - HTTP HEAD probe (follow redirects) for extra header intel
#   - HTTP method probes: OPTIONS + TRACE
#   - CORS probe (Origin: https://example.com)
#   - OIDC well-known probe
#   - Exposure files: robots.txt, /.well-known/security.txt, /security.txt, humans.txt, sitemap.xml, ads.txt
#     * robots: signal parse
#     * security.txt: field extraction
#     * sitemap: extract top locs
#   - OpenAPI common paths
#   - Mixed content heuristic (http:// inside HTML when final is https)
#   - Surface hints (forms/password/upload/login/api)
#   - Security headers + cookie flags + rate limit headers
#   - Tech fingerprint (Wappalyzer-lite++): server/framework/CMS/js libs/analytics + CDN/WAF
#
# Saves:
#   output/scans/<slug>_<timestamp>/{scan_observations.v1.json, active_set.v1.json}
#
# NOTE (v1.8.0 schema):
#   scan_observations.v1.json now contains:
#     { version, generated_at, engine, target, observations (raw), derived, risks, tech }
#   active_set.v1.json now contains:
#     { version: "v2", generated_at, features, evidence, facts }

from __future__ import annotations

from pathlib import Path
import sys
import time
import json
import re
import ssl
import socket
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple, Optional
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, build_opener, HTTPRedirectHandler, HTTPSHandler
from urllib.error import URLError, HTTPError

from colorama import init

# Project root (../)  -- DO NOT CHANGE
ROOT = Path(__file__).resolve().parents[1]

WRITE_OUTPUTS = True
USER_AGENT = "SpektronScan/1.8.0"

GREEN_NEON = "\033[92m"
RESET = "\033[0m"

# Basic ANSI helpers (keeps professional CLI but still readable on plain terminals)
C_DIM = "\033[2m"
C_BOLD = "\033[1m"
C_RED = "\033[31m"
C_YEL = "\033[33m"
C_GRN = "\033[32m"
C_BLU = "\033[34m"
C_CYA = "\033[36m"

init(convert=True, strip=False, wrap=True)


# ===== Banner =====
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


# ===== Utilities =====
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_slug(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9._-]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return s or "target"


def json_dump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)


class NoAutoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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
        flags = []
        while rest and rest[0].startswith("-"):
            flags.append(rest.pop(0))
        for f in flags:
            if f in ("-k", "--insecure"):
                insecure = True
        if not rest:
            raise ValueError("target vazio")
        return (" ".join(rest).strip(), insecure)

    # allow direct url/host
    return (raw, insecure)


def normalize_target(target: str) -> str:
    """
    Normalizes into a URL. Defaults to https:// if missing scheme.
    Keeps path/query, strips fragment.
    """
    t = (target or "").strip()
    if not t:
        raise ValueError("target vazio")
    if "://" not in t:
        t = "https://" + t
    u = urlparse(t)
    if not u.netloc:
        raise ValueError("target inválido")
    u = u._replace(fragment="")
    return urlunparse(u)


def make_ssl_context(verify: bool) -> ssl.SSLContext:
    if verify:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def headers_to_dict(headers_items: List[Tuple[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in headers_items:
        out[str(k)] = str(v)
    return out


def _absolutize_location(base_url: str, location: str) -> str:
    if not location:
        return base_url
    loc = location.strip()
    if "://" in loc:
        return loc
    base = urlparse(base_url)
    if loc.startswith("//"):
        return f"{base.scheme}:{loc}"
    if loc.startswith("/"):
        return f"{base.scheme}://{base.netloc}{loc}"
    base_path = base.path or "/"
    if not base_path.endswith("/"):
        base_path = base_path.rsplit("/", 1)[0] + "/"
    return f"{base.scheme}://{base.netloc}{base_path}{loc}"


def _guess_body_encoding(content_type: Optional[str]) -> str:
    if not content_type:
        return "utf-8"
    m = re.search(r"charset\s*=\s*([A-Za-z0-9_\-]+)", content_type, re.I)
    if m:
        return m.group(1).strip()
    return "utf-8"


def _clip(s: str, n: int) -> str:
    s = s or ""
    return s[:n] if len(s) > n else s


def _is_cert_verify_error(msg: str) -> bool:
    m = (msg or "").lower()
    return ("certificate verify failed" in m) or ("certificateverifyfailed" in m) or ("certificate_verify_failed" in m)


def _now_local_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


# ===== DNS probes (best-effort) =====
_NSLOOKUP_TIMEOUT_S = 5


def _run_nslookup(qtype: str, host: str) -> str:
    """
    Best-effort Windows-friendly: nslookup -type=<TYPE> host
    Returns stdout/stderr (decoded) or "".
    """
    try:
        proc = subprocess.run(
            ["nslookup", f"-type={qtype}", host],
            capture_output=True,
            text=True,
            timeout=_NSLOOKUP_TIMEOUT_S,
            check=False,
        )
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return out.strip()
    except Exception:
        return ""


def _parse_nslookup_cname(text: str) -> List[str]:
    hits = re.findall(r"canonical name\s*=\s*([^\s]+)", text, flags=re.I)
    return [h.rstrip(".") for h in hits]


def _parse_nslookup_mx(text: str) -> List[Dict[str, Any]]:
    exch = re.findall(r"mail exchanger\s*=\s*([^\s]+)", text, flags=re.I)
    out = []
    for e in exch:
        out.append({"exchange": e.rstrip("."), "preference": None})
    return out


def _parse_nslookup_txt(text: str) -> List[str]:
    lines = []
    for m in re.finditer(r"text\s*=\s*(.+)", text, flags=re.I):
        v = m.group(1).strip()
        lines.append(v.strip())
    quoted = re.findall(r"\"([^\"]+)\"", text)
    for q in quoted:
        if q and q not in lines:
            lines.append(q)
    uniq = []
    seen = set()
    for x in lines:
        x2 = x.strip()
        if not x2:
            continue
        if x2 not in seen:
            seen.add(x2)
            uniq.append(x2)
    return uniq


def resolve_dns_bundle(host: str) -> Dict[str, Any]:
    """
    Passive DNS bundle:
      - A/AAAA via getaddrinfo
      - CNAME/MX/TXT via nslookup best-effort
    """
    out: Dict[str, Any] = {"ok": True, "a": [], "aaaa": [], "cname": [], "mx": [], "txt": []}

    try:
        ips_v4 = set()
        ips_v6 = set()
        infos = socket.getaddrinfo(host, None)
        for fam, _, _, _, sockaddr in infos:
            if fam == socket.AF_INET:
                ips_v4.add(sockaddr[0])
            elif fam == socket.AF_INET6:
                ips_v6.add(sockaddr[0])
        out["a"] = sorted(ips_v4)
        out["aaaa"] = sorted(ips_v6)
    except Exception as e:
        out["ok"] = False
        out["error"] = str(e)

    cname_txt = _run_nslookup("CNAME", host)
    mx_txt = _run_nslookup("MX", host)
    txt_txt = _run_nslookup("TXT", host)

    if cname_txt:
        out["cname"] = _parse_nslookup_cname(cname_txt)
    if mx_txt:
        out["mx"] = _parse_nslookup_mx(mx_txt)
    if txt_txt:
        out["txt"] = _parse_nslookup_txt(txt_txt)

    return out


# ===== TLS probe =====
def tls_probe(host: str, port: int, timeout_s: float, verify: bool) -> Dict[str, Any]:
    """
    Pure TLS handshake probe (passive).

    Notes:
      - When verify=False, ssl.getpeercert() may be empty on some platforms.
      - We always try to capture the peer certificate in DER (binary_form=True) to compute
        a stable fingerprint (SHA-256) even when the chain is untrusted.
      - peer_cert_available refers to the *parsed* dict availability (human fields),
        not to whether the server presented a cert at all.
    """
    out: Dict[str, Any] = {"ok": False, "verify": bool(verify)}
    ctx = make_ssl_context(verify=verify)

    try:
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                out["ok"] = True
                out["tls_version"] = ssock.version()
                cipher = ssock.cipher()
                out["cipher"] = {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]}

                der: Optional[bytes] = None
                try:
                    der = ssock.getpeercert(binary_form=True)
                except Exception:
                    der = None

                if der:
                    out["peer_cert_der_len"] = len(der)
                    out["peer_cert_sha256"] = hashlib.sha256(der).hexdigest()
                else:
                    out["peer_cert_der_len"] = 0
                    out["peer_cert_sha256"] = None

                cert = ssock.getpeercert()
                out["peer_cert_available"] = bool(cert)

                if cert:
                    out["cert"] = {
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter"),
                        "subjectAltName": cert.get("subjectAltName", []),
                    }
                else:
                    out["cert"] = None

    except Exception as e:
        out["error"] = str(e)

    return out


# ===== HTTP probe =====
def http_probe(
    url: str,
    timeout_s: float,
    user_agent: str,
    max_redirects: int,
    tls_verify: bool,
    sample_bytes: int = 4096,
    follow_redirects: bool = True,
    method: str = "GET",
    extra_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Fetches URL.
    - If follow_redirects=True: follows redirects up to max_redirects (manual), keeps chain
    - If follow_redirects=False: returns first response (even if 30x) without following
    Captures status + headers + body sample.
    Supports TLS verify on/off via HTTPSHandler(context=...).
    Returns tls_verify as:
      - None if NO https was attempted in the chain
      - bool(tls_verify) if https was attempted at least once
    """
    chain: List[Dict[str, Any]] = []
    current = url
    total_started = time.time()

    ctx = make_ssl_context(verify=tls_verify)
    opener = build_opener(NoAutoRedirect(), HTTPSHandler(context=ctx))

    final_status: Optional[int] = None
    redirects = 0
    body_sample = ""
    body_encoding = "utf-8"
    body_truncated = False

    hdrs = {"User-Agent": user_agent, "Accept": "*/*"}
    if extra_headers:
        for k, v in extra_headers.items():
            hdrs[str(k)] = str(v)

    loops = (max_redirects + 1) if follow_redirects else 1
    any_https = False

    def _finish(ok: bool, err: Optional[str] = None) -> Dict[str, Any]:
        timing_total_ms = int((time.time() - total_started) * 1000)
        return {
            "ok": ok,
            "tls_verify": (bool(tls_verify) if any_https else None),
            "method": method,
            "error": err,
            "final_url": current,
            "final_status": final_status,
            "redirects": redirects,
            "timing_total_ms": timing_total_ms,
            "chain": chain,
            "body_encoding": body_encoding,
            "body_sample_bytes": sample_bytes,
            "body_sample_truncated": body_truncated,
            "body_sample": body_sample,
        }

    for _ in range(loops):
        if (urlparse(current).scheme or "").lower() == "https":
            any_https = True

        req = Request(current, headers=hdrs, method=method)
        started = time.time()

        try:
            resp = opener.open(req, timeout=timeout_s)
            status = resp.getcode()
            final_status = status

            headers_raw = list(resp.headers.items())
            headers = headers_to_dict(headers_raw)

            ctype = headers.get("Content-Type") or headers.get("content-type")
            body_encoding = _guess_body_encoding(ctype)

            raw = b""
            if sample_bytes > 0 and method.upper() != "HEAD":
                raw = resp.read(sample_bytes + 1)
                if len(raw) > sample_bytes:
                    raw = raw[:sample_bytes]
                    body_truncated = True
                try:
                    body_sample = raw.decode(body_encoding, errors="replace")
                except Exception:
                    body_encoding = "utf-8"
                    body_sample = raw.decode("utf-8", errors="replace")

            elapsed_ms = int((time.time() - started) * 1000)
            chain.append({"url": current, "status": status, "headers_raw": headers_raw, "headers": headers, "elapsed_ms": elapsed_ms})

            if follow_redirects and status in (301, 302, 303, 307, 308):
                loc = headers.get("Location") or headers.get("location")
                if loc and redirects < max_redirects:
                    redirects += 1
                    current = _absolutize_location(current, loc)
                    continue

            return _finish(True)

        except HTTPError as e:
            status = e.code
            final_status = status

            headers_raw = list(e.headers.items()) if e.headers else []
            headers = headers_to_dict(headers_raw)

            raw = b""
            if sample_bytes > 0 and method.upper() != "HEAD":
                try:
                    raw = e.read(sample_bytes + 1)  # type: ignore
                except Exception:
                    raw = b""
                if len(raw) > sample_bytes:
                    raw = raw[:sample_bytes]
                    body_truncated = True
                ctype = headers.get("Content-Type") or headers.get("content-type")
                body_encoding = _guess_body_encoding(ctype)
                try:
                    body_sample = raw.decode(body_encoding, errors="replace")
                except Exception:
                    body_encoding = "utf-8"
                    body_sample = raw.decode("utf-8", errors="replace")

            elapsed_ms = int((time.time() - started) * 1000)
            chain.append({"url": current, "status": status, "headers_raw": headers_raw, "headers": headers, "elapsed_ms": elapsed_ms})

            if follow_redirects and status in (301, 302, 303, 307, 308):
                loc = headers.get("Location") or headers.get("location")
                if loc and redirects < max_redirects:
                    redirects += 1
                    current = _absolutize_location(current, loc)
                    continue

            return _finish(True)

        except URLError as e:
            elapsed_ms = int((time.time() - started) * 1000)
            chain.append({"url": current, "status": None, "headers_raw": [], "headers": {}, "elapsed_ms": elapsed_ms, "error": str(e)})
            return _finish(False, str(e))

        except Exception as e:
            elapsed_ms = int((time.time() - started) * 1000)
            chain.append({"url": current, "status": None, "headers_raw": [], "headers": {}, "elapsed_ms": elapsed_ms, "error": str(e)})
            return _finish(False, str(e))

    return _finish(False, "redirect_limit_exceeded")


def transport_from_http(http_obs: Dict[str, Any], input_url: str) -> Dict[str, Any]:
    chain = http_obs.get("chain") or []
    urls = [c.get("url") for c in chain if c.get("url")] if chain else [input_url]
    final_url = http_obs.get("final_url") or input_url

    in_u = urlparse(input_url)
    out_u = urlparse(final_url)

    redirect_kind = None
    if (in_u.scheme or "").lower() == "http" and (out_u.scheme or "").lower() == "https":
        redirect_kind = "http_to_https"
    elif (in_u.hostname or "").lower().startswith("www.") and (out_u.hostname or "").lower() == (in_u.hostname or "")[4:].lower():
        redirect_kind = "www_to_apex"
    elif (out_u.hostname or "").lower().startswith("www.") and (in_u.hostname or "").lower() == (out_u.hostname or "")[4:].lower():
        redirect_kind = "apex_to_www"
    elif (in_u.path or "/") != (out_u.path or "/"):
        redirect_kind = "path_canonicalization"

    permanent = None
    if chain:
        st = chain[0].get("status")
        if st in (301, 308):
            permanent = True
        elif st in (302, 303, 307):
            permanent = False

    return {
        "input_url": input_url,
        "input_scheme": in_u.scheme or None,
        "final_url": final_url,
        "final_scheme": out_u.scheme or None,
        "redirects": int(http_obs.get("redirects") or 0),
        "redirect_chain": urls if urls else [input_url, final_url],
        "tls_in_play": (out_u.scheme == "https"),
        "redirect_kind": redirect_kind,
        "redirect_permanent_hint": permanent,
        "input_host": in_u.hostname,
        "final_host": out_u.hostname,
    }


def oidc_well_known_probe(base_url: str, timeout_s: float, user_agent: str, tls_verify: bool) -> Dict[str, Any]:
    u = urlparse(base_url)
    if not u.scheme or not u.netloc:
        return {"ok": False, "tls_verify": bool(tls_verify), "error": "bad_base_url"}

    wk = f"{u.scheme}://{u.netloc}/.well-known/openid-configuration"
    r = http_probe(wk, timeout_s=timeout_s, user_agent=user_agent, max_redirects=2, tls_verify=tls_verify, sample_bytes=0)

    if not r.get("ok"):
        return {"ok": False, "tls_verify": bool(tls_verify), "url": wk, "error": r.get("error")}

    status = r.get("final_status")
    if status == 404:
        return {"ok": False, "tls_verify": bool(tls_verify), "url": wk, "status": 404, "final_url": r.get("final_url"), "error": "oidc_well_known_not_found"}

    return {"ok": True, "tls_verify": bool(tls_verify), "url": wk, "status": status, "final_url": r.get("final_url")}


def _same_origin_url(base_url: str, path: str) -> str:
    u = urlparse(base_url)
    return f"{u.scheme}://{u.netloc}{path}"


def _parse_security_txt_fields(text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        v = v.strip()
        if not k:
            continue
        if k not in out:
            out[k] = []
        out[k].append(v)
    return out


def _parse_sitemap_locs(xml_text: str, limit: int = 20) -> List[str]:
    locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", xml_text or "", flags=re.I)
    uniq = []
    seen = set()
    for l in locs:
        l2 = l.strip()
        if l2 and l2 not in seen:
            seen.add(l2)
            uniq.append(l2)
        if len(uniq) >= limit:
            break
    return uniq


def fetch_common_files(base_url: str, timeout_s: float, user_agent: str, tls_verify: bool) -> Dict[str, Any]:
    paths = ["/robots.txt", "/.well-known/security.txt", "/security.txt", "/humans.txt", "/sitemap.xml", "/ads.txt"]

    out: Dict[str, Any] = {"ok": True, "tls_verify": bool(tls_verify), "items": []}
    for p in paths:
        url = _same_origin_url(base_url, p)
        r = http_probe(url, timeout_s=timeout_s, user_agent=user_agent, max_redirects=2, tls_verify=tls_verify, sample_bytes=4096)

        item: Dict[str, Any] = {"path": p, "url": url, "ok": bool(r.get("ok")), "status": r.get("final_status"), "final_url": r.get("final_url")}

        if r.get("ok") and (r.get("final_status") in (200, 206)):
            item["body_sample"] = r.get("body_sample", "")
            item["body_sample_truncated"] = bool(r.get("body_sample_truncated"))

            bs = (item["body_sample"] or "")
            low = bs.lower()

            if p.endswith("robots.txt"):
                item["signals"] = {"has_disallow": ("disallow:" in low), "has_allow": ("allow:" in low), "has_sitemap": ("sitemap:" in low)}

            elif p.endswith("security.txt"):
                item["signals"] = {
                    "has_contact": ("contact:" in low),
                    "has_expires": ("expires:" in low),
                    "has_encryption": ("encryption:" in low),
                    "has_acknowledgments": ("acknowledgments:" in low),
                }
                item["fields"] = _parse_security_txt_fields(bs)

            elif p.endswith("sitemap.xml"):
                if "<urlset" in low or "<sitemapindex" in low:
                    item["signals"] = {"looks_xml": True}
                    item["locs_top"] = _parse_sitemap_locs(bs, limit=20)
                else:
                    item["signals"] = {"looks_xml": False}

        out["items"].append(item)

    return out


def fetch_openapi_common(base_url: str, timeout_s: float, user_agent: str, tls_verify: bool) -> Dict[str, Any]:
    paths = ["/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml", "/api-docs", "/v2/api-docs", "/v3/api-docs"]
    out: Dict[str, Any] = {"ok": True, "tls_verify": bool(tls_verify), "items": []}

    for p in paths:
        url = _same_origin_url(base_url, p)
        sample = 65536 if p.endswith(".json") else 2048
        r = http_probe(url, timeout_s=timeout_s, user_agent=user_agent, max_redirects=2, tls_verify=tls_verify, sample_bytes=sample)

        item: Dict[str, Any] = {"path": p, "url": url, "ok": bool(r.get("ok")), "status": r.get("final_status"), "final_url": r.get("final_url")}

        if r.get("ok") and r.get("final_status") in (200, 206):
            body = (r.get("body_sample") or "").strip()
            low = body.lower()
            looks_openapi = ("openapi" in low) or ("swagger" in low) or ("paths" in low and "info" in low)
            item["body_sample"] = body
            item["body_sample_truncated"] = bool(r.get("body_sample_truncated"))
            item["signals"] = {"looks_openapi": bool(looks_openapi)}
            if looks_openapi and p.endswith(".json"):
                try:
                    import json as _json
                    spec = _json.loads(body)
                    info = spec.get("info") if isinstance(spec, dict) else {}
                    paths_obj = spec.get("paths") if isinstance(spec, dict) else {}
                    servers = spec.get("servers") if isinstance(spec, dict) else None
                    item["openapi_summary"] = {
                        "openapi": spec.get("openapi") if isinstance(spec, dict) else None,
                        "swagger": spec.get("swagger") if isinstance(spec, dict) else None,
                        "title": (info or {}).get("title") if isinstance(info, dict) else None,
                        "version": (info or {}).get("version") if isinstance(info, dict) else None,
                        "paths_count": len(paths_obj) if isinstance(paths_obj, dict) else None,
                        "servers_count": len(servers) if isinstance(servers, list) else (1 if servers else None),
                    }
                except Exception:
                    pass

        out["items"].append(item)

    return out


def detect_mixed_content(final_scheme: str, body_html: str, max_examples: int = 5) -> Dict[str, Any]:
    if final_scheme != "https":
        return {"ok": True, "count": 0, "examples": []}
    b = body_html or ""
    hits = re.findall(r"http://[^\s\"'<>]+", b, flags=re.I)
    uniq = []
    seen = set()
    for h in hits:
        h2 = h.strip()
        if h2 not in seen:
            seen.add(h2)
            uniq.append(h2)
        if len(uniq) >= max_examples:
            break
    return {"ok": True, "count": len(set(hits)), "examples": uniq}


def surface_hints(final_url: str, body_html: str) -> Dict[str, Any]:
    b = (body_html or "")
    low = b.lower()

    forms = re.findall(r"<form\b[^>]*>", low)
    forms_count = len(forms)
    has_password = ("type=\"password\"" in low) or ("type='password'" in low)
    has_upload = ("type=\"file\"" in low) or ("type='file'" in low)

    login_hints = any(k in low for k in ["login", "sign in", "signin", "auth", "password", "username"])

    api_hints = []
    for m in re.finditer(r"(?:href|src)\s*=\s*[\"']([^\"']+)[\"']", low):
        u = m.group(1)
        if "/api" in u and u not in api_hints:
            api_hints.append(u)
        if len(api_hints) >= 10:
            break

    return {"ok": True, "forms_count": forms_count, "forms_sample": [], "has_password_field": bool(has_password), "has_upload_field": bool(has_upload), "login_hints": bool(login_hints), "api_hints": api_hints}


SEC_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
]

RATELIMIT_HEADERS = ["ratelimit-limit", "ratelimit-remaining", "ratelimit-reset", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"]


def _get_header_ci(headers: Dict[str, str], name: str) -> Optional[str]:
    ln = name.lower()
    for k, v in headers.items():
        if str(k).lower() == ln:
            return str(v)
    return None


def parse_set_cookie_headers(headers_raw: List[Tuple[str, str]]) -> List[str]:
    out = []
    for k, v in headers_raw:
        if str(k).lower() == "set-cookie":
            out.append(str(v))
    return out


def analyze_cookies(set_cookie_values: List[str]) -> Dict[str, Any]:
    cookies: Dict[str, Any] = {}
    for sc in set_cookie_values:
        parts = [p.strip() for p in sc.split(";") if p.strip()]
        if not parts:
            continue
        name_value = parts[0]
        name = name_value.split("=", 1)[0].strip()
        attrs = {p.lower(): True for p in parts[1:]}
        samesite = None
        for p in parts[1:]:
            if p.lower().startswith("samesite="):
                samesite = p.split("=", 1)[1].strip()
        cookies[name] = {"raw": sc, "secure": ("secure" in attrs), "httponly": ("httponly" in attrs), "samesite": samesite}
    return cookies


def security_audit(http_obs: Dict[str, Any], final_scheme: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "headers_present": {h: None for h in SEC_HEADERS},
        "rate_limit_headers_present": {h: None for h in RATELIMIT_HEADERS},
        "cookies": {},
        "findings": [],
        "tls_verify": http_obs.get("tls_verify"),
    }

    if not http_obs or not http_obs.get("ok"):
        out["error"] = "http_not_ok"
        return out

    chain = http_obs.get("chain") or []
    last = chain[-1] if chain else {}
    headers = last.get("headers") or {}
    headers_raw = last.get("headers_raw") or []

    for h in SEC_HEADERS:
        out["headers_present"][h] = _get_header_ci(headers, h)
    for h in RATELIMIT_HEADERS:
        out["rate_limit_headers_present"][h] = _get_header_ci(headers, h)

    set_cookie = parse_set_cookie_headers(headers_raw)
    out["cookies"] = analyze_cookies(set_cookie)

    def add_finding(fid: str, sev: str, title: str, detail: str, evidence: Any):
        out["findings"].append({"id": fid, "severity": sev, "title": title, "detail": detail, "evidence": evidence})

    hsts = out["headers_present"]["strict-transport-security"]
    csp = out["headers_present"]["content-security-policy"]
    xfo = out["headers_present"]["x-frame-options"]
    xcto = out["headers_present"]["x-content-type-options"]
    refpol = out["headers_present"]["referrer-policy"]

    if final_scheme == "https" and not hsts:
        add_finding("SEC_HDR_HSTS_MISSING", "medium", "HSTS ausente em HTTPS", "Resposta HTTPS não inclui Strict-Transport-Security (HSTS).", {"header": "strict-transport-security"})
    if not csp:
        add_finding("SEC_HDR_CSP_MISSING", "low", "CSP ausente", "Resposta não inclui Content-Security-Policy (CSP).", {"header": "content-security-policy"})
    if not xcto:
        add_finding("SEC_HDR_XCTO_MISSING", "low", "X-Content-Type-Options ausente", "Resposta não inclui X-Content-Type-Options: nosniff.", {"header": "x-content-type-options"})

    if not xfo and not (csp and "frame-ancestors" in (csp or "").lower()):
        add_finding("SEC_HDR_CLICKJACKING_GAP", "low", "Proteção contra clickjacking não evidente", "Sem X-Frame-Options e sem CSP frame-ancestors (pode permitir embed).", {"x-frame-options": xfo, "content-security-policy": csp})

    if not refpol:
        add_finding("SEC_HDR_REFERRER_POLICY_MISSING", "info", "Referrer-Policy ausente", "Resposta não inclui Referrer-Policy (pode vazar paths/query em navegação).", {"header": "referrer-policy"})

    if not any(out["rate_limit_headers_present"].get(h) for h in RATELIMIT_HEADERS):
        add_finding("SEC_HDR_RATELIMIT_MISSING", "info", "Headers de rate limit ausentes", "Resposta não expõe headers comuns de rate limit (pode existir via outro endpoint).", {"headers_checked": RATELIMIT_HEADERS})

    for name, info in out["cookies"].items():
        if final_scheme == "https" and not info.get("secure"):
            add_finding("COOKIE_SECURE_MISSING", "medium", "Cookie sem Secure em HTTPS", f"Cookie '{name}' não tem flag Secure em resposta HTTPS.", {"cookie": name, "raw": info.get("raw")})
        if not info.get("httponly"):
            add_finding("COOKIE_HTTPONLY_MISSING", "low", "Cookie sem HttpOnly", f"Cookie '{name}' não tem flag HttpOnly (JS pode ler).", {"cookie": name, "raw": info.get("raw")})
        if not info.get("samesite"):
            add_finding("COOKIE_SAMESITE_MISSING", "info", "Cookie sem SameSite", f"Cookie '{name}' não declara SameSite (CSRF pode ficar mais fácil dependendo do contexto).", {"cookie": name, "raw": info.get("raw")})

    return out


def method_probes(url: str, timeout_s: float, user_agent: str, tls_verify: bool) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": True, "tls_verify": bool(tls_verify), "items": []}
    for m in ["OPTIONS", "TRACE"]:
        r = http_probe(url, timeout_s=timeout_s, user_agent=user_agent, max_redirects=2, tls_verify=tls_verify, sample_bytes=0, follow_redirects=False, method=m)
        item: Dict[str, Any] = {"method": m, "url": url, "ok": bool(r.get("ok")), "status": r.get("final_status")}
        if r.get("ok"):
            chain = r.get("chain") or []
            last = chain[-1] if chain else {}
            headers = last.get("headers") or {}
            allow = _get_header_ci(headers, "allow")
            if allow:
                item["allow"] = allow
        out["items"].append(item)
    return out


def cors_probe(url: str, timeout_s: float, user_agent: str, tls_verify: bool) -> Dict[str, Any]:
    origin = "https://example.com"
    headers = {"Origin": origin, "User-Agent": user_agent, "Accept": "*/*"}
    resp = http_probe(
        url,
        timeout_s=timeout_s,
        user_agent=user_agent,
        max_redirects=0,
        tls_verify=tls_verify,
        sample_bytes=0,
        follow_redirects=True,
        method="GET",
        extra_headers=headers,
    )

    out: Dict[str, Any] = {
        "ok": bool(resp.get("ok")),
        "tls_verify": bool(tls_verify),
        "url": url,
        "origin": origin,
        "acao": None,
        "acac": None,
        "reflected": False,
        "risk": "none",
    }

    if not resp.get("ok"):
        out["error"] = resp.get("error")
        return out

    chain = resp.get("chain") or []
    last = chain[-1] if chain else {}
    hdrs = last.get("headers") or {}

    acao = _get_header_ci(hdrs, "access-control-allow-origin")
    acac = _get_header_ci(hdrs, "access-control-allow-credentials")
    out["acao"] = acao
    out["acac"] = acac

    if not acao:
        out["risk"] = "none"
        return out

    acao_v = (acao or "").strip()
    acac_v = (acac or "").strip().lower() if acac else ""

    out["reflected"] = (acao_v == origin)

    if acao_v == "*" and acac_v == "true":
        out["risk"] = "high"
    elif out["reflected"] and acac_v == "true":
        out["risk"] = "high"
    elif out["reflected"]:
        out["risk"] = "low"
    elif acao_v == "*":
        out["risk"] = "none"
    else:
        out["risk"] = "medium"

    return out


def _add_tech(tech: List[Dict[str, Any]], name: str, category: str, confidence: str, evidence: Any):
    tech.append({"name": name, "category": category, "confidence": confidence, "evidence": evidence})


def _detect_edge_from_headers(headers: Dict[str, str], headers_raw: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    server = _get_header_ci(headers, "server") or ""
    via = _get_header_ci(headers, "via") or ""
    x_cache = _get_header_ci(headers, "x-cache") or ""
    cf_ray = _get_header_ci(headers, "cf-ray")
    cf_cache = _get_header_ci(headers, "cf-cache-status")
    akamai_ghost = _get_header_ci(headers, "x-akamai-transformed")
    incapsula = _get_header_ci(headers, "x-cdn") or _get_header_ci(headers, "x-iinfo")
    sucuri = _get_header_ci(headers, "x-sucuri-id") or _get_header_ci(headers, "x-sucuri-cache")
    cloudfront = _get_header_ci(headers, "x-amz-cf-id") or _get_header_ci(headers, "x-amz-cf-pop")
    fastly = _get_header_ci(headers, "x-served-by") or _get_header_ci(headers, "x-cache-hits")
    varnish = _get_header_ci(headers, "x-varnish")
    vercel = _get_header_ci(headers, "x-vercel-id")
    netlify = _get_header_ci(headers, "x-nf-request-id")

    s = server.lower()

    if "cloudflare" in s or cf_ray or cf_cache:
        _add_tech(out, "Cloudflare", "CDN/WAF", "high", {"server": server, "cf-ray": cf_ray, "cf-cache-status": cf_cache})
    if "akamai" in s or akamai_ghost or ("akamai" in via.lower()):
        _add_tech(out, "Akamai", "CDN/WAF", "medium", {"server": server, "via": via, "x-akamai-transformed": akamai_ghost})
    if "fastly" in s or ("fastly" in via.lower()) or fastly:
        _add_tech(out, "Fastly", "CDN", "medium", {"server": server, "via": via, "x-served-by/x-cache-hits": fastly})
    if cloudfront:
        _add_tech(out, "Amazon CloudFront", "CDN", "medium", {"x-amz-cf": cloudfront})
    if incapsula:
        _add_tech(out, "Imperva Incapsula", "CDN/WAF", "low", {"x-cdn/x-iinfo": incapsula})
    if sucuri:
        _add_tech(out, "Sucuri", "CDN/WAF", "low", {"header": "x-sucuri-*"})
    if varnish:
        _add_tech(out, "Varnish", "Edge/Cache", "low", {"x-varnish": varnish})
    if vercel:
        _add_tech(out, "Vercel", "PaaS/Edge", "medium", {"x-vercel-id": vercel})
    if netlify:
        _add_tech(out, "Netlify", "PaaS/Edge", "low", {"x-nf-request-id": netlify})
    if x_cache and "hit" in x_cache.lower():
        _add_tech(out, "Caching Proxy", "Edge/Cache", "low", {"x-cache": x_cache})

    return out


def tech_fingerprint(observations: Dict[str, Any]) -> List[Dict[str, Any]]:
    tech: List[Dict[str, Any]] = []

    http = observations.get("http") or {}
    chain = http.get("chain") or []
    last = chain[-1] if chain else {}
    headers = last.get("headers") or {}
    headers_raw = last.get("headers_raw") or []
    body = (http.get("body_sample") or "")

    server = _get_header_ci(headers, "server")
    xpb = _get_header_ci(headers, "x-powered-by")
    via = _get_header_ci(headers, "via")

    edge_hits = _detect_edge_from_headers(headers, headers_raw)
    edge_present = bool(edge_hits)

    if server:
        s = server.lower()
        if "nginx" in s:
            _add_tech(tech, "nginx", "Web Server", ("high" if not edge_present else "low"), {"header": "server", "value": server})
        if "apache" in s:
            _add_tech(tech, "Apache", "Web Server", ("high" if not edge_present else "low"), {"header": "server", "value": server})
        if "microsoft-iis" in s:
            _add_tech(tech, "IIS", "Web Server", ("high" if not edge_present else "low"), {"header": "server", "value": server})
        if "openresty" in s:
            _add_tech(tech, "OpenResty", "Web Server", ("medium" if not edge_present else "low"), {"header": "server", "value": server})

    if xpb:
        xp = xpb.lower()
        if "php" in xp:
            _add_tech(tech, "PHP", "Language/Runtime", "high", {"header": "x-powered-by", "value": xpb})
        if "express" in xp:
            _add_tech(tech, "Express", "Web Framework", "high", {"header": "x-powered-by", "value": xpb})
        if "asp.net" in xp or "aspnet" in xp:
            _add_tech(tech, "ASP.NET", "Web Framework", "high", {"header": "x-powered-by", "value": xpb})

    if via and "heroku-router" in via.lower():
        _add_tech(tech, "Heroku", "PaaS", "medium", {"header": "via", "value": via})

    tech.extend(edge_hits)

    hsts = _get_header_ci(headers, "strict-transport-security")
    if hsts:
        _add_tech(tech, "HSTS (Strict-Transport-Security)", "Security Header", "high", {"header": "strict-transport-security", "value": hsts})

    set_cookie = parse_set_cookie_headers(headers_raw)
    for sc in set_cookie:
        low = sc.lower()
        if "jsessionid=" in low:
            _add_tech(tech, "Java/JSP (JSESSIONID)", "Language/Runtime", "medium", {"set-cookie": _clip(sc, 200)})
        if "phpsessid=" in low:
            _add_tech(tech, "PHP (PHPSESSID)", "Language/Runtime", "medium", {"set-cookie": _clip(sc, 200)})
        if "asp.net_sessionid=" in low:
            _add_tech(tech, "ASP.NET (Session)", "Language/Runtime", "medium", {"set-cookie": _clip(sc, 200)})

    b = body.lower()

    if "wp-content/" in b or "wp-includes/" in b:
        _add_tech(tech, "WordPress", "CMS", "high", {"html": "wp-content/wp-includes"})
    if "drupal-settings-json" in b or "sites/all/" in b:
        _add_tech(tech, "Drupal", "CMS", "medium", {"html": "drupal markers"})
    if "joomla!" in b or "/media/system/js/" in b:
        _add_tech(tech, "Joomla", "CMS", "medium", {"html": "joomla markers"})

    if "ng-version" in b or "angularjs" in b:
        _add_tech(tech, "Angular", "Frontend Framework", "medium", {"html": "angular markers"})
    if ("data-reactroot" in b) or ("__react" in b):
        _add_tech(tech, "React", "Frontend Framework", "medium", {"html": "react markers"})
    if ("__vue__" in b) or ("data-v-" in b):
        _add_tech(tech, "Vue.js", "Frontend Framework", "medium", {"html": "vue markers"})
    if "__next" in b:
        _add_tech(tech, "Next.js", "Frontend Framework", "medium", {"html": "__next"})
    if "__nuxt" in b:
        _add_tech(tech, "Nuxt", "Frontend Framework", "medium", {"html": "__nuxt"})

    m = re.search(r"(?:src=|href=)[\"'][^\"']*jquery[-\.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)\.min\.js", b)
    if m:
        _add_tech(tech, f"jQuery {m.group(1)}", "JavaScript Library", "high", {"script_src_match": True})

    if "googletagmanager.com/gtm.js" in b:
        _add_tech(tech, "Google Tag Manager", "Analytics", "high", {"html": "gtm.js"})
    if "google-analytics.com" in b or "gtag(" in b:
        _add_tech(tech, "Google Analytics", "Analytics", "medium", {"html": "ga/gtag"})

    conf_rank = {"low": 1, "info": 1, "medium": 2, "high": 3}
    merged: Dict[str, Dict[str, Any]] = {}
    for t in tech:
        name = t.get("name")
        if not name:
            continue
        if name not in merged or conf_rank.get(t.get("confidence", "low"), 1) > conf_rank.get(merged[name].get("confidence", "low"), 1):
            merged[name] = t

    return list(merged.values())


def parse_hsts(hsts_value: Optional[str]) -> Dict[str, Any]:
    if not hsts_value:
        return {"present": False, "value": None, "max_age": None, "include_subdomains": False, "preload": False}
    v = str(hsts_value).strip()
    low = v.lower()
    max_age = None
    m = re.search(r"max-age\s*=\s*([0-9]+)", low)
    if m:
        try:
            max_age = int(m.group(1))
        except Exception:
            max_age = None
    return {"present": True, "value": v, "max_age": max_age, "include_subdomains": ("includesubdomains" in low), "preload": ("preload" in low)}


def derive_https_posture(raw_obs: Dict[str, Any]) -> Dict[str, Any]:
    transport = (raw_obs or {}).get("transport") or {}
    http_main = (raw_obs or {}).get("http") or {}
    http_downgrade = (raw_obs or {}).get("http_downgrade_snapshot") or None

    input_scheme = (transport.get("input_scheme") or "").lower()
    final_scheme = (transport.get("final_scheme") or "").lower()
    redirects = int(transport.get("redirects") or 0)
    redirect_kind = transport.get("redirect_kind")

    posture = "http_only"
    if final_scheme == "https":
        if input_scheme == "https":
            posture = "opportunistic_https"
        else:
            posture = "enforced_by_redirect" if redirects > 0 and redirect_kind in ("http_to_https", "scheme_upgrade") else "opportunistic_https"

    if input_scheme == "https" and http_downgrade and http_downgrade.get("ok"):
        st = int(http_downgrade.get("final_status") or http_downgrade.get("status") or 0)
        hdrs = {}
        try:
            chain = http_downgrade.get("chain") or []
            last = chain[-1] if chain else {}
            hdrs = last.get("headers") or {}
        except Exception:
            hdrs = {}
        loc = _get_header_ci(hdrs, "location")
        if st in (301, 302, 303, 307, 308) and isinstance(loc, str) and loc.lower().startswith("https://"):
            posture = "enforced_by_redirect"
        elif 200 <= st < 400:
            posture = "opportunistic_https"

    chain = (http_main or {}).get("chain") or []
    last = chain[-1] if chain else {}
    last_headers = last.get("headers") or {}
    hsts_val = _get_header_ci(last_headers, "strict-transport-security")
    hsts = parse_hsts(hsts_val)

    if final_scheme == "https" and hsts.get("present") and posture in ("opportunistic_https", "enforced_by_redirect"):
        posture = "browser_enforced_hsts" if (hsts.get("preload") or posture != "enforced_by_redirect") else posture

    return {
        "input_scheme": input_scheme or None,
        "final_scheme": final_scheme or None,
        "https_posture": posture,
        "hsts": hsts,
        "redirects": transport.get("redirects"),
        "final_url": transport.get("final_url"),
        "redirect_kind": transport.get("redirect_kind"),
        "redirect_permanent_hint": transport.get("redirect_permanent_hint"),
        "input_host": transport.get("input_host"),
        "final_host": transport.get("final_host"),
        "http_downgrade_probe": {
            "attempted": bool(http_downgrade is not None),
            "ok": bool(http_downgrade.get("ok")) if isinstance(http_downgrade, dict) else False,
            "status": (http_downgrade.get("final_status") if isinstance(http_downgrade, dict) else None),
        } if http_downgrade is not None else {"attempted": False},
    }


def _parse_jquery_version(body: str) -> Optional[str]:
    if not body:
        return None
    b = body.lower()
    m = re.search(r"(?:src=|href=)[\"'][^\"']*jquery[-\.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)\.min\.js", b)
    return m.group(1) if m else None


def derive_legacy_html(raw_obs: Dict[str, Any]) -> Dict[str, Any]:
    http = raw_obs.get("http") or {}
    body = http.get("body_sample") or ""
    if not body:
        return {"present": False}

    low = body.lower()
    signals: List[str] = []

    m = re.search(r"<!doctype\s+([^>]+)>", low, flags=re.IGNORECASE)
    if m:
        dt = m.group(1).strip()
        if "xhtml" in dt or "transitional" in dt:
            signals.append(f"doctype:{_clip(dt, 90)}")

    if "charset=iso-8859" in low or "charset=windows-125" in low:
        signals.append("charset:legacy")

    jq = _parse_jquery_version(body)
    if jq:
        signals.append(f"jquery:{jq}")

    present = bool(signals)
    confidence = "low"
    if any(s.startswith("doctype:") for s in signals) and any(s.startswith("jquery:") for s in signals):
        confidence = "medium"

    return {"present": present, "signals": signals, "confidence": confidence}


def derive_stack(raw_obs: Dict[str, Any], tech: List[Dict[str, Any]]) -> Dict[str, Any]:
    http = raw_obs.get("http") or {}
    chain = http.get("chain") or []
    last = chain[-1] if chain else {}
    headers = last.get("headers") or {}
    headers_raw = last.get("headers_raw") or []

    edge_hits = _detect_edge_from_headers(headers, headers_raw)
    edge_names = [t.get("name") for t in edge_hits if t.get("name")]
    edge_provider = edge_names[0] if edge_names else None

    server = _get_header_ci(headers, "server")
    origin_hint = None
    origin_conf = "low"
    if server:
        s = str(server).lower()
        edge_tokens = ["cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "imperva", "sucuri", "varnish", "vercel", "netlify"]
        if edge_provider and any(tok in s for tok in edge_tokens):
            origin_hint = None
            origin_conf = "low"
        else:
            origin_hint = server
            origin_conf = "medium"

    legacy = derive_legacy_html(raw_obs)

    return {
        "edge": {"provider": edge_provider, "signals": edge_names, "confidence": "high" if edge_provider else "low"},
        "origin_server_hint": {"name": origin_hint, "confidence": origin_conf, "source": "header:server" if origin_hint else None},
        "legacy_html": legacy,
    }


def derive_risks(raw_obs: Dict[str, Any], derived: Dict[str, Any]) -> List[Dict[str, Any]]:
    risks: List[Dict[str, Any]] = []

    tls = raw_obs.get("tls") or {}
    dtr = (derived.get("transport") or {})
    posture = dtr.get("https_posture")

    if tls.get("present") and tls.get("ok") and (tls.get("verify_effective") is False):
        fb = raw_obs.get("tls_fallback") or {}
        risks.append(
            {
                "id": "TLS_VERIFY_DISABLED",
                "severity": "medium",
                "title": "Coleta com verificação TLS desabilitada",
                "detail": "O scan coletou evidências com verify_effective=false (fallback ou flag insegura).",
                "evidence_refs": ["observations.tls.verify_effective", "observations.tls_fallback", "observations.http.tls_verify"],
                "meta": {"reason": fb.get("reason"), "fallback_used": bool(fb.get("used_insecure"))},
            }
        )

    if posture in ("disabled_or_http_only", "opportunistic_https"):
        sev = "medium" if posture == "disabled_or_http_only" else "low"
        risks.append(
            {
                "id": "HTTPS_NOT_ENFORCED",
                "severity": sev,
                "title": "HTTPS não aparenta estar estritamente aplicado",
                "detail": "Sem redirecionamento/HSTS consistente, usuários podem cair em HTTP por downgrade, links antigos ou erro operacional.",
                "evidence_refs": ["derived.transport.https_posture", "observations.http_input_snapshot", "observations.transport"],
                "meta": {"https_posture": posture},
            }
        )

    return risks


def finalize_scan_document(raw_obs: Dict[str, Any]) -> Dict[str, Any]:
    tech = raw_obs.get("tech") or []
    derived = {"transport": derive_https_posture(raw_obs), "stack": derive_stack(raw_obs, tech)}
    risks = derive_risks(raw_obs, derived)

    observations_raw = {
        "dns": raw_obs.get("dns"),
        "http_input_snapshot": raw_obs.get("http_input_snapshot"),
        "http": raw_obs.get("http"),
        "http_head": raw_obs.get("http_head"),
        "transport": raw_obs.get("transport"),
        "tls": raw_obs.get("tls"),
        "tls_fallback": raw_obs.get("tls_fallback"),
        "method_probes": raw_obs.get("method_probes"),
        "cors_probe": raw_obs.get("cors_probe"),
        "oidc_probe": raw_obs.get("oidc_probe"),
        "exposure_files": raw_obs.get("exposure_files"),
        "openapi": raw_obs.get("openapi"),
        "mixed_content": raw_obs.get("mixed_content"),
        "surface": raw_obs.get("surface"),
        "security": raw_obs.get("security"),
    }

    return {"version": raw_obs.get("version"), "generated_at": raw_obs.get("generated_at"), "engine": raw_obs.get("engine"), "target": raw_obs.get("target"), "observations": observations_raw, "derived": derived, "risks": risks, "tech": tech}


def build_active_set(scan_doc: Dict[str, Any]) -> Dict[str, Any]:
    features: List[str] = []
    evidence: Dict[str, Any] = {}
    facts: List[Dict[str, Any]] = []

    def add_feature(feature: str, ev: Any):
        if feature not in evidence:
            features.append(feature)
            evidence[feature] = ev

    def add_fact(subject: str, predicate: str, obj: Any, confidence: str, ev_refs: List[str], meta: Optional[Dict[str, Any]] = None):
        f = {"subject": subject, "predicate": predicate, "object": obj, "confidence": confidence, "evidence_refs": ev_refs}
        if meta:
            f["meta"] = meta
        facts.append(f)

    tgt = scan_doc.get("target") or {}
    host = tgt.get("host")
    if host:
        add_feature(f"target.host={host}", {"src": "target.host"})
        add_fact("target", "host", host, "high", ["target.host"])

    der = scan_doc.get("derived") or {}
    dtr = der.get("transport") or {}
    posture = dtr.get("https_posture")
    if posture:
        add_feature(f"transport.https_posture={posture}", {"src": "derived.transport.https_posture"})
        add_fact("transport", "https_posture", posture, "high", ["derived.transport.https_posture"])
    if dtr.get("final_scheme"):
        add_feature(f"transport.final_scheme={str(dtr.get('final_scheme')).lower()}", {"src": "derived.transport.final_scheme"})
    if dtr.get("redirects") is not None:
        add_feature(f"transport.redirects={dtr.get('redirects')}", {"src": "derived.transport.redirects"})
    if dtr.get("redirect_kind"):
        add_feature(f"transport.redirect_kind={dtr.get('redirect_kind')}", {"src": "derived.transport.redirect_kind"})
        add_fact("transport", "redirect_kind", dtr.get("redirect_kind"), "medium", ["derived.transport.redirect_kind"])

    hsts = (dtr.get("hsts") or {})
    if hsts.get("present"):
        add_feature("security.hsts=true", {"src": "derived.transport.hsts.present"})
        add_fact("security", "hsts_present", True, "high", ["derived.transport.hsts.present"])
        if hsts.get("preload"):
            add_feature("security.hsts.preload=true", {"src": "derived.transport.hsts.preload"})
            add_fact("security", "hsts_preload", True, "high", ["derived.transport.hsts.preload"])
        if hsts.get("include_subdomains"):
            add_feature("security.hsts.include_subdomains=true", {"src": "derived.transport.hsts.include_subdomains"})

    obs = scan_doc.get("observations") or {}
    http = obs.get("http") or {}
    if http.get("ok"):
        last = (http.get("chain") or [{}])[-1]
        status = last.get("status")
        if status is not None:
            add_feature(f"http.status={status}", {"src": "observations.http.chain[-1].status"})
            add_fact("http", "status", status, "high", ["observations.http.chain[-1].status"])
        headers = last.get("headers") or {}
        ctype = _get_header_ci(headers, "content-type")
        if ctype:
            add_feature(f"http.content_type={str(ctype).split(';')[0].strip().lower()}", {"src": "observations.http.chain[-1].headers.content-type"})
        srv = _get_header_ci(headers, "server")
        if srv:
            add_feature("http.server.present=true", {"src": "observations.http.chain[-1].headers.server"})

        if http.get("tls_verify") is not None:
            add_feature(f"http.tls_verify={bool(http.get('tls_verify'))}".lower(), {"src": "observations.http.tls_verify"})
            add_fact("http", "tls_verify", bool(http.get("tls_verify")), "high", ["observations.http.tls_verify"])

    tls = obs.get("tls") or {}
    if tls.get("present"):
        add_feature(f"tls.present={bool(tls.get('present'))}".lower(), {"src": "observations.tls.present"})
        if tls.get("ok"):
            tv = tls.get("tls_version")
            if tv:
                add_feature(f"tls.version={str(tv).lower()}", {"src": "observations.tls.tls_version"})
                add_fact("tls", "version", str(tv), "high", ["observations.tls.tls_version"])
            cipher = (tls.get("cipher") or {}).get("name")
            if cipher:
                add_feature(f"tls.cipher={str(cipher).lower()}", {"src": "observations.tls.cipher.name"})
            add_feature(f"tls.verify_effective={bool(tls.get('verify_effective'))}".lower(), {"src": "observations.tls.verify_effective"})
            add_fact("tls", "verify_effective", bool(tls.get("verify_effective")), "high", ["observations.tls.verify_effective"])
            if "peer_cert_available" in tls:
                add_feature(f"tls.peer_cert_available={bool(tls.get('peer_cert_available'))}".lower(), {"src": "observations.tls.peer_cert_available"})
            if "peer_cert_der_len" in tls:
                add_feature(f"tls.peer_cert_der_len>0={bool((tls.get('peer_cert_der_len') or 0) > 0)}".lower(), {"src": "observations.tls.peer_cert_der_len"})
                if tls.get("peer_cert_sha256"):
                    add_fact("tls", "peer_cert_sha256", tls.get("peer_cert_sha256"), "high", ["observations.tls.peer_cert_sha256"])

    dns = obs.get("dns") or {}
    if dns.get("ok"):
        a_list = dns.get("a") or []
        aaaa_list = dns.get("aaaa") or []
        mx_list = dns.get("mx") or []
        txt_list = dns.get("txt") or []

        add_feature(f"dns.a.count={len(a_list)}", {"src": "observations.dns.a"})
        add_feature(f"dns.aaaa.count={len(aaaa_list)}", {"src": "observations.dns.aaaa"})
        add_feature(f"dns.mx.count={len(mx_list)}", {"src": "observations.dns.mx"})
        add_feature("dns.txt.present=true" if txt_list else "dns.txt.present=false", {"src": "observations.dns.txt"})

        if a_list:
            add_fact("dns", "a_records", a_list[:50], "high", ["observations.dns.a"])
        if aaaa_list:
            add_fact("dns", "aaaa_records", aaaa_list[:50], "high", ["observations.dns.aaaa"])
        if mx_list:
            add_fact("dns", "mx_records", mx_list[:50], "high", ["observations.dns.mx"])
        if txt_list:
            add_fact("dns", "txt_records_sample", txt_list[:20], "medium", ["observations.dns.txt"])

    wk = obs.get("oidc_probe") or {}
    if wk.get("ok"):
        add_feature("auth.framework=oidc", {"src": "observations.oidc_probe.status", "url": wk.get("url")})
        add_fact("auth", "framework", "oidc", "medium", ["observations.oidc_probe.url"])

    dst = der.get("stack") or {}
    edge = (dst.get("edge") or {}).get("provider")
    if edge:
        add_feature(f"edge.provider={str(edge).lower()}", {"src": "derived.stack.edge.provider"})
        add_fact("stack", "edge_provider", edge, "high", ["derived.stack.edge.provider"])

    legacy = (dst.get("legacy_html") or {})
    if legacy.get("present"):
        add_feature("frontend.legacy_signals=true", {"src": "derived.stack.legacy_html.present"})
        add_fact("frontend", "legacy_signals", True, legacy.get("confidence", "low"), ["derived.stack.legacy_html.signals"])

    for t in (scan_doc.get("tech") or [])[:12]:
        nm = t.get("name")
        if nm:
            add_feature(f"tech={nm}", {"src": "tech", "category": t.get("category"), "confidence": t.get("confidence")})

    return {"version": "v2", "generated_at": utc_now_iso(), "features": features, "evidence": evidence, "facts": facts}


def _fmt_ok(v: bool) -> str:
    return f"{C_GRN}OK{RESET}" if v else f"{C_RED}FAIL{RESET}"


def _extract_cert_cn(cert_subject: Any) -> Optional[str]:
    try:
        for rdn in cert_subject or []:
            for k, v in rdn:
                if str(k).lower() == "commonname":
                    return str(v)
    except Exception:
        return None
    return None


def _sev_color(sev: str) -> str:
    s = (sev or "").lower()
    if s in ("critical", "high"):
        return C_RED
    if s == "medium":
        return C_YEL
    if s == "low":
        return C_CYA
    return C_DIM


def _count_by_sev(items: List[Dict[str, Any]]) -> Dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for it in items or []:
        s = (it.get("severity") or "info").lower()
        if s not in out:
            s = "info"
        out[s] += 1
    return out


def print_scan_summary(scan_doc: Dict[str, Any], active_set: Dict[str, Any]) -> None:
    tgt = scan_doc.get("target") or {}
    der = scan_doc.get("derived") or {}
    dtr = der.get("transport") or {}
    obs = scan_doc.get("observations") or {}

    title = f"{tgt.get('normalized')}"
    in_s = dtr.get("input_scheme")
    out_s = dtr.get("final_scheme")

    print("\n" + "─" * 84)
    print(f"{C_BOLD}[+] SUMMARY{RESET}  {C_DIM}{title}{RESET}")
    print(f"{C_DIM}    input_scheme={in_s}  final_scheme={out_s}  redirects={dtr.get('redirects')}  posture={dtr.get('https_posture')}{RESET}")
    print("─" * 84)

    dns = (obs.get("dns") or {})
    print(f"[DNS] {_fmt_ok(bool(dns.get('ok')))}")
    if dns.get("ok"):
        a = dns.get("a") or []
        aaaa = dns.get("aaaa") or []
        if a:
            print(f"  • A:    {', '.join(a[:6])}" + (" ..." if len(a) > 6 else ""))
        if aaaa:
            print(f"  • AAAA: {', '.join(aaaa[:6])}" + (" ..." if len(aaaa) > 6 else ""))
        cname = dns.get("cname") or []
        if cname:
            print(f"  • CNAME: {', '.join(cname[:4])}" + (" ..." if len(cname) > 4 else ""))
        mx = dns.get("mx") or []
        if mx:
            ex = [m.get("exchange") for m in mx if isinstance(m, dict) and m.get("exchange")]
            if ex:
                print(f"  • MX:   {', '.join(ex[:4])}" + (" ..." if len(ex) > 4 else ""))

    print(f"[TRANSPORT] kind={dtr.get('redirect_kind')}  final={dtr.get('final_url')}")
    hsts = dtr.get("hsts") or {}
    if hsts.get("present"):
        extra = []
        if hsts.get("include_subdomains"):
            extra.append("includeSubDomains")
        if hsts.get("preload"):
            extra.append("preload")
        print(f"  • HSTS: present  max-age={hsts.get('max_age')}" + (f"  [{', '.join(extra)}]" if extra else ""))

    tls = (obs.get("tls") or {})
    if tls.get("present"):
        ok_tls = bool(tls.get("ok"))
        ve = tls.get("verify_effective")
        print(f"[TLS] {_fmt_ok(ok_tls)}  verify_effective={ve}")
        if ok_tls:
            tv = tls.get("tls_version")
            cipher = (tls.get("cipher") or {}).get("name")
            cert = tls.get("cert") or {}
            cn = _extract_cert_cn((cert or {}).get("subject")) if cert else None
            if tv:
                print(f"  • version: {tv}")
            if cipher:
                print(f"  • cipher:  {cipher}")
            if cn:
                print(f"  • cert CN: {cn}")
            if "peer_cert_available" in tls:
                print(f"  • peer_cert_available: {tls.get('peer_cert_available')}")
            if "peer_cert_der_len" in tls:
                print(f"  • peer_cert_der_len: {tls.get('peer_cert_der_len')}")
        else:
            if tls.get("error"):
                print(f"  • error: {tls.get('error')}")
        if tls.get("fallback_used"):
            print(f"  • {C_YEL}fallback{RESET}: verify disabled due to cert error")
    else:
        print("[TLS] skipped (final not https)")

    http = (obs.get("http") or {})
    print(f"[HTTP] {_fmt_ok(bool(http.get('ok')))}  tls_verify={http.get('tls_verify')}")
    if http.get("ok"):
        print(f"  • status:    {http.get('final_status')}")
        print(f"  • final_url: {http.get('final_url')}")
        print(f"  • redirects: {http.get('redirects')}  total_ms: {http.get('timing_total_ms')}")
        chain = http.get("chain") or []
        if chain:
            last = chain[-1]
            headers = last.get("headers") or {}
            server = _get_header_ci(headers, "server")
            ctype = _get_header_ci(headers, "content-type")
            acao = _get_header_ci(headers, "access-control-allow-origin")
            if server:
                print(f"  • server:    {server}")
            if ctype:
                print(f"  • type:      {ctype}")
            if acao:
                print(f"  • ACAO:      {acao}")
    else:
        if http.get("error"):
            print(f"  • error: {http.get('error')}")

    http_head = obs.get("http_head") or {}
    if http_head.get("ok"):
        print(f"[HEAD] {_fmt_ok(True)}  tls_verify={http_head.get('tls_verify')}  status={http_head.get('final_status')}")

    mp = obs.get("method_probes") or {}
    if mp.get("items"):
        items = mp["items"][:4]
        s = "  • " + " | ".join([f"{it.get('method')}={it.get('status')}" for it in items])
        print("[METHODS]")
        print(s)

    cp = obs.get("cors_probe") or {}
    if cp:
        print(f"[CORS] acao={cp.get('acao')}  acac={cp.get('acac')}  risk={cp.get('risk')}")

    oidc = obs.get("oidc_probe") or {}
    print(f"[OIDC] {_fmt_ok(bool(oidc.get('ok')))}")
    if oidc.get("ok"):
        print(f"  • status: {oidc.get('status')}")
        print(f"  • url:    {oidc.get('final_url') or oidc.get('url')}")
    else:
        if oidc.get("error"):
            print(f"  • note: {oidc.get('error')}")

    risks = scan_doc.get("risks") or []
    if risks:
        by = _count_by_sev(risks)
        print(f"[RISKS] total={len(risks)}  (high+={by['critical']+by['high']}, medium={by['medium']}, low={by['low']}, info={by['info']})")
        for r in risks[:8]:
            sev = (r.get("severity") or "info").lower()
            print(f"  • {_sev_color(sev)}[{sev}]{RESET} {r.get('id')}: {r.get('title')}")
        if len(risks) > 8:
            print("  • ...")

    sec = obs.get("security") or {}
    findings = sec.get("findings") or []
    if findings:
        by2 = _count_by_sev(findings)
        print(f"[SECURITY] findings={len(findings)}  (high+={by2['critical']+by2['high']}, medium={by2['medium']}, low={by2['low']}, info={by2['info']})")
        sev_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        findings_sorted = sorted(findings, key=lambda x: sev_rank.get((x.get("severity") or "info").lower(), 1), reverse=True)
        for f in findings_sorted[:8]:
            sev = (f.get("severity") or "info").lower()
            print(f"  • {_sev_color(sev)}({sev}){RESET} {f.get('id')}: {f.get('title')}")
        if len(findings_sorted) > 8:
            print("  • ...")
    elif sec.get("error"):
        print(f"[SECURITY] skipped: {sec.get('error')}")

    tech = scan_doc.get("tech") or []
    print(f"[TECH] detected={len(tech)}")
    for t in tech[:12]:
        print(f"  • {t.get('name')}  {C_DIM}[{t.get('category')}] ({t.get('confidence')}){RESET}")
    if len(tech) > 12:
        print("  • ...")

    feats = active_set.get("features") or []
    facts = active_set.get("facts") or []
    print(f"[ACTIVE_SET] features={len(feats)}  facts={len(facts)}")
    for f in feats[:12]:
        print(f"  • {f}")
    if len(feats) > 12:
        print("  • ...")

    print("─" * 84 + "\n")


def _bar(i: int, n: int) -> str:
    width = 24
    filled = int((i / n) * width) if n else width
    return "[" + "#" * filled + "." * (width - filled) + f"] {i}/{n}"


def run_scan_cmd(cmd: str, timeout_s: float = 10.0, max_redirects: int = 8) -> Dict[str, Any]:
    parsed, insecure_flag = parse_scan_command(cmd)
    input_url = normalize_target(parsed)

    in_u = urlparse(input_url)
    host = in_u.hostname or ""
    port = in_u.port or (443 if in_u.scheme == "https" else 80)

    verify_requested = not insecure_flag

    raw_obs: Dict[str, Any] = {
        "version": "v1.8.0",
        "generated_at": utc_now_iso(),
        "engine": {"name": "spektron", "module": "scan", "version": "v1.8.0"},
        "run": {"timeout_s": timeout_s, "max_redirects": max_redirects, "sample_bytes": 4096, "user_agent": USER_AGENT},
        "target": {"input": cmd, "parsed_target": parsed, "normalized": input_url, "scheme": in_u.scheme, "host": host, "port": port},
        "transport": None,
        "dns": None,
        "tls": {"present": False},
        "http_input_snapshot": None,
        "http": None,
        "http_head": None,
        "tls_fallback": {"attempted": False, "used_insecure": False, "reason": None},
        "method_probes": None,
        "cors_probe": None,
        "oidc_probe": None,
        "exposure_files": None,
        "openapi": None,
        "mixed_content": None,
        "surface": None,
        "security": None,
        "tech": [],
    }

    steps = ["DNS", "HTTP_INPUT_SNAPSHOT", "HTTP_MAIN", "HTTP_HEAD", "TRANSPORT", "TLS", "METHODS", "CORS", "OIDC", "FILES", "OPENAPI", "MIXED", "SURFACE", "SECURITY", "TECH"]
    total = len(steps)
    done = 0

    print(f"\n[+] TARGET: {input_url}  | verify_requested={verify_requested}")
    print("[+] SCANNING...\n")

    done += 1
    print("[+] SCANNING... (DNS)")
    sys.stdout.write(_bar(done, total) + "  resolving A/AAAA (+extras)...\n")
    raw_obs["dns"] = resolve_dns_bundle(host) if host else {"ok": False, "error": "no_host", "a": [], "aaaa": [], "cname": [], "mx": [], "txt": []}

    done += 1
    print("[+] SCANNING... (HTTP_INPUT_SNAPSHOT)")
    sys.stdout.write(_bar(done, total) + "  input snapshot (no redirects)...\n")
    raw_obs["http_input_snapshot"] = http_probe(input_url, timeout_s=timeout_s, user_agent=USER_AGENT, max_redirects=0, tls_verify=verify_requested, sample_bytes=0, follow_redirects=False, method="GET")

    raw_obs["http_downgrade_snapshot"] = None
    try:
        if input_url.lower().startswith("https://"):
            from urllib.parse import urlsplit, urlunsplit
            parts = urlsplit(input_url)
            http_url = urlunsplit(("http", parts.netloc.split("@")[-1], parts.path or "/", parts.query, parts.fragment))
            raw_obs["http_downgrade_snapshot"] = http_probe(
                http_url,
                timeout_s=timeout_s,
                user_agent=USER_AGENT,
                max_redirects=0,
                tls_verify=True,
                sample_bytes=0,
                follow_redirects=False,
                method="GET",
            )
    except Exception as _e:
        raw_obs["http_downgrade_snapshot"] = {"ok": False, "error": f"http_downgrade_probe_failed:{type(_e).__name__}"}

    done += 1
    print("[+] SCANNING... (HTTP_MAIN)")
    sys.stdout.write(_bar(done, total) + "  http fetch (follow redirects)...\n")
    http_main = http_probe(input_url, timeout_s=timeout_s, user_agent=USER_AGENT, max_redirects=max_redirects, tls_verify=verify_requested, sample_bytes=4096, follow_redirects=True, method="GET")

    if (not insecure_flag) and (not http_main.get("ok")) and _is_cert_verify_error(str(http_main.get("error", ""))):
        raw_obs["tls_fallback"]["attempted"] = True
        raw_obs["tls_fallback"]["used_insecure"] = True
        raw_obs["tls_fallback"]["reason"] = "CERTIFICATE_VERIFY_FAILED"
        http_main = http_probe(input_url, timeout_s=timeout_s, user_agent=USER_AGENT, max_redirects=max_redirects, tls_verify=False, sample_bytes=4096, follow_redirects=True, method="GET")

    raw_obs["http"] = http_main

    done += 1
    print("[+] SCANNING... (HTTP_HEAD)")
    sys.stdout.write(_bar(done, total) + "  http HEAD (follow redirects)...\n")
    tls_for_head = verify_requested
    if http_main.get("tls_verify") is not None:
        tls_for_head = bool(http_main.get("tls_verify"))
    http_head = http_probe(input_url, timeout_s=timeout_s, user_agent=USER_AGENT, max_redirects=max_redirects, tls_verify=tls_for_head, sample_bytes=0, follow_redirects=True, method="HEAD")
    raw_obs["http_head"] = http_head

    done += 1
    print("[+] SCANNING... (TRANSPORT)")
    sys.stdout.write(_bar(done, total) + "  mapping input->final...\n")
    raw_obs["transport"] = transport_from_http(raw_obs["http"] or {}, input_url=input_url)

    final_url = (raw_obs["transport"] or {}).get("final_url") or input_url
    final_scheme = (raw_obs["transport"] or {}).get("final_scheme") or in_u.scheme
    final_u = urlparse(final_url)

    done += 1
    print("[+] SCANNING... (TLS)")
    sys.stdout.write(_bar(done, total) + "  tls handshake (final if https)...\n")
    if final_scheme == "https":
        raw_obs["tls"]["present"] = True
        verify_effective = verify_requested
        if raw_obs["tls_fallback"]["used_insecure"]:
            verify_effective = False
        if insecure_flag:
            verify_effective = False

        tls1 = tls_probe(final_u.hostname or host, final_u.port or 443, timeout_s=timeout_s, verify=verify_effective)
        raw_obs["tls"].update(
            {
                "ok": bool(tls1.get("ok")),
                "verify": bool(verify_effective),
                "tls_version": tls1.get("tls_version"),
                "cipher": tls1.get("cipher"),
                "cert": tls1.get("cert"),
                "peer_cert_available": tls1.get("peer_cert_available"),
                "peer_cert_der_len": tls1.get("peer_cert_der_len"),
                "peer_cert_sha256": tls1.get("peer_cert_sha256"),
                "verify_requested": bool(verify_requested),
                "verify_effective": bool(verify_effective),
                "fallback_used": bool(raw_obs["tls_fallback"]["used_insecure"] or insecure_flag),
            }
        )
        if not tls1.get("ok"):
            raw_obs["tls"]["error"] = tls1.get("error")
    else:
        raw_obs["tls"] = {"present": False}

    effective_verify_for_https = bool(raw_obs["tls"].get("verify_effective", verify_requested))

    done += 1
    print("[+] SCANNING... (METHODS)")
    sys.stdout.write(_bar(done, total) + "  OPTIONS/TRACE...\n")
    raw_obs["method_probes"] = method_probes(final_url, timeout_s=timeout_s, user_agent=USER_AGENT, tls_verify=effective_verify_for_https)

    done += 1
    print("[+] SCANNING... (CORS)")
    sys.stdout.write(_bar(done, total) + "  origin probe...\n")
    raw_obs["cors_probe"] = cors_probe(final_url, timeout_s=timeout_s, user_agent=USER_AGENT, tls_verify=effective_verify_for_https)

    done += 1
    print("[+] SCANNING... (OIDC)")
    sys.stdout.write(_bar(done, total) + "  .well-known/openid-configuration...\n")
    raw_obs["oidc_probe"] = oidc_well_known_probe(final_url, timeout_s=timeout_s, user_agent=USER_AGENT, tls_verify=effective_verify_for_https)

    done += 1
    print("[+] SCANNING... (FILES)")
    sys.stdout.write(_bar(done, total) + "  robots/security/humans/sitemap/ads...\n")

    done += 1
    print("[+] SCANNING... (OPENAPI)")
    sys.stdout.write(_bar(done, total) + "  common OpenAPI/Swagger paths...\n")

    tls_verify_effective = bool(raw_obs["tls"].get("verify_effective", verify_requested))
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {
            ex.submit(fetch_common_files, final_url, timeout_s, USER_AGENT, tls_verify_effective): "exposure_files",
            ex.submit(fetch_openapi_common, final_url, timeout_s, USER_AGENT, tls_verify_effective): "openapi",
        }
        for fut in as_completed(futs):
            key = futs[fut]
            try:
                raw_obs[key] = fut.result()
            except Exception as e:
                raw_obs[key] = {"ok": False, "error": str(e), "tls_verify": tls_verify_effective}

    done += 1
    print("[+] SCANNING... (MIXED)")
    sys.stdout.write(_bar(done, total) + "  mixed content heuristic...\n")
    body = (raw_obs.get("http") or {}).get("body_sample") or ""
    raw_obs["mixed_content"] = detect_mixed_content(final_scheme=str(final_scheme), body_html=body)

    done += 1
    print("[+] SCANNING... (SURFACE)")
    sys.stdout.write(_bar(done, total) + "  surface hints...\n")
    raw_obs["surface"] = surface_hints(final_url, body)

    done += 1
    print("[+] SCANNING... (SECURITY)")
    sys.stdout.write(_bar(done, total) + "  headers + cookies + ratelimit...\n")
    raw_obs["security"] = security_audit(raw_obs.get("http") or {}, final_scheme=str(final_scheme))

    if raw_obs.get("tls", {}).get("present") and raw_obs.get("tls", {}).get("verify_effective") is False:
        (raw_obs.get("security", {}).get("findings", [])).append(
            {
                "id": "TLS_VERIFY_DISABLED",
                "severity": "medium",
                "title": "TLS verify desabilitado (effective=false)",
                "detail": "O scan coletou evidências com verify_effective=false (fallback ou flag insegura).",
                "evidence": {"final_scheme": final_scheme, "fallback": raw_obs.get("tls_fallback"), "http_tls_verify": (raw_obs.get("http") or {}).get("tls_verify")},
            }
        )

    done += 1
    print("[+] SCANNING... (TECH)")
    sys.stdout.write(_bar(done, total) + "  fingerprinting...\n")
    raw_obs["tech"] = tech_fingerprint(raw_obs)

    print("\n[+] DONE")

    scan_doc = finalize_scan_document(raw_obs)
    active_set = build_active_set(scan_doc)

    out: Dict[str, Any] = {"observations": scan_doc, "active_set": active_set}

    if WRITE_OUTPUTS:
        slug = safe_slug(host or in_u.netloc or "target")
        ts = _now_local_stamp()
        out_dir = ROOT / "output" / "scans" / f"{slug}_{ts}"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "scan_observations.v1.json").write_text(json_dump(scan_doc) + "\n", encoding="utf-8")
        (out_dir / "active_set.v1.json").write_text(json_dump(active_set) + "\n", encoding="utf-8")
        out["saved_to"] = str(out_dir)

    return out


def main():
    print_banner()
    print("[+] LOADING...")
    time.sleep(0.2)
    print("[+] READY! Type: scan https://target.com  | scan -k https://target.com  | exit\n")

    while True:
        try:
            cmd = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[+] SEE YOU SOON!")
            break

        if not cmd:
            continue
        if cmd.lower() in ("exit", "quit", "q"):
            print("[+] SEE YOU SOON!")
            break

        try:
            result = run_scan_cmd(cmd, timeout_s=10.0, max_redirects=8)
            # FIX: always call with (scan_doc, active_set)
            print_scan_summary(result["observations"], result["active_set"])
            if "saved_to" in result:
                print(f"{C_DIM}[+] saved_to:{RESET} {result['saved_to']}\n")
        except Exception as e:
            print(f"[!] error: {e}\n")


if __name__ == "__main__":
    main()
