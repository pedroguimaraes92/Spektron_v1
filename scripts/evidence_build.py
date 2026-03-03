from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

JSON = Dict[str, Any]

ROOT = Path(__file__).resolve().parents[1]
OUT_EVIDENCE_DIR = ROOT / "output" / "evidence"

CORE_DIR = ROOT / "CORE"
CORE_TYPES_PATH = CORE_DIR / "core_types.v1.json"
EVIDENCE_TYPES_PATH = CORE_DIR / "evidence_types.v1.json"



def _now_utc_iso_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_json(path: Path) -> JSON:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _is_dir(p: Path) -> bool:
    try:
        return p.exists() and p.is_dir()
    except Exception:
        return False


def _is_file(p: Path) -> bool:
    try:
        return p.exists() and p.is_file()
    except Exception:
        return False


def _scan_id_from_filename(p: Path) -> str:
    """
    scan_id derivado do nome do arquivo scan_*.json (sem heurística frágil).
    Ex: scan_petstore.swagger.io_20260225T201210Z.json -> petstore.swagger.io_20260225T201210Z
    """
    name = p.name
    if name.lower().startswith("scan_"):
        name = name[5:]
    if name.lower().endswith(".json"):
        name = name[:-5]
    return name



def _canonicalize(obj: Any, *, key_hint: Optional[str] = None) -> Any:
    """
    Canonicalização estável para hashing determinístico:
      - dict: ordena chaves
      - list: se for lista de primitivos, ordena
      - strings: strip; alguns campos vão para lower()
    """
    if obj is None:
        return None

    if isinstance(obj, bool):
        return bool(obj)
    if isinstance(obj, int):
        return int(obj)
    if isinstance(obj, float):
        return float(obj)

    if isinstance(obj, str):
        v = obj.strip()
        if key_hint in ("name", "proto", "provider", "confidence"):
            v = v.lower()
        return v

    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k in sorted(obj.keys(), key=lambda x: str(x)):
            out[str(k)] = _canonicalize(obj[k], key_hint=str(k))
        return out

    if isinstance(obj, list):
        if all(isinstance(x, (str, int, float, bool)) or x is None for x in obj):
            normed = [_canonicalize(x) for x in obj]
            try:
                return sorted(normed, key=lambda x: str(x))
            except Exception:
                return normed
        return [_canonicalize(x) for x in obj]

    return str(obj).strip()


def _stable_id(target_normalized: str, ev_type: str, value: JSON) -> str:
    payload = {
        "target": _canonicalize(target_normalized),
        "type": _canonicalize(ev_type),
        "value": _canonicalize(value),
    }
    s = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    h = hashlib.sha256(s.encode("utf-8")).hexdigest()
    return f"ev_{h[:24]}"


def _load_contracts() -> Tuple[JSON, JSON, Dict[str, JSON], Dict[str, str]]:
    core = _read_json(CORE_TYPES_PATH)
    ev = _read_json(EVIDENCE_TYPES_PATH)

    ev_schemas: Dict[str, JSON] = {}
    for item in (ev.get("evidence_types") or []):
        if isinstance(item, dict) and isinstance(item.get("type"), str):
            ev_schemas[item["type"]] = item.get("value_schema") or {}

    default_strength = ev.get("default_strength") or {}
    if not isinstance(default_strength, dict):
        default_strength = {}

    return core, ev, ev_schemas, {k: str(v) for k, v in default_strength.items()}


def _strength_for(ev_type: str, default_strength: Dict[str, str]) -> str:
    s = (default_strength.get(ev_type) or "").strip().lower()
    if s in ("weak", "moderate", "strong"):
        return s
    return "moderate"



SEC_HEADERS_BASE = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def _headers_from_scan(scan: JSON) -> JSON:
    obs = scan.get("observations") or {}
    http = (obs.get("http") or {})

    chain = http.get("chain") or []
    if isinstance(chain, list) and chain:
        last = chain[-1] if isinstance(chain[-1], dict) else {}
        hdrs = last.get("headers") or {}
        if isinstance(hdrs, dict):
            return hdrs

    head = (http.get("head") or {})
    hdrs2 = head.get("headers") or {}
    if isinstance(hdrs2, dict):
        return hdrs2

    return {}


def _lower_headers(headers: JSON) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        if k is None:
            continue
        ks = str(k).strip().lower()
        if not ks:
            continue
        out[ks] = str(v) if v is not None else ""
    return out


def _parse_set_cookie_header(raw: str) -> List[str]:
    """
    Separa múltiplos Set-Cookie possivelmente concatenados por vírgula.
    Evita quebrar a vírgula do Expires.
    """
    s = raw or ""
    if not s.strip():
        return []

    parts: List[str] = []
    buf: List[str] = []
    i = 0
    n = len(s)

    while i < n:
        ch = s[i]
        if ch == ",":
            j = i + 1
            while j < n and s[j] == " ":
                j += 1

            k = j
            eq_pos = -1
            semi_pos = -1
            while k < n:
                if s[k] == "=" and eq_pos == -1:
                    eq_pos = k
                if s[k] == ";":
                    semi_pos = k
                    break
                if s[k] == ",":
                    break
                k += 1

            if eq_pos != -1 and (semi_pos == -1 or eq_pos < semi_pos):
                parts.append("".join(buf).strip())
                buf = []
                i += 1
                continue

        buf.append(ch)
        i += 1

    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)

    return [p for p in parts if p]


def _parse_cookie(cookie_str: str) -> Optional[JSON]:
    """
    Retorna:
      {name, secure, httponly, samesite}
    """
    if not cookie_str:
        return None
    segs = [x.strip() for x in cookie_str.split(";") if x.strip()]
    if not segs:
        return None
    if "=" not in segs[0]:
        return None

    name = segs[0].split("=", 1)[0].strip()
    if not name:
        return None

    flags = {s.lower(): s for s in segs[1:]}
    secure = True if "secure" in flags else None
    httponly = True if "httponly" in flags else None

    samesite_val = None
    for seg in segs[1:]:
        if "=" in seg:
            k, v = seg.split("=", 1)
            if k.strip().lower() == "samesite":
                v2 = v.strip()
                if v2:
                    samesite_val = v2
                break

    return {"name": name, "secure": secure, "httponly": httponly, "samesite": samesite_val}


def _days_until_not_after(not_after: Optional[str]) -> Optional[int]:
    if not not_after:
        return None
    fmts = ["%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"]
    for fmt in fmts:
        try:
            dt = datetime.strptime(not_after, fmt).replace(tzinfo=timezone.utc)
            delta = dt - datetime.now(timezone.utc)
            return int(delta.total_seconds() // 86400)
        except Exception:
            continue
    return None


def _is_self_signed(cert: Any) -> Optional[bool]:
    if not isinstance(cert, dict):
        return None
    subj = cert.get("subject")
    iss = cert.get("issuer")
    if subj is None or iss is None:
        return None
    try:
        return json.dumps(subj, sort_keys=True) == json.dumps(iss, sort_keys=True)
    except Exception:
        return None



def _mk_evidence(
    *,
    target_normalized: str,
    scan_id: str,
    scan_file: str,
    ts: str,
    ev_type: str,
    value: JSON,
    strength: str,
    probe: str,
) -> JSON:
    eid = _stable_id(target_normalized, ev_type, value)
    return {
        "id": eid,
        "type": ev_type,
        "value": value,
        "source": {
            "kind": "scan",
            "scan_id": scan_id,
            "scan_file": scan_file,
            "probe": probe,
        },
        "strength": strength,
        "timestamp": ts,
        "privacy_class": "public",
        "tags": [],
    }


def build_evidences_for_scan(scan: JSON, scan_path: Path, default_strength: Dict[str, str]) -> List[JSON]:
    target = scan.get("target") or {}
    target_norm = str(target.get("normalized") or "").strip()
    host = str(target.get("host") or "").strip()
    scheme = str(target.get("scheme") or "").strip().lower()
    port = target.get("port")

    obs = scan.get("observations") or {}
    ts = str(scan.get("generated_at") or _now_utc_iso_z())

    scan_id = _scan_id_from_filename(scan_path)
    scan_file = scan_path.name

    evidences: List[JSON] = []

    if isinstance(port, int) and port > 0:
        service_hint = None
        if scheme == "https":
            service_hint = "https"
        elif scheme == "http":
            service_hint = "http"
        evidences.append(
            _mk_evidence(
                target_normalized=target_norm,
                scan_id=scan_id,
                scan_file=scan_file,
                ts=ts,
                ev_type="net.port.open",
                value={"port": int(port), "proto": "tcp", "service_hint": service_hint},
                strength=_strength_for("net.port.open", default_strength),
                probe="target",
            )
        )

    http_obs = (obs.get("http") or {})
    final_url = str(http_obs.get("final_url") or target_norm).strip()
    final_status = http_obs.get("final_status")

    if scheme == "http" and target_norm:
        redirect_to = None
        tr = (obs.get("transport") or {})
        rc = tr.get("redirect_chain") or []
        if isinstance(rc, list) and len(rc) >= 2:
            redirect_to = str(rc[-1])
        elif isinstance(http_obs.get("redirects"), int) and http_obs.get("redirects") > 0:
            redirect_to = final_url
        evidences.append(
            _mk_evidence(
                target_normalized=target_norm,
                scan_id=scan_id,
                scan_file=scan_file,
                ts=ts,
                ev_type="net.service.http",
                value={
                    "url": target_norm,
                    "status": int(final_status) if isinstance(final_status, int) else None,
                    "redirect_to": redirect_to,
                },
                strength=_strength_for("net.service.http", default_strength),
                probe="http",
            )
        )

    if scheme == "https" and target_norm:
        evidences.append(
            _mk_evidence(
                target_normalized=target_norm,
                scan_id=scan_id,
                scan_file=scan_file,
                ts=ts,
                ev_type="net.service.https",
                value={"url": target_norm, "status": int(final_status) if isinstance(final_status, int) else None},
                strength=_strength_for("net.service.https", default_strength),
                probe="http",
            )
        )

    dns_obs = (obs.get("dns") or {})
    if host:
        for ip in (dns_obs.get("a") or []):
            if isinstance(ip, str) and ip.strip():
                evidences.append(
                    _mk_evidence(
                        target_normalized=target_norm,
                        scan_id=scan_id,
                        scan_file=scan_file,
                        ts=ts,
                        ev_type="dns.record.a",
                        value={"host": host, "ip": ip.strip()},
                        strength=_strength_for("dns.record.a", default_strength),
                        probe="dns",
                    )
                )

        for ip in (dns_obs.get("aaaa") or []):
            if isinstance(ip, str) and ip.strip():
                evidences.append(
                    _mk_evidence(
                        target_normalized=target_norm,
                        scan_id=scan_id,
                        scan_file=scan_file,
                        ts=ts,
                        ev_type="dns.record.aaaa",
                        value={"host": host, "ip": ip.strip()},
                        strength=_strength_for("dns.record.aaaa", default_strength),
                        probe="dns",
                    )
                )

        for cn in (dns_obs.get("cname") or []):
            if isinstance(cn, str) and cn.strip():
                evidences.append(
                    _mk_evidence(
                        target_normalized=target_norm,
                        scan_id=scan_id,
                        scan_file=scan_file,
                        ts=ts,
                        ev_type="dns.record.cname",
                        value={"host": host, "cname": cn.strip()},
                        strength=_strength_for("dns.record.cname", default_strength),
                        probe="dns",
                    )
                )

        for txt in (dns_obs.get("txt") or []):
            if isinstance(txt, str) and txt.strip():
                evidences.append(
                    _mk_evidence(
                        target_normalized=target_norm,
                        scan_id=scan_id,
                        scan_file=scan_file,
                        ts=ts,
                        ev_type="dns.record.txt",
                        value={"host": host, "txt": txt.strip()},
                        strength=_strength_for("dns.record.txt", default_strength),
                        probe="dns",
                    )
                )

    tls_obs = (obs.get("tls") or {})
    tls_present = bool(tls_obs.get("present")) if isinstance(tls_obs, dict) else False
    if tls_present:
        evidences.append(
            _mk_evidence(
                target_normalized=target_norm,
                scan_id=scan_id,
                scan_file=scan_file,
                ts=ts,
                ev_type="tls.present",
                value={"present": True},
                strength=_strength_for("tls.present", default_strength),
                probe="tls",
            )
        )

        v = None
        if isinstance(tls_obs.get("tls_version"), str):
            v = tls_obs.get("tls_version")
        elif isinstance((tls_obs.get("handshake") or {}).get("tls_version"), str):
            v = (tls_obs.get("handshake") or {}).get("tls_version")
        if v:
            evidences.append(
                _mk_evidence(
                    target_normalized=target_norm,
                    scan_id=scan_id,
                    scan_file=scan_file,
                    ts=ts,
                    ev_type="tls.version",
                    value={"version": str(v)},
                    strength=_strength_for("tls.version", default_strength),
                    probe="tls",
                )
            )

        verified = None
        err = None
        if isinstance(tls_obs.get("ok"), bool):
            verified = bool(tls_obs.get("ok"))
        if verified is False:
            e = tls_obs.get("error")
            if isinstance(e, str) and e.strip():
                err = e.strip()
        if verified is not None:
            evidences.append(
                _mk_evidence(
                    target_normalized=target_norm,
                    scan_id=scan_id,
                    scan_file=scan_file,
                    ts=ts,
                    ev_type="tls.verify",
                    value={"verified": bool(verified), "error": err},
                    strength=_strength_for("tls.verify", default_strength),
                    probe="tls",
                )
            )

        cipher_name = None
        c = tls_obs.get("cipher")
        if isinstance(c, dict) and isinstance(c.get("name"), str) and c.get("name").strip():
            cipher_name = c.get("name").strip()
        else:
            h = tls_obs.get("handshake")
            if isinstance(h, dict):
                c2 = h.get("cipher")
                if isinstance(c2, dict) and isinstance(c2.get("name"), str) and c2.get("name").strip():
                    cipher_name = c2.get("name").strip()
        if cipher_name:
            evidences.append(
                _mk_evidence(
                    target_normalized=target_norm,
                    scan_id=scan_id,
                    scan_file=scan_file,
                    ts=ts,
                    ev_type="tls.cipher_suite",
                    value={"name": cipher_name},
                    strength=_strength_for("tls.cipher_suite", default_strength),
                    probe="tls",
                )
            )

        cert = tls_obs.get("cert")
        if not isinstance(cert, dict):
            h = tls_obs.get("handshake")
            if isinstance(h, dict):
                cert = h.get("cert")

        not_after = cert.get("notAfter") if isinstance(cert, dict) else None
        days = None
        if isinstance(tls_obs.get("cert_days_remaining"), int):
            days = int(tls_obs.get("cert_days_remaining"))
        elif isinstance(not_after, str):
            days = _days_until_not_after(not_after)

        if isinstance(days, int):
            evidences.append(
                _mk_evidence(
                    target_normalized=target_norm,
                    scan_id=scan_id,
                    scan_file=scan_file,
                    ts=ts,
                    ev_type="tls.cert.expiry_days",
                    value={"days": int(days)},
                    strength=_strength_for("tls.cert.expiry_days", default_strength),
                    probe="tls",
                )
            )

        ss = _is_self_signed(cert)
        if ss is not None:
            evidences.append(
                _mk_evidence(
                    target_normalized=target_norm,
                    scan_id=scan_id,
                    scan_file=scan_file,
                    ts=ts,
                    ev_type="tls.cert.chain",
                    value={"is_self_signed": bool(ss), "has_intermediate": None},
                    strength=_strength_for("tls.cert.chain", default_strength),
                    probe="tls",
                )
            )

    if final_url and isinstance(final_status, int):
        evidences.append(
            _mk_evidence(
                target_normalized=target_norm,
                scan_id=scan_id,
                scan_file=scan_file,
                ts=ts,
                ev_type="http.status",
                value={"url": final_url, "status": int(final_status)},
                strength=_strength_for("http.status", default_strength),
                probe="http",
            )
        )

    tr = (obs.get("transport") or {})
    redirect_chain = tr.get("redirect_chain")
    if isinstance(redirect_chain, list) and len(redirect_chain) >= 2:
        from_url = str(redirect_chain[0])
        to_url = str(redirect_chain[-1])
        hops = max(0, len(redirect_chain) - 1)
        schemes = [str(u).split(":", 1)[0].lower() for u in redirect_chain if isinstance(u, str) and ":" in u]
        evidences.append(
            _mk_evidence(
                target_normalized=target_norm,
                scan_id=scan_id,
                scan_file=scan_file,
                ts=ts,
                ev_type="http.redirect.chain",
                value={
                    "hops": hops,
                    "from": from_url,
                    "to": to_url,
                    "includes_http": ("http" in schemes),
                    "includes_https": ("https" in schemes),
                },
                strength=_strength_for("http.redirect.chain", default_strength),
                probe="transport",
            )
        )
    else:
        chain = http_obs.get("chain")
        if isinstance(chain, list) and len(chain) >= 2:
            try:
                from_url = str(chain[0].get("url"))
                to_url = str(chain[-1].get("url"))
                hops = max(0, len(chain) - 1)
                schemes = [
                    str((it.get("url") or "")).split(":", 1)[0].lower()
                    for it in chain
                    if isinstance(it, dict)
                ]
                evidences.append(
                    _mk_evidence(
                        target_normalized=target_norm,
                        scan_id=scan_id,
                        scan_file=scan_file,
                        ts=ts,
                        ev_type="http.redirect.chain",
                        value={
                            "hops": hops,
                            "from": from_url,
                            "to": to_url,
                            "includes_http": ("http" in schemes),
                            "includes_https": ("https" in schemes),
                        },
                        strength=_strength_for("http.redirect.chain", default_strength),
                        probe="http",
                    )
                )
            except Exception:
                pass

    headers = _headers_from_scan(scan)
    hl = _lower_headers(headers)
    url_for_headers = final_url or target_norm

    sec = (obs.get("security") or {})
    headers_present_map = (sec.get("headers_present") or {})
    if not isinstance(headers_present_map, dict):
        headers_present_map = {}

    present: Dict[str, str] = {}
    for hname in SEC_HEADERS_BASE:
        v = None
        if hname in headers_present_map:
            v = headers_present_map.get(hname)
        else:
            v = hl.get(hname.lower())
        if isinstance(v, str) and v.strip():
            present[hname] = v.strip()

    for hname, v in present.items():
        evidences.append(
            _mk_evidence(
                target_normalized=target_norm,
                scan_id=scan_id,
                scan_file=scan_file,
                ts=ts,
                ev_type="http.header.present",
                value={"url": url_for_headers, "name": hname, "value": v},
                strength=_strength_for("http.header.present", default_strength),
                probe="security_headers",
            )
        )

    missing_names: List[str] = []
    for hname in SEC_HEADERS_BASE:
        if hname == "Strict-Transport-Security" and scheme != "https":
            continue
        if hname not in present:
            missing_names.append(hname)

    for hname in missing_names:
        evidences.append(
            _mk_evidence(
                target_normalized=target_norm,
                scan_id=scan_id,
                scan_file=scan_file,
                ts=ts,
                ev_type="http.header.missing",
                value={"url": url_for_headers, "name": hname},
                strength=_strength_for("http.header.missing", default_strength),
                probe="security_headers",
            )
        )

    set_cookie_raw = None
    for k in ("set-cookie", "set_cookie", "setcookie"):
        if k in hl and hl.get(k):
            set_cookie_raw = hl.get(k)
            break

    if set_cookie_raw:
        for one in _parse_set_cookie_header(set_cookie_raw):
            cobj = _parse_cookie(one)
            if not cobj:
                continue
            evidences.append(
                _mk_evidence(
                    target_normalized=target_norm,
                    scan_id=scan_id,
                    scan_file=scan_file,
                    ts=ts,
                    ev_type="http.cookie.set",
                    value={
                        "name": cobj.get("name"),
                        "secure": cobj.get("secure"),
                        "httponly": cobj.get("httponly"),
                        "samesite": cobj.get("samesite"),
                    },
                    strength=_strength_for("http.cookie.set", default_strength),
                    probe="http",
                )
            )

    server = hl.get("server")
    if isinstance(server, str) and server.strip():
        evidences.append(
            _mk_evidence(
                target_normalized=target_norm,
                scan_id=scan_id,
                scan_file=scan_file,
                ts=ts,
                ev_type="http.banner.server",
                value={"value": server.strip()},
                strength=_strength_for("http.banner.server", default_strength),
                probe="http",
            )
        )

    powered = hl.get("x-powered-by")
    if isinstance(powered, str) and powered.strip():
        evidences.append(
            _mk_evidence(
                target_normalized=target_norm,
                scan_id=scan_id,
                scan_file=scan_file,
                ts=ts,
                ev_type="http.banner.powered_by",
                value={"value": powered.strip()},
                strength=_strength_for("http.banner.powered_by", default_strength),
                probe="http",
            )
        )

    tech_items = scan.get("tech") or []
    if isinstance(tech_items, list):
        for t in tech_items:
            if not isinstance(t, dict):
                continue
            name = t.get("name")
            conf = t.get("confidence")
            if not isinstance(name, str) or not name.strip():
                continue
            conf_s = str(conf or "").strip().lower()
            if conf_s not in ("low", "medium", "high"):
                conf_s = "medium"
            evidences.append(
                _mk_evidence(
                    target_normalized=target_norm,
                    scan_id=scan_id,
                    scan_file=scan_file,
                    ts=ts,
                    ev_type="tech.detected",
                    value={"name": name.strip(), "version": None, "confidence": conf_s},
                    strength=_strength_for("tech.detected", default_strength),
                    probe="tech",
                )
            )

    cloud = (obs.get("cloud") or {})
    if isinstance(cloud, dict):
        provider = cloud.get("provider")
        if isinstance(provider, str) and provider.strip():
            prov = provider.strip().lower()
            if prov not in ("aws", "azure", "gcp"):
                prov = "other"
            evidences.append(
                _mk_evidence(
                    target_normalized=target_norm,
                    scan_id=scan_id,
                    scan_file=scan_file,
                    ts=ts,
                    ev_type="cloud.ip_match",
                    value={
                        "provider": prov,
                        "region": cloud.get("region") if isinstance(cloud.get("region"), str) else None,
                        "service": cloud.get("service") if isinstance(cloud.get("service"), str) else None,
                    },
                    strength=_strength_for("cloud.ip_match", default_strength),
                    probe="cloud",
                )
            )

    uniq: Dict[str, JSON] = {}
    for e in evidences:
        if not isinstance(e, dict):
            continue
        eid = e.get("id")
        if isinstance(eid, str) and eid and eid not in uniq:
            uniq[eid] = e

    return list(uniq.values())



def _build_global_index(per_scan_outputs: List[Tuple[str, str, str, int, List[JSON]]]) -> JSON:
    """
    per_scan_outputs: [(scan_id, host, evidence_filename, count, evidences)]
    """
    by_host: Dict[str, Any] = {}
    by_type: Dict[str, Any] = {}
    scan_files: Dict[str, Any] = {}
    total = 0

    for scan_id, host, ev_file, count, evidences in per_scan_outputs:
        total += int(count)
        scan_files[scan_id] = {"host": host, "evidence_file": ev_file, "count": int(count)}

        h = host or "unknown"
        if h not in by_host:
            by_host[h] = {"count": 0, "scans": [], "types": {}}
        by_host[h]["count"] += int(count)
        by_host[h]["scans"].append(scan_id)

        for e in evidences:
            t = e.get("type")
            if not isinstance(t, str):
                continue
            by_host[h]["types"][t] = int(by_host[h]["types"].get(t, 0)) + 1

            if t not in by_type:
                by_type[t] = {"count": 0, "hosts": []}
            by_type[t]["count"] += 1
            if h not in by_type[t]["hosts"]:
                by_type[t]["hosts"].append(h)

    for _h, obj in by_host.items():
        try:
            obj["scans"] = sorted(set(obj.get("scans") or []))
        except Exception:
            pass
        try:
            obj["types"] = dict(sorted((obj.get("types") or {}).items(), key=lambda kv: kv[0]))
        except Exception:
            pass

    for _t, obj in by_type.items():
        try:
            obj["hosts"] = sorted(set(obj.get("hosts") or []))
        except Exception:
            pass

    return {
        "schema_version": "v1",
        "generated_at": _now_utc_iso_z(),
        "scans_processed": len(per_scan_outputs),
        "total_evidences": total,
        "by_host": dict(sorted(by_host.items(), key=lambda kv: kv[0])),
        "by_type": dict(sorted(by_type.items(), key=lambda kv: kv[0])),
        "scan_files": dict(sorted(scan_files.items(), key=lambda kv: kv[0])),
    }



def _collect_scan_files(arg: str) -> List[Path]:
    p = Path(arg)
    if _is_dir(p):
        return sorted([x for x in p.glob("scan_*.json") if x.is_file()])
    if _is_file(p):
        return [p]
    return []


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print("usage: python scripts/evidence_build.py <scan.json|scan_dir>")
        return 2

    if not CORE_TYPES_PATH.exists() or not EVIDENCE_TYPES_PATH.exists():
        print("error: CORE contracts not found (CORE/core_types.v1.json, CORE/evidence_types.v1.json).")
        return 2

    _, _, _ev_schemas, default_strength = _load_contracts()

    scan_files: List[Path] = []
    for a in argv[1:]:
        scan_files.extend(_collect_scan_files(a))

    # de-dupe
    seen = set()
    uniq_files: List[Path] = []
    for f in scan_files:
        fp = str(f.resolve())
        if fp in seen:
            continue
        seen.add(fp)
        uniq_files.append(f)
    scan_files = uniq_files

    if not scan_files:
        print("error: no scan_*.json found.")
        return 2

    per_scan_outputs: List[Tuple[str, str, str, int, List[JSON]]] = []

    for sp in scan_files:
        try:
            scan = _read_json(sp)
        except Exception:
            continue

        scan_id = _scan_id_from_filename(sp)
        host = str((scan.get("target") or {}).get("host") or "")
        evidences = build_evidences_for_scan(scan, sp, default_strength)

        out_obj = {
            "schema_version": "v1",
            "scan_id": scan_id,
            "source_scan": {
                "file": sp.name,
                "generated_at": scan.get("generated_at"),
                "engine": scan.get("engine"),
                "version": scan.get("version"),
            },
            "target": scan.get("target"),
            "evidences": evidences,
        }

        out_name = f"evidence_{scan_id}.v1.json"
        out_path = OUT_EVIDENCE_DIR / out_name
        _write_json(out_path, out_obj)

        per_scan_outputs.append((scan_id, host, out_name, len(evidences), evidences))

    index_obj = _build_global_index(per_scan_outputs)
    index_path = OUT_EVIDENCE_DIR / "evidence_index.v1.json"
    _write_json(index_path, index_obj)

    print(f"scans: {len(per_scan_outputs)}")
    for scan_id, _host, ev_file, cnt, _evidences in per_scan_outputs:
        print(f"{scan_id}: evidences={cnt} -> {OUT_EVIDENCE_DIR / ev_file}")
    print(f"index -> {index_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

