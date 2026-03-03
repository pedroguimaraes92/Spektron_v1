from __future__ import annotations

from typing import Any, Dict, List, Optional
import ssl, socket, hashlib
from datetime import datetime, timezone

JSON = Dict[str, Any]

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _parse_notafter(s: Optional[str]) -> Optional[str]:
    return s

def _days_until(not_after: Optional[str]) -> Optional[int]:
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

def _handshake(host: str, port: int, *, insecure: bool, min_v: Optional[int], max_v: Optional[int]) -> JSON:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        if min_v is not None:
            ctx.minimum_version = ssl.TLSVersion(min_v)
        if max_v is not None:
            ctx.maximum_version = ssl.TLSVersion(max_v)
    except Exception:
        pass

    with socket.create_connection((host, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            c = ssock.cipher()
            der = ssock.getpeercert(binary_form=True) or b""
            cert = ssock.getpeercert() or {}
            san = []
            for t, v in cert.get("subjectAltName", []) or []:
                san.append([t, v])
            return {
                "ok": True,
                "tls_version": ssock.version(),
                "cipher": {"name": c[0], "protocol": c[1], "bits": c[2]} if c else None,
                "peer_cert_sha256": _sha256(der) if der else None,
                "cert": {
                    "notAfter": cert.get("notAfter"),
                    "notBefore": cert.get("notBefore"),
                    "subjectAltName": san,
                    "issuer": cert.get("issuer"),
                    "subject": cert.get("subject"),
                } if cert else None,
            }

def probe_tls(host: str, port: int, *, insecure: bool) -> JSON:
    res: JSON = {
        "present": False,
        "ok": False,
        "verify": not insecure,
        "handshake": None,
        "supported_versions": [],
        "cert_days_remaining": None,
        "error": None,
    }

    try:
        h = _handshake(host, port, insecure=insecure, min_v=None, max_v=None)
        res["present"] = True
        res["ok"] = True
        res["handshake"] = h
        try:
            na = ((h.get("cert") or {}).get("notAfter")) if isinstance(h.get("cert"), dict) else None
            res["cert_days_remaining"] = _days_until(na)
        except Exception:
            pass
    except ssl.SSLError as e:
        res["present"] = True
        res["ok"] = False
        res["error"] = str(e)
        return res
    except Exception as e:
        res["present"] = False
        res["ok"] = False
        res["error"] = str(e)
        return res

    vers = []
    mapping = [
        ("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLSv1_1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ("TLSv1_2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
        ("TLSv1_3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ]
    for name, v in mapping:
        if v is None:
            continue
        try:
            _handshake(host, port, insecure=insecure, min_v=v.value, max_v=v.value)
            vers.append({"version": name, "supported": True})
        except Exception:
            vers.append({"version": name, "supported": False})
    res["supported_versions"] = vers
    return res
