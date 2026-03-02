from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from core.net import fetch, NetPolicy

JSON = Dict[str, Any]

def _risk_from(acao: Optional[str], acac: Optional[str], origin: str, reflected: bool) -> str:
    acac_true = (acac or "").strip().lower() == "true"
    if reflected and acac_true:
        return "high"
    if reflected:
        return "medium"
    # wildcard without credentials is usually lower risk (still can matter for read-only endpoints)
    if (acao or "").strip() == "*" and not acac_true:
        return "low"
    return "info"

def _preflight(base_url: str, *, verify: bool, origin: str, req_method: str = "GET", req_headers: str = "Authorization") -> JSON:
    headers = {
        "Origin": origin,
        "Access-Control-Request-Method": req_method,
        "Access-Control-Request-Headers": req_headers,
    }
    r = fetch(base_url, "OPTIONS", verify=verify, headers=headers, allow_redirects=True, policy=NetPolicy())
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error"), "status": r.get("final_status"), "final_url": r.get("final_url")}
    hdrs = {}
    try:
        hdrs = (r.get("chain") or [])[-1].get("headers") or {}
    except Exception:
        hdrs = {}
    return {
        "ok": True,
        "status": r.get("final_status"),
        "acao": hdrs.get("Access-Control-Allow-Origin"),
        "acac": hdrs.get("Access-Control-Allow-Credentials"),
        "acam": hdrs.get("Access-Control-Allow-Methods"),
        "acah": hdrs.get("Access-Control-Allow-Headers"),
        "acma": hdrs.get("Access-Control-Max-Age"),
    }

def probe_cors(base_url: str, *, verify: bool) -> JSON:
    """
    Passive, multi-origin CORS probing (enterprise baseline):
    - reflected origin
    - wildcard
    - null origin
    - preflight signal
    """
    origins = [
        "https://example.com",
        "https://evil.com",
        "null",
    ]
    items: List[JSON] = []
    for origin in origins:
        headers = {"Origin": origin}
        r = fetch(base_url, "GET", verify=verify, headers=headers, allow_redirects=True, policy=NetPolicy(max_sample_bytes=1024))
        if not r.get("ok"):
            items.append({"origin_test": origin, "ok": False, "error": r.get("error")})
            continue
        hdrs = {}
        try:
            hdrs = (r.get("chain") or [])[-1].get("headers") or {}
        except Exception:
            hdrs = {}
        acao = hdrs.get("Access-Control-Allow-Origin")
        acac = hdrs.get("Access-Control-Allow-Credentials")
        reflected = (acao == origin)
        items.append({
            "origin_test": origin,
            "ok": True,
            "status": r.get("final_status"),
            "final_url": r.get("final_url"),
            "acao": acao,
            "acac": acac,
            "reflected": reflected,
            "risk": _risk_from(acao, acac, origin, reflected),
        })

    # preflight with a likely-auth header
    pre = _preflight(base_url, verify=verify, origin="https://evil.com", req_method="GET", req_headers="Authorization")
    return {"ok": True, "url": base_url, "items": items, "preflight": pre}
