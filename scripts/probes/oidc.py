from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urljoin

from core.net import fetch, NetPolicy

JSON = Dict[str, Any]

def probe_oidc(base_url: str, *, verify: bool) -> JSON:
    url = urljoin(base_url, "/.well-known/openid-configuration")
    r = fetch(url, "GET", verify=verify, allow_redirects=True, policy=NetPolicy(max_body_bytes=131072, max_sample_bytes=16384))
    if not r.get("ok"):
        return {"ok": False, "url": url, "error": r.get("error")}
    if r.get("final_status") != 200:
        return {"ok": False, "url": url, "status": r.get("final_status"), "final_url": r.get("final_url"), "error": "oidc_not_found"}
    body = (r.get("body_sample") or "").strip()
    meta = None
    try:
        import json
        meta = json.loads(body) if body.startswith("{") else None
    except Exception:
        meta = None
    summary = None
    if isinstance(meta, dict):
        summary = {
            "issuer": meta.get("issuer"),
            "jwks_uri": meta.get("jwks_uri"),
            "authorization_endpoint": meta.get("authorization_endpoint"),
            "token_endpoint": meta.get("token_endpoint"),
            "userinfo_endpoint": meta.get("userinfo_endpoint"),
        }
    return {"ok": True, "url": url, "status": 200, "final_url": r.get("final_url"), "summary": summary, "body_truncated": bool(r.get("body_truncated"))}
