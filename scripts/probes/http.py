from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urljoin

from core.net import fetch, NetPolicy

JSON = Dict[str, Any]

def probe_methods(base_url: str, *, verify: bool) -> JSON:
    items: List[JSON] = []
    for m in ("OPTIONS", "TRACE"):
        r = fetch(base_url, m, verify=verify, allow_redirects=True, policy=NetPolicy(max_sample_bytes=0))
        items.append({"method": m, "url": base_url, "ok": bool(r.get("ok")), "status": r.get("final_status"), "final_url": r.get("final_url")})
    return {"ok": True, "items": items}

def probe_exposure_files(base_url: str, *, verify: bool) -> JSON:
    paths = ["/robots.txt", "/.well-known/security.txt", "/security.txt", "/humans.txt", "/sitemap.xml", "/ads.txt"]
    items: List[JSON] = []
    for p in paths:
        u = urljoin(base_url, p)
        r = fetch(u, "GET", verify=verify, allow_redirects=True, policy=NetPolicy(max_body_bytes=65536, max_sample_bytes=4096))
        item: JSON = {"path": p, "url": u, "ok": bool(r.get("ok")), "status": r.get("final_status"), "final_url": r.get("final_url")}
        body = r.get("body_sample") or ""
        if body and r.get("final_status") == 200:
            item["body_sample"] = body
            item["body_sample_truncated"] = bool(r.get("body_sample_truncated"))
            signals: Dict[str, Any] = {}
            if p == "/robots.txt":
                signals["has_disallow"] = "Disallow" in body
                signals["has_allow"] = "Allow" in body
                signals["has_sitemap"] = "Sitemap" in body
            if p.endswith(".xml") or body.lstrip().startswith("<?xml"):
                signals["looks_xml"] = True
            item["signals"] = signals
        items.append(item)
    return {"ok": True, "items": items}
