from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from core.net import fetch, NetPolicy

JSON = Dict[str, Any]

CANDIDATES = [
    "/swagger.json", "/swagger.yaml", "/swagger.yml",
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/api-docs", "/v2/api-docs", "/v3/api-docs",
]

def _looks_openapi(text: str) -> bool:
    t = text.lower()
    return ("openapi" in t) or ("swagger" in t) or ("paths:" in t and "info:" in t)

def _parse_json(text: str) -> Optional[Dict[str, Any]]:
    try:
        import json
        return json.loads(text)
    except Exception:
        return None

def _parse_yaml_best_effort(text: str) -> Optional[Dict[str, Any]]:
    try:
        import yaml
        obj = yaml.safe_load(text)
        return obj if isinstance(obj, dict) else None
    except Exception:
        out: Dict[str, Any] = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k in ("openapi", "swagger"):
                out[k] = v
            if k == "title":
                out.setdefault("info", {})["title"] = v
            if k == "version":
                out.setdefault("info", {})["version"] = v
        return out or None

def _summarize(doc: Dict[str, Any]) -> Dict[str, Any]:
    info = doc.get("info") or {}
    paths = doc.get("paths") or {}
    servers = doc.get("servers") or []
    return {
        "openapi": doc.get("openapi"),
        "swagger": doc.get("swagger"),
        "title": info.get("title"),
        "version": info.get("version"),
        "paths_count": len(paths) if isinstance(paths, dict) else None,
        "servers_count": len(servers) if isinstance(servers, list) else None,
    }

def probe_openapi(base_url: str, *, verify: bool) -> JSON:
    items: List[JSON] = []
    pol = NetPolicy(max_body_bytes=262144, max_sample_bytes=65536)
    for p in CANDIDATES:
        u = urljoin(base_url, p)
        r = fetch(u, "GET", verify=verify, allow_redirects=True, policy=pol)
        item: JSON = {"path": p, "url": u, "ok": bool(r.get("ok")), "status": r.get("final_status"), "final_url": r.get("final_url")}
        if not r.get("ok") or r.get("final_status") != 200:
            items.append(item)
            continue
        body = (r.get("body_sample") or "")
        item["body_truncated"] = bool(r.get("body_truncated"))
        item["signals"] = {"looks_openapi": _looks_openapi(body)}
        # parse
        doc = None
        if p.endswith(".json") or body.lstrip().startswith("{"):
            doc = _parse_json(body)
        elif p.endswith((".yaml", ".yml")) or "openapi:" in body.lower():
            doc = _parse_yaml_best_effort(body)
        if isinstance(doc, dict):
            item["openapi_summary"] = _summarize(doc)
        items.append(item)
    return {"ok": True, "items": items}
