from __future__ import annotations

from typing import Any, Dict, List

def detect_tech(headers: Dict[str,str], body_sample: str) -> List[Dict[str, Any]]:
    h = { (k or "").lower(): v for k,v in (headers or {}).items() }
    out: List[Dict[str, Any]] = []

    server = h.get("server", "") or ""
    via = h.get("via", "") or ""
    if "cloudflare" in server.lower():
        out.append({
            "name": "Cloudflare",
            "category": "CDN/WAF",
            "confidence": "high",
            "evidence": {"server": server, "cf-ray": h.get("cf-ray"), "cf-cache-status": h.get("cf-cache-status")},
        })
    if "heroku" in via.lower():
        out.append({
            "name": "Heroku",
            "category": "PaaS",
            "confidence": "medium",
            "evidence": {"header": "via", "value": via},
        })
    if "gtm.js" in (body_sample or "").lower():
        out.append({
            "name": "Google Tag Manager",
            "category": "Analytics",
            "confidence": "high",
            "evidence": {"html": "gtm.js"},
        })
    if "js.stripe.com" in (body_sample or "").lower():
        out.append({
            "name": "Stripe JS",
            "category": "Payments",
            "confidence": "medium",
            "evidence": {"html": "js.stripe.com"},
        })
    return out
