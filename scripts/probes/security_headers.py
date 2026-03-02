from __future__ import annotations

from typing import Any, Dict, List, Optional

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

RATE_HEADERS = [
    "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
]

def analyze_security_headers(headers: Dict[str,str]) -> Dict[str, Any]:
    h = { (k or "").lower(): v for k,v in (headers or {}).items() }
    present = {k: h.get(k) for k in SEC_HEADERS}
    rate = {k: h.get(k) for k in RATE_HEADERS}

    findings: List[Dict[str, Any]] = []
    if present.get("strict-transport-security") is None:
        findings.append({
            "id": "SEC_HDR_HSTS_MISSING",
            "severity": "medium",
            "title": "HSTS ausente em HTTPS",
            "detail": "Resposta HTTPS não inclui Strict-Transport-Security (HSTS). ",
            "evidence": {"header": "strict-transport-security"},
        })
    if present.get("content-security-policy") is None:
        findings.append({
            "id": "SEC_HDR_CSP_MISSING",
            "severity": "low",
            "title": "CSP ausente",
            "detail": "Resposta não inclui Content-Security-Policy (CSP). ",
            "evidence": {"header": "content-security-policy"},
        })
    if all(v is None for v in rate.values()):
        findings.append({
            "id": "SEC_HDR_RATELIMIT_MISSING",
            "severity": "info",
            "title": "Headers de rate limit ausentes",
            "detail": "Resposta não expõe headers comuns de rate limit (pode existir via outro endpoint). ",
            "evidence": {"headers_checked": RATE_HEADERS},
        })

    return {
        "headers_present": present,
        "rate_limit_headers_present": rate,
        "cookies": {},
        "findings": findings,
    }
