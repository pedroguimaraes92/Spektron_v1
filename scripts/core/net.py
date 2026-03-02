from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, List
import time

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore

JSON = Dict[str, Any]

TRANSIENT_STATUS = {408, 425, 429, 500, 502, 503, 504}

@dataclass(frozen=True)
class NetPolicy:
    timeout_s: float = 12.0
    connect_timeout_s: float = 6.0
    max_retries: int = 1
    backoff_s: float = 0.35
    max_body_bytes: int = 262144  # 256 KiB safe cap for passive recon
    max_sample_bytes: int = 4096

def _headers_raw(headers: Dict[str, str]) -> List[List[str]]:
    return [[k, v] for k, v in headers.items()]

def _safe_text(b: bytes) -> str:
    # keep deterministic decode
    try:
        return b.decode("utf-8", "ignore")
    except Exception:
        try:
            return b.decode("latin-1", "ignore")
        except Exception:
            return ""

def _sample_bytes(b: bytes, limit: int) -> Tuple[str, bool, int]:
    trunc = len(b) > limit
    if trunc:
        b2 = b[:limit]
        return _safe_text(b2), True, len(b2)
    return _safe_text(b), False, len(b)

def fetch(
    url: str,
    method: str = "GET",
    *,
    verify: bool,
    headers: Optional[Dict[str, str]] = None,
    policy: Optional[NetPolicy] = None,
    allow_redirects: bool = True,
    stream: bool = True,
) -> JSON:
    """
    Enterprise-ish fetch:
    - captures redirect chain (response.history)
    - bounded body read (max_body_bytes)
    - returns ok/error/timing/retries
    """
    if requests is None:
        return {"ok": False, "error": "requests_not_available", "url": url, "method": method.upper()}

    pol = policy or NetPolicy()
    t0 = time.time()
    err: Optional[str] = None
    retries = 0

    # requests timeout can be (connect, read)
    timeout = (pol.connect_timeout_s, pol.timeout_s)

    def _do_req() -> Any:
        return requests.request(
            method.upper(),
            url,
            headers=headers or {},
            timeout=timeout,
            verify=verify,
            allow_redirects=allow_redirects,
            stream=stream,
        )

    resp = None
    for attempt in range(pol.max_retries + 1):
        try:
            resp = _do_req()
            # retry only if HTTP transient
            if resp is not None and resp.status_code in TRANSIENT_STATUS and attempt < pol.max_retries:
                retries += 1
                time.sleep(pol.backoff_s * (attempt + 1))
                continue
            break
        except Exception as e:
            err = str(e)
            if attempt < pol.max_retries:
                retries += 1
                time.sleep(pol.backoff_s * (attempt + 1))
                continue
            resp = None

    total_ms = int((time.time() - t0) * 1000)

    if resp is None:
        return {
            "ok": False,
            "url": url,
            "method": method.upper(),
            "tls_verify": verify,
            "error": err or "request_failed",
            "timing_total_ms": total_ms,
            "retries": retries,
        }

    # redirect chain: history + final
    chain: List[JSON] = []

    def _one(r: Any) -> JSON:
        return {
            "url": r.url,
            "status": r.status_code,
            "headers_raw": _headers_raw(dict(r.headers)),
            "headers": dict(r.headers),
            "elapsed_ms": int(getattr(r, "elapsed", 0).total_seconds() * 1000) if getattr(r, "elapsed", None) else None,
        }

    try:
        for h in list(resp.history or []):
            chain.append(_one(h))
        chain.append(_one(resp))
    except Exception:
        pass

    # bounded read
    body_bytes = b""
    body_truncated = False
    body_sample = ""
    body_sample_truncated = False
    body_sample_bytes = 0
    body_encoding = getattr(resp, "encoding", None) or "utf-8"

    if method.upper() != "HEAD":
        try:
            read = 0
            chunks: List[bytes] = []
            for chunk in resp.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                chunks.append(chunk)
                read += len(chunk)
                if read >= pol.max_body_bytes:
                    body_truncated = True
                    break
            body_bytes = b"".join(chunks)
        except Exception:
            # fallback to .content but capped
            try:
                body_bytes = (resp.content or b"")[: pol.max_body_bytes]
                body_truncated = len(resp.content or b"") > pol.max_body_bytes
            except Exception:
                body_bytes = b""

        body_sample, body_sample_truncated, body_sample_bytes = _sample_bytes(body_bytes, pol.max_sample_bytes)

    return {
        "ok": True,
        "url": url,
        "method": method.upper(),
        "tls_verify": verify,
        "final_url": resp.url,
        "final_status": resp.status_code,
        "redirects": max(0, len(chain) - 1),
        "timing_total_ms": total_ms,
        "retries": retries,
        "chain": chain,
        "body_encoding": body_encoding,
        "body_bytes": len(body_bytes),
        "body_truncated": body_truncated,
        "body_sample_bytes": body_sample_bytes,
        "body_sample_truncated": body_sample_truncated,
        "body_sample": body_sample or "",
    }
