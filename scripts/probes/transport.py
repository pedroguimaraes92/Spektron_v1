from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

def derive_transport(input_url: str, final_url: str, redirects: int, redirect_chain: List[str]) -> Dict[str, Any]:
    u_in = urlparse(input_url)
    u_fin = urlparse(final_url)
    return {
        "input_url": input_url,
        "input_scheme": u_in.scheme,
        "final_url": final_url,
        "final_scheme": u_fin.scheme,
        "redirects": redirects,
        "redirect_chain": redirect_chain or [final_url],
        "tls_in_play": u_fin.scheme == "https",
        "redirect_kind": None,
        "redirect_permanent_hint": None,
        "input_host": u_in.hostname,
        "final_host": u_fin.hostname,
    }
