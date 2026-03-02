from __future__ import annotations

from typing import Tuple
from urllib.parse import urlparse

from .errors import InputError

DEFAULT_SCHEME = "https"

def parse_scan_command(s: str) -> Tuple[str, bool]:
    """Accepts:
      - "scan <url|host>"
      - "scan -k <url|host>"
      - "scan --insecure <url|host>"
      - "<url|host>"  (treated as scan)
    Returns: (target_str, insecure_bool)
    """
    raw = (s or "").strip()
    if not raw:
        raise InputError("target vazio")

    parts = raw.split()
    insecure = False

    if parts[0].lower() == "scan":
        rest = parts[1:]
        flags = []
        while rest and rest[0].startswith("-"):
            flags.append(rest.pop(0))
        for f in flags:
            if f in ("-k", "--insecure"):
                insecure = True
        if not rest:
            raise InputError("target vazio")
        return (" ".join(rest).strip(), insecure)

    return (raw, insecure)

def normalize_target(raw: str) -> Tuple[str, str, str, str, int]:
    """Returns: (input, parsed_target, normalized_url, scheme, port, host is in parsed)."""
    s = (raw or "").strip()
    if not s:
        raise InputError("target vazio")

    # If user gave host only, assume https.
    if "://" not in s:
        s2 = f"{DEFAULT_SCHEME}://{s}"
    else:
        s2 = s

    u = urlparse(s2)
    scheme = (u.scheme or DEFAULT_SCHEME).lower()
    host = (u.hostname or "").strip()
    if not host:
        raise InputError("host inválido")
    port = u.port or (443 if scheme == "https" else 80)

    # Preserve path/query/fragment for "parsed_target"
    parsed_target = s2
    # Normalized = scheme://host[:port?]/ (drop path for consistency)
    norm = f"{scheme}://{host}"
    if (scheme == "https" and port != 443) or (scheme == "http" and port != 80):
        norm = f"{norm}:{port}"
    norm = norm + "/"
    return (raw, parsed_target, norm, scheme, port, host)
