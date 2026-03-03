from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

JSON = Dict[str, Any]

@dataclass(frozen=True)
class Target:
    input: str
    parsed_target: str
    normalized: str
    scheme: str
    host: str
    port: int

@dataclass
class ScanContext:
    root: Any
    version: str
    generated_at: str
    scan_id: str
    started_at: str
    ended_at: Optional[str]
    insecure: bool
    target: Target

@dataclass
class ProbeStatus:
    ok: bool
    timing_ms: int
    error: Optional[str] = None
