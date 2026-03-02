from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import uuid

from .contracts import Target, ScanContext

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def make_context(*, root: Path, version: str, insecure: bool, target: Target) -> ScanContext:
    ts = now_iso()
    return ScanContext(
        root=root,
        version=version,
        generated_at=ts,
        scan_id=str(uuid.uuid4()),
        started_at=ts,
        ended_at=None,
        insecure=insecure,
        target=target,
    )

def finish_context(ctx: ScanContext) -> ScanContext:
    ctx.ended_at = now_iso()
    return ctx
