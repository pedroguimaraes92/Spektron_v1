# spektron_engine/core_loader.py
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional


class CoreLoadError(RuntimeError):
    """Raised when SPEKTRON/CORE assets are missing or invalid."""


# ---- Expected CORE assets (filenames + schema_version) ----

_EXPECTED_FILES: Dict[str, str] = {
    "core_types": "core_types.v1.json",
    "evidence_types": "evidence_types.v1.json",
    "impact_model": "impact_model.v1.json",
    "weakness_catalog": "weakness_catalog.v1.json",
    "control_catalog": "control_catalog.v1.json",
    "rules_entry": "rules_entry.v1.json",
    "rules_weakness": "rules_weakness.v1.json",
    "mappings_attack": "mappings_attack.v1.json",
    "mappings_controls": "mappings_controls.v1.json",
    "path_policy": "path_policy.v1.json",
    "scoring_policy": "scoring_policy.v1.json",
}

_EXPECTED_SCHEMA: Dict[str, str] = {
    "core_types": "spektron.core_types.v1",
    "evidence_types": "spektron.evidence_types.v1",
    "impact_model": "spektron.impact_model.v1",
    "weakness_catalog": "spektron.weakness_catalog.v1",
    "control_catalog": "spektron.control_catalog.v1",
    "rules_entry": "spektron.rules_entry.v1",
    "rules_weakness": "spektron.rules_weakness.v1",
    "mappings_attack": "spektron.mappings_attack.v1",
    "mappings_controls": "spektron.mappings_controls.v1",
    "path_policy": "spektron.path_policy.v1",
    "scoring_policy": "spektron.scoring_policy.v1",
}

# Basic ISO 8601 validator: accepts "Z" or offset, with or without fractional seconds.
_ISO8601_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,9})?"
    r"(?:Z|[+-]\d{2}:\d{2})$"
)


def _is_iso8601(s: Any) -> bool:
    if not isinstance(s, str):
        return False
    return bool(_ISO8601_RE.match(s))


def _ensure(condition: bool, msg: str) -> None:
    if not condition:
        raise CoreLoadError(msg)


def _read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise CoreLoadError(f"CORE file not found: {path}")
    if not path.is_file():
        raise CoreLoadError(f"CORE path is not a file: {path}")

    try:
        text = path.read_text(encoding="utf-8")
    except Exception as e:
        raise CoreLoadError(f"Failed to read CORE file: {path} ({e})") from e

    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        # Provide a small context window near the error location
        start = max(0, e.pos - 80)
        end = min(len(text), e.pos + 80)
        excerpt = text[start:end].replace("\n", "\\n")
        raise CoreLoadError(
            f"Invalid JSON in CORE file: {path} (line {e.lineno}, col {e.colno}). "
            f"Context: …{excerpt}…"
        ) from e

    _ensure(isinstance(doc, dict), f"CORE file root must be an object: {path}")
    return doc  # type: ignore[return-value]


def _validate_root(doc: Mapping[str, Any], *, expected_schema: str, file_path: Path) -> None:
    schema_version = doc.get("schema_version")
    generated_at = doc.get("generated_at")
    stability = doc.get("stability")

    _ensure(
        schema_version == expected_schema,
        f"Invalid schema_version in {file_path}: expected '{expected_schema}', got '{schema_version}'",
    )
    _ensure(
        stability == "FROZEN",
        f"Invalid stability in {file_path}: expected 'FROZEN', got '{stability}'",
    )
    _ensure(
        _is_iso8601(generated_at),
        f"Invalid generated_at in {file_path}: expected ISO8601 string (e.g. 2026-02-25T12:34:56Z), got '{generated_at}'",
    )


def _index_by_unique_key(items: Any, *, key_name: str, ctx: str) -> Dict[str, Dict[str, Any]]:
    _ensure(isinstance(items, list), f"{ctx} must be a list")
    out: Dict[str, Dict[str, Any]] = {}

    for i, obj in enumerate(items):
        _ensure(isinstance(obj, dict), f"{ctx}[{i}] must be an object")
        k = obj.get(key_name)
        _ensure(isinstance(k, str) and k.strip() != "", f"{ctx}[{i}].{key_name} must be a non-empty string")

        if k in out:
            raise CoreLoadError(f"Duplicate key '{k}' for {ctx} by '{key_name}'")
        out[k] = obj  # raw dict for maximum compatibility

    return out


@dataclass(frozen=True)
class CoreBundle:
    # Raw docs
    core_types: Dict[str, Any]
    evidence_types: Dict[str, Any]
    impact_model: Dict[str, Any]
    weakness_catalog: Dict[str, Any]
    control_catalog: Dict[str, Any]
    rules_entry: Dict[str, Any]
    rules_weakness: Dict[str, Any]
    mappings_attack: Dict[str, Any]
    mappings_controls: Dict[str, Any]
    path_policy: Dict[str, Any]
    scoring_policy: Dict[str, Any]

    # Indices
    evidence_types_by_type: Dict[str, Dict[str, Any]]
    impacts_by_id: Dict[str, Dict[str, Any]]
    weaknesses_by_id: Dict[str, Dict[str, Any]]
    controls_by_id: Dict[str, Dict[str, Any]]
    entries_by_id: Dict[str, Dict[str, Any]]
    entry_rules_by_id: Dict[str, Dict[str, Any]]
    weakness_rules_by_id: Dict[str, Dict[str, Any]]
    mappings_attack_by_from: Dict[str, Dict[str, Any]]
    mappings_controls_by_from: Dict[str, Dict[str, Any]]


def load_core(core_dir: str | Path) -> CoreBundle:
    """
    Load and validate all SPEKTRON/CORE JSON assets from `core_dir`,
    returning a CoreBundle with raw documents and id-based indices.
    """
    base = Path(core_dir)
    _ensure(base.exists() and base.is_dir(), f"core_dir must be an existing directory: {base}")

    # Read + validate all docs
    docs: Dict[str, Dict[str, Any]] = {}
    for key, filename in _EXPECTED_FILES.items():
        path = base / filename
        doc = _read_json(path)
        _validate_root(doc, expected_schema=_EXPECTED_SCHEMA[key], file_path=path)
        docs[key] = doc

    # Build indices (strong validation + duplicates check)
    evidence_types_by_type = _index_by_unique_key(
        docs["evidence_types"].get("evidence_types"),
        key_name="type",
        ctx="evidence_types.evidence_types",
    )

    impacts_by_id = _index_by_unique_key(
        docs["impact_model"].get("impacts"),
        key_name="impact_id",
        ctx="impact_model.impacts",
    )

    weaknesses_by_id = _index_by_unique_key(
        docs["weakness_catalog"].get("weaknesses"),
        key_name="weakness_id",
        ctx="weakness_catalog.weaknesses",
    )

    controls_by_id = _index_by_unique_key(
        docs["control_catalog"].get("controls"),
        key_name="control_id",
        ctx="control_catalog.controls",
    )

    entries_by_id = _index_by_unique_key(
        docs["rules_entry"].get("entries"),
        key_name="entry_id",
        ctx="rules_entry.entries",
    )

    entry_rules_by_id = _index_by_unique_key(
        docs["rules_entry"].get("rule_set"),
        key_name="rule_id",
        ctx="rules_entry.rule_set",
    )

    weakness_rules_by_id = _index_by_unique_key(
        docs["rules_weakness"].get("rules"),
        key_name="rule_id",
        ctx="rules_weakness.rules",
    )

    mappings_attack_by_from = _index_by_unique_key(
        docs["mappings_attack"].get("mappings"),
        key_name="from",
        ctx="mappings_attack.mappings",
    )

    mappings_controls_by_from = _index_by_unique_key(
        docs["mappings_controls"].get("mappings"),
        key_name="from",
        ctx="mappings_controls.mappings",
    )

    return CoreBundle(
        core_types=docs["core_types"],
        evidence_types=docs["evidence_types"],
        impact_model=docs["impact_model"],
        weakness_catalog=docs["weakness_catalog"],
        control_catalog=docs["control_catalog"],
        rules_entry=docs["rules_entry"],
        rules_weakness=docs["rules_weakness"],
        mappings_attack=docs["mappings_attack"],
        mappings_controls=docs["mappings_controls"],
        path_policy=docs["path_policy"],
        scoring_policy=docs["scoring_policy"],
        evidence_types_by_type=evidence_types_by_type,
        impacts_by_id=impacts_by_id,
        weaknesses_by_id=weaknesses_by_id,
        controls_by_id=controls_by_id,
        entries_by_id=entries_by_id,
        entry_rules_by_id=entry_rules_by_id,
        weakness_rules_by_id=weakness_rules_by_id,
        mappings_attack_by_from=mappings_attack_by_from,
        mappings_controls_by_from=mappings_controls_by_from,
    )


__all__ = ["CoreLoadError", "CoreBundle", "load_core"]
