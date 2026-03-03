import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=False)


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def _match_value(value_obj: Any, match: Dict[str, Any]) -> bool:
    if not isinstance(match, dict):
        return True
    if not isinstance(value_obj, dict):
        return False

    for k, expected in match.items():
        actual = value_obj.get(k)
        if isinstance(expected, dict):
            if not _match_value(actual, expected):
                return False
        else:
            if isinstance(expected, str):
                if actual is None:
                    return False
                if str(actual).strip().lower() != expected.strip().lower():
                    return False
            else:
                if actual != expected:
                    return False
    return True


@dataclass(frozen=True)
class Evidence:
    id: str
    type: str
    value: Dict[str, Any]
    strength: str


@dataclass
class CoreBundle:
    rules_entry: Dict[str, Any]
    rules_weakness: Dict[str, Any]
    weakness_catalog: Dict[str, Any]
    impact_model: Dict[str, Any]
    mappings_attack: Dict[str, Any]
    mappings_controls: Dict[str, Any]
    control_catalog: Dict[str, Any]
    scoring_policy: Dict[str, Any]
    path_policy: Dict[str, Any]
    core_types: Dict[str, Any]
    evidence_types: Dict[str, Any]


def _resolve_core_dir(script_path: Path) -> Path:
    """
    Expected layout:
      SPEKTRON/
        CORE/
        scripts/attack_build.py
    """
    spektron_root = script_path.resolve().parent.parent
    core_dir = spektron_root / "CORE"
    if core_dir.exists():
        return core_dir

    cwd_core = Path.cwd() / "CORE"
    if cwd_core.exists():
        return cwd_core

    raise FileNotFoundError("CORE directory not found (expected SPEKTRON/CORE or ./CORE).")


def _load_core(core_dir: Path) -> CoreBundle:
    def p(name: str) -> Path:
        return core_dir / name

    return CoreBundle(
        rules_entry=_read_json(p("rules_entry.v1.json")),
        rules_weakness=_read_json(p("rules_weakness.v1.json")),
        weakness_catalog=_read_json(p("weakness_catalog.v1.json")),
        impact_model=_read_json(p("impact_model.v1.json")),
        mappings_attack=_read_json(p("mappings_attack.v1.json")),
        mappings_controls=_read_json(p("mappings_controls.v1.json")),
        control_catalog=_read_json(p("control_catalog.v1.json")),
        scoring_policy=_read_json(p("scoring_policy.v1.json")),
        path_policy=_read_json(p("path_policy.v1.json")),
        core_types=_read_json(p("core_types.v1.json")),
        evidence_types=_read_json(p("evidence_types.v1.json")),
    )


def _load_evidence_file(path: Path) -> Tuple[str, Dict[str, Any], List[Evidence]]:
    raw = _read_json(path)
    scan_id = raw.get("scan_id") or raw.get("scan", {}).get("scan_id") or raw.get("source_scan", {}).get("scan_id")
    if not scan_id:
        raise ValueError("Evidence file missing scan_id.")

    evidences_raw = raw.get("evidences") or []
    evidences: List[Evidence] = []
    for ev in evidences_raw:
        evidences.append(
            Evidence(
                id=ev.get("id"),
                type=ev.get("type"),
                value=ev.get("value") or {},
                strength=ev.get("strength") or "moderate",
            )
        )
    return scan_id, raw, evidences


def _index_evidences(evidences: List[Evidence]) -> Dict[str, List[Evidence]]:
    idx: Dict[str, List[Evidence]] = {}
    for ev in evidences:
        idx.setdefault(ev.type, []).append(ev)
    for k in list(idx.keys()):
        idx[k].sort(key=lambda e: e.id or "")
    return idx


def _find_evidences(idx: Dict[str, List[Evidence]], ev_type: str, where: Optional[Dict[str, Any]] = None) -> List[Evidence]:
    candidates = idx.get(ev_type, [])
    if not where:
        return candidates[:]

    out: List[Evidence] = []
    for ev in candidates:
        if "name" in where and isinstance(where["name"], str):
            v = dict(ev.value) if isinstance(ev.value, dict) else {}
            if "name" in v and isinstance(v["name"], str):
                v["name"] = v["name"].strip().lower()
            w = dict(where)
            w["name"] = where["name"].strip().lower()
            if _match_value(v, w):
                out.append(ev)
        else:
            if _match_value(ev.value, where):
                out.append(ev)
    return out


def _eval_entry_rule(entry_def: Dict[str, Any], idx: Dict[str, List[Evidence]]) -> Optional[Dict[str, Any]]:
    """
    v1: evidence_requirements is a list of requirements; each requirement uses 'any_of'.
    Deterministic: choose first matching clause in file order, then smallest evidence id.
    """
    reqs = entry_def.get("evidence_requirements") or []
    used_refs: List[str] = []

    for req in reqs:
        any_of = req.get("any_of") or []
        chosen: Optional[Evidence] = None

        for clause in any_of:
            t = clause.get("type")
            m = clause.get("match")
            if not t:
                continue
            matches = _find_evidences(idx, t, m)
            if matches:
                chosen = matches[0]
                break

        if not chosen or not chosen.id:
            return None
        used_refs.append(chosen.id)

    return {
        "entry_id": entry_def.get("entry_id"),
        "title": entry_def.get("title"),
        "description": entry_def.get("description"),
        "refs": sorted(set(used_refs)),
    }


def _build_entries(core: CoreBundle, idx: Dict[str, List[Evidence]]) -> Dict[str, Dict[str, Any]]:
    entries: Dict[str, Dict[str, Any]] = {}
    for entry_def in core.rules_entry.get("entries", []):
        result = _eval_entry_rule(entry_def, idx)
        if result and result.get("entry_id"):
            entries[result["entry_id"]] = result
    return entries


def _eval_when_expr(
    when: Dict[str, Any],
    idx: Dict[str, List[Evidence]],
    entries: Dict[str, Dict[str, Any]],
) -> Tuple[bool, List[str], List[str]]:
    """
    v1 rule language:
      when: { all: [ { any: [ { evidence: <token>, where?: {...} }, ... ] }, ... ] }

    token can be:
      - evidence type (e.g., "http.header.missing")
      - entry id (e.g., "entry:https_reachable")

    Deterministic:
      - for each 'any' group: first matching condition in file order
      - for evidence: smallest evidence id
    """
    refs: List[str] = []
    used_entries: List[str] = []

    groups = when.get("all") or []
    for g in groups:
        any_list = g.get("any") or []
        group_ok = False
        group_refs: List[str] = []
        group_entries: List[str] = []

        for cond in any_list:
            token = cond.get("evidence")
            where = cond.get("where")
            if not token:
                continue

            if isinstance(token, str) and token.startswith("entry:"):
                if token in entries:
                    group_ok = True
                    group_entries.append(token)
                    group_refs.extend(entries[token].get("refs", []))
                    break
            else:
                matches = _find_evidences(idx, token, where)
                if matches:
                    group_ok = True
                    if matches[0].id:
                        group_refs.append(matches[0].id)
                    break

        if not group_ok:
            return False, [], []
        refs.extend(group_refs)
        used_entries.extend(group_entries)

    return True, sorted(set(refs)), sorted(set(used_entries))


def _build_weaknesses(core: CoreBundle, idx: Dict[str, List[Evidence]], entries: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for rule in core.rules_weakness.get("rules", []):
        ok, refs, used_entry_ids = _eval_when_expr(rule.get("when") or {}, idx, entries)
        if not ok:
            continue
        out.append(
            {
                "rule_id": rule.get("rule_id"),
                "weakness_id": rule.get("weakness_id"),
                "title": rule.get("title"),
                "confidence": rule.get("confidence") or "medium",
                "refs": refs,
                "used_entries": used_entry_ids,
            }
        )
    out.sort(key=lambda w: (w.get("weakness_id") or "", w.get("rule_id") or ""))
    return out


def _index_by_id(items: List[Dict[str, Any]], id_key: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for it in items:
        _id = it.get(id_key)
        if _id:
            out[_id] = it
    return out


def _select_entry_for_weakness(weak: Dict[str, Any], entries: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    preferred = [
        "entry:https_reachable",
        "entry:http_reachable",
        "entry:internet_facing",
        "entry:cloud_provider_public",
    ]
    used = weak.get("used_entries") or []
    for eid in preferred:
        if eid in used and eid in entries:
            return entries[eid]
    for eid in preferred:
        if eid in entries:
            return entries[eid]
    for eid in sorted(entries.keys()):
        return entries[eid]
    return None


def _select_impact(core: CoreBundle, weakness_def: Dict[str, Any]) -> Dict[str, Any]:
    impacts = core.impact_model.get("impacts", [])
    impacts_by_id = _index_by_id(impacts, "impact_id")

    for hid in (weakness_def.get("impact_hints") or []):
        if hid in impacts_by_id:
            return impacts_by_id[hid]

    default_impact = core.path_policy.get("impact_selection", {}).get("default_impact", "impact:information_disclosure")
    if default_impact in impacts_by_id:
        return impacts_by_id[default_impact]

    if impacts:
        return impacts[0]
    raise ValueError("Impact model has no impacts.")


def _select_technique(core: CoreBundle, weakness_id: str) -> Dict[str, Any]:
    for m in core.mappings_attack.get("mappings", []):
        if m.get("from") == weakness_id:
            techniques = m.get("techniques") or []
            if techniques:
                t = techniques[0]
                return {
                    "framework": t.get("framework"),
                    "technique_id": t.get("technique_id"),
                    "title": t.get("title"),
                    "confidence": t.get("confidence") or "low",
                }

    fb = core.path_policy.get("technique_selection", {}).get("fallback") or {}
    return {
        "framework": fb.get("framework", "custom"),
        "technique_id": fb.get("technique_id", "custom:unknown"),
        "title": fb.get("title", "Unspecified exploitation technique"),
        "confidence": fb.get("confidence", "very_low"),
    }


def _select_controls(core: CoreBundle, weakness_id: str, entry_id: str) -> List[Dict[str, Any]]:
    control_ids: List[str] = []
    for m in core.mappings_controls.get("mappings", []):
        if m.get("from") == weakness_id:
            control_ids = list(m.get("controls") or [])
            break

    catalog_by_id = _index_by_id(core.control_catalog.get("controls", []), "control_id")
    controls_full: List[Dict[str, Any]] = [catalog_by_id[cid] for cid in control_ids if cid in catalog_by_id]

    def priority(c: Dict[str, Any]) -> tuple:
        eff = c.get("effect") or {}
        cuts_entries = set(eff.get("cuts_entries") or [])
        mitigates = set(eff.get("mitigates_weaknesses") or [])
        if entry_id in cuts_entries:
            p = 0
        elif weakness_id in mitigates:
            p = 1
        else:
            p = 2
        return (p, c.get("control_id") or "")

    controls_full.sort(key=priority)
    max_n = int(core.path_policy.get("control_selection", {}).get("max_controls_per_path", 6))
    controls_full = controls_full[:max_n]

    out: List[Dict[str, Any]] = []
    for c in controls_full:
        out.append(
            {
                "control_id": c.get("control_id"),
                "title": c.get("title"),
                "kind": c.get("kind"),
                "references": c.get("references") or {},
            }
        )
    return out


def _bucket_for_score(thresholds: List[Dict[str, Any]], score: int) -> str:
    for t in thresholds:
        mn = int(t.get("min", 0))
        mx = int(t.get("max", 100))
        if mn <= score <= mx:
            return t.get("label", "Unknown")
    return "Unknown"


def _strength_multiplier(strength: str) -> float:
    s = (strength or "").strip().lower()
    if s == "weak":
        return 0.85
    if s == "strong":
        return 1.10
    return 1.00


def _confidence_multiplier(conf: str) -> float:
    c = (conf or "").strip().lower()
    if c == "very_low":
        return 0.75
    if c == "low":
        return 0.85
    if c == "high":
        return 1.10
    if c == "very_high":
        return 1.20
    return 1.00


def _score_path(
    core: CoreBundle,
    weakness_def: Dict[str, Any],
    impact_def: Dict[str, Any],
    entry_ids_present: List[str],
    weakness_refs: List[Evidence],
) -> Dict[str, Any]:
    policy = core.scoring_policy.get("attack_path_score", {})
    thresholds = policy.get("bucket_thresholds") or []

    likelihood = float(weakness_def.get("base_likelihood", 0.0))
    impact_weight = float(impact_def.get("base_weight", 0.0))
    exposure_multiplier = 1.0

    if weakness_refs:
        likelihood *= max((_strength_multiplier(ev.strength) for ev in weakness_refs))

    likelihood *= _confidence_multiplier(weakness_def.get("confidence", "medium"))

    if "entry:internet_facing" in entry_ids_present:
        likelihood *= 1.10
    if "entry:http_reachable" in entry_ids_present:
        likelihood *= 1.08

    has_known_vuln = any(ev.type in {"vuln.cve", "vuln.known", "vuln.detected"} for ev in weakness_refs)
    if has_known_vuln:
        likelihood *= 1.25

    asset_crit = "medium"
    mult_map = {"low": 0.85, "medium": 1.0, "high": 1.2, "critical": 1.35}
    impact_weight *= mult_map.get(asset_crit, 1.0)

    if "entry:cloud_provider_public" in entry_ids_present:
        exposure_multiplier += 0.05
    if weakness_def.get("weakness_id") == "weakness:tls_unverified":
        exposure_multiplier += 0.05

    clamp_text = (policy.get("components", {}).get("exposure_multiplier", {}) or {}).get("clamp", "0.8..1.25")
    try:
        a, b = clamp_text.split("..", 1)
        lo = float(a)
        hi = float(b)
        exposure_multiplier = max(lo, min(hi, exposure_multiplier))
    except Exception:
        exposure_multiplier = max(0.8, min(1.25, exposure_multiplier))

    raw = likelihood * impact_weight * exposure_multiplier
    score_0_100 = int(round(100 * _clamp01(raw)))
    bucket = _bucket_for_score(thresholds, score_0_100)

    return {
        "score_0_100": score_0_100,
        "bucket": bucket,
        "components": {
            "likelihood": round(likelihood, 6),
            "impact_weight": round(impact_weight, 6),
            "exposure_multiplier": round(exposure_multiplier, 6),
        },
    }


def _make_graph(paths: List[Dict[str, Any]]) -> Dict[str, Any]:
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    def upsert_node(node_id: str, node_type: str, label: str, refs: Optional[List[str]] = None) -> None:
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "type": node_type, "label": label, "refs": sorted(set(refs or []))}
        else:
            if refs:
                merged = set(nodes[node_id].get("refs") or [])
                merged.update(refs)
                nodes[node_id]["refs"] = sorted(merged)

    for p in paths:
        entry = p["entry"]
        weak = p["weakness"]
        tech = p["technique"]
        impact = p["impact"]
        controls = p.get("controls") or []

        entry_node = entry["entry_id"]
        weak_node = weak["weakness_id"]
        tech_node = f"technique:{tech.get('framework')}:{tech.get('technique_id')}"
        impact_node = impact["impact_id"]

        upsert_node(entry_node, "entry", entry.get("title") or entry_node, entry.get("refs") or [])
        upsert_node(weak_node, "weakness", weak.get("title") or weak_node, weak.get("refs") or [])
        upsert_node(tech_node, "technique", tech.get("title") or tech_node, weak.get("refs") or [])
        upsert_node(impact_node, "impact", impact.get("title") or impact_node, weak.get("refs") or [])

        edges.append({"source": entry_node, "target": weak_node, "type": "entry_to_weakness"})
        edges.append({"source": weak_node, "target": tech_node, "type": "weakness_to_technique"})
        edges.append({"source": tech_node, "target": impact_node, "type": "technique_to_impact"})

        for c in controls:
            cid = c.get("control_id")
            if not cid:
                continue
            upsert_node(cid, "control", c.get("title") or cid, [])
            edges.append({"source": impact_node, "target": cid, "type": "impact_to_control"})

    node_list = sorted(nodes.values(), key=lambda n: (n["type"], n["id"]))
    edge_list = sorted(edges, key=lambda e: (e["source"], e["target"], e["type"]))
    return {"nodes": node_list, "edges": edge_list}


def _make_summary(paths: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(paths)
    max_score = max((p["score"]["score_0_100"] for p in paths), default=0)
    high = sum(1 for p in paths if p["score"]["bucket"] in {"High", "Critical"})
    med = sum(1 for p in paths if p["score"]["bucket"] == "Medium")
    low = sum(1 for p in paths if p["score"]["bucket"] == "Low")

    top3 = [
        {"path_id": p["id"], "score": p["score"]["score_0_100"], "weakness_id": p["weakness"]["weakness_id"]}
        for p in paths[:3]
    ]

    return {
        "total_paths": total,
        "max_score": max_score,
        "high_count": high,
        "medium_count": med,
        "low_count": low,
        "top_3": top3,
    }


def _dedupe_paths(paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    best: Dict[str, Dict[str, Any]] = {}
    for p in paths:
        k = f"{p['entry']['entry_id']}|{p['weakness']['weakness_id']}|{p['impact']['impact_id']}"
        cur = best.get(k)
        if cur is None or p["score"]["score_0_100"] > cur["score"]["score_0_100"]:
            best[k] = p
    out = list(best.values())
    out.sort(key=lambda p: (-p["score"]["score_0_100"], p["id"]))
    return out


def main(argv: List[str]) -> int:
    if len(argv) != 2:
        print("Usage: python scripts/attack_build.py output/evidence/evidence_<scan_id>.v1.json")
        return 2

    evidence_path = Path(argv[1])
    if not evidence_path.exists():
        print(f"Evidence file not found: {evidence_path}")
        return 2

    core_dir = _resolve_core_dir(Path(__file__))
    core = _load_core(core_dir)

    scan_id, _evidence_raw, evidences = _load_evidence_file(evidence_path)
    idx = _index_evidences(evidences)

    entries = _build_entries(core, idx)
    weaknesses = _build_weaknesses(core, idx, entries)

    weakness_catalog_by_id = _index_by_id(core.weakness_catalog.get("weaknesses", []), "weakness_id")

    paths: List[Dict[str, Any]] = []
    for w in weaknesses:
        wid = w.get("weakness_id")
        if not wid:
            continue
        wcat = weakness_catalog_by_id.get(wid)
        if not wcat:
            continue

        entry = _select_entry_for_weakness(w, entries)
        if not entry:
            continue

        impact = _select_impact(core, wcat)
        technique = _select_technique(core, wid)
        controls = _select_controls(core, wid, entry["entry_id"])

        ref_ids = set(w.get("refs") or [])
        evidence_objs = [ev for ev in evidences if ev.id in ref_ids]
        entry_ids_present = list(entries.keys())

        score = _score_path(
            core=core,
            weakness_def={**wcat, **{"confidence": w.get("confidence"), "weakness_id": wid}},
            impact_def=impact,
            entry_ids_present=entry_ids_present,
            weakness_refs=evidence_objs,
        )

        path_id = f"path:{scan_id}:{wid}:{entry['entry_id']}:{impact['impact_id']}"
        path_refs = sorted(set((entry.get("refs") or []) + (w.get("refs") or [])))

        paths.append(
            {
                "id": path_id,
                "entry": entry,
                "weakness": {
                    "weakness_id": wid,
                    "title": wcat.get("title"),
                    "category": wcat.get("category"),
                    "cia": wcat.get("cia"),
                    "base_likelihood": wcat.get("base_likelihood"),
                    "rule_id": w.get("rule_id"),
                    "confidence": w.get("confidence"),
                    "refs": w.get("refs") or [],
                },
                "technique": technique,
                "impact": {
                    "impact_id": impact.get("impact_id"),
                    "title": impact.get("title"),
                    "tier": impact.get("tier"),
                    "cia": impact.get("cia"),
                    "base_weight": impact.get("base_weight"),
                },
                "controls": controls,
                "score": score,
                "refs": path_refs,
            }
        )

    paths.sort(key=lambda p: (-p["score"]["score_0_100"], p["id"]))
    paths = _dedupe_paths(paths)

    max_paths = int(core.path_policy.get("path_model", {}).get("max_paths_per_target", 50))
    paths = paths[:max_paths]

    graph = _make_graph(paths)
    summary = _make_summary(paths)

    out_dir = Path("output") / "attack"
    out_paths = out_dir / f"attack_paths_{scan_id}.v1.json"
    out_graph = out_dir / f"attack_graph_{scan_id}.v1.json"
    out_summary = out_dir / f"attack_summary_{scan_id}.v1.json"

    _write_json(out_paths, paths)
    _write_json(out_graph, graph)
    _write_json(out_summary, summary)

    print(f"paths: {len(paths)}")
    top = [p["score"]["score_0_100"] for p in paths[:3]]
    print(f"top3: {top}")
    print(f"files: {out_paths.as_posix()}, {out_graph.as_posix()}, {out_summary.as_posix()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

