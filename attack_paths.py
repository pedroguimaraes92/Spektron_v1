"""Spektron v1 — Attack Paths UI

CONGELADO (UI module only):
 - Does NOT touch global QSS / background / sidebar / topbar.
 - Reads ONLY offline JSON outputs from output/attack.
 - Hub mode mirrors SettingsView hub pattern (single card + tiles).
 - Viewer mode is a close match to the provided mock.

Files read (offline):
  output/attack/attack_paths_<scan_id>.v1.json
  output/attack/attack_summary_<scan_id>.v1.json
  output/attack/attack_graph_<scan_id>.v1.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QColor, QFont, QPixmap, QIcon, QPainter, QLinearGradient, QPen, QFontMetrics
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QFrame,
    QPushButton,
    QGraphicsDropShadowEffect,
    QSizePolicy,
    QStackedWidget,
    QStackedLayout,
    QScrollArea,
    QButtonGroup,
)


ROOT = Path(__file__).resolve().parent
ASSETS = ROOT / "assets"
ICONS = ASSETS / "icons"


def _ui_font(px: int, weight=QFont.Weight.Normal) -> QFont:
    """Unified font helper.

    NOTE: PySide6 expects QFont.Weight (enum) for setWeight(). Some legacy Qt
    constants are ints (e.g., QFont.Weight.Bold == 75). We convert deterministically.
    """
    f = QFont("Segoe UI")
    if not f.exactMatch():
        f = QFont("Inter")
    if not f.exactMatch():
        f = QFont("Arial")
    f.setPixelSize(int(px))

    try:
        if isinstance(weight, QFont.Weight):
            w = weight
        else:
            w = QFont.Weight(int(weight))
    except Exception:
        w = QFont.Weight.Normal

    f.setWeight(w)
    return f


def _safe_read_json(path: Path) -> Any:
    try:
        if not path.exists():
            return None
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None



def _score_to_float(v: Any) -> Optional[float]:
    """Extract numeric score (0-100) from varied JSON shapes."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        try:
            return float(v)
        except Exception:
            return None
    if isinstance(v, str):
        try:
            return float(v.strip())
        except Exception:
            return None
    if isinstance(v, dict):
        # Spektron v1 shape: {"score_0_100": 56, "bucket": "High", ...}
        for k in ("score_0_100", "score", "value", "risk_score", "attack_path_score"):
            if k in v:
                try:
                    return float(v.get(k))
                except Exception:
                    pass
    return None


def _score_bucket(v: Any) -> str:
    if isinstance(v, dict):
        b = _first_str(v.get("bucket"), v.get("risk"), v.get("level"), default="")
        return b.strip()
    return ""


def _bucket_to_risk(bucket: str) -> Optional[str]:
    b = (bucket or "").strip().upper()
    if not b:
        return None
    if b in {"HIGH", "H"}:
        return "HIGH"
    if b in {"MED", "MEDIUM", "M"}:
        return "MEDIUM"
    if b in {"LOW", "L"}:
        return "LOW"
    return None


def _collect_refs(*vals: Any) -> List[str]:
    """Collect evidence ref IDs from multiple possible locations."""
    out: List[str] = []
    for v in vals:
        if v is None:
            continue
        if isinstance(v, list):
            out.extend([_str_or_empty(x) for x in v])
            continue
        if isinstance(v, dict):
            # common key is "refs"
            if "refs" in v:
                out.extend([_str_or_empty(x) for x in _to_list(v.get("refs"))])
            continue
        s = _str_or_empty(v)
        if s:
            out.append(s)

    # de-dup while preserving order
    seen = set()
    dedup: List[str] = []
    for s in out:
        k = s.strip().lower()
        if k and k not in seen:
            seen.add(k)
            dedup.append(s)
    return dedup


def _read_evidence_output(scan_id: str) -> Any:
    """Best-effort read of offline evidence output (if present)."""
    base = ROOT / "output" / "evidence"
    p1 = base / f"evidence_{scan_id}.v1.json"
    p2 = base / f"evidence_{scan_id}.json"
    return _safe_read_json(p1) or _safe_read_json(p2)


def _build_evidence_map(doc: Any) -> Dict[str, str]:
    """Map evidence_id -> short human text.

    Spektron evidence output uses:
      {"evidences": [ {id, type, value{...}, ...}, ... ]}

    We also accept legacy shapes (evidence/items/results, list, or dict keyed by id).
    """
    def _ev_text(it: Dict[str, Any]) -> str:
        et = _first_str(it.get("type"), it.get("kind"), default="").strip()
        v = it.get("value") if isinstance(it.get("value"), dict) else {}
        # Deterministic, professional summaries (no invented claims).
        if et == "http.header.missing":
            name = _first_str(v.get("name"), default="").strip()
            url = _first_str(v.get("url"), default="").strip()
            if name and url:
                return f"Missing HTTP header: {name} ({url})"
            if name:
                return f"Missing HTTP header: {name}"
        if et == "http.header.present":
            name = _first_str(v.get("name"), default="").strip()
            if name:
                return f"HTTP header present: {name}"
        if et.startswith("http.banner."):
            key = et.split(".", 2)[-1].replace("_", "-")
            val = _first_str(v.get("value"), v.get("banner"), default="").strip()
            if val:
                return f"{key} banner exposed: {val}"
        if et == "http.status":
            url = _first_str(v.get("url"), default="").strip()
            st = v.get("status")
            if url and st is not None:
                return f"HTTP status {st} on {url}"
        if et == "net.service.https":
            url = _first_str(v.get("url"), default="").strip()
            st = v.get("status")
            if url and st is not None:
                return f"HTTPS reachable ({st}) on {url}"
            if url:
                return f"HTTPS reachable on {url}"
        if et == "net.port.open":
            port = v.get("port")
            proto = _first_str(v.get("proto"), default="tcp").strip() or "tcp"
            svc = _first_str(v.get("service_hint"), default="").strip()
            if port is not None and svc:
                return f"Open {proto.upper()} port {port} ({svc})"
            if port is not None:
                return f"Open {proto.upper()} port {port}"
        if et.startswith("dns.record."):
            rr = et.split(".", 2)[-1].upper()
            host = _first_str(v.get("host"), default="").strip()
            ip = _first_str(v.get("ip"), default="").strip()
            if host and ip:
                return f"DNS {rr}: {host} → {ip}"
        if et == "tls.version":
            ver = _first_str(v.get("version"), default="").strip()
            if ver:
                return f"TLS version: {ver}"
        if et == "tls.cipher_suite":
            name = _first_str(v.get("name"), default="").strip()
            if name:
                return f"TLS cipher suite: {name}"
        if et == "tls.verify":
            verified = v.get("verified")
            if verified is True:
                return "TLS certificate verified"
            if verified is False:
                err = _first_str(v.get("error"), default="").strip()
                return f"TLS certificate verification failed{': ' + err if err else ''}"
        if et == "tls.cert.expiry_days":
            days = v.get("days")
            if days is not None:
                return f"TLS certificate expires in {days} days"
        if et == "tls.present":
            present = v.get("present")
            if present is True:
                return "TLS supported"
        # Fallback: prefer explicit text fields, otherwise concise type + value.
        text = _first_str(
            it.get("text"),
            it.get("summary"),
            it.get("title"),
            it.get("label"),
            default="",
        ).strip()
        if text:
            return text
        if et:
            if isinstance(v, dict) and v:
                # pick a stable single value if present
                for k in ("name", "url", "value", "host", "ip", "status", "port"):
                    if k in v:
                        return f"{et}: {v.get(k)}"
            return et
        return ""

    items: List[Any] = []
    if isinstance(doc, list):
        items = doc
    elif isinstance(doc, dict):
        # sometimes already keyed by id
        if all(isinstance(k, str) and isinstance(v, dict) for k, v in doc.items()) and any(
            isinstance(v, dict) and ("type" in v or "text" in v or "title" in v) for v in doc.values()
        ):
            for k, v in doc.items():
                vv = dict(v)
                vv.setdefault("id", k)
                items.append(vv)
        else:
            items = (
                doc.get("evidences")
                or doc.get("evidence")
                or doc.get("items")
                or doc.get("results")
                or doc.get("facts")
                or doc.get("signals")
                or doc.get("entries")
                or []
            )
            if not isinstance(items, list):
                items = []

    out: Dict[str, str] = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        eid = _first_str(it.get("id"), it.get("evidence_id"), it.get("uid"), it.get("ref"), default="").strip()
        if not eid:
            continue
        txt = _ev_text(it).strip()
        if txt:
            out[eid] = txt

    return out


def _resolve_evidence(ref_ids: List[str], ev_map: Dict[str, str]) -> List[str]:
    if not ref_ids or not ev_map:
        return []
    out: List[str] = []
    for rid in ref_ids:
        t = ev_map.get(rid)
        if t:
            out.append(t)
    # de-dup while preserving order
    seen = set()
    dedup: List[str] = []
    for s in out:
        k = s.strip().lower()
        if k and k not in seen:
            seen.add(k)
            dedup.append(s)
    return dedup

def _to_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def _str_or_empty(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v.strip()
    try:
        return str(v).strip()
    except Exception:
        return ""


def _first_str(*vals: Any, default: str = "") -> str:
    for v in vals:
        s = _str_or_empty(v)
        if s:
            return s
    return default


def _node_text(node: Any) -> str:
    """Best-effort string extraction for node-like fields.

JSON formats can vary. We try common keys first.
"""
    if node is None:
        return ""
    if isinstance(node, str):
        return node.strip()
    if isinstance(node, (int, float, bool)):
        return str(node)
    if isinstance(node, dict):
        return _first_str(
            node.get("label"),
            node.get("title"),
            node.get("name"),
            node.get("text"),
            node.get("value"),
            node.get("ref"),
            node.get("id"),
        )
    if isinstance(node, list):
        parts = [_node_text(x) for x in node]
        parts = [p for p in parts if p]
        return "; ".join(parts)
    return _str_or_empty(node)


def _items_to_strings(items: Any) -> List[str]:
    out: List[str] = []
    for it in _to_list(items):
        if it is None:
            continue
        if isinstance(it, str):
            s = it.strip()
            if s:
                out.append(s)
            continue
        if isinstance(it, dict):
            s = _first_str(
                it.get("text"),
                it.get("title"),
                it.get("label"),
                it.get("name"),
                it.get("value"),
                default="",
            )
            if s:
                out.append(s)
            continue
        try:
            s = str(it).strip()
            if s:
                out.append(s)
        except Exception:
            pass
    # de-dup while preserving order
    seen = set()
    dedup: List[str] = []
    for s in out:
        k = s.strip().lower()
        if k and k not in seen:
            seen.add(k)
            dedup.append(s)
    return dedup



def _elide_multiline(text: str, font: QFont, width: int, max_lines: int = 2) -> str:
    """Word-wrap to up to N lines and elide the last line if needed."""
    t = (text or "").strip()
    if not t:
        return ""
    try:
        fm = QFontMetrics(font)
    except Exception:
        return t
    words = t.split()
    if not words:
        return t

    lines: List[str] = []
    cur = ""
    wi = 0
    while wi < len(words) and len(lines) < max_lines:
        w = words[wi]
        trial = (cur + " " + w).strip()
        if not cur:
            # first token always starts the line
            cur = w
            wi += 1
            continue
        if fm.horizontalAdvance(trial) <= width:
            cur = trial
            wi += 1
            continue
        # line full
        lines.append(cur)
        cur = ""
        if len(lines) == max_lines - 1:
            break

    if cur and len(lines) < max_lines:
        lines.append(cur)

    # remaining words -> append to last line and elide
    if wi < len(words) and lines:
        tail = " ".join(words[wi:])
        last = (lines[-1] + " " + tail).strip()
        lines[-1] = fm.elidedText(last, Qt.ElideRight, width)

    # safety: ensure last line fits
    if lines:
        if fm.horizontalAdvance(lines[-1]) > width:
            lines[-1] = fm.elidedText(lines[-1], Qt.ElideRight, width)

    return "\n".join(lines[:max_lines])
def _tech_display(v: Any) -> str:
    """Professional technique display.
    - If technique_id is present, show: "<ID> — <Title>"
    - If unknown/unspecified, show neutral inference text (no amateur phrasing).
    """
    if v is None:
        return ""
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return ""
        s_low = s.lower()
        if "unspecified" in s_low or "unknown" in s_low:
            return "Technique inference (passive)"
        return s
    if isinstance(v, dict):
        tid = _first_str(v.get("technique_id"), v.get("id"), v.get("technique"), default="").strip()
        title = _first_str(v.get("title"), v.get("name"), v.get("label"), default="").strip()
        t_low = (title or "").lower()
        if tid.lower().startswith("custom") or "unspecified" in t_low or "unknown" in t_low:
            return "Technique inference (passive)"
        if tid and title:
            return f"{tid} — {title}"
        if title:
            return title
        if tid:
            return tid
    return _node_text(v)



def _risk_from_value(risk: Any, score: Optional[float]) -> str:
    r = _str_or_empty(risk).upper()
    if r in {"HIGH", "MED", "MEDIUM", "LOW"}:
        return "MEDIUM" if r == "MED" else r

    # Fallback only (when JSON has no explicit risk):
    # Keep it deterministic and conservative.
    if score is None:
        return "LOW"
    try:
        s = float(score)
    except Exception:
        return "LOW"
    if s >= 50:
        return "HIGH"
    if s >= 25:
        return "MEDIUM"
    return "LOW"


def _risk_icon_file(risk: str) -> str:
    r = (risk or "").upper().strip()
    if r == "HIGH":
        return "icon_high.png"
    if r in {"MED", "MEDIUM"}:
        return "icon_medium.png"
    return "icon_low.png"


def _existing_icon(fname: str, fallback: str) -> Path:
    p = ICONS / fname
    if p.exists():
        return p
    # Fallback required by spec — do not invent icons.
    return ICONS / fallback


def _read_attack_outputs(scan_id: str) -> Tuple[Any, Any, Any]:
    base = ROOT / "output" / "attack"
    paths_p = base / f"attack_paths_{scan_id}.v1.json"
    summary_p = base / f"attack_summary_{scan_id}.v1.json"
    graph_p = base / f"attack_graph_{scan_id}.v1.json"
    return _safe_read_json(paths_p), _safe_read_json(summary_p), _safe_read_json(graph_p)



def _extract_paths(doc: Any) -> List[Dict[str, Any]]:
    """Normalize attack_paths JSON into a list of dicts.

We support multiple shapes:
 - {"paths": [...]} or {"attack_paths": [...]} or {"items": [...]}
 - [ ... ]

Each normalized entry contains:
  id, score, risk, entry, weakness, technique, impact, evidence[], controls[], refs[]
"""
    raw_list: List[Any] = []
    if isinstance(doc, list):
        raw_list = doc
    elif isinstance(doc, dict):
        raw_list = (
            doc.get("paths")
            or doc.get("attack_paths")
            or doc.get("items")
            or doc.get("results")
            or []
        )
        if not isinstance(raw_list, list):
            raw_list = []

    out: List[Dict[str, Any]] = []
    for idx, it in enumerate(raw_list):
        if not isinstance(it, dict):
            out.append(
                {
                    "id": str(idx),
                    "score": None,
                    "risk": "LOW",
                    "entry": "",
                    "weakness": _node_text(it),
                    "technique": "",
                    "impact": "",
                    "evidence": [],
                    "controls": [],
                    "refs": [],
                    "_raw": it,
                }
            )
            continue

        pid = _first_str(it.get("id"), it.get("path_id"), it.get("uid"), default=str(idx))

        # score can be numeric OR object (Spektron v1 uses {"score_0_100": ...})
        score_obj = it.get("score")
        if score_obj is None:
            score_obj = it.get("attack_path_score")
        if score_obj is None:
            score_obj = it.get("risk_score")

        score = _score_to_float(score_obj)
        bucket = _score_bucket(score_obj)

        # node objects (keep raw for refs + better text formatting)
        entry_obj = it.get("entry") or it.get("entry_point") or it.get("start")
        weakness_obj = it.get("weakness") or it.get("finding") or it.get("vulnerability")
        technique_obj = (
            it.get("technique")
            or it.get("technique_ref")
            or it.get("techniqueRef")
            or it.get("mitre")
            or it.get("step_technique")
        )
        impact_obj = it.get("impact") or it.get("outcome") or it.get("goal")

        entry = _node_text(entry_obj)
        weakness = _node_text(weakness_obj)

        # technique: prefer MITRE id + title when available; hide "Unspecified..." copy
        technique = _node_text(technique_obj)
        if isinstance(technique_obj, dict):
            tid = _first_str(technique_obj.get("technique_id"), technique_obj.get("id"), default="").strip()
            title = _first_str(technique_obj.get("title"), technique_obj.get("label"), technique_obj.get("name"), default="").strip()
            fw = _first_str(technique_obj.get("framework"), default="").strip().lower()
            if fw == "mitre" and tid and title:
                technique = f"{tid} — {title}"
            elif title:
                technique = title
            # professional fallback for unknown technique
            if tid in {"custom:unknown", "unknown"} or (title and title.lower().startswith("unspecified")):
                technique = "Technique inference (passive)"

        impact = _node_text(impact_obj)

        # evidence may be inline in some engines; Spektron v1 stores refs (ev_...) instead
        evidence = _items_to_strings(
            it.get("evidence")
            or it.get("evidence_supporting_this_path")
            or it.get("evidence_supporting")
            or it.get("signals")
            or it.get("proof")
        )

        controls = _items_to_strings(
            it.get("controls")
            or it.get("how_to_cut")
            or it.get("mitigations")
            or it.get("recommendations")
            or it.get("remediations")
        )

        # collect evidence refs (path.refs + node.refs)
        refs = _collect_refs(it.get("refs"), entry_obj, weakness_obj, technique_obj, impact_obj)

        # Risk can be explicit, derived from bucket, or fallback to score thresholds
        risk_raw = it.get("risk")
        if risk_raw is None:
            risk_raw = it.get("severity")
        if risk_raw is None:
            risk_raw = it.get("level")

        risk = _risk_from_value(risk_raw, score)
        b_risk = _bucket_to_risk(bucket)
        if b_risk and (risk_raw is None or str(risk_raw).strip() == ""):
            risk = b_risk

        out.append(
            {
                "id": pid,
                "score": score,
                "risk": risk,
                "entry": entry,
                "weakness": weakness,
                "technique": technique,
                "impact": impact,
                "evidence": evidence,
                "controls": controls,
                "refs": refs,
                "_raw": it,
            }
        )

    def _score_key(p: Dict[str, Any]) -> float:
        s = p.get("score")
        try:
            return float(s) if s is not None else -1.0
        except Exception:
            return -1.0

    out.sort(key=_score_key, reverse=True)
    return out


def _summary_from_docs(paths: List[Dict[str, Any]], summary_doc: Any) -> Dict[str, Any]:
    # Prefer summary json if present
    if isinstance(summary_doc, dict):
        total = summary_doc.get("total_paths") or summary_doc.get("total")
        max_score = summary_doc.get("max_score") or summary_doc.get("max")
        high = summary_doc.get("high") or summary_doc.get("high_count")
        med = summary_doc.get("medium") or summary_doc.get("med") or summary_doc.get("medium_count")
        low = summary_doc.get("low") or summary_doc.get("low_count")
        try:
            if total is not None and max_score is not None:
                return {
                    "total": int(total),
                    "max_score": int(float(max_score)),
                    "high": int(high) if high is not None else None,
                    "medium": int(med) if med is not None else None,
                    "low": int(low) if low is not None else None,
                }
        except Exception:
            pass

    # Fallback: compute from normalized paths
    total = len(paths)
    max_score = 0
    hi = 0
    md = 0
    lo = 0
    for p in paths:
        s = p.get("score")
        try:
            max_score = max(max_score, int(float(s or 0)))
        except Exception:
            pass
        r = (p.get("risk") or "LOW").upper()
        if r == "HIGH":
            hi += 1
        elif r in {"MED", "MEDIUM"}:
            md += 1
        else:
            lo += 1
    return {"total": total, "max_score": max_score, "high": hi, "medium": md, "low": lo}


class _HubTileButton(QPushButton):
    """Same concept and sizing as SettingsView hub tiles (single card, no nested cards)."""

    def __init__(self, title: str, subtitle: str, icon_file: str, parent=None):
        super().__init__(parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setCheckable(False)
        self.setFixedHeight(96)
        self.setMinimumWidth(420)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        icon = QIcon(str(_existing_icon(icon_file, "icon_attack_paths.png")))

        self._title = QLabel(title)
        self._title.setFont(_ui_font(14, QFont.Weight.DemiBold))
        self._title.setStyleSheet("color: rgba(255,255,255,235);")

        self._subtitle = QLabel(subtitle)
        self._subtitle.setFont(_ui_font(11, QFont.Weight.Normal))
        self._subtitle.setStyleSheet("color: rgba(255,255,255,140);")

        self._icon = QLabel()
        self._icon.setFixedSize(44, 44)
        self._icon.setAlignment(Qt.AlignCenter)
        self._icon.setStyleSheet("background: transparent;")
        pm = icon.pixmap(QSize(34, 34))
        if not pm.isNull():
            self._icon.setPixmap(pm)

        icon_glow = QGraphicsDropShadowEffect()
        icon_glow.setBlurRadius(18)
        icon_glow.setOffset(0, 0)
        icon_glow.setColor(QColor(124, 255, 158, 70))
        self._icon.setGraphicsEffect(icon_glow)

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(4)
        text_col.addWidget(self._title)
        text_col.addWidget(self._subtitle)
        text_col.addStretch(1)

        row = QHBoxLayout()
        row.setContentsMargins(18, 14, 18, 14)
        row.setSpacing(14)
        row.addWidget(self._icon)
        row.addLayout(text_col, 1)

        self.setLayout(row)
        self.setStyleSheet(
            """
            QPushButton {
                background-color: rgba(0,0,0,22);
                border: 1px solid rgba(124,255,158,26);
                border-radius: 14px;
                text-align: left;
            }
            QPushButton:hover {
                background-color: rgba(124,255,158,8);
                border: 1px solid rgba(124,255,158,44);
            }
            QPushButton:pressed {
                background-color: rgba(124,255,158,12);
                border: 1px solid rgba(124,255,158,70);
            }
            """
        )

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(18)
        shadow.setOffset(0, 6)
        shadow.setColor(QColor(0, 0, 0, 110))
        self.setGraphicsEffect(shadow)


class _GlowLine(QWidget):
    """A thin horizontal line with subtle glow (used between diagram nodes)."""

    def __init__(self, left: QColor, right: QColor, parent=None):
        super().__init__(parent)
        self._left = left
        self._right = right
        self.setFixedHeight(16)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def paintEvent(self, event):
        w = self.width()
        h = self.height()
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        # main line
        g = QLinearGradient(0, 0, w, 0)
        g.setColorAt(0.0, QColor(self._left.red(), self._left.green(), self._left.blue(), 220))
        g.setColorAt(1.0, QColor(self._right.red(), self._right.green(), self._right.blue(), 220))
        pen = QPen()
        pen.setWidth(8)
        pen.setBrush(g)
        pen.setCapStyle(Qt.RoundCap)
        p.setPen(pen)
        p.drawLine(0, h // 2, w, h // 2)

        # glow
        g2 = QLinearGradient(0, 0, w, 0)
        g2.setColorAt(0.0, QColor(self._left.red(), self._left.green(), self._left.blue(), 110))
        g2.setColorAt(1.0, QColor(self._right.red(), self._right.green(), self._right.blue(), 110))
        pen2 = QPen()
        pen2.setWidth(22)
        pen2.setBrush(g2)
        pen2.setCapStyle(Qt.RoundCap)
        p.setPen(pen2)
        p.drawLine(0, h // 2, w, h // 2)





class _DiagramRail(QWidget):
    """Attack chain rail (mock-like).

    Goals:
    - No "tube" look (thin core + subtle glow).
    - Do NOT cut through outline icons.
    - Segment the rail BETWEEN nodes (gaps around icon plates).
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setFixedHeight(90)

        self._nodes: List['_NodeBlock'] = []

    def set_nodes(self, nodes: List['_NodeBlock']) -> None:
        self._nodes = [n for n in (nodes or []) if n is not None]
        self.update()

    def _centers(self) -> List[Tuple[int, int]]:
        """Return [(x,y), ...] centers for node icon plates in rail coordinates."""
        pts: List[Tuple[int, int]] = []
        for n in self._nodes:
            try:
                x, y = n.plate_center_in(self)
                pts.append((int(x), int(y)))
            except Exception:
                pass

        if len(pts) == 4:
            return pts

        # fallback (evenly spaced)
        w = max(1, self.width())
        y = 43
        xs = [int(w * 0.18), int(w * 0.42), int(w * 0.66), int(w * 0.90)]
        return [(xs[0], y), (xs[1], y), (xs[2], y), (xs[3], y)]

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        pts = self._centers()
        if len(pts) != 4:
            return

        # Gap around plates so the rail NEVER passes under the icon.
        plate_half = 31
        gap = plate_half + 10

        x0, y = pts[0]
        x3, _ = pts[3]
        start = x0 + gap
        end = x3 - gap
        if end <= start:
            return

        # 1) Base track (dark, subtle)
        track_pen = QPen(QColor(255, 255, 255, 22))
        track_pen.setWidth(6)
        track_pen.setCapStyle(Qt.RoundCap)
        p.setPen(track_pen)
        p.drawLine(start, y, end, y)

        # Helper to draw one segment with glow + core
        def draw_segment(xa: int, xb: int, ca: QColor, cb: QColor):
            if xb <= xa:
                return

            # glow
            g_glow = QLinearGradient(xa, 0, xb, 0)
            g_glow.setColorAt(0.0, QColor(ca.red(), ca.green(), ca.blue(), 70))
            g_glow.setColorAt(1.0, QColor(cb.red(), cb.green(), cb.blue(), 70))
            pen_glow = QPen()
            pen_glow.setWidth(16)
            pen_glow.setBrush(g_glow)
            pen_glow.setCapStyle(Qt.RoundCap)
            p.setPen(pen_glow)
            p.drawLine(xa, y, xb, y)

            # core
            g = QLinearGradient(xa, 0, xb, 0)
            g.setColorAt(0.0, QColor(ca.red(), ca.green(), ca.blue(), 220))
            g.setColorAt(1.0, QColor(cb.red(), cb.green(), cb.blue(), 220))
            pen = QPen()
            pen.setWidth(6)
            pen.setBrush(g)
            pen.setCapStyle(Qt.RoundCap)
            p.setPen(pen)
            p.drawLine(xa, y, xb, y)

        # segment endpoints (gap around each node)
        c0x, _ = pts[0]
        c1x, _ = pts[1]
        c2x, _ = pts[2]
        c3x, _ = pts[3]

        s0 = c0x + gap
        e0 = c1x - gap
        s1 = c1x + gap
        e1 = c2x - gap
        s2 = c2x + gap
        e2 = c3x - gap

        green = QColor(124, 255, 158)
        yellow = QColor(255, 206, 120)
        orange = QColor(255, 155, 80)
        red = QColor(255, 90, 90)

        draw_segment(s0, e0, green, yellow)
        draw_segment(s1, e1, yellow, orange)
        draw_segment(s2, e2, orange, red)


class _RailPixmap(QLabel):
    """PNG rail layer (transparent background), aligned to the mock.

    - Drawn as a QLabel pixmap (no paintEvent math).
    - Pixmap is kept TOP-aligned so the rail sits at the same Y as the node plates.
    """

    def __init__(self, img_path: Path, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.setStyleSheet("background: transparent;")
        self.setAlignment(Qt.AlignHCenter | Qt.AlignTop)

        self._src = QPixmap(str(img_path)) if (img_path and img_path.exists()) else QPixmap()
        self._src_h = int(self._src.height()) if not self._src.isNull() else 0

    def _refresh(self) -> None:
        if self._src.isNull():
            self.clear()
            return
        w = max(1, int(self.width()))
        h = max(1, int(self._src_h))
        pm = self._src.scaled(w, h, Qt.IgnoreAspectRatio, Qt.SmoothTransformation)
        self.setPixmap(pm)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._refresh()

    def showEvent(self, e):
        super().showEvent(e)
        self._refresh()




class _NodeBlock(QFrame):
    """Single node in the attack chain (Entry/Weakness/Technique/Impact).

    UI NOTE:
    - Icons are outline/transparent PNGs. A continuous rail behind them will "cut through" the icon.
      To match the mock, we draw a subtle backplate under the icon to mask the rail.
    """

    def __init__(self, title: str, icon_file: str, glow: QColor, parent=None):
        super().__init__(parent)
        self.setObjectName("node")
        self.setStyleSheet("QFrame#node { background: transparent; }")
        self.setFixedWidth(264)

        # Backplate to mask the rail behind outline icons
        self._plate = QFrame()
        self._plate.setFixedSize(76, 76)
        self._plate.setStyleSheet(
            """
            QFrame {
                background-color: rgba(0,0,0,26);
                border: 1px solid rgba(255,255,255,10);
                border-radius: 38px;
            }
            """
        )

        self._icon = QLabel(self._plate)
        self._icon.setFixedSize(76, 76)
        self._icon.setAlignment(Qt.AlignCenter)
        self._icon.setStyleSheet("background: transparent;")

        pm = QPixmap(str(_existing_icon(icon_file, "icon_attack_paths.png")))
        if not pm.isNull():
            self._icon.setPixmap(pm.scaled(66, 66, Qt.KeepAspectRatio, Qt.SmoothTransformation))

        eff = QGraphicsDropShadowEffect()
        eff.setBlurRadius(34)
        eff.setOffset(0, 0)
        eff.setColor(glow)
        self._plate.setGraphicsEffect(eff)

        self._title = QLabel(title)
        self._title.setFont(_ui_font(14, QFont.Weight.DemiBold))
        self._title.setStyleSheet("color: rgba(255,255,255,232);")
        self._title.setAlignment(Qt.AlignHCenter)

        self._detail = QLabel("—")
        self._detail.setFont(_ui_font(11, QFont.Weight.Normal))
        self._detail.setStyleSheet("color: rgba(255,255,255,150);")
        self._detail.setAlignment(Qt.AlignHCenter)
        self._detail.setWordWrap(True)
        self._detail.setFixedHeight(72)  # more breathing room (3 lines + padding)

        v = QVBoxLayout()
        # Top margin aligns the plate center over the rail (y=44 in _DiagramRail)
        v.setContentsMargins(0, 6, 0, 0)
        v.setSpacing(6)
        v.addWidget(self._plate, 0, Qt.AlignHCenter)
        v.addWidget(self._title)
        v.addWidget(self._detail)
        self.setLayout(v)

    def plate_center_in(self, widget: QWidget) -> Tuple[int, int]:
        """Center of the icon plate in coordinates of *widget*."""
        # plate is the visual anchor for the rail
        c = self._plate.rect().center()
        pt = self._plate.mapTo(widget, c)
        return int(pt.x()), int(pt.y())

    def set_detail(self, text: str) -> None:
        t = (text or "").strip() or "—"
        width = int(self.width()) - 18
        if t != "—":
            t = _elide_multiline(t, self._detail.font(), max(160, width), 3) or t
        self._detail.setText(t)





class _ScoreBlock(QFrame):
    """Attack Path Score badge (single card, no nested pill).

    User requirement:
    - Only ONE card.
    - Risk (HIGH/MED/LOW) is text inside the card, colored.
    - No notch/arrow.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("score_block")
        self.setFixedSize(170, 98)
        self.setStyleSheet("QFrame#score_block { background: transparent; }")

        self._border = QColor(255, 206, 120, 190)
        self._bg = QColor(0, 0, 0, 18)
        self._risk_color = QColor(255, 206, 120, 230)

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(28)
        shadow.setOffset(0, 10)
        shadow.setColor(QColor(0, 0, 0, 140))
        self.setGraphicsEffect(shadow)

        self._k = QLabel("ATTACK PATH SCORE")
        self._k.setFont(_ui_font(9, QFont.Weight.DemiBold))
        self._k.setStyleSheet("color: rgba(255,255,255,150); letter-spacing: 3px;")
        self._k.setAlignment(Qt.AlignHCenter)

        self._score = QLabel("—")
        self._score.setFont(_ui_font(34, QFont.Weight.Bold))
        self._score.setStyleSheet("color: rgba(255,255,255,244);")
        self._score.setAlignment(Qt.AlignHCenter)

        self._risk = QLabel("—")
        self._risk.setFont(_ui_font(12, QFont.Weight.Bold))
        self._risk.setAlignment(Qt.AlignHCenter)
        self._risk.setStyleSheet("color: rgba(255,206,120,230); letter-spacing: 3px;")

        v = QVBoxLayout()
        v.setContentsMargins(16, 12, 16, 12)
        v.setSpacing(4)
        v.addWidget(self._k)
        v.addWidget(self._score)
        v.addWidget(self._risk)
        self.setLayout(v)

        self.set_values("—", "—")

    def set_values(self, score_text: str, risk: str) -> None:
        s = (score_text or "—").strip() or "—"
        r = (risk or "—").strip().upper() or "—"
        if r == "MED":
            r = "MEDIUM"

        self._score.setText(s)
        self._risk.setText(r)

        if r == "HIGH":
            self._border = QColor(255, 155, 80, 210)
            self._bg = QColor(255, 155, 80, 8)
            self._risk_color = QColor(255, 155, 80, 235)
        elif r == "MEDIUM":
            self._border = QColor(255, 206, 120, 210)
            self._bg = QColor(255, 206, 120, 7)
            self._risk_color = QColor(255, 206, 120, 235)
        else:
            self._border = QColor(190, 210, 255, 190)
            self._bg = QColor(190, 210, 255, 6)
            self._risk_color = QColor(190, 210, 255, 235)

        self._risk.setStyleSheet(
            f"color: rgba({self._risk_color.red()}, {self._risk_color.green()}, {self._risk_color.blue()}, {self._risk_color.alpha()}); letter-spacing: 3px;"
        )
        self._score.setStyleSheet(
            f"color: rgba({self._risk_color.red()}, {self._risk_color.green()}, {self._risk_color.blue()}, 245);"
        )
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = self.rect().adjusted(2, 2, -2, -2)

        # Base fill gradient (subtle)
        g = QLinearGradient(0, r.top(), 0, r.bottom())
        g.setColorAt(0.0, QColor(self._bg.red(), self._bg.green(), self._bg.blue(), 44))
        g.setColorAt(0.6, QColor(0, 0, 0, 14))
        g.setColorAt(1.0, QColor(0, 0, 0, 8))
        p.setPen(Qt.NoPen)
        p.setBrush(g)
        p.drawRoundedRect(r, 18, 18)

        # Outer stroke
        pen = QPen(QColor(self._border.red(), self._border.green(), self._border.blue(), 200))
        pen.setWidth(2)
        p.setPen(pen)
        p.setBrush(Qt.NoBrush)
        p.drawRoundedRect(r, 18, 18)

        # Inner stroke
        pen2 = QPen(QColor(255, 255, 255, 18))
        pen2.setWidth(1)
        p.setPen(pen2)
        p.drawRoundedRect(r.adjusted(3, 3, -3, -3), 16, 16)

        super().paintEvent(event)



class _PathItemButton(QPushButton):
    def __init__(self, path: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setCheckable(True)
        self.setMinimumHeight(88)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)

        score = path.get("score")
        score_txt = "—"
        if score is not None:
            try:
                score_txt = str(int(float(score)))
            except Exception:
                score_txt = _str_or_empty(score) or "—"

        risk = (path.get("risk") or "LOW").upper()
        risk_label = "MED" if risk == "MEDIUM" else risk

        # Color accents for list items (score + risk)
        if risk == "HIGH":
            ar, ag, ab = 255, 155, 80
            accent = "rgba(255,155,80,240)"
        elif risk in {"MED", "MEDIUM"}:
            ar, ag, ab = 255, 206, 120
            accent = "rgba(255,206,120,240)"
        else:
            ar, ag, ab = 124, 255, 158
            accent = "rgba(124,255,158,230)"

        weakness = path.get("weakness") or "—"
        impact = path.get("impact") or "—"

        self._score = QLabel(score_txt)
        self._score.setFont(_ui_font(20, QFont.Weight.Bold))
        self._score.setStyleSheet(f"color: {accent};")

        self._risk = QLabel(risk_label)
        self._risk.setFont(_ui_font(10, QFont.Weight.DemiBold))
        self._risk.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self._risk.setStyleSheet(f"color: {accent};")

        self._risk_icon = QLabel()
        self._risk_icon.setFixedSize(18, 18)
        pm = QPixmap(str(_existing_icon(_risk_icon_file(risk), "icon_low.png")))
        if not pm.isNull():
            self._risk_icon.setPixmap(pm.scaled(16, 16, Qt.KeepAspectRatio, Qt.SmoothTransformation))

        title = QLabel(weakness)
        title.setFont(_ui_font(12, QFont.Weight.DemiBold))
        title.setStyleSheet("color: rgba(255,255,255,225);")
        title.setWordWrap(True)
        title.setFixedHeight(38)

        subtitle = QLabel(f"Impact: {impact}")
        subtitle.setFont(_ui_font(12, QFont.Weight.Normal))
        subtitle.setStyleSheet("color: rgba(255,255,255,135);")
        subtitle.setWordWrap(True)
        subtitle.setFixedHeight(34)

        left_col = QVBoxLayout()
        left_col.setContentsMargins(0, 0, 0, 0)
        left_col.setSpacing(2)
        left_col.addWidget(self._score)

        rrow = QHBoxLayout()
        rrow.setContentsMargins(0, 0, 0, 0)
        rrow.setSpacing(6)
        rrow.addWidget(self._risk_icon)
        rrow.addWidget(self._risk)
        rrow.addStretch(1)
        left_col.addLayout(rrow)
        left_w = QWidget()
        left_w.setLayout(left_col)
        left_w.setFixedWidth(70)
        left_w.setStyleSheet("background: transparent;")

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(4)
        text_col.addWidget(title)
        text_col.addWidget(subtitle)
        text_w = QWidget()
        text_w.setLayout(text_col)
        text_w.setStyleSheet("background: transparent;")

        row = QHBoxLayout()
        row.setContentsMargins(14, 12, 14, 12)
        row.setSpacing(12)
        row.addWidget(left_w)
        row.addWidget(text_w, 1)
        self.setLayout(row)

        self.setStyleSheet(
            f"""
            QPushButton {{
                background-color: transparent;
                border: none;
                border-left: 4px solid rgba(0,0,0,0);
                border-bottom: 1px solid rgba(255,255,255,10);
                text-align: left;
                padding-left: 12px;
                padding-right: 4px;
            }}
            QPushButton:hover {{
                background-color: rgba({ar},{ag},{ab},12);
                border-left: 4px solid rgba({ar},{ag},{ab},210);
            }}
            QPushButton:checked {{
                background-color: rgba(0,0,0,26);
                border-left: 4px solid rgba({ar},{ag},{ab},240);
                border-bottom: 1px solid rgba({ar},{ag},{ab},60);
            }}
            QPushButton:checked:hover {{
                background-color: rgba({ar},{ag},{ab},16);
            }}
            """
        )


class AttackPathsWidget(QWidget):
    """Attack Paths UI with Hub mode + Viewer mode (mock-like)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background: transparent;")

        self._current_scan_id: Optional[str] = None
        self._all_paths: List[Dict[str, Any]] = []
        self._summary_doc: Dict[str, Any] = {}
        self._evidence_map: Dict[str, str] = {}
        self._paths: List[Dict[str, Any]] = []
        self._summary: Dict[str, Any] = {"total": 0, "max_score": 0, "high": 0, "medium": 0, "low": 0}
        self._path_buttons: Dict[str, _PathItemButton] = {}
        self._path_by_id: Dict[str, Dict[str, Any]] = {}
        self._last_opened_by_scan: Dict[str, str] = {}

        # Icon cache
        self._pix_cache: Dict[str, QPixmap] = {}

        # Build UI shell (same alignment style as SettingsView)
        root = QVBoxLayout()
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.setAlignment(Qt.AlignTop)

        self._icon_label = QLabel()
        self._icon_label.setAlignment(Qt.AlignHCenter)
        self._set_top_icon("icon_attack_paths.png")

        icon_glow = QGraphicsDropShadowEffect()
        icon_glow.setBlurRadius(22)
        icon_glow.setOffset(0, 0)
        icon_glow.setColor(QColor(124, 255, 158, 60))
        self._icon_label.setGraphicsEffect(icon_glow)

        self._card = QFrame()
        self._card.setObjectName("attack_card")
        self._card.setMinimumWidth(1280)
        self._card.setMaximumWidth(1480)
        # IMPORTANT: do NOT force a tall minimum height.
        # If we do, the main window's body area becomes taller than the screen
        # and the sidebar bottom (About) gets clipped.
        self._card.setMinimumHeight(0)
        self._card.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self._card.setStyleSheet(
            """
            QFrame#attack_card {
                background-color: rgba(0,0,0,2);
                border: 1px solid rgba(124,255,158,22);
                border-radius: 18px;
            }
            """
        )

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(28)
        shadow.setOffset(0, 10)
        shadow.setColor(QColor(0, 0, 0, 120))
        self._card.setGraphicsEffect(shadow)

        card_layout = QVBoxLayout()
        card_layout.setContentsMargins(64, 44, 64, 44)
        card_layout.setSpacing(0)


        title = QLabel("Attack Paths")
        title.setFont(_ui_font(22, QFont.Weight.DemiBold))
        title.setStyleSheet("color: rgba(255,255,255,238);")
        title.setAlignment(Qt.AlignLeft)

        subtitle = QLabel("Attack Path Visualizer (Spektron v1)")
        subtitle.setFont(_ui_font(14, QFont.Weight.Normal))
        subtitle.setStyleSheet("color: rgba(255,255,255,135);")
        subtitle.setAlignment(Qt.AlignLeft)

        # Header icon (viewer only): centered on the same visual line as the title.
        self._header_icon = QLabel()
        self._header_icon.setFixedSize(120, 120)
        self._header_icon.setAlignment(Qt.AlignCenter)
        self._header_icon.setStyleSheet("background: transparent;")
        self._header_icon.setStyleSheet("background: transparent; margin-top: -8px;")
        hipm = self._pix("icon_attack_paths.png")
        if not hipm.isNull():
            self._header_icon.setPixmap(hipm.scaled(130, 130, Qt.KeepAspectRatio, Qt.SmoothTransformation))

        hglow = QGraphicsDropShadowEffect()
        hglow.setBlurRadius(26)
        hglow.setOffset(0, 0)
        hglow.setColor(QColor(124, 255, 158, 80))
        self._header_icon.setGraphicsEffect(hglow)
        self._header_icon.setVisible(False)

        left_block = QWidget()
        left_block.setStyleSheet("background: transparent;")
        left_block.setFixedWidth(460)
        left_v = QVBoxLayout()
        left_v.setContentsMargins(0, 0, 0, 0)
        left_v.setSpacing(8)
        left_v.addWidget(title)
        left_v.addWidget(subtitle)
        left_block.setLayout(left_v)

        right_spacer = QWidget()
        right_spacer.setFixedWidth(460)
        right_spacer.setStyleSheet("background: transparent;")

        header_row = QHBoxLayout()
        header_row.setContentsMargins(0, 0, 0, 0)
        header_row.setSpacing(0)
        header_row.setAlignment(Qt.AlignTop)
        header_row.addWidget(left_block)
        header_row.addStretch(1)
        header_row.addWidget(self._header_icon, 0, Qt.AlignTop | Qt.AlignHCenter)
        header_row.addStretch(1)
        header_row.addWidget(right_spacer)

        header_wrap = QWidget()
        header_wrap.setStyleSheet("background: transparent;")
        header_wrap.setLayout(header_row)

        card_layout.addWidget(header_wrap)
        card_layout.addSpacing(8)

        self._content_host = QWidget()
        self._content_host.setStyleSheet("background: transparent;")
        # IMPORTANT: never fix the content height. Let it shrink to fit the
        # available viewport so the main menu sidebar doesn't get clipped.
        self._content_host.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        host_layout = QVBoxLayout()
        host_layout.setContentsMargins(22, 22, 22, 22)
        host_layout.setSpacing(0)
        self._stack = QStackedWidget()
        self._stack.setStyleSheet("background: transparent;")
        host_layout.addWidget(self._stack)
        self._content_host.setLayout(host_layout)

        card_layout.addWidget(self._content_host)
        self._card.setLayout(card_layout)

        root.addSpacing(42)
        root.addWidget(self._icon_label, alignment=Qt.AlignHCenter)
        root.addSpacing(18)
        root.addWidget(self._card, alignment=Qt.AlignHCenter)
        root.addStretch(1)
        self.setLayout(root)

        # Build pages
        self._pages: Dict[str, QWidget] = {}
        self._build_hub_page()
        self._build_viewer_page()
        self._go_hub()

    # ==========================
    # Public API (Deep Links)
    # ==========================
    def set_scan_id(self, scan_id: Optional[str]) -> None:
        self._current_scan_id = (scan_id or "").strip() or None

    def open_last_attack_path(self, scan_id: str) -> None:
        self._current_scan_id = (scan_id or "").strip() or None
        self._ensure_loaded()
        target_id = None
        if self._current_scan_id:
            target_id = self._last_opened_by_scan.get(self._current_scan_id)
        if target_id is None and self._paths:
            target_id = self._paths[0]["id"]
        self._open_viewer(target_id)

    def open_top_risk(self, scan_id: str) -> None:
        self._current_scan_id = (scan_id or "").strip() or None
        self._ensure_loaded()

        # Top Risk = TOP 3 only (highest scores).
        top_ids: List[str] = []
        t3 = self._summary_doc.get("top_3") if isinstance(self._summary_doc, dict) else None
        if isinstance(t3, list):
            for it in t3:
                if isinstance(it, dict):
                    pid = _first_str(it.get("path_id"), it.get("id"), it.get("path"), default="").strip()
                    if pid:
                        top_ids.append(pid)

        if not top_ids:
            top_ids = [p["id"] for p in (self._all_paths or self._paths)[:3]]

        by_id = {p["id"]: p for p in (self._all_paths or [])}
        subset: List[Dict[str, Any]] = []
        for pid in top_ids:
            if pid in by_id:
                subset.append(by_id[pid])

        if not subset:
            subset = (self._all_paths or self._paths)[:3]

        self._paths = subset
        self._path_by_id = {p["id"]: p for p in self._paths}
        self._rebuild_path_list()

        top_id = self._paths[0]["id"] if self._paths else None
        self._open_viewer(top_id)


    def open_browser(self, scan_id: str) -> None:
        sid = (scan_id or "").strip()
        if not sid:
            # Sidebar entry point: open HUB
            self._go_hub()
            return
        self._current_scan_id = sid
        self._ensure_loaded()
        first_id = self._paths[0]["id"] if self._paths else None
        self._open_viewer(first_id)

    def open_path_by_id(self, scan_id: str, path_id: str) -> None:
        self._current_scan_id = (scan_id or "").strip() or None
        self._ensure_loaded()
        pid = (path_id or "").strip()
        self._open_viewer(pid if pid else None)

    # ==========================
    # Icons
    # ==========================
    def _set_top_icon(self, fname: str) -> None:
        pm = self._pix(fname)
        if not pm.isNull():
            self._icon_label.setPixmap(pm.scaled(118, 118, Qt.KeepAspectRatio, Qt.SmoothTransformation))

    def _pix(self, fname: str) -> QPixmap:
        if fname in self._pix_cache:
            return self._pix_cache[fname]
        pm = QPixmap(str(_existing_icon(fname, "icon_attack_paths.png")))
        if pm.isNull():
            pm = QPixmap(str(_existing_icon("icon_attack_paths.png", "icon_attack_paths.png")))
        self._pix_cache[fname] = pm
        return pm

    # ==========================
    # Navigation
    # ==========================
    def _go_hub(self) -> None:
        # HUB (tiles) is frozen: keep the top icon outside the card.
        try:
            self._icon_label.setVisible(True)
        except Exception:
            pass
        try:
            if hasattr(self, "_header_icon") and self._header_icon is not None:
                self._header_icon.setVisible(False)
        except Exception:
            pass
        self._stack.setCurrentWidget(self._pages["HUB"])

    def _go_viewer(self) -> None:
        # Viewer (Last / Top) — icon moves inside the card for a cleaner, product feel.
        try:
            self._icon_label.setVisible(False)
        except Exception:
            pass
        try:
            if hasattr(self, "_header_icon") and self._header_icon is not None:
                self._header_icon.setVisible(True)
        except Exception:
            pass
        self._stack.setCurrentWidget(self._pages["VIEWER"])

    # ==========================
    # Data loading
    # ==========================
    def _ensure_loaded(self) -> None:
        sid = self._current_scan_id
        if not sid:
            self._all_paths = []
            self._paths = []
            self._summary_doc = {}
            self._evidence_map = {}
            self._summary = {"total": 0, "max_score": 0, "high": 0, "medium": 0, "low": 0}
            self._path_by_id = {}
            self._rebuild_path_list()
            self._set_empty_state("No attack paths available for this scan.")
            return

        paths_doc, summary_doc, _graph_doc = _read_attack_outputs(sid)
        ev_doc = _read_evidence_output(sid)

        self._summary_doc = summary_doc if isinstance(summary_doc, dict) else {}
        self._evidence_map = _build_evidence_map(ev_doc)

        self._all_paths = _extract_paths(paths_doc)

        # Hydrate evidence column using refs -> evidence output (when available).
        if self._evidence_map:
            for p in self._all_paths:
                if not p.get("evidence"):
                    p["evidence"] = _resolve_evidence(p.get("refs", []), self._evidence_map)

        # Default visible set = ALL
        self._paths = self._all_paths
        self._summary = _summary_from_docs(self._all_paths, summary_doc)
        self._path_by_id = {p["id"]: p for p in self._paths}
        self._rebuild_path_list()

        if not self._paths:
            self._set_empty_state("No attack paths available for this scan.")
        else:
            self._set_empty_state("")


    # ==========================
    # Hub Page
    # ==========================
    def _build_hub_page(self) -> None:
        page = QWidget()
        page.setStyleSheet("background: transparent;")
        outer = QVBoxLayout()
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(12)

        title = QLabel("Configuration")
        title.setFont(_ui_font(13, QFont.Weight.DemiBold))
        title.setStyleSheet("color: rgba(255,255,255,215);")
        outer.addWidget(title)
        outer.addSpacing(6)

        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(14)

        btn_last = _HubTileButton(
            "Last Attack Path",
            "Open the last viewed path for the active scan",
            "icon_attack_paths.png",
        )
        btn_top = _HubTileButton(
            "Top Risk",
            "Open the highest score path for the active scan",
            "icon_high.png",
        )

        btn_last.clicked.connect(self._hub_open_last)
        btn_top.clicked.connect(self._hub_open_top)

        grid.addWidget(btn_last, 0, 0)
        grid.addWidget(btn_top, 0, 1)

        outer.addLayout(grid)
        outer.addStretch(1)
        page.setLayout(outer)

        self._pages["HUB"] = page
        self._stack.addWidget(page)

    def _hub_open_last(self) -> None:
        sid = self._current_scan_id or ""
        self.open_last_attack_path(sid)

    def _hub_open_top(self) -> None:
        sid = self._current_scan_id or ""
        self.open_top_risk(sid)

    def _hub_open_browse(self) -> None:
        sid = self._current_scan_id or ""
        if not sid:
            # No active scan — still open viewer with empty state.
            self._ensure_loaded()
            self._open_viewer(None)
            return
        self.open_browser(sid)

    # ==========================
    # Viewer Page
    # ==========================
    def _build_viewer_page(self) -> None:
        page = QWidget()
        page.setStyleSheet("background: transparent;")

        outer = QVBoxLayout()
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(12)
        # Header row inside viewer: Back + title + stats
        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(10)

        back_btn = QPushButton()
        back_btn.setCursor(Qt.PointingHandCursor)
        back_btn.setFixedSize(34, 34)
        back_btn.setIcon(QIcon(str(_existing_icon("icon_back.png", "icon_back.png"))))
        back_btn.setIconSize(QSize(18, 18))
        back_btn.setStyleSheet(
            """
            QPushButton {
                background-color: rgba(0,0,0,18);
                border: 1px solid rgba(124,255,158,22);
                border-radius: 10px;
                padding: 0px;
            }
            QPushButton:hover {
                background-color: rgba(124,255,158,8);
                border: 1px solid rgba(124,255,158,44);
            }
            QPushButton:pressed {
                background-color: rgba(124,255,158,12);
                border: 1px solid rgba(124,255,158,70);
            }
            """
        )
        back_btn.clicked.connect(self._go_hub)

        h_title = QLabel("ATTACK PATHS")
        h_title.setFont(_ui_font(12, QFont.Weight.DemiBold))
        h_title.setStyleSheet("color: rgba(255,255,255,220); letter-spacing: 2px;")

        self._stats = QLabel("Total Paths: —   |   Max Score: —   |   High: —   Medium: —   Low: —")
        self._stats.setFont(_ui_font(11, QFont.Weight.Normal))
        self._stats.setStyleSheet("color: rgba(255,255,255,140);")
        self._stats.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        header.addWidget(back_btn)
        header.addWidget(h_title)
        header.addWidget(self._stats)
        outer.addLayout(header)

        # Main split
        main = QHBoxLayout()
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(14)

        # Left list panel
        left_panel = QFrame()
        left_panel.setObjectName("left_panel")
        left_panel.setFixedWidth(390)
        left_panel.setStyleSheet(
            """
            QFrame#left_panel {
                background-color: rgba(0,0,0,12);
                border: 1px solid rgba(255,255,255,12);
                border-radius: 12px;
            }
            """
        )
        lp = QVBoxLayout()
        lp.setContentsMargins(14, 12, 14, 12)
        lp.setSpacing(10)

        lph = QLabel("ATTACK PATHS")
        lph.setFont(_ui_font(11, QFont.Weight.DemiBold))
        lph.setStyleSheet("color: rgba(255,255,255,190); letter-spacing: 2px;")
        lp.addWidget(lph)

        self._paths_scroll = QScrollArea()
        self._paths_scroll.setWidgetResizable(True)
        self._paths_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._paths_scroll.setStyleSheet(
            """
            QScrollArea {
                background: transparent;
                border: none;
            }
            QScrollArea > QWidget > QWidget { background: transparent; }
            QScrollBar:vertical {
                width: 10px;
                background: transparent;
                margin: 10px 6px 10px 0px;
            }
            QScrollBar::handle:vertical {
                background: rgba(245,247,250,60);
                min-height: 36px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical:hover {
                background: rgba(124,255,158,75);
            }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical { height: 0px; }
            QScrollBar::add-page:vertical,
            QScrollBar::sub-page:vertical { background: transparent; }
            """
        )

        self._paths_list_wrap = QWidget()
        self._paths_list_wrap.setStyleSheet("background: transparent;")
        self._paths_list_layout = QVBoxLayout()
        self._paths_list_layout.setContentsMargins(0, 0, 0, 0)
        self._paths_list_layout.setSpacing(0)
        self._paths_list_layout.addStretch(1)
        self._paths_list_wrap.setLayout(self._paths_list_layout)
        self._paths_scroll.setWidget(self._paths_list_wrap)
        lp.addWidget(self._paths_scroll, 1)

        left_panel.setLayout(lp)
        main.addWidget(left_panel)

        # Center + bottom area
        center_panel = QFrame()
        center_panel.setStyleSheet("background: transparent;")
        cp = QVBoxLayout()
        cp.setContentsMargins(0, 0, 0, 0)
        cp.setSpacing(12)


        # Score / risk block (professional badge)
        self._score_block = _ScoreBlock()
        cp.addWidget(self._score_block, 0, Qt.AlignHCenter)
        cp.addSpacing(6)

        # Diagram (continuous rail behind nodes, closer to mock)
        diagram_wrap = QWidget()
        diagram_wrap.setStyleSheet("background: transparent;")
        stack = QStackedLayout()
        stack.setContentsMargins(0, 0, 0, 0)
        stack.setStackingMode(QStackedLayout.StackAll)

        rail = _RailPixmap(ICONS / "icon_attack_chain_rail.png")
        stack.addWidget(rail)

        fg = QWidget()
        fg.setStyleSheet("background: transparent;")
        fg_row = QHBoxLayout()
        fg_row.setContentsMargins(0, 0, 0, 0)
        fg_row.setSpacing(0)
        fg_row.setAlignment(Qt.AlignHCenter)

        c_green = QColor(124, 255, 158, 90)
        c_yellow = QColor(255, 206, 120, 90)
        c_orange = QColor(255, 155, 80, 90)
        c_red = QColor(255, 90, 90, 90)

        self._node_entry = _NodeBlock("Entry", "icon_entry_node.png", c_green)
        self._node_weak = _NodeBlock("Weakness", "icon_weakness_node.png", c_yellow)
        self._node_tech = _NodeBlock("Technique", "icon_technique_node.png", c_orange)
        self._node_imp = _NodeBlock("Impact", "icon_impact_node.png", c_red)

        fg_row.addStretch(1)
        fg_row.addWidget(self._node_entry)
        fg_row.addStretch(1)
        fg_row.addWidget(self._node_weak)
        fg_row.addStretch(1)
        fg_row.addWidget(self._node_tech)
        fg_row.addStretch(1)
        fg_row.addWidget(self._node_imp)
        fg_row.addStretch(1)

        fg.setLayout(fg_row)
        stack.addWidget(fg)

        stack.setCurrentWidget(fg)
        fg.raise_()

        diagram_wrap.setLayout(stack)
        cp.addWidget(diagram_wrap)

        # Divider
        div = QFrame()
        div.setFixedHeight(1)
        div.setStyleSheet("background-color: rgba(255,255,255,10);")
        cp.addSpacing(6)
        cp.addWidget(div)
        cp.addSpacing(6)

        # Bottom two columns
        bottom = QHBoxLayout()
        bottom.setContentsMargins(0, 0, 0, 0)
        bottom.setSpacing(18)

        self._evidence_col = self._mk_list_col("EVIDENCE SUPPORTING THIS PATH")
        self._cut_col = self._mk_list_col("HOW TO CUT THIS PATH")

        bottom.addWidget(self._evidence_col, 1)
        bottom.addWidget(self._cut_col, 1)
        cp.addLayout(bottom, 1)

        # Empty state overlay (shown when no paths)
        self._empty = QLabel("")
        self._empty.setWordWrap(True)
        self._empty.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        self._empty.setFont(_ui_font(12, QFont.Weight.DemiBold))
        self._empty.setStyleSheet("color: rgba(255,255,255,135);")
        cp.addWidget(self._empty)

        center_panel.setLayout(cp)
        main.addWidget(center_panel, 1)

        outer.addLayout(main, 1)
        page.setLayout(outer)

        self._pages["VIEWER"] = page
        self._stack.addWidget(page)

        self._path_group = QButtonGroup(self)
        self._path_group.setExclusive(True)

    def _mk_list_col(self, title: str) -> QFrame:
        box = QFrame()
        box.setStyleSheet(
            """
            QFrame {
                background: transparent;
            }
            """
        )
        v = QVBoxLayout()
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(8)

        t = QLabel(title)
        t.setFont(_ui_font(11, QFont.Weight.DemiBold))
        t.setStyleSheet("color: rgba(255,255,255,190); letter-spacing: 2px;")
        v.addWidget(t)

        inner = QVBoxLayout()
        inner.setContentsMargins(0, 0, 0, 0)
        inner.setSpacing(8)
        inner.addStretch(1)
        wrap = QWidget()
        wrap.setLayout(inner)
        wrap.setStyleSheet("background: transparent;")
        wrap.setMinimumHeight(52)  # keep viewer height stable (>= 2 rows)
        v.addWidget(wrap, 1)

        box.setLayout(v)
        box._items_layout = inner  # type: ignore[attr-defined]
        return box

    # ==========================
    # Viewer helpers
    # ==========================
    def _set_empty_state(self, msg: str) -> None:
        self._empty.setText(msg or "")
        self._empty.setVisible(bool(msg))

    def _rebuild_path_list(self) -> None:
        # Update stats
        s = self._summary
        self._stats.setText(
            f"Total Paths: {s.get('total','—')}   |   Max Score: {s.get('max_score','—')}   |   High: {s.get('high','—')}   Medium: {s.get('medium','—')}   Low: {s.get('low','—')}"
        )

        # Clear old list
        while self._paths_list_layout.count() > 0:
            item = self._paths_list_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                try:
                    self._path_group.removeButton(w)  # type: ignore[arg-type]
                except Exception:
                    pass
                w.setParent(None)

        self._path_buttons = {}

        if not self._paths:
            empty = QLabel("No paths")
            empty.setFont(_ui_font(11, QFont.Weight.DemiBold))
            empty.setStyleSheet("color: rgba(255,255,255,120);")
            empty.setAlignment(Qt.AlignHCenter)
            self._paths_list_layout.addWidget(empty)
            self._paths_list_layout.addStretch(1)
            return

        for p in self._paths:
            btn = _PathItemButton(p)
            pid = p["id"]
            btn.clicked.connect(lambda _=False, x=pid: self._on_select_path(x))
            self._path_group.addButton(btn)
            self._path_buttons[pid] = btn
            self._paths_list_layout.addWidget(btn)

        self._paths_list_layout.addStretch(1)

    def _open_viewer(self, path_id: Optional[str]) -> None:
        self._go_viewer()
        if not self._paths:
            self._set_empty_state("No attack paths available for this scan.")
            return

        pid = path_id
        if not pid or pid not in self._path_by_id:
            pid = self._paths[0]["id"]

        btn = self._path_buttons.get(pid)
        if btn is not None:
            btn.setChecked(True)
        self._on_select_path(pid)

    def _on_select_path(self, path_id: str) -> None:
        p = self._path_by_id.get(path_id)
        if not p:
            return

        # Remember last selection per scan
        if self._current_scan_id:
            self._last_opened_by_scan[self._current_scan_id] = path_id

        score = p.get("score")
        score_txt = "—"
        if score is not None:
            try:
                score_txt = str(int(float(score)))
            except Exception:
                score_txt = _str_or_empty(score) or "—"

        risk = (p.get("risk") or "LOW").upper()
        risk_lbl = "MEDIUM" if risk == "MED" else risk

        self._score_block.set_values(score_txt, risk_lbl)

        self._node_entry.set_detail(_node_text(p.get("entry")) or "—")
        self._node_weak.set_detail(_node_text(p.get("weakness")) or "—")
        self._node_tech.set_detail(_tech_display(p.get("technique")) or "—")
        self._node_imp.set_detail(_node_text(p.get("impact")) or "—")

        self._fill_list_col(self._evidence_col, p.get("evidence") or [])
        self._fill_list_col(self._cut_col, p.get("controls") or [])

        self._set_empty_state("")

    def _fill_list_col(self, col: QFrame, items: Any) -> None:
        lay = getattr(col, "_items_layout", None)
        if lay is None:
            return

        # Clear
        while lay.count() > 0:
            it = lay.takeAt(0)
            w = it.widget()
            if w is not None:
                w.setParent(None)

        rows = _items_to_strings(items)
        if not rows:
            empty = QLabel("—")
            empty.setFont(_ui_font(11, QFont.Weight.Normal))
            empty.setStyleSheet("color: rgba(255,255,255,120);")
            lay.addWidget(empty)
            lay.addStretch(1)
            return

        for s in rows[:12]:
            row = QWidget()
            hl = QHBoxLayout(row)
            hl.setContentsMargins(0, 0, 0, 0)
            hl.setSpacing(10)

            check = QLabel("✓")
            check.setFont(_ui_font(12, QFont.Weight.Bold))
            check.setStyleSheet("color: rgba(124,255,158,220);")
            check.setFixedWidth(14)

            txt = QLabel(s)
            txt.setWordWrap(True)
            txt.setFont(_ui_font(11, QFont.Weight.Normal))
            txt.setStyleSheet("color: rgba(255,255,255,175);")

            hl.addWidget(check)
            hl.addWidget(txt, 1)
            lay.addWidget(row)

        lay.addStretch(1)
