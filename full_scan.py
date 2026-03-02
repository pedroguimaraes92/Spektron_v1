# full_scan.py
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from PySide6.QtCore import Qt, QSize, QProcess, Signal
from PySide6.QtGui import QPixmap, QFont, QColor
from PySide6.QtWidgets import (
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QFrame,
    QProgressBar,
    QGraphicsDropShadowEffect,
    QSizePolicy,
)

# Reuso TOTAL da estética/renderer do QuickScan (sem alterar quickscan.py)
from quickscan import (
    OutputView,
    FlowLayout,
    Chip,
    Badge,
    _pick_ui_font,
    _pick_mono_font,
    _extract_summary_from_json,
)

ROOT = Path(__file__).resolve().parent

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_SAVED_RE = re.compile(r"^\[\+\]\s+saved:\s+(?P<path>.+\.json)\s*$", re.IGNORECASE | re.MULTILINE)


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s or "")


def _pick_ui_font_local(point: int = 10) -> QFont:
    f = QFont("Segoe UI")
    if not f.exactMatch():
        f = QFont("Inter")
    if not f.exactMatch():
        f = QFont("Arial")
    f.setPointSize(point)
    return f


def _scan_id_from_scan_path(scan_path: Path) -> str:
    name = scan_path.name
    if name.lower().startswith("scan_"):
        name = name[5:]
    if name.lower().endswith(".json"):
        name = name[:-5]
    return name


def _find_latest_scan_json(start_ts: float) -> Path | None:
    candidates = []
    for rel in ("output/scan", "output/scans"):
        p = (ROOT / rel)
        if not p.exists() or not p.is_dir():
            continue
        for f in p.glob("scan_*.json"):
            try:
                if f.stat().st_mtime >= start_ts - 1.0:
                    candidates.append(f)
            except Exception:
                pass
    if not candidates:
        return None
    candidates.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    return candidates[0]


def _safe_get(d: Any, path: List[Any], default=None):
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def _badge_for_http_status(code: Any) -> tuple[str, str]:
    try:
        c = int(code)
    except Exception:
        return ("Unknown", "neutral")

    if 200 <= c <= 299:
        return ("Found", "ok")
    if 300 <= c <= 399:
        return ("Redirect", "warn")
    if c == 404:
        return ("Not Found", "neutral")
    if c in (401, 403):
        return ("Restricted", "warn")
    if 400 <= c <= 499:
        return ("Client Error", "warn")
    if 500 <= c <= 599:
        return ("Server Error", "crit")
    return ("Error", "warn")


def _risk_badge(risk: str) -> tuple[str, str]:
    r = (risk or "").strip().lower()
    if r == "high":
        return ("High", "high")
    if r == "medium":
        return ("Medium", "med")
    if r == "low":
        return ("Low", "low")
    return ("Info", "info")


class FullOutputView(OutputView):
    """
    Mesmo visual do OutputView do QuickScan, mas com:
    - texto neutro (sem "quick report" / sem "minimal view")
    - renderer de FULL REPORT (mais seções em cards)
    """

    def set_scanning(self):
        self.clear()
        card, head, body, bv = self._add_card("SCANNING")

        g = QGraphicsDropShadowEffect(head)
        g.setBlurRadius(self._scan_glow_blur)
        g.setOffset(0, 0)
        g.setColor(QColor(140, 255, 140, self._scan_glow_alpha))
        head.setGraphicsEffect(g)

        msg = QLabel("Collecting signals and generating full scan findings.")
        msg.setObjectName("muted")
        msg.setWordWrap(True)
        msg.setFont(_pick_ui_font(10))
        bv.addWidget(msg)

        chips_wrap = QWidget()
        flow = FlowLayout(chips_wrap, margin=0, h_spacing=10, v_spacing=10)
        chips_wrap.setLayout(flow)
        for t in ("Transport", "TLS", "DNS", "Headers", "Exposure", "API Docs", "CORS"):
            flow.addWidget(Chip(t))
        bv.addWidget(chips_wrap)

    def set_processing(self, title: str, message: str):
        self.clear()
        card, head, body, bv = self._add_card(title)

        g = QGraphicsDropShadowEffect(head)
        g.setBlurRadius(self._scan_glow_blur)
        g.setOffset(0, 0)
        g.setColor(QColor(140, 255, 140, self._scan_glow_alpha))
        head.setGraphicsEffect(g)

        msg = QLabel(message)
        msg.setObjectName("muted")
        msg.setWordWrap(True)
        msg.setFont(_pick_ui_font(10))
        bv.addWidget(msg)

    def render_full_report(self, doc: Dict[str, Any]):
        """
        Render FULL scan report using QuickScan card aesthetic.
        Uses the same primitives (_add_card, Badge, Chip, FlowLayout).
        """
        self.clear()

        # --- Baseline summary (same as quickscan) for consistent sections ---
        summary = _extract_summary_from_json(doc)

        # =====================
        # 1) TARGET (quick style)
        # =====================
        target_url = summary.get("target") or _safe_get(doc, ["target", "normalized"]) or "-"
        tls_version = summary.get("tls_version") or _safe_get(doc, ["observations", "tls", "tls_version"]) or "-"
        tls_verify = bool(_safe_get(doc, ["observations", "tls", "verify"], False))

        card, head, body, bv = self._add_card("TARGET")
        t = QLabel(str(target_url))
        t.setObjectName("mono")
        t.setFont(_pick_mono_font(10))
        t.setTextInteractionFlags(Qt.TextSelectableByMouse)
        t.setWordWrap(True)
        bv.addWidget(t)

        tls_label = "TLS" if not tls_version or tls_version == "-" else str(tls_version).strip()
        tls_label = f"{tls_label} · Verified" if tls_verify else f"{tls_label} · OK"
        bv.addWidget(Badge(tls_label, "ok" if tls_verify else "neutral"))

        # =====================
        # 2) SCAN SUMMARY (produto, sem CLI)
        # =====================
        card, head, body, bv = self._add_card("SCAN SUMMARY")
        host = _safe_get(doc, ["target", "host"]) or "-"
        scheme = _safe_get(doc, ["target", "scheme"]) or "-"
        port = _safe_get(doc, ["target", "port"])
        gen = _safe_get(doc, ["generated_at"]) or "-"

        line1 = QLabel(f"{host}  ·  {scheme}{'' if port is None else f':{port}'}")
        line1.setObjectName("muted")
        line1.setFont(_pick_ui_font(10))
        bv.addWidget(line1)

        line2 = QLabel(f"Generated: {gen}")
        line2.setObjectName("hint")
        line2.setFont(_pick_ui_font(9))
        bv.addWidget(line2)

        # =====================
        # 3) TRANSPORT & TLS (card)
        # =====================
        card, head, body, bv = self._add_card("TRANSPORT & TLS")

        final_url = _safe_get(doc, ["observations", "transport", "final_url"]) or "-"
        redirects = _safe_get(doc, ["observations", "transport", "redirects"])
        cipher = _safe_get(doc, ["observations", "tls", "cipher", "name"]) or "-"
        cert_exp = _safe_get(doc, ["observations", "tls", "cert", "notAfter"]) or "-"

        r0 = QLabel(f"Final URL: {final_url}")
        r0.setObjectName("muted")
        r0.setWordWrap(True)
        r0.setFont(_pick_ui_font(10))
        bv.addWidget(r0)

        r1 = QLabel(f"Redirects: {redirects if redirects is not None else '-'}")
        r1.setObjectName("muted")
        r1.setFont(_pick_ui_font(10))
        bv.addWidget(r1)

        chips_wrap = QWidget()
        flow = FlowLayout(chips_wrap, margin=0, h_spacing=10, v_spacing=10)
        chips_wrap.setLayout(flow)
        if tls_version and tls_version != "-":
            flow.addWidget(Chip(str(tls_version)))
        if cipher and cipher != "-":
            flow.addWidget(Chip(str(cipher)))
        if cert_exp and cert_exp != "-":
            flow.addWidget(Chip(f"Cert exp: {cert_exp}"))
        bv.addWidget(chips_wrap)

        # =====================
        # 4) DNS RECORDS (card)
        # =====================
        card, head, body, bv = self._add_card("DNS RECORDS")

        a = _safe_get(doc, ["observations", "dns", "a"], []) or []
        aaaa = _safe_get(doc, ["observations", "dns", "aaaa"], []) or []
        cname = _safe_get(doc, ["observations", "dns", "cname"], []) or []
        mx = _safe_get(doc, ["observations", "dns", "mx"], []) or []
        txt = _safe_get(doc, ["observations", "dns", "txt"], []) or []

        if a or aaaa:
            ips = []
            ips.extend([f"A: {x}" for x in a[:3]])
            ips.extend([f"AAAA: {x}" for x in aaaa[:2]])
            for s in ips:
                lab = QLabel(s)
                lab.setObjectName("mono")
                lab.setFont(_pick_mono_font(10))
                lab.setTextInteractionFlags(Qt.TextSelectableByMouse)
                lab.setWordWrap(True)
                bv.addWidget(lab)
        else:
            empty = QLabel("No DNS IP records reported.")
            empty.setObjectName("hint")
            empty.setFont(_pick_ui_font(9))
            bv.addWidget(empty)

        if cname:
            wrap = QWidget()
            flow = FlowLayout(wrap, margin=0, h_spacing=10, v_spacing=10)
            wrap.setLayout(flow)
            for x in cname[:6]:
                flow.addWidget(Chip(f"CNAME: {x}"))
            bv.addWidget(wrap)

        if mx:
            wrap = QWidget()
            flow = FlowLayout(wrap, margin=0, h_spacing=10, v_spacing=10)
            wrap.setLayout(flow)
            for x in mx[:6]:
                if isinstance(x, dict):
                    flow.addWidget(Chip(f"MX: {x.get('exchange','-')}"))
                else:
                    flow.addWidget(Chip(f"MX: {x}"))
            bv.addWidget(wrap)

        if txt:
            note = QLabel(f"TXT records: {len(txt)}")
            note.setObjectName("hint")
            note.setFont(_pick_ui_font(9))
            bv.addWidget(note)

        # =====================
        # 5) SECURITY FINDINGS (quick style)
        # =====================
        # reuse quickscan summary findings already normalized
        findings = summary.get("findings") or []
        card, head, body, bv = self._add_card("SECURITY FINDINGS")
        if findings:
            for f in findings[:12]:
                row = QFrame()
                row.setObjectName("row")
                hl = QHBoxLayout(row)
                hl.setContentsMargins(0, 0, 0, 0)
                hl.setSpacing(10)

                tone = (f.get("tone") or "info").strip()
                sev = (f.get("severity") or "INFO").strip()
                title = (f.get("title") or "").strip()

                hl.addWidget(Badge(sev, tone))
                lbl = QLabel(title)
                lbl.setObjectName("row_text")
                lbl.setWordWrap(True)
                lbl.setFont(_pick_ui_font(10))
                hl.addWidget(lbl, 1)
                bv.addWidget(row)
        else:
            empty = QLabel("No security findings were reported.")
            empty.setObjectName("hint")
            empty.setFont(_pick_ui_font(9))
            bv.addWidget(empty)

        # =====================
        # 6) Exposure Files (card) - Found/Not Found summary
        # =====================
        card, head, body, bv = self._add_card("EXPOSURE FILES")
        exp_items = _safe_get(doc, ["observations", "exposure_files", "items"], []) or []
        found = [it for it in exp_items if isinstance(it, dict) and int(it.get("status") or 0) in (200, 204)]
        not_found = [it for it in exp_items if isinstance(it, dict) and int(it.get("status") or 0) == 404]

        # headline badges
        hrow = QHBoxLayout()
        hrow.setContentsMargins(0, 0, 0, 0)
        hrow.setSpacing(10)
        w = QWidget()
        w.setLayout(hrow)
        hrow.addWidget(Badge(f"Found: {len(found)}", "ok" if found else "neutral"))
        hrow.addWidget(Badge(f"Not Found: {len(not_found)}", "neutral"))
        hrow.addStretch(1)
        bv.addWidget(w)

        if found:
            wrap = QWidget()
            flow = FlowLayout(wrap, margin=0, h_spacing=10, v_spacing=10)
            wrap.setLayout(flow)
            for it in found[:10]:
                flow.addWidget(Chip(str(it.get("path") or "-")))
            bv.addWidget(wrap)
        else:
            empty = QLabel("No exposure files were found.")
            empty.setObjectName("hint")
            empty.setFont(_pick_ui_font(9))
            bv.addWidget(empty)

        # =====================
        # 7) API DOCS (OpenAPI discovery)
        # =====================
        card, head, body, bv = self._add_card("API DOCS")
        oa_items = _safe_get(doc, ["observations", "openapi", "items"], []) or []
        oa_found = [it for it in oa_items if isinstance(it, dict) and int(it.get("status") or 0) in (200, 204)]
        if oa_found:
            wrap = QWidget()
            flow = FlowLayout(wrap, margin=0, h_spacing=10, v_spacing=10)
            wrap.setLayout(flow)
            for it in oa_found[:10]:
                flow.addWidget(Chip(str(it.get("path") or "-")))
            bv.addWidget(wrap)
        else:
            # show a compact shortlist with human labels (no raw status codes)
            shown = 0
            for it in oa_items[:8]:
                if not isinstance(it, dict):
                    continue
                pth = it.get("path") or "-"
                lbl, tone = _badge_for_http_status(it.get("status"))
                row = QFrame()
                row.setObjectName("row")
                hl = QHBoxLayout(row)
                hl.setContentsMargins(0, 0, 0, 0)
                hl.setSpacing(10)
                hl.addWidget(Badge(lbl, tone))
                txt = QLabel(str(pth))
                txt.setObjectName("row_text")
                txt.setFont(_pick_ui_font(10))
                hl.addWidget(txt, 1)
                bv.addWidget(row)
                shown += 1
                if shown >= 6:
                    break
            if not oa_items:
                empty = QLabel("No API documentation probes were run.")
                empty.setObjectName("hint")
                empty.setFont(_pick_ui_font(9))
                bv.addWidget(empty)

        # =====================
        # 8) CORS (card)
        # =====================
        card, head, body, bv = self._add_card("CORS PROBE")
        cors = _safe_get(doc, ["observations", "cors_probe"], {}) or {}
        ok = bool(cors.get("ok"))
        if ok:
            origin = cors.get("origin") or "-"
            acao = cors.get("acao")
            acac = cors.get("acac")
            reflected = bool(cors.get("reflected", False))
            risk = cors.get("risk") or "info"
            risk_lbl, risk_tone = _risk_badge(str(risk))

            top = QHBoxLayout()
            top.setContentsMargins(0, 0, 0, 0)
            top.setSpacing(10)
            w = QWidget()
            w.setLayout(top)
            top.addWidget(Badge(f"Risk: {risk_lbl}", risk_tone))
            top.addStretch(1)
            bv.addWidget(w)

            o = QLabel(f"Origin: {origin}")
            o.setObjectName("muted")
            o.setWordWrap(True)
            o.setFont(_pick_ui_font(10))
            bv.addWidget(o)

            chips = QWidget()
            flow = FlowLayout(chips, margin=0, h_spacing=10, v_spacing=10)
            chips.setLayout(flow)
            if acao is not None:
                flow.addWidget(Chip(f"ACAO: {acao}"))
            if acac is not None:
                flow.addWidget(Chip(f"ACAC: {acac}"))
            flow.addWidget(Chip(f"Reflected: {'Yes' if reflected else 'No'}"))
            bv.addWidget(chips)
        else:
            empty = QLabel("CORS probe did not complete successfully.")
            empty.setObjectName("hint")
            empty.setFont(_pick_ui_font(9))
            bv.addWidget(empty)

        # =====================
        # 9) TECHNOLOGIES + HEADERS (two-column like quickscan)
        # =====================
        missing_headers = summary.get("missing_headers") or []
        tech = summary.get("tech") or []

        two = QFrame()
        two.setObjectName("two_col")
        grid = QHBoxLayout(two)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(12)

        headers_card = QFrame()
        headers_card.setObjectName("out_card")
        hv = QVBoxLayout(headers_card)
        hv.setContentsMargins(14, 12, 14, 12)
        hv.setSpacing(10)
        htitle = QLabel("MISSING SECURITY HEADERS")
        htitle.setObjectName("out_card_title")
        htitle.setFont(_pick_ui_font(10))
        hv.addWidget(htitle)

        if missing_headers:
            wrap = QWidget()
            flow = FlowLayout(wrap, margin=0, h_spacing=10, v_spacing=10)
            wrap.setLayout(flow)
            for h in missing_headers:
                flow.addWidget(Chip(h))
            hv.addWidget(wrap)
        else:
            lab = QLabel("None detected.")
            lab.setObjectName("hint")
            lab.setFont(_pick_ui_font(9))
            hv.addWidget(lab)

        tech_card = QFrame()
        tech_card.setObjectName("out_card")
        tv = QVBoxLayout(tech_card)
        tv.setContentsMargins(14, 12, 14, 12)
        tv.setSpacing(10)
        ttitle = QLabel("TECHNOLOGIES DETECTED")
        ttitle.setObjectName("out_card_title")
        ttitle.setFont(_pick_ui_font(10))
        tv.addWidget(ttitle)

        if tech:
            for titem in tech[:14]:
                name = (titem.get("name") or "-").strip()
                cat = (titem.get("category") or "").strip()
                conf = (titem.get("confidence") or "Unknown").strip()
                row = QFrame()
                row.setObjectName("row")
                hl = QHBoxLayout(row)
                hl.setContentsMargins(0, 0, 0, 0)
                hl.setSpacing(10)

                label = f"{name} — {cat}" if cat else name
                lbl = QLabel(label)
                lbl.setObjectName("row_text")
                lbl.setWordWrap(True)
                lbl.setFont(_pick_ui_font(10))
                hl.addWidget(lbl, 1)

                conf_tone = "ok" if conf == "High" else "med" if conf == "Medium" else "low" if conf == "Low" else "neutral"
                hl.addWidget(Badge(conf, conf_tone))
                tv.addWidget(row)
        else:
            lab = QLabel("No technologies detected.")
            lab.setObjectName("hint")
            lab.setFont(_pick_ui_font(9))
            tv.addWidget(lab)

        grid.addWidget(headers_card, 1)
        grid.addWidget(tech_card, 1)

        # OutputView internals: insert just before spacer
        self._layout.insertWidget(self._layout.count() - 1, two)

        # =====================
        # 10) OPEN PORTS (quick style)
        # =====================
        ports = summary.get("open_ports") or []
        card, head, body, bv = self._add_card("OPEN PORTS")
        ports_text = ", ".join(str(p) for p in ports) if ports else "None reported"
        p = QLabel(ports_text)
        p.setObjectName("mono")
        p.setFont(_pick_mono_font(10))
        p.setTextInteractionFlags(Qt.TextSelectableByMouse)
        p.setWordWrap(True)
        bv.addWidget(p)


class FullScanWidget(QWidget):
    viewAttackPathsRequested = Signal(str)  # scan_id
    viewTopRiskRequested = Signal(str)      # scan_id
    openReportsRequested = Signal(str)      # scan_id

    def __init__(self, parent=None):
        super().__init__(parent)

        self._proc: QProcess | None = None
        self._stdout = ""
        self._stderr = ""
        self._scan_start_ts = 0.0

        self._scan_json_path: Path | None = None
        self._scan_id: str | None = None
        self._stage = "idle"  # idle | scan | evidence | attack

        self._build_ui()
        self._apply_styles()
        self._reset_view()

    # =========================
    # UI
    # =========================
    def _build_ui(self):
        self.setStyleSheet("background: transparent;")

        root = QVBoxLayout()
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.setAlignment(Qt.AlignCenter)

        self.card = QFrame()
        self.card.setObjectName("card")
        self.card.setMinimumSize(QSize(980, 620))
        self.card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        glow = QGraphicsDropShadowEffect(self.card)
        glow.setBlurRadius(28)
        glow.setOffset(0, 0)
        glow.setColor(QColor(140, 255, 140, 28))
        self.card.setGraphicsEffect(glow)

        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(22, 18, 22, 18)
        card_layout.setSpacing(12)

        self.header = QFrame()
        self.header.setObjectName("header")
        header_layout = QHBoxLayout(self.header)
        header_layout.setContentsMargins(12, 10, 12, 10)
        header_layout.setSpacing(12)

        self.logo = QLabel()
        self.logo.setFixedSize(56, 56)
        logo_path = ROOT / "assets" / "spektron_cat.png"
        if logo_path.exists():
            pm = QPixmap(str(logo_path))
            if not pm.isNull():
                self.logo.setPixmap(pm.scaled(56, 56, Qt.KeepAspectRatio, Qt.SmoothTransformation))

        self.brand = QLabel("SPEKTRON")
        self.brand.setObjectName("brand")
        self.brand.setFont(_pick_ui_font_local(11))

        header_layout.addWidget(self.logo, 0, Qt.AlignLeft | Qt.AlignVCenter)
        header_layout.addWidget(self.brand, 0, Qt.AlignLeft | Qt.AlignVCenter)
        header_layout.addStretch(1)
        card_layout.addWidget(self.header)

        self.title = QLabel("FULL SCAN")
        self.title.setObjectName("title")
        self.title.setAlignment(Qt.AlignHCenter)
        self.title.setFont(_pick_ui_font_local(12))
        card_layout.addWidget(self.title)

        self.target_strip = QFrame()
        self.target_strip.setObjectName("target_strip")
        target_layout = QHBoxLayout(self.target_strip)
        target_layout.setContentsMargins(14, 12, 14, 12)
        target_layout.setSpacing(12)

        self.lbl_target = QLabel("TARGET")
        self.lbl_target.setObjectName("lbl_target")
        self.lbl_target.setFixedWidth(78)
        self.lbl_target.setFont(_pick_ui_font_local(10))

        self.in_target = QLineEdit()
        self.in_target.setObjectName("in_target")
        self.in_target.setPlaceholderText("https://example.com")
        self.in_target.setFont(_pick_ui_font_local(10))
        self.in_target.returnPressed.connect(self._on_run_full_scan)

        target_layout.addWidget(self.lbl_target)
        target_layout.addWidget(self.in_target)
        card_layout.addWidget(self.target_strip)

        self.lbl_section = QLabel("SECURITY FINDINGS")
        self.lbl_section.setObjectName("lbl_section")
        self.lbl_section.setFont(_pick_ui_font_local(10))
        card_layout.addWidget(self.lbl_section)

        self.output = FullOutputView()
        self.output.setMinimumHeight(320)
        self.output._scan_glow_alpha = 100
        self.output._scan_glow_blur = 18
        self.output._scan_glow_pulse = False
        card_layout.addWidget(self.output, 1)

        # Sem pipeline text
        self.footer_text = QLabel("Full scan results are available in Reports.")
        self.footer_text.setObjectName("footer")
        self.footer_text.setFont(_pick_ui_font_local(15))
        self.footer_text.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.footer_text.setFixedHeight(22)
        self.footer_text.setWordWrap(False)
        self.footer_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.footer_text.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        card_layout.addWidget(self.footer_text)

        self.footer_bar = QFrame()
        self.footer_bar.setObjectName("footer_bar")
        footer_layout = QVBoxLayout(self.footer_bar)
        footer_layout.setContentsMargins(0, 0, 0, 0)
        footer_layout.setSpacing(18)

        # Progress bar (mesmo comportamento do QuickScan)
        self.loading = QProgressBar()
        self.loading.setObjectName("loading")
        self.loading.setFixedHeight(6)
        self.loading.setTextVisible(False)
        self.loading.setRange(0, 100)
        self.loading.setValue(0)
        self.loading.setVisible(True)
        footer_layout.addWidget(self.loading)

        buttons = QHBoxLayout()
        buttons.setSpacing(25)

        self.btn_run = QPushButton("RUN SCAN")
        self.btn_run.setObjectName("btn_run")
        self.btn_run.setFixedSize(210, 44)
        self.btn_run.setFont(_pick_ui_font_local(10))
        self.btn_run.clicked.connect(self._on_run_full_scan)

        self.btn_clean = QPushButton("CLEAN")
        self.btn_clean.setObjectName("btn_exit")  # mantém o mesmo estilo/QSS
        self.btn_clean.setFixedSize(170, 44)
        self.btn_clean.setFont(_pick_ui_font_local(10))
        self.btn_clean.clicked.connect(self._reset_view)

        buttons.addStretch(1)
        buttons.addWidget(self.btn_run)
        buttons.addWidget(self.btn_clean)
        buttons.addStretch(1)
        footer_layout.addLayout(buttons)

        post = QHBoxLayout()
        post.setSpacing(14)

        self.btn_view_paths = QPushButton("View Attack Paths")
        self.btn_view_paths.setObjectName("btn_post")
        self.btn_view_paths.setFixedSize(210, 40)
        self.btn_view_paths.setFont(_pick_ui_font_local(10))
        self.btn_view_paths.clicked.connect(self._emit_view_paths)

        self.btn_view_top = QPushButton("View Top Risk")
        self.btn_view_top.setObjectName("btn_post")
        self.btn_view_top.setFixedSize(210, 40)
        self.btn_view_top.setFont(_pick_ui_font_local(10))
        self.btn_view_top.clicked.connect(self._emit_view_top_risk)

        self.btn_open_reports = QPushButton("Open Reports")
        self.btn_open_reports.setObjectName("btn_post")
        self.btn_open_reports.setFixedSize(210, 40)
        self.btn_open_reports.setFont(_pick_ui_font_local(10))
        self.btn_open_reports.clicked.connect(self._emit_open_reports)

        post.addStretch(1)
        post.addWidget(self.btn_view_paths)
        post.addWidget(self.btn_view_top)
        post.addWidget(self.btn_open_reports)
        post.addStretch(1)

        self._post_row_wrap = QWidget()
        self._post_row_wrap.setLayout(post)
        self._post_row_wrap.setStyleSheet("background: transparent;")
        self._post_row_wrap.hide()

        footer_layout.addSpacing(10)
        footer_layout.addWidget(self._post_row_wrap)

        card_layout.addWidget(self.footer_bar)
        root.addWidget(self.card, alignment=Qt.AlignCenter)
        self.setLayout(root)

    def _apply_styles(self):
        title_glow = QGraphicsDropShadowEffect(self.title)
        title_glow.setBlurRadius(12)
        title_glow.setOffset(0, 0)
        title_glow.setColor(QColor(140, 255, 140, 28))
        self.title.setGraphicsEffect(title_glow)

        # Mesmo QSS do QuickScan (escopo local), sem mexer no global
        self.setStyleSheet("""
            QWidget { background: transparent; color: rgba(235,238,242,210); }

            QFrame#card {
                background: rgba(18, 19, 21, 150);
                border: 1px solid rgba(140, 255, 140, 22);
                border-radius: 8px;
            }

            QFrame#header {
                background: rgba(30, 32, 35, 115);
                border: 1px solid rgba(255,255,255,12);
                border-radius: 8px;
            }

            QLabel#brand {
                font-size: 15px;
                font-weight: 700;
                letter-spacing: 3px;
                color: rgba(245, 247, 250, 200);
            }

            QLabel#title {
                font-size: 30px;
                font-weight: 600;
                letter-spacing: 10px;
                color: rgba(170, 255, 170, 145);
                margin-top: 6px;
                margin-bottom: 6px;
            }

            QFrame#target_strip {
                background: rgba(26, 28, 31, 135);
                border: 1px solid rgba(255,255,255,11);
                border-radius: 8px;
            }

            QLabel#lbl_target {
                color: rgba(220, 226, 232, 135);
                font-size: 11px;
                letter-spacing: 2px;
            }

            QLineEdit#in_target {
                background: rgba(0,0,0,50);
                border: 1px solid rgba(255,255,255,11);
                border-radius: 8px;
                padding: 10px 12px;
                color: rgba(245, 247, 250, 220);
                selection-background-color: rgba(140,255,140,22);
            }
            QLineEdit#in_target:focus {
                border: 1px solid rgba(140,255,140,34);
            }

            QLabel#lbl_section {
                color: rgba(165, 255, 165, 140);
                font-size: 13px;
                font-weight: 600;
                letter-spacing: 2px;
                margin-top: 6px;
                margin-left: 2px;
            }

            QScrollArea#output_area {
                background: rgba(10, 11, 12, 95);
                border: 1px solid rgba(255,255,255,11);
                border-radius: 8px;
            }
            QWidget#output_content { background: transparent; }
            QScrollArea#output_area > QWidget > QWidget { background: transparent; }

            QScrollBar:vertical {
                width: 10px;
                background: transparent;
                margin: 10px 8px 10px 0px;
            }
            QScrollBar::handle:vertical {
                background: rgba(245,247,250,60);
                min-height: 36px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical:hover {
                background: rgba(140,255,140,75);
            }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical { height: 0px; }
            QScrollBar::add-page:vertical,
            QScrollBar::sub-page:vertical { background: transparent; }

            QFrame#out_card {
                background: rgba(10, 11, 12, 75);
                border: 1px solid rgba(255,255,255,12);
                border-radius: 12px;
            }

            QLabel#out_card_title {
                color: rgba(165, 255, 165, 160);
                font-size: 12px;
                font-weight: 700;
                letter-spacing: 2px;
            }

            QLabel#mono { color: rgba(245,247,250,220); }
            QLabel#muted { color: rgba(245,247,250,170); }
            QLabel#hint { color: rgba(235,238,242,120); }

            QFrame#row {
                background: transparent;
                border-bottom: 1px solid rgba(255,255,255,8);
                padding-bottom: 8px;
            }
            QLabel#row_text { color: rgba(245,247,250,210); }

            QLabel#chip {
                background: rgba(255,255,255,10);
                border: 1px solid rgba(255,255,255,16);
                border-radius: 999px;
                color: rgba(245,247,250,190);
            }

            QLabel#badge_ok {
                background: rgba(140,255,140,20);
                border: 1px solid rgba(140,255,140,40);
                border-radius: 999px;
                padding: 6px 10px;
                color: rgba(245,247,250,235);
                letter-spacing: 1px;
            }
            QLabel#badge_warn {
                background: rgba(255,210,120,20);
                border: 1px solid rgba(255,210,120,42);
                border-radius: 999px;
                padding: 6px 10px;
                color: rgba(245,247,250,235);
                letter-spacing: 1px;
            }
            QLabel#badge_neutral {
                background: rgba(255,255,255,10);
                border: 1px solid rgba(255,255,255,16);
                border-radius: 999px;
                padding: 6px 10px;
                color: rgba(245,247,250,210);
                letter-spacing: 1px;
            }
            QLabel#badge_info {
                background: rgba(190,210,255,16);
                border: 1px solid rgba(190,210,255,32);
                border-radius: 999px;
                padding: 6px 10px;
                color: rgba(245,247,250,235);
                letter-spacing: 1px;
            }
            QLabel#badge_low {
                background: rgba(190,210,255,16);
                border: 1px solid rgba(190,210,255,32);
                border-radius: 999px;
                padding: 6px 10px;
                color: rgba(245,247,250,235);
                letter-spacing: 1px;
            }
            QLabel#badge_med {
                background: rgba(255,210,120,18);
                border: 1px solid rgba(255,210,120,36);
                border-radius: 999px;
                padding: 6px 10px;
                color: rgba(245,247,250,235);
                letter-spacing: 1px;
            }
            QLabel#badge_high {
                background: rgba(255,155,80,18);
                border: 1px solid rgba(255,155,80,38);
                border-radius: 999px;
                padding: 6px 10px;
                color: rgba(245,247,250,235);
                letter-spacing: 1px;
            }
            QLabel#badge_crit {
                background: rgba(255,90,90,18);
                border: 1px solid rgba(255,90,90,40);
                border-radius: 999px;
                padding: 6px 10px;
                color: rgba(245,247,250,235);
                letter-spacing: 1px;
            }

            QLabel#footer {
                color: rgba(235,238,242,120);
                font-size: 12px;
                margin-left: 2px;
                margin-top: 6px;
                margin-bottom: 2px;
            }

            QFrame#footer_bar {
                background: transparent;
                border-top: 1px solid rgba(255,255,255,9);
                margin-top: 6px;
            }

            QProgressBar#loading {
                background: rgba(0,0,0,45);
                border: 1px solid rgba(140,255,140,18);
                border-radius: 5px;
            }
            QProgressBar#loading::chunk {
                background: rgba(140,255,140,150);
                border-radius: 5px;
            }

            QPushButton#btn_run {
                background: rgba(22, 24, 26, 145);
                border: 1px solid rgba(140,255,140,55);
                border-radius: 8px;
                color: rgba(205, 255, 205, 200);
                letter-spacing: 3px;
            }
            QPushButton#btn_run:hover { background: rgba(28, 30, 32, 155); }
            QPushButton#btn_run:pressed { background: rgba(16, 17, 18, 165); }

            QPushButton#btn_exit {
                background: rgba(22, 23, 24, 140);
                border: 1px solid rgba(255,255,255,14);
                border-radius: 8px;
                color: rgba(235,238,242,170);
                letter-spacing: 3px;
            }
            QPushButton#btn_exit:hover {
                border: 1px solid rgba(140,255,140,28);
                color: rgba(205,255,205,185);
            }

            QPushButton#btn_post {
                background: rgba(22, 23, 24, 140);
                border: 1px solid rgba(255,255,255,14);
                border-radius: 8px;
                color: rgba(235,238,242,170);
                letter-spacing: 1px;
            }
            QPushButton#btn_post:hover {
                border: 1px solid rgba(140,255,140,28);
                color: rgba(205,255,205,185);
            }
            QPushButton#btn_post:disabled {
                border: 1px solid rgba(255,255,255,10);
                color: rgba(255,255,255,95);
            }
        """)

    # =========================
    # Reset/Clean
    # =========================
    def _reset_view(self):
        if self._proc is not None:
            try:
                self._proc.kill()
            except Exception:
                pass
            self._proc = None

        self._stdout = ""
        self._stderr = ""
        self._scan_start_ts = 0.0
        self._scan_json_path = None
        self._scan_id = None
        self._stage = "idle"

        self._set_busy(False)
        self._reset_post_buttons()
        self.output.set_error("READY", "Enter a target and run the full scan.")

    # =========================
    # Pipeline
    # =========================
    def _set_busy(self, busy: bool):
        self.btn_run.setEnabled(not busy)
        self.btn_clean.setEnabled(True)
        self.in_target.setEnabled(not busy)

        if busy:
            self.loading.setRange(0, 0)  # indeterminate (igual QuickScan)
            eff = QGraphicsDropShadowEffect(self.loading)
            eff.setBlurRadius(24)
            eff.setOffset(0, 0)
            eff.setColor(QColor(140, 255, 140, 95))
            self.loading.setGraphicsEffect(eff)
        else:
            self.loading.setGraphicsEffect(None)
            self.loading.setRange(0, 100)
            self.loading.setValue(0)

        self.loading.style().unpolish(self.loading)
        self.loading.style().polish(self.loading)
        self.loading.update()

    def _reset_post_buttons(self):
        self._post_row_wrap.hide()
        self.btn_view_paths.setEnabled(False)
        self.btn_view_top.setEnabled(False)
        self.btn_open_reports.setEnabled(False)

    def _on_run_full_scan(self):
        target = (self.in_target.text() or "").strip()
        if not target or self._proc is not None:
            return

        self._stdout = ""
        self._stderr = ""
        self._scan_start_ts = time.time()
        self._scan_json_path = None
        self._scan_id = None
        self._reset_post_buttons()

        self._stage = "scan"
        self._set_busy(True)
        self.output.set_scanning()

        self._proc = QProcess(self)
        self._proc.setProcessChannelMode(QProcess.SeparateChannels)
        self._proc.finished.connect(self._on_finished)
        self._proc.errorOccurred.connect(self._on_proc_error)
        self._proc.readyReadStandardOutput.connect(self._on_ready_stdout)
        self._proc.readyReadStandardError.connect(self._on_ready_stderr)
        self._proc.setWorkingDirectory(str(ROOT))

        env = self._proc.processEnvironment()
        env.insert("PYTHONIOENCODING", "utf-8")
        env.insert("PYTHONUTF8", "1")
        self._proc.setProcessEnvironment(env)

        py = sys.executable
        self._proc.start(py, ["scripts/scan2.py", "scan", target])

    def _on_proc_error(self, _err):
        self._proc = None
        self._stage = "idle"
        self._set_busy(False)
        self.output.set_error("ERROR", "Scan process failed to start.")

    def _on_ready_stdout(self):
        if not self._proc:
            return
        self._stdout += bytes(self._proc.readAllStandardOutput()).decode(errors="replace")

    def _on_ready_stderr(self):
        if not self._proc:
            return
        self._stderr += bytes(self._proc.readAllStandardError()).decode(errors="replace")

    def _resolve_scan_json_path(self) -> Path | None:
        stdout = _strip_ansi(self._stdout or "")
        m = _SAVED_RE.search(stdout)
        if m:
            raw = (m.group("path") or "").strip()
            p = Path(raw)
            if not p.is_absolute():
                p = (ROOT / p).resolve()
            if p.exists():
                return p

        p2 = _find_latest_scan_json(self._scan_start_ts)
        if p2 and p2.exists():
            return p2

        return None

    def _on_finished(self, exit_code, _exit_status):
        if self._proc is not None:
            try:
                self._stdout += bytes(self._proc.readAllStandardOutput()).decode(errors="replace")
            except Exception:
                pass
            try:
                self._stderr += bytes(self._proc.readAllStandardError()).decode(errors="replace")
            except Exception:
                pass

        self._proc = None

        if exit_code not in (0, None):
            self._stage = "idle"
            self._set_busy(False)
            self.output.set_error("FAILED", "Scan failed to complete.")
            return

        if self._stage == "scan":
            scan_path = self._resolve_scan_json_path()
            if scan_path is None or not scan_path.exists():
                self._stage = "idle"
                self._set_busy(False)
                self.output.set_error("FAILED", "Scan finished but no report was produced.")
                return

            self._scan_json_path = scan_path
            self._scan_id = _scan_id_from_scan_path(scan_path)

            self._stage = "evidence"
            self.output.set_processing("PROCESSING", "Generating full scan reports.")
            self._run_evidence_build(scan_path)
            return

        if self._stage == "evidence":
            if not self._scan_id:
                self._stage = "idle"
                self._set_busy(False)
                self.output.set_error("FAILED", "Missing scan id.")
                return

            evidence_path = ROOT / "output" / "evidence" / f"evidence_{self._scan_id}.v1.json"
            if not evidence_path.exists():
                self._stage = "idle"
                self._set_busy(False)
                self.output.set_error("FAILED", "Evidence report could not be generated.")
                return

            self._stage = "attack"
            self.output.set_processing("PROCESSING", "Finalizing attack path reports.")
            self._run_attack_build(evidence_path)
            return

        if self._stage == "attack":
            self._stage = "idle"
            self._set_busy(False)
            self._on_pipeline_success()
            return

        self._stage = "idle"
        self._set_busy(False)

    def _run_evidence_build(self, scan_path: Path):
        self._stdout = ""
        self._stderr = ""

        self._proc = QProcess(self)
        self._proc.setProcessChannelMode(QProcess.SeparateChannels)
        self._proc.finished.connect(self._on_finished)
        self._proc.errorOccurred.connect(self._on_proc_error)
        self._proc.readyReadStandardOutput.connect(self._on_ready_stdout)
        self._proc.readyReadStandardError.connect(self._on_ready_stderr)
        self._proc.setWorkingDirectory(str(ROOT))

        env = self._proc.processEnvironment()
        env.insert("PYTHONIOENCODING", "utf-8")
        env.insert("PYTHONUTF8", "1")
        self._proc.setProcessEnvironment(env)

        py = sys.executable
        self._proc.start(py, ["scripts/evidence_build.py", str(scan_path)])

    def _run_attack_build(self, evidence_path: Path):
        self._stdout = ""
        self._stderr = ""

        self._proc = QProcess(self)
        self._proc.setProcessChannelMode(QProcess.SeparateChannels)
        self._proc.finished.connect(self._on_finished)
        self._proc.errorOccurred.connect(self._on_proc_error)
        self._proc.readyReadStandardOutput.connect(self._on_ready_stdout)
        self._proc.readyReadStandardError.connect(self._on_ready_stderr)
        self._proc.setWorkingDirectory(str(ROOT))

        env = self._proc.processEnvironment()
        env.insert("PYTHONIOENCODING", "utf-8")
        env.insert("PYTHONUTF8", "1")
        self._proc.setProcessEnvironment(env)

        py = sys.executable
        self._proc.start(py, ["scripts/attack_build.py", str(evidence_path)])

    def _on_pipeline_success(self):
        if not self._scan_id or not self._scan_json_path:
            self.output.set_error("DONE", "Full scan completed.")
            return

        # Render FULL REPORT (cards bonitos, sem CLI)
        try:
            with open(self._scan_json_path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            self.output.render_full_report(doc)
        except Exception:
            self.output.set_error("DONE", "Full scan completed.")

        # enable post-scan buttons only if outputs exist
        evidence = ROOT / "output" / "evidence" / f"evidence_{self._scan_id}.v1.json"
        paths = ROOT / "output" / "attack" / f"attack_paths_{self._scan_id}.v1.json"
        summary = ROOT / "output" / "attack" / f"attack_summary_{self._scan_id}.v1.json"

        if evidence.exists() and paths.exists() and summary.exists():
            self.btn_view_paths.setEnabled(True)
            self.btn_view_top.setEnabled(True)
            self.btn_open_reports.setEnabled(True)
            self._post_row_wrap.show()

    # =========================
    # Post-scan signals
    # =========================
    def _emit_view_paths(self):
        if self._scan_id:
            self.viewAttackPathsRequested.emit(self._scan_id)

    def _emit_view_top_risk(self):
        if self._scan_id:
            self.viewTopRiskRequested.emit(self._scan_id)

    def _emit_open_reports(self):
        if self._scan_id:
            self.openReportsRequested.emit(self._scan_id)
