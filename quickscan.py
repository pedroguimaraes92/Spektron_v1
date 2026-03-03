# quickscan.py
import json
import re
import sys
import time
from pathlib import Path

from PySide6.QtCore import Qt, QSize, QProcess, QTimer, QRect, QPoint, QSizeF
from PySide6.QtGui import QPixmap, QFont, QIcon, QColor
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
    QApplication,
    QScrollArea,
    QSizePolicy,
    QLayout,
    QLayoutItem,
    QSpacerItem,
)

ROOT = Path(__file__).resolve().parent

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_SAVED_RE = re.compile(r"^\[\+\]\s+saved:\s+(?P<path>.+\.json)\s*$", re.IGNORECASE | re.MULTILINE)

FOOTER_TEXT = "For full scan with attack paths: Main Menu > Targets > Scans"


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s or "")


def _pick_ui_font(point: int = 10):
    f = QFont("Segoe UI")
    if not f.exactMatch():
        f = QFont("Inter")
    if not f.exactMatch():
        f = QFont("Arial")
    f.setPointSize(point)
    return f


def _pick_mono_font(point_size: int = 11):
    f = QFont("Cascadia Code")
    if not f.exactMatch():
        f = QFont("JetBrains Mono")
    if not f.exactMatch():
        f = QFont("Fira Code")
    if not f.exactMatch():
        f = QFont("Cascadia Mono")
    if not f.exactMatch():
        f = QFont("Consolas")
    f.setStyleHint(QFont.Monospace)
    f.setPointSize(point_size)
    return f


def _safe_get(d, path, default=None):
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


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


def _title_case_header(h: str) -> str:
    if not h:
        return "-"
    parts = str(h).strip().split("-")
    out = []
    for p in parts:
        if not p:
            continue
        pl = p.lower()
        if pl in ("x", "dnt", "www"):
            out.append(pl.upper())
        elif len(pl) <= 2 and pl.isalpha():
            out.append(pl.upper())
        else:
            out.append(pl[:1].upper() + pl[1:])
    return "-".join(out) if out else "-"


def _confidence_label(conf: str) -> str:
    c = (conf or "").strip().lower()
    if c in ("high", "conf-high"):
        return "High"
    if c in ("medium", "conf-medium", "med"):
        return "Medium"
    if c in ("low", "conf-low"):
        return "Low"
    return "Unknown"


def _severity_label(sev: str) -> str:
    s = (sev or "").strip().lower()
    if s in ("critical",):
        return "CRITICAL"
    if s in ("high",):
        return "HIGH"
    if s in ("medium", "med"):
        return "MEDIUM"
    if s in ("low",):
        return "LOW"
    if s in ("info", "informational"):
        return "INFO"
    return "INFO"


def _severity_tone(sev: str) -> str:
    s = (sev or "").strip().lower()
    if s == "critical":
        return "crit"
    if s == "high":
        return "high"
    if s == "medium":
        return "med"
    if s == "low":
        return "low"
    return "info"


def _to_english_finding(title: str) -> str:
    """Best-effort normalization of finding titles to English (UI-only)."""
    t = (title or "").strip()
    if not t:
        return t

    low = t.lower()

    if any(x in low for x in ("missing", "rate limit", "headers", "tls", "hsts", "csp", "not ", "disabled", "enabled")) and not any(
        x in low for x in ("ausente", "cabeç", "cabec", "falt", "insegur")
    ):
        return t

    mappings = [
        (r"\bcsp\s+ausente\b", "CSP header missing"),
        (r"\bhsts\s+ausente\s+em\s+https\b", "HSTS missing over HTTPS"),
        (r"\bheaders?\s+de\s+rate\s+limit\s+ausentes\b", "Rate limit headers missing"),
        (r"\bheaders?\s+ausentes\b", "Security headers missing"),
        (r"\bausente\b", "missing"),
    ]
    out = t
    for pat, rep in mappings:
        out = re.sub(pat, rep, out, flags=re.IGNORECASE)

    if out and out[0].islower():
        out = out[0].upper() + out[1:]
    return out


def _extract_summary_from_json(doc: dict) -> dict:
    out = {}

    out["target"] = _safe_get(doc, ["target", "normalized"]) or _safe_get(doc, ["target", "input"]) or "-"

    tls_present = _safe_get(doc, ["observations", "tls", "present"])
    tls_ok = _safe_get(doc, ["observations", "tls", "ok"])
    tls_verify = _safe_get(doc, ["observations", "tls", "verify"])
    tls_version = _safe_get(doc, ["observations", "tls", "tls_version"])
    out["tls_version"] = tls_version or "-"

    if tls_present is True:
        if tls_ok is True:
            out["tls_status"] = "OK"
            out["tls_verify"] = bool(tls_verify)
        else:
            out["tls_status"] = "Issues"
            out["tls_verify"] = bool(tls_verify)
    else:
        out["tls_status"] = "Not present"
        out["tls_verify"] = bool(tls_verify)

    headers_present = _safe_get(doc, ["observations", "security", "headers_present"], {}) or {}
    missing = []
    if isinstance(headers_present, dict):
        for k, v in headers_present.items():
            if v is None:
                missing.append(_title_case_header(k))
    out["missing_headers"] = sorted(missing)

    findings = _safe_get(doc, ["observations", "security", "findings"], []) or []
    clean_findings = []
    if isinstance(findings, list):
        for f in findings:
            if not isinstance(f, dict):
                continue
            fid = (f.get("id") or "").strip()
            sev = (f.get("severity") or "").strip()
            title = _to_english_finding((f.get("title") or "").strip())
            if not title:
                continue
            clean_findings.append(
                {
                    "id": fid,
                    "severity": _severity_label(sev),
                    "tone": _severity_tone(sev),
                    "title": title,
                }
            )
    out["findings"] = clean_findings

    tech = []
    tech_items = doc.get("tech") if isinstance(doc.get("tech"), list) else []
    for item in tech_items:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        cat = item.get("category")
        conf = _confidence_label(item.get("confidence"))
        if name and cat:
            tech.append({"name": str(name), "category": str(cat), "confidence": conf})
        elif name:
            tech.append({"name": str(name), "category": "", "confidence": conf})
    out["tech"] = tech

    ports = []
    cand_paths = [
        ["observations", "open_ports"],
        ["observations", "ports"],
        ["derived", "open_ports"],
    ]
    for p in cand_paths:
        val = _safe_get(doc, p)
        if isinstance(val, list):
            for x in val:
                if isinstance(x, int):
                    ports.append(x)
                elif isinstance(x, dict) and isinstance(x.get("port"), int):
                    ports.append(x["port"])
            break
    if not ports:
        tp = _safe_get(doc, ["target", "port"])
        if isinstance(tp, int):
            ports = [tp]
    out["open_ports"] = sorted(list(dict.fromkeys(ports)))

    return out



class FlowLayout(QLayout):
    """A minimal flow layout for wrapping 'chip' widgets."""
    def __init__(self, parent=None, margin=0, h_spacing=8, v_spacing=8):
        super().__init__(parent)
        self._items: list[QLayoutItem] = []
        self.setContentsMargins(margin, margin, margin, margin)
        self._h = h_spacing
        self._v = v_spacing

    def addItem(self, item: QLayoutItem):
        self._items.append(item)

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, index: int):
        if 0 <= index < len(self._items):
            return self._items[index]
        return None

    def takeAt(self, index: int):
        if 0 <= index < len(self._items):
            return self._items.pop(index)
        return None

    def expandingDirections(self):
        return Qt.Orientations(Qt.Orientation(0))

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, width: int) -> int:
        return self._do_layout(QRect(0, 0, width, 0), test_only=True)

    def setGeometry(self, rect: QRect):
        super().setGeometry(rect)
        self._do_layout(rect, test_only=False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        left, top, right, bottom = self.getContentsMargins()
        size += QSize(left + right, top + bottom)
        return size

    def _do_layout(self, rect: QRect, test_only: bool) -> int:
        x = rect.x()
        y = rect.y()
        line_h = 0

        left, top, right, bottom = self.getContentsMargins()
        effective = rect.adjusted(left, top, -right, -bottom)
        x = effective.x()
        y = effective.y()
        line_h = 0

        for item in self._items:
            w = item.sizeHint().width()
            h = item.sizeHint().height()
            if x + w > effective.right() and line_h > 0:
                x = effective.x()
                y += line_h + self._v
                line_h = 0

            if not test_only:
                item.setGeometry(QRect(QPoint(x, y), item.sizeHint()))

            x += w + self._h
            line_h = max(line_h, h)

        return (y + line_h + bottom) - rect.y()


class Badge(QLabel):
    def __init__(self, text: str, tone: str = "neutral", parent=None):
        super().__init__(text, parent)
        self.setObjectName(f"badge_{tone}")
        self.setAlignment(Qt.AlignCenter)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.setFont(_pick_ui_font(9))


class Chip(QLabel):
    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self.setObjectName("chip")
        self.setAlignment(Qt.AlignCenter)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.setFont(_pick_ui_font(9))
        self.setContentsMargins(10, 6, 10, 6)


class OutputView(QScrollArea):
    """Scrollable, structured output (cards, rows, chips)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("output_area")
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)

        self._content = QWidget()
        self._content.setObjectName("output_content")
        self._layout = QVBoxLayout(self._content)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(12)

        # keep a bottom spacer so content stays top-aligned
        self._spacer = QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding)
        self._layout.addItem(self._spacer)

        self.setWidget(self._content)

        self._scan_glow_anim = None
        self._scan_glow_alpha = 90
        self._scan_glow_blur = 16
        self._scan_glow_pulse = False

    def clear(self):
        
        while self._layout.count() > 0:
            item = self._layout.takeAt(0)
            if item is None:
                continue
            w = item.widget()
            if w is not None:
                w.deleteLater()

        self._layout.addItem(self._spacer)

    def _add_card(self, title: str):
        card = QFrame()
        card.setObjectName("out_card")
        v = QVBoxLayout(card)
        v.setContentsMargins(14, 12, 14, 12)
        v.setSpacing(10)

        head = QLabel(title)
        head.setObjectName("out_card_title")
        head.setFont(_pick_ui_font(10))
        v.addWidget(head)

        body = QFrame()
        body.setObjectName("out_card_body")
        bv = QVBoxLayout(body)
        bv.setContentsMargins(0, 0, 0, 0)
        bv.setSpacing(8)

        v.addWidget(body)
        self._layout.insertWidget(self._layout.count() - 1, card)
        return card, head, body, bv

    def set_scanning(self):
        self.clear()
        card, head, body, bv = self._add_card("SCANNING")
        # Subtle neon glow on SCANNING while running
        g = QGraphicsDropShadowEffect(head)
        g.setBlurRadius(self._scan_glow_blur)
        g.setOffset(0, 0)
        g.setColor(QColor(140, 255, 140, self._scan_glow_alpha))
        head.setGraphicsEffect(g)

        if self._scan_glow_pulse:
            try:
                from PySide6.QtCore import QPropertyAnimation
                self._scan_glow_anim = QPropertyAnimation(g, b"blurRadius", head)
                self._scan_glow_anim.setDuration(1200)
                self._scan_glow_anim.setStartValue(self._scan_glow_blur)
                self._scan_glow_anim.setEndValue(self._scan_glow_blur * 1.8)
                self._scan_glow_anim.setLoopCount(-1)
                self._scan_glow_anim.setEasingCurve(Qt.InOutSine)
                self._scan_glow_anim.start()
            except Exception:
                self._scan_glow_anim = None

        msg = QLabel("Collecting signals and generating a quick report.")
        msg.setObjectName("muted")
        msg.setWordWrap(True)
        msg.setFont(_pick_ui_font(10))
        bv.addWidget(msg)

        chips_wrap = QWidget()
        flow = FlowLayout(chips_wrap, margin=0, h_spacing=10, v_spacing=10)
        chips_wrap.setLayout(flow)
        for t in ("Transport", "Headers", "Fingerprints", "Ports"):
            flow.addWidget(Chip(t))
        bv.addWidget(chips_wrap)

        note = QLabel("This view is intentionally minimal. Full scan results are available from the main menu.")
        note.setObjectName("hint")
        note.setWordWrap(True)
        note.setFont(_pick_ui_font(9))
        bv.addWidget(note)

    def set_error(self, title: str, message: str, hint: str | None = None, tone: str = "warn"):
        self.clear()
        card, head, body, bv = self._add_card(title)
        msg = QLabel(message)
        msg.setObjectName("muted")
        msg.setWordWrap(True)
        msg.setFont(_pick_ui_font(10))
        bv.addWidget(msg)
        if hint:
            h = QLabel(hint)
            h.setObjectName("hint")
            h.setWordWrap(True)
            h.setFont(_pick_ui_font(9))
            bv.addWidget(h)

    def render_summary(self, summary: dict):
        self.clear()

        target = summary.get("target") or "-"
        tls_status = str(summary.get("tls_status", "-")).lower()
        tls_verify = bool(summary.get("tls_verify", False))
        tls_version = summary.get("tls_version", "-")
        findings = summary.get("findings") or []
        missing = summary.get("missing_headers") or []
        tech = summary.get("tech") or []
        ports = summary.get("open_ports") or []

        # TARGET + TLS
        card, head, body, bv = self._add_card("TARGET")
        t = QLabel(target)
        t.setObjectName("mono")
        t.setFont(_pick_mono_font(10))
        t.setTextInteractionFlags(Qt.TextSelectableByMouse)
        t.setWordWrap(True)
        bv.addWidget(t)

        # TLS badge
        tls_label = "TLS" if not tls_version or tls_version == "-" else str(tls_version).strip()
        if tls_status == "ok":
            tls_label = f"{tls_label} · Verified" if tls_verify else f"{tls_label} · OK"
            tls_tone = "ok"
        elif tls_status == "issues":
            tls_label = f"{tls_label} · Issues"
            tls_tone = "warn"
        else:
            tls_label = f"{tls_label} · Verified" if tls_verify else tls_label
            tls_tone = "neutral"

        bv.addWidget(Badge(tls_label, tls_tone))

        # SECURITY FINDINGS
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

        two = QFrame()
        two.setObjectName("two_col")
        grid = QHBoxLayout(two)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(12)

        # HEADERS
        headers_card = QFrame()
        headers_card.setObjectName("out_card")
        hv = QVBoxLayout(headers_card)
        hv.setContentsMargins(14, 12, 14, 12)
        hv.setSpacing(10)
        head = QLabel("MISSING SECURITY HEADERS")
        head.setObjectName("out_card_title")
        head.setFont(_pick_ui_font(10))
        hv.addWidget(head)

        if missing:
            wrap = QWidget()
            flow = FlowLayout(wrap, margin=0, h_spacing=10, v_spacing=10)
            wrap.setLayout(flow)
            for h in missing:
                flow.addWidget(Chip(h))
            hv.addWidget(wrap)
        else:
            hv.addWidget(QLabel("None detected.", objectName="hint"))

        # TECH
        tech_card = QFrame()
        tech_card.setObjectName("out_card")
        tv = QVBoxLayout(tech_card)
        tv.setContentsMargins(14, 12, 14, 12)
        tv.setSpacing(10)
        th = QLabel("TECHNOLOGIES DETECTED")
        th.setObjectName("out_card_title")
        th.setFont(_pick_ui_font(10))
        tv.addWidget(th)

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
            tv.addWidget(QLabel("No technologies detected.", objectName="hint"))

        grid.addWidget(headers_card, 1)
        grid.addWidget(tech_card, 1)
        self._layout.insertWidget(self._layout.count() - 1, two)

        # PORTS
        card, head, body, bv = self._add_card("OPEN PORTS")
        ports_text = ", ".join(str(p) for p in ports) if ports else "None reported"
        p = QLabel(ports_text)
        p.setObjectName("mono")
        p.setFont(_pick_mono_font(10))
        p.setTextInteractionFlags(Qt.TextSelectableByMouse)
        p.setWordWrap(True)
        bv.addWidget(p)


class QuickScanWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)
        self.setWindowTitle("Spektron — Quick Scan")
        self.setMinimumSize(QSize(980, 620))

        icon_path = ROOT / "assets" / "spektron_cat.png"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        self._proc = None
        self._stdout = ""
        self._stderr = ""
        self._scan_start_ts = 0.0

        self._build_ui()
        self._apply_styles()

        self._did_autosize = False

        self._loading_glow_alpha = 95
        self._loading_glow_blur = 24

    def _build_ui(self):
        self.bg = QLabel(self)
        self.bg.setObjectName("bg")
        self.bg.setScaledContents(True)

        bg_path = ROOT / "assets" / "launcher_bg.png"
        if bg_path.exists():
            pm = QPixmap(str(bg_path))
            if not pm.isNull():
                self.bg.setPixmap(pm)

        self.card = QFrame(self)
        self.card.setObjectName("card")

        self.bg.lower()
        self.card.raise_()

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
        self.brand.setFont(_pick_ui_font(11))

        header_layout.addWidget(self.logo, 0, Qt.AlignLeft | Qt.AlignVCenter)
        header_layout.addWidget(self.brand, 0, Qt.AlignLeft | Qt.AlignVCenter)
        header_layout.addStretch(1)

        card_layout.addWidget(self.header)

        self.title = QLabel("QUICK SCAN")
        self.title.setObjectName("title")
        self.title.setAlignment(Qt.AlignHCenter)
        self.title.setFont(_pick_ui_font(12))
        card_layout.addWidget(self.title)

        self.target_strip = QFrame()
        self.target_strip.setObjectName("target_strip")
        target_layout = QHBoxLayout(self.target_strip)
        target_layout.setContentsMargins(14, 12, 14, 12)
        target_layout.setSpacing(12)

        self.lbl_target = QLabel("TARGET")
        self.lbl_target.setObjectName("lbl_target")
        self.lbl_target.setFixedWidth(78)
        self.lbl_target.setFont(_pick_ui_font(10))

        self.in_target = QLineEdit()
        self.in_target.setObjectName("in_target")
        self.in_target.setPlaceholderText("https://example.com")
        self.in_target.setFont(_pick_ui_font(10))
        self.in_target.returnPressed.connect(self._on_run_scan)

        target_layout.addWidget(self.lbl_target)
        target_layout.addWidget(self.in_target)
        card_layout.addWidget(self.target_strip)

        self.lbl_section = QLabel("SECURITY FINDINGS")
        self.lbl_section.setObjectName("lbl_section")
        self.lbl_section.setFont(_pick_ui_font(10))
        card_layout.addWidget(self.lbl_section)

        self.output = OutputView()
        self.output.setMinimumHeight(320)
        self.output._scan_glow_alpha = 100
        self.output._scan_glow_blur = 18
        self.output._scan_glow_pulse = False
        card_layout.addWidget(self.output, 1)
        card_layout.addSpacing(50)

        self.footer_text = QLabel(FOOTER_TEXT)
        self.footer_text.setObjectName("footer")
        self.footer_text.setFont(_pick_ui_font(15))
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
        footer_layout.setSpacing(0)

        self.loading = QProgressBar()
        self.loading.setObjectName("loading")
        self.loading.setFixedHeight(10)
        self.loading.setTextVisible(False)
        self.loading.setRange(0, 1)
        self.loading.setValue(0)
        self.loading.setProperty("busy", False)
        self.loading.setVisible(True)
        footer_layout.addWidget(self.loading)

        buttons = QHBoxLayout()
        buttons.setSpacing(14)

        self.btn_run = QPushButton("RUN SCAN")
        self.btn_run.setObjectName("btn_run")
        self.btn_run.setFixedSize(210, 44)
        self.btn_run.setFont(_pick_ui_font(10))
        self.btn_run.clicked.connect(self._on_run_scan)

        self.btn_exit = QPushButton("EXIT")
        self.btn_exit.setObjectName("btn_exit")
        self.btn_exit.setFixedSize(170, 44)
        self.btn_exit.setFont(_pick_ui_font(10))
        self.btn_exit.clicked.connect(self.close)

        buttons.addStretch(1)
        buttons.addWidget(self.btn_run)
        buttons.addWidget(self.btn_exit)
        buttons.addStretch(1)

        footer_layout.addLayout(buttons)
        card_layout.addWidget(self.footer_bar)

    def _apply_styles(self):
        title_glow = QGraphicsDropShadowEffect(self.title)
        title_glow.setBlurRadius(12)
        title_glow.setOffset(0, 0)
        title_glow.setColor(QColor(140, 255, 140, 28))
        self.title.setGraphicsEffect(title_glow)

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

            /* Output area: subtle, not flashy */
            QScrollArea#output_area {
                background: rgba(10, 11, 12, 95);
                border: 1px solid rgba(255,255,255,11);
                border-radius: 8px;
            }
            QWidget#output_content { background: transparent; }
            QScrollArea#output_area > QWidget > QWidget { background: transparent; }

            /* Minimal scrollbar */
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

            QLabel#mono {
                color: rgba(245,247,250,220);
            }

            QLabel#muted {
                color: rgba(245,247,250,170);
            }
            QLabel#hint {
                color: rgba(235,238,242,120);
            }

            QFrame#row {
                background: transparent;
                border-bottom: 1px solid rgba(255,255,255,8);
                padding-bottom: 8px;
            }
            QLabel#row_text {
                color: rgba(245,247,250,210);
            }

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
        """)

    def showEvent(self, event):
        super().showEvent(event)
        QTimer.singleShot(0, self._autosize_and_center)

    def _autosize_and_center(self):
        if self._did_autosize:
            return
        self._did_autosize = True
        try:
            screen = QApplication.primaryScreen()
            if not screen:
                return
            geo = screen.availableGeometry()
            w = int(geo.width() * 0.90)
            h = int(geo.height() * 0.90)
            self.resize(w, h)
            x = geo.x() + (geo.width() - w) // 2
            y = geo.y() + (geo.height() - h) // 2
            self.move(x, y)
            self._layout_card()
        except Exception:
            pass
        QTimer.singleShot(0, self._update_footer_elide)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.bg.setGeometry(0, 0, self.width(), self.height())
        self._layout_card()

    def _layout_card(self):
        w = self.width()
        h = self.height()
        card_w = int(w * 0.84)
        card_h = int(h * 0.78)
        x = (w - card_w) // 2
        y = (h - card_h) // 2
        self.card.setGeometry(x, y, card_w, card_h)
        QTimer.singleShot(0, self._update_footer_elide)

    def _update_footer_elide(self):
        try:
            fm = self.footer_text.fontMetrics()
            maxw = max(10, self.card.width() - 40)
            self.footer_text.setText(fm.elidedText(FOOTER_TEXT, Qt.ElideRight, maxw))
        except Exception:
            pass

    def _set_busy(self, busy: bool):

        self.btn_run.setEnabled(not busy)
        self.btn_exit.setEnabled(not busy)
        self.in_target.setEnabled(not busy)


        if busy:
            self.loading.setRange(0, 0) 
            eff = QGraphicsDropShadowEffect(self.loading)
            eff.setBlurRadius(self._loading_glow_blur)
            eff.setOffset(0, 0)
            eff.setColor(QColor(140, 255, 140, self._loading_glow_alpha))
            self.loading.setGraphicsEffect(eff)
        else:
            self.loading.setRange(0, 100)
            self.loading.setValue(0)
            self.loading.setGraphicsEffect(None)

        self.loading.style().unpolish(self.loading)
        self.loading.style().polish(self.loading)
        self.loading.update()

    def _on_run_scan(self):
        target = (self.in_target.text() or "").strip()
        if not target:
            return
        if self._proc is not None:
            return

        self._stdout = ""
        self._stderr = ""
        self._scan_start_ts = time.time()

        self.output.set_scanning()
        self._set_busy(True)

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
        args = ["scripts/scan2.py", "scan", target]
        self._proc.start(py, args)

    def _on_proc_error(self, err):
        self._proc = None
        self._set_busy(False)
        self.output.set_error("SCAN ERROR", "The scan process could not be started or crashed.")

    def _on_ready_stdout(self):
        if not self._proc:
            return
        data = bytes(self._proc.readAllStandardOutput()).decode(errors="replace")
        self._stdout += data

    def _on_ready_stderr(self):
        if not self._proc:
            return
        data = bytes(self._proc.readAllStandardError()).decode(errors="replace")
        self._stderr += data

    def _on_finished(self, exit_code, exit_status):
        if self._proc is not None:
            try:
                self._stdout += bytes(self._proc.readAllStandardOutput()).decode(errors="replace")
            except Exception:
                pass
            try:
                self._stderr += bytes(self._proc.readAllStandardError()).decode(errors="replace")
            except Exception:
                pass

        stdout = _strip_ansi(self._stdout or "")
        _ = _strip_ansi(self._stderr or "")

        self._proc = None
        self._set_busy(False)

        json_path = None

        m = _SAVED_RE.search(stdout)
        if m:
            raw = (m.group("path") or "").strip()
            p = Path(raw)
            if not p.is_absolute():
                p = (ROOT / p).resolve()
            json_path = p

        if (json_path is None) or (not json_path.exists()):
            json_path = _find_latest_scan_json(self._scan_start_ts)

        if json_path is None or not json_path.exists():
            hint = None
            if exit_code not in (0, None):
                hint = f"Process exit code: {exit_code}"
            self.output.set_error("NO REPORT PRODUCED", "The scan finished but no report file was found.", hint=hint)
            return

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                doc = json.load(f)

            summary = _extract_summary_from_json(doc)
            self.output.render_summary(summary)

        except Exception:
            self.output.set_error("REPORT PARSE ERROR", "A report was produced, but it could not be parsed.")
        finally:
            try:
                json_path.unlink(missing_ok=True)
            except Exception:
                pass


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = QuickScanWindow()
    w.show()
    sys.exit(app.exec())
