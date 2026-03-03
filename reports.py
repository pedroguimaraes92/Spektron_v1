from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon, QPixmap, QColor
from PySide6.QtWidgets import (
    QWidget,
    QLabel,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QFrame,
    QPushButton,
    QComboBox,
    QMessageBox,
    QSizePolicy,
    QScrollArea,
    QSpacerItem,
    QGraphicsDropShadowEffect,
)

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        PageBreak,
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
except Exception:
    A4 = None



_SCAN_RE_EVIDENCE = re.compile(r"^evidence_(?P<scan>.+?)\.v1\.json$", re.IGNORECASE)
_SCAN_RE_ATTACK = re.compile(
    r"^(attack_(?:summary|paths|graph))_(?P<scan>.+?)\.v1\.json$", re.IGNORECASE
)
_SCAN_RE_REPORT_PDF = re.compile(r"^report_(?P<scan>.+?)\.pdf$", re.IGNORECASE)
_SCAN_RE_EXPORT_ZIP = re.compile(r"^export_(?P<scan>.+?)\.zip$", re.IGNORECASE)


def _root_dir() -> Path:
    p = Path(__file__).resolve()
    if p.parent.name.lower() == "ui":
        return p.parent.parent
    return p.parent


def _out_dir(name: str) -> Path:
    return _root_dir() / "output" / name


def _safe_read_json(p: Path) -> Optional[Any]:
    try:
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _open_path_cross_platform(path: Path) -> None:
    path = path.resolve()
    try:
        if os.name == "nt":
            os.startfile(str(path)) 
        elif sys.platform == "darwin":
            subprocess.run(["open", str(path)], check=False)
        else:
            subprocess.run(["xdg-open", str(path)], check=False)
    except Exception:
        pass


def _scan_ids_available() -> List[str]:
    ids = set()

    ev_dir = _out_dir("evidence")
    atk_dir = _out_dir("attack")
    rep_dir = _out_dir("reports")

    if ev_dir.exists():
        for f in ev_dir.iterdir():
            if not f.is_file():
                continue
            m = _SCAN_RE_EVIDENCE.match(f.name)
            if m:
                ids.add(m.group("scan"))

    if atk_dir.exists():
        for f in atk_dir.iterdir():
            if not f.is_file():
                continue
            m = _SCAN_RE_ATTACK.match(f.name)
            if m:
                ids.add(m.group("scan"))

    if rep_dir.exists():
        for f in rep_dir.iterdir():
            if not f.is_file():
                continue
            m = _SCAN_RE_REPORT_PDF.match(f.name)
            if m:
                ids.add(m.group("scan"))
            m = _SCAN_RE_EXPORT_ZIP.match(f.name)
            if m:
                ids.add(m.group("scan"))

    return sorted(ids)


def _paths_for_scan(scan_id: str) -> Dict[str, Path]:
    ev = _out_dir("evidence") / f"evidence_{scan_id}.v1.json"
    atk_sum = _out_dir("attack") / f"attack_summary_{scan_id}.v1.json"
    atk_paths = _out_dir("attack") / f"attack_paths_{scan_id}.v1.json"
    atk_graph = _out_dir("attack") / f"attack_graph_{scan_id}.v1.json"
    pdf = _out_dir("reports") / f"report_{scan_id}.pdf"
    z = _out_dir("reports") / f"export_{scan_id}.zip"

    return {
        "evidence": ev,
        "attack_summary": atk_sum,
        "attack_paths": atk_paths,
        "attack_graph": atk_graph,
        "pdf": pdf,
        "zip": z,
    }


def _bucket_counts_from_paths(paths: List[Dict[str, Any]]) -> Dict[str, int]:
    c = {"HIGH": 0, "MED": 0, "LOW": 0}
    for p in paths:
        b = (((p.get("score") or {}).get("bucket")) or "").upper().strip()
        if b.startswith("H"):
            c["HIGH"] += 1
        elif b.startswith("M"):
            c["MED"] += 1
        elif b.startswith("L"):
            c["LOW"] += 1
    return c


def _max_score_from_paths(paths: List[Dict[str, Any]]) -> float:
    m = 0.0
    for p in paths:
        try:
            s = float(((p.get("score") or {}).get("score_0_100")) or 0.0)
            if s > m:
                m = s
        except Exception:
            continue
    return m


def _top_paths(paths: List[Dict[str, Any]], n: int = 5) -> List[Dict[str, Any]]:
    def key_fn(p: Dict[str, Any]) -> float:
        try:
            return float(((p.get("score") or {}).get("score_0_100")) or 0.0)
        except Exception:
            return 0.0

    return sorted(paths, key=key_fn, reverse=True)[:n]



def _ensure_reports_dir() -> Path:
    d = _out_dir("reports")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _make_pdf(scan_id: str) -> Tuple[bool, str, Optional[Path]]:
    if A4 is None:
        return False, "ReportLab is not available.", None

    files = _paths_for_scan(scan_id)
    evidence = _safe_read_json(files["evidence"])
    summary = _safe_read_json(files["attack_summary"])
    paths = _safe_read_json(files["attack_paths"])

    if not isinstance(paths, list):
        return False, "attack_paths JSON not found or invalid.", None

    total_paths = len(paths)
    max_score = _max_score_from_paths(paths)
    buckets = _bucket_counts_from_paths(paths)

    target = None
    if isinstance(evidence, dict):
        target = evidence.get("target") or evidence.get("host") or evidence.get("url")

    out_pdf = _ensure_reports_dir() / f"report_{scan_id}.pdf"

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=18, spaceAfter=8)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=6)
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9, leading=12)
    mono = ParagraphStyle("mono", parent=styles["BodyText"], fontName="Courier", fontSize=8, leading=10)

    story: List[Any] = []
    story.append(Paragraph("Spektron v1 — Report", h1))
    story.append(Paragraph(f"Scan ID: <b>{scan_id}</b>", body))
    if target:
        story.append(Paragraph(f"Target: <b>{target}</b>", body))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", body))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Executive Summary", h2))
    story.append(Paragraph(f"Total paths: <b>{total_paths}</b>", body))
    story.append(Paragraph(f"Max score: <b>{max_score:.1f}</b>", body))
    story.append(Paragraph(f"Breakdown: HIGH {buckets['HIGH']} · MED {buckets['MED']} · LOW {buckets['LOW']}", body))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Ranked Attack Paths", h2))
    rows = [["Score", "Bucket", "Entry", "Weakness", "Impact"]]
    for p in _top_paths(paths, n=min(50, len(paths))):
        score = ((p.get("score") or {}).get("score_0_100")) or 0
        bucket = ((p.get("score") or {}).get("bucket")) or ""
        entry = ((p.get("entry") or {}).get("title")) or ""
        weak = ((p.get("weakness") or {}).get("title")) or ""
        impact = ((p.get("impact") or {}).get("title")) or ""
        rows.append([f"{float(score):.1f}", str(bucket), str(entry), str(weak), str(impact)])

    table = Table(rows, colWidths=[18 * mm, 18 * mm, 48 * mm, 52 * mm, 48 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#333333")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(table)
    story.append(PageBreak())

    story.append(Paragraph("Top 10 Details", h2))
    for p in _top_paths(paths, n=min(10, len(paths))):
        pid = p.get("id", "")
        score = ((p.get("score") or {}).get("score_0_100")) or 0
        bucket = ((p.get("score") or {}).get("bucket")) or ""
        story.append(Paragraph(f"<b>Path {pid}</b> — {float(score):.1f} ({bucket})", body))
        entry = ((p.get("entry") or {}).get("title")) or ""
        weak = ((p.get("weakness") or {}).get("title")) or ""
        tech = ((p.get("technique") or {}).get("title")) or ""
        impact = ((p.get("impact") or {}).get("title")) or ""
        story.append(Paragraph(f"Entry: {entry}", body))
        story.append(Paragraph(f"Weakness: {weak}", body))
        story.append(Paragraph(f"Technique: {tech}", body))
        story.append(Paragraph(f"Impact: {impact}", body))

        controls = p.get("controls") or []
        if isinstance(controls, list) and controls:
            story.append(Paragraph("Controls:", body))
            for c in controls[:10]:
                story.append(Paragraph(f"• {c}", body))

        refs = p.get("refs") or []
        if isinstance(refs, list) and refs:
            story.append(Paragraph("Refs:", body))
            for r in refs[:10]:
                story.append(Paragraph(str(r), mono))

        story.append(Spacer(1, 8))

    story.append(PageBreak())
    story.append(Paragraph("Appendix — Source files", h2))
    for k, fp in files.items():
        if fp.exists():
            story.append(Paragraph(f"{k}: {fp.as_posix()}", mono))

    try:
        doc = SimpleDocTemplate(str(out_pdf), pagesize=A4, title="Spektron Report")
        doc.build(story)
        return True, "PDF generated.", out_pdf
    except Exception as e:
        return False, f"Failed to generate PDF: {e}", None


def _make_zip(scan_id: str) -> Tuple[bool, str, Optional[Path]]:
    files = _paths_for_scan(scan_id)
    _ensure_reports_dir()
    out_zip = files["zip"]

    members: List[Tuple[Path, str]] = []
    for k in ("evidence", "attack_summary", "attack_paths", "attack_graph", "pdf"):
        p = files[k]
        if p.exists():
            members.append((p, p.name))

    if not members:
        return False, "No artifacts found for this scan.", None

    try:
        with zipfile.ZipFile(str(out_zip), "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for src, arc in members:
                zf.write(str(src), arcname=arc)
        return True, "ZIP generated.", out_zip
    except Exception as e:
        return False, f"Failed to generate ZIP: {e}", None



class _Card(QFrame):
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self.setFrameShape(QFrame.NoFrame)
        self.setStyleSheet("""
            QFrame#Card{
                background: rgba(0,0,0,60);
                border: 1px solid rgba(120,255,170,55);
                border-radius: 18px;
            }
        """)


class _HubButton(QPushButton):
    def __init__(self, title: str, subtitle: str, icon_path: Path, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setCheckable(False)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setMinimumHeight(78)
        self.setMinimumWidth(420)
        self.setMaximumWidth(520)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.setSpacing(14)

        ico = QLabel()
        pm = QPixmap(str(icon_path))
        if not pm.isNull():
            pm = pm.scaled(26, 26, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        ico.setPixmap(pm)
        ico.setFixedSize(26, 26)

        tx = QVBoxLayout()
        tx.setSpacing(2)
        t = QLabel(title)
        t.setObjectName("HubTitle")
        s = QLabel(subtitle)
        s.setObjectName("HubSub")
        tx.addWidget(t)
        tx.addWidget(s)

        lay.addWidget(ico, 0, Qt.AlignVCenter)
        lay.addLayout(tx, 1)

        self.setStyleSheet("""
            QPushButton{
                background: rgba(0,0,0,25);
                border: 1px solid rgba(120,255,170,110);
                border-radius: 14px;
                color: rgba(255,255,255,220);
                text-align: left;
            }
            QPushButton:hover{
                background: rgba(120,255,170,22);
                border: 1px solid rgba(120,255,170,170);
            }
            QLabel#HubTitle{
                font-size: 14px;
                font-weight: 600;
                color: rgba(255,255,255,235);
            }
            QLabel#HubSub{
                font-size: 11px;
                color: rgba(255,255,255,140);
            }
        """)


class ReportsWidget(QWidget):
    """
    Reports hub + 2 sections:
    - Export: generate PDF/ZIP
    - Folders: open output folders
    """
    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)

        # Icons
        root = _root_dir()
        icons = root / "assets" / "icons"
        self._icon_main = icons / "icon_reports.png"
        self._icon_back = icons / "icon_back.png"
        self._icon_export = icons / "icon_export.png"
        self._icon_folders = icons / "icon_exit.png"

        self._current_scan: Optional[str] = None
        self._scan_ids: List[str] = []

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.setAlignment(Qt.AlignTop)

        self._icon_label = QLabel()
        self._icon_label.setAlignment(Qt.AlignHCenter)
        icon_glow = QGraphicsDropShadowEffect()
        icon_glow.setBlurRadius(22)
        icon_glow.setOffset(0, 0)
        icon_glow.setColor(QColor(124, 255, 158, 60))
        self._icon_label.setGraphicsEffect(icon_glow)

        outer.addSpacing(30)
        outer.addWidget(self._icon_label, alignment=Qt.AlignHCenter)
        outer.addSpacing(16)

        self.card = _Card()
        self.card.setMinimumHeight(460)
        self.card.setMaximumHeight(520)
        outer.addWidget(self.card, 0, Qt.AlignHCenter)
        outer.addStretch(1)

        card_lay = QVBoxLayout(self.card)
        card_lay.setContentsMargins(26, 22, 26, 22)
        card_lay.setSpacing(16)


        hdr = QVBoxLayout()
        hdr.setSpacing(4)
        self.title = QLabel("Reports")
        self.title.setStyleSheet("color: rgba(255,255,255,238); font-family: 'Segoe UI'; font-size: 22px; font-weight: 600;")
        self.sub = QLabel("Export and folder management (offline)")
        self.sub.setStyleSheet("color: rgba(255,255,255,135); font-family: 'Segoe UI'; font-size: 12px;")
        hdr.addWidget(self.title)
        hdr.addWidget(self.sub)
        card_lay.addLayout(hdr)

        self.host = QFrame()
        self.host.setFrameShape(QFrame.NoFrame)
        self.host.setStyleSheet("background: rgba(0,0,0,0);")
        card_lay.addWidget(self.host, 1)

        self.host_lay = QVBoxLayout(self.host)
        self.host_lay.setContentsMargins(0, 0, 0, 0)
        self.host_lay.setSpacing(0)

        self.page_hub = QWidget()
        self.page_export = QWidget()
        self.page_folders = QWidget()

        self.host_lay.addWidget(self.page_hub)
        self.host_lay.addWidget(self.page_export)
        self.host_lay.addWidget(self.page_folders)

        self._build_hub()
        self._build_export()
        self._build_folders()

        self._set_page("hub")
        self._refresh_scan_ids()


    def _input_style(self) -> str:
        return """
            QComboBox{
                background: rgba(0,0,0,35);
                border: 1px solid rgba(120,255,170,120);
                border-radius: 12px;
                padding: 8px 12px;
                color: rgba(255,255,255,220);
            }
            QComboBox::drop-down{
                border: none;
                width: 26px;
            }
            QComboBox QAbstractItemView{
                background: rgba(0,0,0,220);
                border: 1px solid rgba(120,255,170,90);
                selection-background-color: rgba(120,255,170,55);
                color: rgba(255,255,255,220);
            }
        """

    def _btn_primary_style(self) -> str:
        return """
            QPushButton{
                background: rgba(120,255,170,20);
                border: 1px solid rgba(120,255,170,160);
                border-radius: 12px;
                padding: 10px 16px;
                color: rgba(255,255,255,235);
                font-family: 'Segoe UI';
                font-size: 12px;
                font-weight: 850;

            }
            QPushButton:hover{
                background: rgba(120,255,170,30);
                border: 1px solid rgba(120,255,170,220);
            }
            QPushButton:disabled{
                background: rgba(0,0,0,25);
                border: 1px solid rgba(120,255,170,60);
                color: rgba(220,255,230,120);
            }
        """

    def _btn_secondary_style(self) -> str:
        return """
            QPushButton{
                background: rgba(0,0,0,25);
                border: 1px solid rgba(120,255,170,110);
                border-radius: 12px;
                padding: 10px 16px;
                color: rgba(255,255,255,220);
                font-family: 'Segoe UI';
                font-size: 12px;
                font-weight: 750;

            }
            QPushButton:hover{
                background: rgba(120,255,170,18);
                border: 1px solid rgba(120,255,170,170);
            }
            QPushButton:disabled{
                background: rgba(0,0,0,20);
                border: 1px solid rgba(120,255,170,50);
                color: rgba(220,255,230,110);
            }
        """

    def _back_btn(self) -> QPushButton:
        b = QPushButton()
        b.setFixedSize(34, 34)
        b.setCursor(Qt.PointingHandCursor)
        b.setIcon(QIcon(str(self._icon_back)))
        b.setIconSize(QSize(18, 18))
        b.setStyleSheet("""
            QPushButton{
                background: rgba(0,0,0,30);
                border: 1px solid rgba(120,255,170,110);
                border-radius: 10px;
            }
            QPushButton:hover{
                background: rgba(120,255,170,20);
                border: 1px solid rgba(120,255,170,170);
            }
        """)
        return b


    def _set_page(self, name: str) -> None:
        self.page_hub.setVisible(name == "hub")
        self.page_export.setVisible(name == "export")
        self.page_folders.setVisible(name == "folders")

        if name == "hub":
            ico = self._icon_main
        elif name == "export":
            ico = self._icon_export
        else:
            ico = self._icon_folders

        pm = QPixmap(str(ico))
        if not pm.isNull():
            pm = pm.scaled(118, 118, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self._icon_label.setPixmap(pm)

    def _section_header(self, title: str) -> Tuple[QHBoxLayout, QPushButton, QLabel]:
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)

        back = self._back_btn()
        lab = QLabel(title)
        lab.setStyleSheet("color: rgba(255,255,255,220); font-family: 'Segoe UI'; font-size: 13px; font-weight: 600;")

        row.addWidget(back, 0, Qt.AlignLeft)
        row.addWidget(lab, 0, Qt.AlignVCenter)
        row.addStretch(1)
        return row, back, lab

    def _build_hub(self) -> None:
        lay = QVBoxLayout(self.page_hub)
        lay.setContentsMargins(0, 10, 0, 0)
        lay.setSpacing(10)

        sec = QLabel("Configuration")
        sec.setStyleSheet("color: rgba(255,255,255,215); font-family: 'Segoe UI'; font-size: 13px; font-weight: 600;")
        lay.addWidget(sec)
        lay.addSpacing(6)

        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(14)
        lay.addLayout(grid)

        b_exp = _HubButton("Export", "Generate PDF and bundle ZIP", self._icon_export)
        b_fol = _HubButton("Folders", "Open output directories", self._icon_folders)

        grid.addWidget(b_exp, 0, 0)
        grid.addWidget(b_fol, 0, 1)

        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        lay.addStretch(1)
        b_exp.clicked.connect(lambda: self._set_page("export"))
        b_fol.clicked.connect(lambda: self._set_page("folders"))

    def _build_export(self) -> None:
        outer = QVBoxLayout(self.page_export)
        outer.setContentsMargins(0, 6, 0, 0)
        outer.setSpacing(12)

        head, back, _ = self._section_header("Export")
        outer.addLayout(head)
        back.clicked.connect(lambda: self._set_page("hub"))

        hint = QLabel("Generate professional artifacts from existing JSON outputs.")
        hint.setStyleSheet("color: rgba(255,255,255,130); font-family: 'Segoe UI'; font-size: 11px;")
        outer.addWidget(hint)

        row = QHBoxLayout()
        row.setSpacing(12)

        lab = QLabel("Scan")
        lab.setStyleSheet("color: rgba(255,255,255,195); font-family: 'Segoe UI'; font-size: 12px; font-weight: 650;")

        self.exp_scan = QComboBox()
        self.exp_scan.setMinimumWidth(520)
        self.exp_scan.setStyleSheet(self._input_style())

        row.addWidget(lab, 0)
        row.addWidget(self.exp_scan, 1)
        outer.addLayout(row)

        buttons = QHBoxLayout()
        buttons.setSpacing(12)

        self.btn_export_pdf = QPushButton("Generate PDF")
        self.btn_export_pdf.setCursor(Qt.PointingHandCursor)
        self.btn_export_pdf.setStyleSheet(self._btn_primary_style())
        self.btn_export_pdf.setMinimumWidth(180)

        self.btn_export_zip = QPushButton("Bundle ZIP")
        self.btn_export_zip.setCursor(Qt.PointingHandCursor)
        self.btn_export_zip.setStyleSheet(self._btn_primary_style())
        self.btn_export_zip.setMinimumWidth(180)

        self.btn_open_pdf2 = QPushButton("Open PDF")
        self.btn_open_pdf2.setCursor(Qt.PointingHandCursor)
        self.btn_open_pdf2.setStyleSheet(self._btn_secondary_style())
        self.btn_open_pdf2.setMinimumWidth(180)

        self.btn_open_zip2 = QPushButton("Open ZIP")
        self.btn_open_zip2.setCursor(Qt.PointingHandCursor)
        self.btn_open_zip2.setStyleSheet(self._btn_secondary_style())
        self.btn_open_zip2.setMinimumWidth(180)

        buttons.addWidget(self.btn_export_pdf)
        buttons.addWidget(self.btn_export_zip)
        buttons.addSpacing(20)
        buttons.addWidget(self.btn_open_pdf2)
        buttons.addWidget(self.btn_open_zip2)
        buttons.addStretch(1)

        outer.addLayout(buttons)

        info = QLabel(
            "Outputs:\n"
            "• output/reports/report_<scan_id>.pdf\n"
            "• output/reports/export_<scan_id>.zip"
        )
        info.setStyleSheet("color: rgba(255,255,255,130); font-family: 'Segoe UI'; font-size: 11px;")
        outer.addWidget(info)
        outer.addStretch(1)

        self.exp_scan.currentIndexChanged.connect(self._sync_current_scan_from_export)
        self.btn_export_pdf.clicked.connect(self._on_generate_pdf)
        self.btn_export_zip.clicked.connect(self._on_bundle_zip)
        self.btn_open_pdf2.clicked.connect(lambda: self._open_artifact("pdf"))
        self.btn_open_zip2.clicked.connect(lambda: self._open_artifact("zip"))

    def _build_folders(self) -> None:
        outer = QVBoxLayout(self.page_folders)
        outer.setContentsMargins(0, 6, 0, 0)
        outer.setSpacing(12)

        head, back, _ = self._section_header("Folders")
        outer.addLayout(head)
        back.clicked.connect(lambda: self._set_page("hub"))

        hint = QLabel("Open output folders.")
        hint.setStyleSheet("color: rgba(255,255,255,130); font-family: 'Segoe UI'; font-size: 11px;")
        outer.addWidget(hint)

        row = QHBoxLayout()
        row.setSpacing(12)

        b1 = QPushButton("Open output/evidence")
        b2 = QPushButton("Open output/attack")
        b3 = QPushButton("Open output/reports")

        for b in (b1, b2, b3):
            b.setCursor(Qt.PointingHandCursor)
            b.setStyleSheet(self._btn_secondary_style())
            b.setMinimumWidth(220)

        row.addWidget(b1)
        row.addWidget(b2)
        row.addWidget(b3)
        row.addStretch(1)

        outer.addLayout(row)
        outer.addStretch(1)

        b1.clicked.connect(lambda: _open_path_cross_platform(_out_dir("evidence")))
        b2.clicked.connect(lambda: _open_path_cross_platform(_out_dir("attack")))
        b3.clicked.connect(lambda: _open_path_cross_platform(_out_dir("reports")))


    def _refresh_scan_ids(self) -> None:
        self._scan_ids = _scan_ids_available()
        prev = self._current_scan

        def fill(cb: QComboBox) -> None:
            cb.blockSignals(True)
            cb.clear()
            cb.addItems(self._scan_ids)
            cb.blockSignals(False)
        fill(self.exp_scan)

        if prev and prev in self._scan_ids:
            self._set_current_scan(prev)
        elif self._scan_ids:
            self._set_current_scan(self._scan_ids[0])
        else:
            self._set_current_scan(None)

    def _set_current_scan(self, scan_id: Optional[str]) -> None:
        self._current_scan = scan_id

        def select(cb: QComboBox) -> None:
            cb.blockSignals(True)
            if scan_id and scan_id in self._scan_ids:
                cb.setCurrentText(scan_id)
            cb.blockSignals(False)
        select(self.exp_scan)
    def _sync_current_scan_from_export(self) -> None:
        s = self.exp_scan.currentText().strip()
        self._set_current_scan(s if s else None)

    def _open_artifact(self, kind: str) -> None:
        scan_id = self._current_scan
        if not scan_id:
            return
        p = _paths_for_scan(scan_id).get(kind)
        if not p:
            return
        if p.exists():
            _open_path_cross_platform(p)
        else:
            QMessageBox.information(self, "Reports", f"File not found:\n{p.as_posix()}")

    def _on_generate_pdf(self) -> None:
        scan_id = self._current_scan
        if not scan_id:
            QMessageBox.information(self, "Reports", "Select a scan first.")
            return
        ok, msg, out = _make_pdf(scan_id)
        if ok:
            QMessageBox.information(self, "Reports", f"{msg}\n{out.as_posix() if out else ''}")
        else:
            QMessageBox.critical(self, "Reports", msg)

    def _on_bundle_zip(self) -> None:
        scan_id = self._current_scan
        if not scan_id:
            QMessageBox.information(self, "Reports", "Select a scan first.")
            return
        ok, msg, out = _make_zip(scan_id)
        if ok:
            QMessageBox.information(self, "Reports", f"{msg}\n{out.as_posix() if out else ''}")
        else:
            QMessageBox.critical(self, "Reports", msg)
