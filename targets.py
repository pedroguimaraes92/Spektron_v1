from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QColor, QFont, QIcon, QPixmap, QFontMetrics
from PySide6.QtWidgets import (
    QWidget,
    QLabel,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QFrame,
    QPushButton,
    QSizePolicy,
    QScrollArea,
    QButtonGroup,
    QGraphicsDropShadowEffect,
    QStackedWidget,
)


ROOT = Path(__file__).resolve().parent
ASSETS = ROOT / "assets"
ICONS = ASSETS / "icons"

_SCAN_ID_RE = re.compile(r"^(?P<target>.+?)_(?P<ts>\d{8}T\d{6}Z)$", re.IGNORECASE)


@dataclass(frozen=True)
class ScanInfo:
    scan_id: str
    target: str
    ts_key: str
    has_attack: bool
    has_evidence: bool
    has_reports: bool


def _ui_font(px: int, weight=QFont.Weight.Normal) -> QFont:
    f = QFont("Segoe UI")
    if not f.exactMatch():
        f = QFont("Inter")
    if not f.exactMatch():
        f = QFont("Arial")
    f.setPixelSize(int(px))
    try:
        if isinstance(weight, QFont.Weight):
            f.setWeight(weight)
        else:
            f.setWeight(QFont.Weight(int(weight)))
    except Exception:
        f.setWeight(QFont.Weight.Normal)
    return f


def _existing_icon(fname: str, fallback: str) -> Path:
    p = ICONS / fname
    if p.exists():
        return p
    return ICONS / fallback


def _parse_scan_id(scan_id: str) -> Tuple[str, str]:
    sid = (scan_id or "").strip()
    m = _SCAN_ID_RE.match(sid)
    if m:
        return (m.group("target") or sid).strip() or sid, (m.group("ts") or "").strip()
    return sid, ""


def _discover_scans() -> List[ScanInfo]:
    atk_dir = ROOT / "output" / "attack"
    ev_dir = ROOT / "output" / "evidence"
    rep_dir = ROOT / "output" / "reports"

    out: List[ScanInfo] = []
    if not atk_dir.exists() or not atk_dir.is_dir():
        return out

    for f in atk_dir.iterdir():
        if not f.is_file():
            continue
        name = f.name
        if not (name.startswith("attack_summary_") and name.endswith(".v1.json")):
            continue

        scan_id = name[len("attack_summary_") : -len(".v1.json")]
        if not scan_id:
            continue

        target, ts = _parse_scan_id(scan_id)

        has_attack = True
        has_evidence = (ev_dir / f"evidence_{scan_id}.v1.json").exists()
        has_reports = (rep_dir / f"report_{scan_id}.pdf").exists() or (rep_dir / f"export_{scan_id}.zip").exists()

        ts_key = ts or ""
        if not ts_key:
            try:
                ts_key = f"{int(f.stat().st_mtime):010d}"
            except Exception:
                ts_key = ""

        out.append(
            ScanInfo(
                scan_id=scan_id,
                target=target,
                ts_key=ts_key,
                has_attack=has_attack,
                has_evidence=has_evidence,
                has_reports=has_reports,
            )
        )

    out.sort(key=lambda x: x.ts_key, reverse=True)
    return out


class _ElideLabel(QLabel):
    def __init__(self, text: str = "", parent=None) -> None:
        super().__init__("", parent)
        self._full = text or ""
        self.setText(text)

    def setText(self, text: str) -> None:
        self._full = text or ""
        self._apply()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._apply()

    def _apply(self) -> None:
        w = max(0, self.width())
        if w <= 4:
            super().setText("")
            return
        fm = QFontMetrics(self.font())
        super().setText(fm.elidedText(self._full, Qt.ElideRight, w))


class _Badge(QLabel):
    def __init__(self, text: str, tone: str, parent=None) -> None:
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignCenter)
        self.setFont(_ui_font(10, QFont.Weight.DemiBold))
        self.setFixedHeight(24)
        self.setContentsMargins(10, 0, 10, 0)

        if tone == "ok":
            bg, bd, fg = "rgba(124,255,158,14)", "rgba(124,255,158,120)", "rgba(255,255,255,220)"
        elif tone == "warn":
            bg, bd, fg = "rgba(255,206,120,12)", "rgba(255,206,120,150)", "rgba(255,255,255,220)"
        else:
            bg, bd, fg = "rgba(255,255,255,8)", "rgba(255,255,255,18)", "rgba(255,255,255,170)"

        self.setStyleSheet(
            f"""
            QLabel {{
                background-color: {bg};
                border: 1px solid {bd};
                color: {fg};
                border-radius: 999px;
                letter-spacing: 1px;
            }}
            """
        )


class _HubButton(QPushButton):
    def __init__(self, title: str, subtitle: str, icon_path: Path, parent=None) -> None:
        super().__init__(parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setCheckable(False)
        self.setFocusPolicy(Qt.NoFocus)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setMinimumHeight(96)
        self.setMinimumWidth(420)

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
        t.setStyleSheet("color: rgba(255,255,255,235); font-size: 14px; font-weight: 600;")
        s = QLabel(subtitle)
        s.setStyleSheet("color: rgba(255,255,255,140); font-size: 11px;")
        tx.addWidget(t)
        tx.addWidget(s)

        lay.addWidget(ico, 0, Qt.AlignVCenter)
        lay.addLayout(tx, 1)

        self.setStyleSheet(
            """
            QPushButton{
                background: rgba(0,0,0,22);
                border: 1px solid rgba(124,255,158,26);
                border-radius: 14px;
                text-align: left;
            }
            QPushButton:hover{
                background: rgba(124,255,158,8);
                border: 1px solid rgba(124,255,158,44);
            }
            QPushButton:pressed{
                background: rgba(124,255,158,12);
                border: 1px solid rgba(124,255,158,70);
            }
            QPushButton:focus{ outline: none; }
            """
        )

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(18)
        shadow.setOffset(0, 6)
        shadow.setColor(QColor(0, 0, 0, 110))
        self.setGraphicsEffect(shadow)


class _TargetItemButton(QPushButton):
    def __init__(self, target: str, count: int, parent=None) -> None:
        super().__init__(parent)
        self._target = target

        self.setCursor(Qt.PointingHandCursor)
        self.setCheckable(True)
        self.setFocusPolicy(Qt.NoFocus)
        self.setMinimumHeight(58)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        name = _ElideLabel(target)
        name.setFont(_ui_font(12, QFont.Weight.DemiBold))
        name.setStyleSheet("color: rgba(255,255,255,225);")
        name.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        cnt = QLabel(f"({int(count)})")
        cnt.setFont(_ui_font(12, QFont.Weight.DemiBold))
        cnt.setStyleSheet("color: rgba(255,255,255,145);")
        cnt.setFixedWidth(56)
        cnt.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        row = QHBoxLayout()
        row.setContentsMargins(16, 10, 16, 10)
        row.setSpacing(10)
        row.addWidget(name, 1)
        row.addWidget(cnt, 0)
        self.setLayout(row)

        self.setStyleSheet(
            """
            QPushButton{
                background-color: transparent;
                border: none;
                border-left: 3px solid rgba(0,0,0,0);
                border-bottom: 1px solid rgba(255,255,255,10);
                text-align: left;
                padding-left: 12px;
                padding-right: 6px;
            }
            QPushButton:hover{
                background-color: rgba(124,255,158,10);
                border-left: 3px solid rgba(124,255,158,210);
            }
            QPushButton:checked{
                background-color: rgba(0,0,0,26);
                border-left: 3px solid rgba(124,255,158,240);
                border-bottom: 1px solid rgba(124,255,158,60);
            }
            QPushButton:checked:hover{
                background-color: rgba(124,255,158,14);
            }
            QPushButton:focus{ outline: none; }
            """
        )

    @property
    def target(self) -> str:
        return self._target


class _ScanItemButton(QPushButton):
    def __init__(self, info: ScanInfo, marker_side: str = "left", parent=None) -> None:
        super().__init__(parent)
        self._info = info

        self.setCursor(Qt.PointingHandCursor)
        self.setCheckable(True)
        self.setFocusPolicy(Qt.NoFocus)
        self.setMinimumHeight(76)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        title = _ElideLabel(info.scan_id)
        title.setFont(_ui_font(12, QFont.Weight.DemiBold))
        title.setStyleSheet("color: rgba(255,255,255,225);")
        title.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        badges_row = QHBoxLayout()
        badges_row.setContentsMargins(0, 0, 0, 0)
        badges_row.setSpacing(8)
        if info.has_attack:
            badges_row.addWidget(_Badge("Attack", "ok"))
        if info.has_evidence:
            badges_row.addWidget(_Badge("Evidence", "ok"))
        if info.has_reports:
            badges_row.addWidget(_Badge("Reports", "warn"))
        badges_row.addStretch(1)

        badges_wrap = QWidget()
        badges_wrap.setLayout(badges_row)
        badges_wrap.setStyleSheet("background: transparent;")

        v = QVBoxLayout()
        v.setContentsMargins(16, 11, 16, 12)
        v.setSpacing(9)
        v.addWidget(title)
        v.addWidget(badges_wrap)
        self.setLayout(v)

        if marker_side == "right":
            self.setStyleSheet(
                """
                QPushButton{
                    background-color: transparent;
                    border: none;
                    border-right: 3px solid rgba(0,0,0,0);
                    border-bottom: 1px solid rgba(255,255,255,10);
                    text-align: left;
                    padding-left: 10px;
                    padding-right: 14px;
                }
                QPushButton:hover{
                    background-color: rgba(124,255,158,10);
                    border-right: 3px solid rgba(124,255,158,210);
                }
                QPushButton:checked{
                    background-color: rgba(0,0,0,26);
                    border-right: 3px solid rgba(124,255,158,240);
                    border-bottom: 1px solid rgba(124,255,158,60);
                }
                QPushButton:checked:hover{
                    background-color: rgba(124,255,158,14);
                }
                QPushButton:focus{ outline: none; }
                """
            )
        else:
            self.setStyleSheet(
                """
                QPushButton{
                    background-color: transparent;
                    border: none;
                    border-left: 3px solid rgba(0,0,0,0);
                    border-bottom: 1px solid rgba(255,255,255,10);
                    text-align: left;
                    padding-left: 12px;
                    padding-right: 6px;
                }
                QPushButton:hover{
                    background-color: rgba(124,255,158,10);
                    border-left: 3px solid rgba(124,255,158,210);
                }
                QPushButton:checked{
                    background-color: rgba(0,0,0,26);
                    border-left: 3px solid rgba(124,255,158,240);
                    border-bottom: 1px solid rgba(124,255,158,60);
                }
                QPushButton:checked:hover{
                    background-color: rgba(124,255,158,14);
                }
                QPushButton:focus{ outline: none; }
                """
            )

    @property
    def scan_id(self) -> str:
        return self._info.scan_id


class TargetsWidget(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setStyleSheet("background: transparent;")

        self._scans: List[ScanInfo] = []
        self._by_target: Dict[str, List[ScanInfo]] = {}
        self._selected_target: Optional[str] = None
        self._selected_scan: Optional[str] = None

        self._icon_main = _existing_icon("icon_quick_scan.png", "icon_quick_scan.png")
        self._icon_browser = _existing_icon("icon_targets.png", "icon_quick_scan.png")
        self._icon_runs = _existing_icon("icon_quick_scan.png", "icon_quick_scan.png")
        self._icon_back = _existing_icon("icon_back.png", "icon_back.png")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.setAlignment(Qt.AlignTop)

        self._icon_label = QLabel()
        self._icon_label.setAlignment(Qt.AlignHCenter)
        icon_glow = QGraphicsDropShadowEffect()
        icon_glow.setBlurRadius(22)
        icon_glow.setOffset(0, 0)
        icon_glow.setColor(QColor(124, 255, 158, 60))
        self._icon_label.setGraphicsEffect(icon_glow)

        root.addSpacing(42)
        root.addWidget(self._icon_label, alignment=Qt.AlignHCenter)
        root.addSpacing(18)

        self._card = QFrame()
        self._card.setObjectName("targets_card")
        self._card.setMinimumWidth(1180)
        self._card.setMaximumWidth(1400)
        self._card.setMinimumHeight(740) 
        self._card.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self._card.setStyleSheet(
            """
            QFrame#targets_card{
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

        root.addWidget(self._card, alignment=Qt.AlignHCenter)
        root.addStretch(1)

        card_lay = QVBoxLayout(self._card)
        card_lay.setContentsMargins(44, 32, 44, 44)
        card_lay.setSpacing(14)

        title = QLabel("Targets")
        title.setFont(_ui_font(22, QFont.Weight.DemiBold))
        title.setStyleSheet("color: rgba(255,255,255,238);")

        subtitle = QLabel("Scan Browser (offline)")
        subtitle.setFont(_ui_font(12, QFont.Weight.Normal))
        subtitle.setStyleSheet("color: rgba(255,255,255,135);")

        card_lay.addWidget(title)
        card_lay.addSpacing(2)
        card_lay.addWidget(subtitle)
        card_lay.addSpacing(10)

        self._stack = QStackedWidget()
        self._stack.setStyleSheet("background: transparent;")
        card_lay.addWidget(self._stack, 1)

        self.page_hub = QWidget()
        self.page_browser = QWidget()
        self.page_runs = QWidget()
        self._stack.addWidget(self.page_hub)
        self._stack.addWidget(self.page_browser)
        self._stack.addWidget(self.page_runs)

        self._build_hub()
        self._build_browser()
        self._build_runs()

        self._set_page("hub")

    def _scroll_style(self) -> str:
        return """
        QScrollArea{
            background: transparent;
            border: none;
        }
        QScrollArea > QWidget > QWidget { background: transparent; }
        QScrollBar:vertical {
            width: 10px;
            background: transparent;
            margin: 8px 6px 8px 0px;
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

    def _btn_primary_style(self) -> str:
        return """
        QPushButton{
            background: rgba(124,255,158,16);
            border: 1px solid rgba(124,255,158,200);
            border-radius: 12px;
            padding: 10px 16px;
            color: rgba(255,255,255,235);
            font-family: 'Segoe UI';
            font-size: 12px;
            font-weight: 850;
        }
        QPushButton:hover{
            background: rgba(124,255,158,22);
            border: 1px solid rgba(124,255,158,230);
        }
        QPushButton:pressed{
            background: rgba(124,255,158,28);
            border: 1px solid rgba(124,255,158,245);
        }
        QPushButton:disabled{
            background: rgba(0,0,0,25);
            border: 1px solid rgba(255,255,255,18);
            color: rgba(255,255,255,90);
        }
        QPushButton:focus{ outline: none; }
        """

    def _btn_secondary_style(self) -> str:
        return """
        QPushButton{
            background: rgba(0,0,0,18);
            border: 1px solid rgba(124,255,158,120);
            border-radius: 12px;
            padding: 10px 16px;
            color: rgba(255,255,255,220);
            font-family: 'Segoe UI';
            font-size: 12px;
            font-weight: 750;
        }
        QPushButton:hover{
            background: rgba(124,255,158,8);
            border: 1px solid rgba(124,255,158,160);
        }
        QPushButton:pressed{
            background: rgba(124,255,158,14);
            border: 1px solid rgba(124,255,158,200);
        }
        QPushButton:disabled{
            background: rgba(0,0,0,20);
            border: 1px solid rgba(255,255,255,18);
            color: rgba(255,255,255,90);
        }
        QPushButton:focus{ outline: none; }
        """

    def _set_top_icon(self, path: Path) -> None:
        pm = QPixmap(str(path))
        if not pm.isNull():
            pm = pm.scaled(118, 118, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self._icon_label.setPixmap(pm)

    def _back_btn(self) -> QPushButton:
        b = QPushButton()
        b.setFixedSize(34, 34)
        b.setCursor(Qt.PointingHandCursor)
        b.setFocusPolicy(Qt.NoFocus)
        b.setIcon(QIcon(str(self._icon_back)))
        b.setIconSize(QSize(18, 18))
        b.setStyleSheet(
            """
            QPushButton{
                background-color: rgba(0,0,0,12);
                border: 1px solid rgba(124,255,158,18);
                border-radius: 10px;
                padding: 0px;
            }
            QPushButton:hover{
                background-color: rgba(124,255,158,8);
                border: 1px solid rgba(124,255,158,44);
            }
            QPushButton:pressed{
                background-color: rgba(124,255,158,12);
                border: 1px solid rgba(124,255,158,70);
            }
            QPushButton:focus{ outline: none; }
            """
        )
        return b

    def _submenu_header(self, title: str) -> Tuple[QHBoxLayout, QPushButton]:
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)
        back = self._back_btn()
        lab = QLabel(title)
        lab.setFont(_ui_font(13, QFont.Weight.DemiBold))
        lab.setStyleSheet("color: rgba(255,255,255,220);")
        row.addWidget(back, 0, Qt.AlignLeft)
        row.addWidget(lab, 0, Qt.AlignVCenter)
        row.addStretch(1)
        return row, back

    def _set_page(self, name: str) -> None:
        self.page_hub.setVisible(name == "hub")
        self.page_browser.setVisible(name == "browser")
        self.page_runs.setVisible(name == "runs")

        if name == "hub":
            self._set_top_icon(self._icon_main)
        elif name == "browser":
            self._set_top_icon(self._icon_browser)
        else:
            self._set_top_icon(self._icon_runs)

        if name in ("browser", "runs"):
            self._refresh_data()
            if name == "browser":
                self._rebuild_browser()
            else:
                self._rebuild_runs()


    def _refresh_data(self) -> None:
        self._scans = _discover_scans()
        by: Dict[str, List[ScanInfo]] = {}
        for s in self._scans:
            by.setdefault(s.target, []).append(s)
        for t in list(by.keys()):
            by[t] = sorted(by[t], key=lambda x: x.ts_key, reverse=True)
        self._by_target = dict(sorted(by.items(), key=lambda kv: kv[0].lower()))

        if self._selected_target and self._selected_target not in self._by_target:
            self._selected_target = None
        if self._selected_scan and all(self._selected_scan != s.scan_id for s in self._scans):
            self._selected_scan = None


    def _build_hub(self) -> None:
        lay = QVBoxLayout(self.page_hub)
        lay.setContentsMargins(0, 10, 0, 0)
        lay.setSpacing(10)

        sec = QLabel("Configuration")
        sec.setFont(_ui_font(13, QFont.Weight.DemiBold))
        sec.setStyleSheet("color: rgba(255,255,255,215);")
        lay.addWidget(sec)
        lay.addSpacing(6)

        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(14)
        lay.addLayout(grid)

        b1 = _HubButton("Browser", "Group scans by target", self._icon_browser)
        b2 = _HubButton("Runs", "All scans (timestamp order)", self._icon_runs)

        grid.addWidget(b1, 0, 0)
        grid.addWidget(b2, 0, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        lay.addStretch(1)

        b1.clicked.connect(lambda: self._set_page("browser"))
        b2.clicked.connect(lambda: self._set_page("runs"))

    def _build_browser(self) -> None:
        lay = QVBoxLayout(self.page_browser)
        lay.setContentsMargins(0, 6, 0, 0)
        lay.setSpacing(12)

        header, back = self._submenu_header("Browser")
        lay.addLayout(header)
        back.clicked.connect(lambda: self._set_page("hub"))

        hint = QLabel("Select a target and open its scans.")
        hint.setFont(_ui_font(11, QFont.Weight.Normal))
        hint.setStyleSheet("color: rgba(255,255,255,130);")
        lay.addWidget(hint)
        
        content_row = QHBoxLayout()
        content_row.setContentsMargins(0, 0, 0, 0)
        content_row.setSpacing(36)

        left = QWidget()
        left.setStyleSheet("background: transparent;")
        left.setMinimumWidth(420)
        left.setMaximumWidth(520)
        left.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        l = QVBoxLayout(left)
        l.setContentsMargins(0, 0, 0, 0)
        l.setSpacing(10)

        t_hdr = QLabel("TARGETS")
        t_hdr.setFont(_ui_font(11, QFont.Weight.DemiBold))
        t_hdr.setStyleSheet("color: rgba(255,255,255,190); letter-spacing: 2px;")
        l.addWidget(t_hdr)

        self.targets_scroll = QScrollArea()
        self.targets_scroll.setWidgetResizable(True)
        self.targets_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.targets_scroll.setStyleSheet(self._scroll_style())
        self.targets_scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        l.addWidget(self.targets_scroll, 1)

        right = QWidget()
        right.setStyleSheet("background: transparent;")
        right.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        r = QVBoxLayout(right)
        r.setContentsMargins(0, 0, 0, 0)
        r.setSpacing(10)

        s_hdr = QLabel("SCANS")
        s_hdr.setFont(_ui_font(11, QFont.Weight.DemiBold))
        s_hdr.setStyleSheet("color: rgba(255,255,255,190); letter-spacing: 2px;")
        r.addWidget(s_hdr)

        self.scans_scroll = QScrollArea()
        self.scans_scroll.setWidgetResizable(True)
        self.scans_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scans_scroll.setStyleSheet(self._scroll_style())
        self.scans_scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        r.addWidget(self.scans_scroll, 1)

        content_row.addWidget(left, 0)
        content_row.addWidget(right, 1)
        lay.addLayout(content_row, 1)

        footer_div = QFrame()
        footer_div.setFixedHeight(1)
        footer_div.setStyleSheet("background-color: rgba(255,255,255,10);")
        lay.addWidget(footer_div)

        footer = QWidget()
        footer.setStyleSheet("background: transparent;")
        f = QHBoxLayout(footer)
        f.setContentsMargins(0, 0, 0, 0)
        f.setSpacing(18)

        self.btn_open_full = QPushButton("Open Full Scan")
        self.btn_open_full.setCursor(Qt.PointingHandCursor)
        self.btn_open_full.setFocusPolicy(Qt.NoFocus)
        self.btn_open_full.setStyleSheet(self._btn_primary_style())
        self.btn_open_full.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self.btn_open_attack = QPushButton("Open Attack Paths")
        self.btn_open_attack.setCursor(Qt.PointingHandCursor)
        self.btn_open_attack.setFocusPolicy(Qt.NoFocus)
        self.btn_open_attack.setStyleSheet(self._btn_secondary_style())
        self.btn_open_attack.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self.btn_open_reports = QPushButton("Open Reports")
        self.btn_open_reports.setCursor(Qt.PointingHandCursor)
        self.btn_open_reports.setFocusPolicy(Qt.NoFocus)
        self.btn_open_reports.setStyleSheet(self._btn_secondary_style())
        self.btn_open_reports.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        f.addStretch(1)
        f.addWidget(self.btn_open_full, 2)
        f.addWidget(self.btn_open_attack, 2)
        f.addWidget(self.btn_open_reports, 2)
        f.addStretch(1)

        lay.addWidget(footer, 0)

        self.browser_empty = QLabel("")
        self.browser_empty.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        self.browser_empty.setWordWrap(True)
        self.browser_empty.setFont(_ui_font(12, QFont.Weight.DemiBold))
        self.browser_empty.setStyleSheet("color: rgba(255,255,255,135);")
        lay.addWidget(self.browser_empty)
        self.browser_empty.hide()

        self.targets_group = QButtonGroup(self)
        self.targets_group.setExclusive(True)
        self.scans_group = QButtonGroup(self)
        self.scans_group.setExclusive(True)

        self.btn_open_full.clicked.connect(self._act_open_full_scan)
        self.btn_open_attack.clicked.connect(self._act_open_attack_paths)
        self.btn_open_reports.clicked.connect(self._act_open_reports)

        self._sync_actions(None)

    def _build_runs(self) -> None:
        lay = QVBoxLayout(self.page_runs)
        lay.setContentsMargins(0, 6, 0, 0)
        lay.setSpacing(12)

        header, back = self._submenu_header("Runs")
        lay.addLayout(header)
        back.clicked.connect(lambda: self._set_page("hub"))

        hint = QLabel("All scans detected from output/attack summaries.")
        hint.setFont(_ui_font(11, QFont.Weight.Normal))
        hint.setStyleSheet("color: rgba(255,255,255,130);")
        lay.addWidget(hint)

        r_hdr = QLabel("RUNS")
        r_hdr.setFont(_ui_font(11, QFont.Weight.DemiBold))
        r_hdr.setStyleSheet("color: rgba(255,255,255,190); letter-spacing: 2px;")
        lay.addWidget(r_hdr)

        self.runs_scroll = QScrollArea()
        self.runs_scroll.setWidgetResizable(True)
        self.runs_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.runs_scroll.setStyleSheet(self._scroll_style())
        lay.addWidget(self.runs_scroll, 1)

        div = QFrame()
        div.setFixedHeight(1)
        div.setStyleSheet("background-color: rgba(255,255,255,10);")
        lay.addWidget(div)

        actions_w = QWidget()
        actions_w.setStyleSheet("background: transparent;")
        actions = QHBoxLayout(actions_w)
        actions.setContentsMargins(0, 0, 0, 0)
        actions.setSpacing(14)

        self.btn_runs_open_full = QPushButton("Open Full Scan")
        self.btn_runs_open_full.setCursor(Qt.PointingHandCursor)
        self.btn_runs_open_full.setFocusPolicy(Qt.NoFocus)
        self.btn_runs_open_full.setStyleSheet(self._btn_primary_style())
        self.btn_runs_open_full.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self.btn_runs_open_attack = QPushButton("Open Attack Paths")
        self.btn_runs_open_attack.setCursor(Qt.PointingHandCursor)
        self.btn_runs_open_attack.setFocusPolicy(Qt.NoFocus)
        self.btn_runs_open_attack.setStyleSheet(self._btn_secondary_style())
        self.btn_runs_open_attack.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self.btn_runs_open_reports = QPushButton("Open Reports")
        self.btn_runs_open_reports.setCursor(Qt.PointingHandCursor)
        self.btn_runs_open_reports.setFocusPolicy(Qt.NoFocus)
        self.btn_runs_open_reports.setStyleSheet(self._btn_secondary_style())
        self.btn_runs_open_reports.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        actions.addWidget(self.btn_runs_open_full, 1)
        actions.addWidget(self.btn_runs_open_attack, 1)
        actions.addWidget(self.btn_runs_open_reports, 1)

        lay.addWidget(actions_w)

        self.runs_empty = QLabel("")
        self.runs_empty.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        self.runs_empty.setWordWrap(True)
        self.runs_empty.setFont(_ui_font(12, QFont.Weight.DemiBold))
        self.runs_empty.setStyleSheet("color: rgba(255,255,255,135);")
        lay.addWidget(self.runs_empty)
        self.runs_empty.hide()

        self.runs_group = QButtonGroup(self)
        self.runs_group.setExclusive(True)

        self.btn_runs_open_full.clicked.connect(self._runs_open_full)
        self.btn_runs_open_attack.clicked.connect(self._runs_open_attack)
        self.btn_runs_open_reports.clicked.connect(self._runs_open_reports)


    def _new_list_container(self) -> Tuple[QWidget, QVBoxLayout]:
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        return w, v

    def _rebuild_browser(self) -> None:
        if not self._scans:
            self.browser_empty.setText("No scans detected.")
            self.browser_empty.show()
            self.targets_scroll.hide()
            self.scans_scroll.hide()
            self._sync_actions(None)
            return

        self.browser_empty.hide()
        self.targets_scroll.show()
        self.scans_scroll.show()

        t_wrap, t_lay = self._new_list_container()
        self.targets_group = QButtonGroup(self)
        self.targets_group.setExclusive(True)

        first_target: Optional[str] = None
        btn_for_target: Dict[str, _TargetItemButton] = {}

        for t, items in self._by_target.items():
            if first_target is None:
                first_target = t
            btn = _TargetItemButton(t, len(items))
            btn_for_target[t] = btn
            self.targets_group.addButton(btn)
            btn.clicked.connect(lambda _=False, tt=t: self._on_target_selected(tt))
            t_lay.addWidget(btn)

        t_lay.addStretch(1)
        self.targets_scroll.setWidget(t_wrap)

        if self._selected_target is None and first_target is not None:
            self._selected_target = first_target

        if self._selected_target in btn_for_target:
            btn_for_target[self._selected_target].setChecked(True)

        self._rebuild_scans_for_target(self._selected_target)

    def _rebuild_scans_for_target(self, target: Optional[str]) -> None:
        s_wrap, s_lay = self._new_list_container()
        self.scans_group = QButtonGroup(self)
        self.scans_group.setExclusive(True)

        if not target or target not in self._by_target:
            s_lay.addStretch(1)
            self.scans_scroll.setWidget(s_wrap)
            self._sync_actions(None)
            return

        for s in self._by_target.get(target, []):
            btn = _ScanItemButton(s, marker_side="right")
            self.scans_group.addButton(btn)
            btn.clicked.connect(lambda _=False, sid=s.scan_id: self._on_scan_selected(sid))
            s_lay.addWidget(btn)

        s_lay.addStretch(1)
        self.scans_scroll.setWidget(s_wrap)
        self._sync_actions(self._selected_scan)

    def _rebuild_runs(self) -> None:
        if not self._scans:
            self.runs_empty.setText("No scans detected.")
            self.runs_empty.show()
            self.runs_scroll.hide()
            self._runs_sync_actions(None)
            return

        self.runs_empty.hide()
        self.runs_scroll.show()

        r_wrap, r_lay = self._new_list_container()
        self.runs_group = QButtonGroup(self)
        self.runs_group.setExclusive(True)

        for s in self._scans:
            btn = _ScanItemButton(s, marker_side="left")
            self.runs_group.addButton(btn)
            btn.clicked.connect(lambda _=False, sid=s.scan_id: self._runs_on_selected(sid))
            r_lay.addWidget(btn)

        r_lay.addStretch(1)
        self.runs_scroll.setWidget(r_wrap)
        self._runs_sync_actions(self._selected_scan)


    def _on_target_selected(self, target: str) -> None:
        self._selected_target = target
        self._selected_scan = None
        self._rebuild_scans_for_target(target)

    def _on_scan_selected(self, scan_id: str) -> None:
        self._selected_scan = scan_id
        self._sync_actions(scan_id)

    def _find_scan(self, scan_id: str) -> Optional[ScanInfo]:
        sid = (scan_id or "").strip()
        for s in self._scans:
            if s.scan_id == sid:
                return s
        return None

    def _sync_actions(self, scan_id: Optional[str]) -> None:
        s = self._find_scan(scan_id or "") if scan_id else None
        self.btn_open_full.setEnabled(bool(s))
        self.btn_open_attack.setEnabled(bool(s and s.has_attack))
        self.btn_open_reports.setEnabled(bool(s and s.has_reports))

    def _host(self):
        return self.window()

    def _act_open_full_scan(self) -> None:
        sid = (self._selected_scan or "").strip()
        if not sid:
            return
        host = self._host()
        if host is not None and hasattr(host, "go_full_scan"):
            try:
                host.go_full_scan(sid)
            except Exception:
                pass

    def _act_open_attack_paths(self) -> None:
        sid = (self._selected_scan or "").strip()
        if not sid:
            return
        host = self._host()
        if host is not None and hasattr(host, "go_attack_paths_last"):
            try:
                host.go_attack_paths_last(sid)
            except Exception:
                pass

    def _act_open_reports(self) -> None:
        sid = (self._selected_scan or "").strip()
        if not sid:
            return
        host = self._host()
        if host is not None and hasattr(host, "go_reports_export"):
            try:
                host.go_reports_export(sid)
            except Exception:
                pass

    def _runs_on_selected(self, scan_id: str) -> None:
        self._selected_scan = scan_id
        self._runs_sync_actions(scan_id)

    def _runs_sync_actions(self, scan_id: Optional[str]) -> None:
        s = self._find_scan(scan_id or "") if scan_id else None
        self.btn_runs_open_full.setEnabled(bool(s))
        self.btn_runs_open_attack.setEnabled(bool(s and s.has_attack))
        self.btn_runs_open_reports.setEnabled(bool(s and s.has_reports))

    def _runs_open_full(self) -> None:
        sid = (self._selected_scan or "").strip()
        if not sid:
            return
        host = self._host()
        if host is not None and hasattr(host, "go_full_scan"):
            try:
                host.go_full_scan(sid)
            except Exception:
                pass

    def _runs_open_attack(self) -> None:
        sid = (self._selected_scan or "").strip()
        if not sid:
            return
        host = self._host()
        if host is not None and hasattr(host, "go_attack_paths_last"):
            try:
                host.go_attack_paths_last(sid)
            except Exception:
                pass

    def _runs_open_reports(self) -> None:
        sid = (self._selected_scan or "").strip()
        if not sid:
            return
        host = self._host()
        if host is not None and hasattr(host, "go_reports_export"):
            try:
                host.go_reports_export(sid)
            except Exception:
                pass

