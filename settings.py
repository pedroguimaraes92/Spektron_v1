# settings.py
# Spektron Settings View — Hub Navigation (no tabs)
#
# NOTE:
# - No changes to settings schema logic, persistence, or validation behavior.
# - UI-only: replaces tab pills with a hub (5 cards) + back navigation.
# - Top icon swaps per section using assets/icons.
#
# Icons (assets/icons):
#   icon_attack_paths.png  -> Attack Engine
#   icon_controls.png      -> General
#   icon_capabilities.png  -> Paths & Storage
#   icon_simulate.png      -> Scan Defaults
#   icon_dns.png           -> Diagnostics
#   icon_back.png          -> Back button

import json
import os
from pathlib import Path
from typing import Any, Dict, Tuple, Optional

from PySide6.QtCore import Qt, QUrl, QTimer, QSize
from PySide6.QtGui import QColor, QFont, QPixmap, QDesktopServices, QIcon
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QFrame,
    QPushButton,
    QGraphicsDropShadowEffect,
    QComboBox,
    QSpinBox,
    QDoubleSpinBox,
    QLineEdit,
    QMessageBox,
    QSizePolicy,
    QStackedWidget,
)

ROOT = Path(__file__).resolve().parent
ASSETS = ROOT / "assets"
ICONS = ASSETS / "icons"

OUTPUT_DIR = ROOT / "output"
SETTINGS_DIR = OUTPUT_DIR / "settings"
SETTINGS_PATH = SETTINGS_DIR / "settings.v1.json"

FIXED_PATHS = {
    "Evidence": "output/evidence",
    "Attack": "output/attack",
    "Targets": "output/targets",
    "Settings": "output/settings",
}

DEFAULTS: Dict[str, Any] = {
    "version": "v1",
    "general": {
        "startup_view": "READY",
        "confirm_destructive_actions": True,
        "reduce_motion": False,
    },
    "scan_defaults": {
        "timeout_sec": 15,
        "concurrency": 6,
        "user_agent": "SpektronScanner/1.0",
        "auto_save_evidence": True,
    },
    "attack_engine": {
        "impact_weight": 1.0,
        "feasibility_weight": 1.0,
        "control_coverage_weight": 1.0,
        "overwrite_attack_outputs": False,
    },
}


def _clamp_int(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(value)))


def _clamp_float(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, float(value)))


def _safe_read_json(path: Path) -> Tuple[Dict[str, Any], bool]:
    try:
        if not path.exists():
            return {}, False
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data, True
        return {}, False
    except Exception:
        return {}, False


def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    text = json.dumps(data, ensure_ascii=False, indent=2)
    with tmp.open("w", encoding="utf-8", newline="\n") as f:
        f.write(text)
        f.write("\n")
    os.replace(str(tmp), str(path))


def _deep_merge_preserve_unknown(base: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base) if isinstance(base, dict) else {}
    for k, v in updates.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge_preserve_unknown(out[k], v)
        else:
            out[k] = v
    return out


def _ensure_output_dirs() -> None:
    (OUTPUT_DIR / "evidence").mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "attack").mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "targets").mkdir(parents=True, exist_ok=True)
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)


class _HubCardButton(QPushButton):
    def __init__(self, title: str, subtitle: str, icon: QIcon, parent=None):
        super().__init__(parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setCheckable(False)
        self.setFixedHeight(96)
        self.setMinimumWidth(420)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self._title = QLabel(title)
        tf = QFont("Segoe UI")
        tf.setPixelSize(14)
        tf.setWeight(QFont.DemiBold)
        self._title.setFont(tf)
        self._title.setStyleSheet("color: rgba(255,255,255,235);")

        self._subtitle = QLabel(subtitle)
        sf = QFont("Segoe UI")
        sf.setPixelSize(11)
        self._subtitle.setFont(sf)
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
        self.setStyleSheet(self._style())

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(18)
        shadow.setOffset(0, 6)
        shadow.setColor(QColor(0, 0, 0, 110))
        self.setGraphicsEffect(shadow)

    def _style(self) -> str:
        return """
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


class SettingsView(QWidget):
    """
    UI-only hub navigation:
      Hub (cards) -> Section page -> Back -> Hub
    No schema or persistence logic changes.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setStyleSheet("background: transparent;")
        _ensure_output_dirs()

        self._raw_loaded: Dict[str, Any] = {}
        self._settings: Dict[str, Any] = {}
        self._load_settings()

        # -------- Icon registry --------
        self._icon_files = {
            "HUB": "icon_settings.png",
            "General": "icon_controls.png",
            "Paths & Storage": "icon_capabilities.png",
            "Scan Defaults": "icon_simulate.png",
            "Attack Engine": "icon_attack_paths.png",
            "Diagnostics": "icon_dns.png",
        }
        self._pix_cache: Dict[str, QPixmap] = {}

        root = QVBoxLayout()
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.setAlignment(Qt.AlignTop)

        # Top icon
        self._icon_label = QLabel()
        self._icon_label.setAlignment(Qt.AlignHCenter)
        self._set_top_icon("HUB")

        icon_glow = QGraphicsDropShadowEffect()
        icon_glow.setBlurRadius(22)
        icon_glow.setOffset(0, 0)
        icon_glow.setColor(QColor(124, 255, 158, 60))
        self._icon_label.setGraphicsEffect(icon_glow)

        # Card
        self._card = QFrame()
        self._card.setMinimumWidth(980)
        self._card.setMaximumWidth(1040)
        self._card.setMinimumHeight(620)
        self._card.setObjectName("settings_card")
        self._card.setStyleSheet("""
            QFrame#settings_card {
                background-color: rgba(0,0,0,2);
                border: 1px solid rgba(124,255,158,22);
                border-radius: 18px;
            }
        """)

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(28)
        shadow.setOffset(0, 10)
        shadow.setColor(QColor(0, 0, 0, 120))
        self._card.setGraphicsEffect(shadow)

        card_layout = QVBoxLayout()
        card_layout.setContentsMargins(38, 30, 38, 28)
        card_layout.setSpacing(0)

        # Header
        title = QLabel("Settings")
        title_font = QFont("Segoe UI")
        title_font.setPixelSize(22)
        title_font.setWeight(QFont.DemiBold)
        title.setFont(title_font)
        title.setStyleSheet("color: rgba(255,255,255,238);")
        title.setAlignment(Qt.AlignLeft)

        subtitle = QLabel("Local-Only configuration")
        subtitle_font = QFont("Segoe UI")
        subtitle_font.setPixelSize(12)
        subtitle.setFont(subtitle_font)
        subtitle.setStyleSheet("color: rgba(255,255,255,135);")
        subtitle.setAlignment(Qt.AlignLeft)

        card_layout.addWidget(title)
        card_layout.addSpacing(8)
        card_layout.addWidget(subtitle)
        card_layout.addSpacing(18)

        # Content host (stacked)
        # NOTE (UI-only): remove the inner "card inside card" frame while preserving
        # the exact content inset and geometry.
        self._content_host = QWidget()
        self._content_host.setStyleSheet("background: transparent;")
        self._content_host.setFixedHeight(420)

        host_layout = QVBoxLayout()
        host_layout.setContentsMargins(16, 16, 16, 16)
        host_layout.setSpacing(0)

        self._stack = QStackedWidget()
        self._stack.setStyleSheet("background: transparent;")
        host_layout.addWidget(self._stack)
        self._content_host.setLayout(host_layout)

        card_layout.addWidget(self._content_host)
        card_layout.addSpacing(18)

        # Footer (buttons)
        footer_row = QHBoxLayout()
        footer_row.setContentsMargins(0, 0, 0, 0)
        footer_row.setSpacing(12)

        self._run_validation_btn = QPushButton("Run validation")
        self._run_validation_btn.setCursor(Qt.PointingHandCursor)
        self._run_validation_btn.setFixedHeight(40)
        self._run_validation_btn.setStyleSheet(self._button_style(kind="secondary"))
        self._apply_button_depth(self._run_validation_btn, strong=False)
        self._run_validation_btn.clicked.connect(self._run_validation)
        self._run_validation_btn.hide()  # only on Diagnostics page

        self._save_btn = QPushButton("Save changes")
        self._save_btn.setCursor(Qt.PointingHandCursor)
        self._save_btn.setFixedHeight(40)
        self._save_btn.setStyleSheet(self._button_style(kind="primary"))
        self._apply_button_depth(self._save_btn, strong=True)
        self._save_btn.clicked.connect(self._save_settings_from_ui)

        footer_row.addWidget(self._run_validation_btn)
        footer_row.addStretch(1)
        footer_row.addWidget(self._save_btn)

        footer_w = QWidget()
        footer_w.setLayout(footer_row)
        footer_w.setStyleSheet("background: transparent;")
        card_layout.addWidget(footer_w)

        self._card.setLayout(card_layout)

        # Toast
        self._toast = QLabel(self._card)
        self._toast.setText("Saved")
        self._toast.setAlignment(Qt.AlignCenter)
        self._toast.setFixedHeight(26)
        self._toast.setFixedWidth(120)
        self._toast.setStyleSheet("""
            QLabel {
                background-color: rgba(124,255,158,14);
                border: 1px solid rgba(124,255,158,120);
                color: rgba(255,255,255,230);
                border-radius: 10px;
                font-family: 'Segoe UI';
                font-size: 11px;
                font-weight: 700;
            }
        """)
        self._toast.hide()

        root.addSpacing(42)
        root.addWidget(self._icon_label, alignment=Qt.AlignHCenter)
        root.addSpacing(18)
        root.addWidget(self._card, alignment=Qt.AlignHCenter)
        root.addStretch(1)
        self.setLayout(root)

        # UI state holders (unchanged logic)
        self._ui_general = {}
        self._ui_scan = {}
        self._ui_attack = {}
        self._diag_badges = {}
        self._diag_vals = {}

        # Build pages
        self._pages: Dict[str, QWidget] = {}
        self._build_hub_page()
        self._build_section_pages()

        self._stack.currentChanged.connect(self._on_page_changed)

        # Start on hub
        self._go_hub()

    # ==============================
    # Layout events
    # ==============================
    def resizeEvent(self, event):
        super().resizeEvent(event)
        try:
            m = 22
            self._toast.move(
                self._card.width() - self._toast.width() - m,
                self._card.height() - self._toast.height() - 62
            )
        except Exception:
            pass

    # ==============================
    # Icon handling
    # ==============================
    def _pix(self, key: str) -> QPixmap:
        if key in self._pix_cache:
            return self._pix_cache[key]
        fname = self._icon_files.get(key, "icon_settings.png")
        pm = QPixmap(str(ICONS / fname))
        if pm.isNull():
            pm = QPixmap(str(ICONS / "icon_about.png"))
        self._pix_cache[key] = pm
        return pm

    def _set_top_icon(self, key: str) -> None:
        pm = self._pix(key)
        if not pm.isNull():
            self._icon_label.setPixmap(pm.scaled(118, 118, Qt.KeepAspectRatio, Qt.SmoothTransformation))

    # ==============================
    # Navigation
    # ==============================
    def _go_hub(self) -> None:
        self._set_top_icon("HUB")
        self._run_validation_btn.hide()
        self._stack.setCurrentWidget(self._pages["HUB"])

    def _go_section(self, name: str) -> None:
        self._set_top_icon(name)
        self._run_validation_btn.setVisible(name == "Diagnostics")
        self._stack.setCurrentWidget(self._pages[name])

    def _on_page_changed(self, _idx: int) -> None:
        # keep run validation visibility safe even if setCurrentWidget happens elsewhere
        current = self._stack.currentWidget()
        section = None
        for k, w in self._pages.items():
            if w is current:
                section = k
                break
        if section is None:
            self._run_validation_btn.hide()
            return
        self._run_validation_btn.setVisible(section == "Diagnostics")

    # ==============================
    # Page builders
    # ==============================
    def _build_hub_page(self) -> None:
        page = QWidget()
        page.setStyleSheet("background: transparent;")
        outer = QVBoxLayout()
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(12)

        title = QLabel("Configuration")
        tf = QFont("Segoe UI")
        tf.setPixelSize(13)
        tf.setWeight(QFont.DemiBold)
        title.setFont(tf)
        title.setStyleSheet("color: rgba(255,255,255,215);")
        outer.addWidget(title)
        outer.addSpacing(6)

        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(14)

        items = [
            ("General", "Core behavior and startup defaults", "icon_controls.png"),
            ("Paths & Storage", "Fixed output structure and folders", "icon_capabilities.png"),
            ("Scan Defaults", "Timeouts, concurrency, and headers", "icon_simulate.png"),
            ("Attack Engine", "Deterministic v1 engine weights", "icon_attack_paths.png"),
            ("Diagnostics", "Environment checks and validation", "icon_dns.png"),
        ]

        def mk_icon(fname: str) -> QIcon:
            pm = QPixmap(str(ICONS / fname))
            if pm.isNull():
                pm = QPixmap()
            return QIcon(pm)

        buttons: Dict[str, _HubCardButton] = {}
        for i, (name, sub, icon_file) in enumerate(items):
            btn = _HubCardButton(name, sub, mk_icon(icon_file))
            btn.clicked.connect(lambda _=False, n=name: self._go_section(n))
            buttons[name] = btn
            r = i // 2
            c = i % 2
            grid.addWidget(btn, r, c)

        # Make last item span both columns for symmetry
        if "Diagnostics" in buttons:
            grid.addWidget(buttons["Diagnostics"], 2, 0, 1, 2)

        outer.addLayout(grid)
        outer.addStretch(1)
        page.setLayout(outer)

        self._pages["HUB"] = page
        self._stack.addWidget(page)

    def _build_section_pages(self) -> None:
        for name in ["General", "Paths & Storage", "Scan Defaults", "Attack Engine", "Diagnostics"]:
            page = QWidget()
            page.setStyleSheet("background: transparent;")
            v = QVBoxLayout()
            v.setContentsMargins(10, 10, 10, 10)
            v.setSpacing(12)

            # Header row: back + section title
            header = QHBoxLayout()
            header.setContentsMargins(0, 0, 0, 0)
            header.setSpacing(10)

            back_btn = QPushButton()
            back_btn.setCursor(Qt.PointingHandCursor)
            back_btn.setFixedSize(34, 34)
            back_btn.setIcon(QIcon(str(ICONS / "icon_back.png")))
            back_btn.setIconSize(QSize(18, 18))
            back_btn.setStyleSheet(self._icon_button_style())
            back_btn.clicked.connect(self._go_hub)

            h_title = QLabel(name)
            hf = QFont("Segoe UI")
            hf.setPixelSize(13)
            hf.setWeight(QFont.DemiBold)
            h_title.setFont(hf)
            h_title.setStyleSheet("color: rgba(255,255,255,220);")

            header.addWidget(back_btn)
            header.addWidget(h_title)
            header.addStretch(1)

            v.addLayout(header)

            # Content container for the existing section renderers
            content = QVBoxLayout()
            content.setContentsMargins(0, 0, 0, 0)
            content.setSpacing(14)

            # Render section into 'content' layout without changing data logic
            self._clear_section_state()
            if name == "General":
                self._render_general(content)
            elif name == "Paths & Storage":
                self._render_paths_storage(content)
            elif name == "Scan Defaults":
                self._render_scan_defaults(content)
            elif name == "Attack Engine":
                self._render_attack_engine(content)
            elif name == "Diagnostics":
                self._render_diagnostics(content)

            content.addStretch(1)

            content_wrap = QWidget()
            content_wrap.setLayout(content)
            v.addWidget(content_wrap, 1)

            page.setLayout(v)
            self._pages[name] = page
            self._stack.addWidget(page)

    # ==============================
    # Visual system
    # ==============================
    def _apply_button_depth(self, btn: QPushButton, strong: bool) -> None:
        eff = QGraphicsDropShadowEffect()
        eff.setOffset(0, 2 if strong else 1)
        eff.setBlurRadius(18 if strong else 14)
        eff.setColor(QColor(0, 0, 0, 140))
        btn.setGraphicsEffect(eff)

    def _icon_button_style(self) -> str:
        return """
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

    def _button_style(self, kind: str) -> str:
        if kind == "secondary":
            return """
                QPushButton {
                    background-color: rgba(0,0,0,0);
                    border: 1px solid rgba(124,255,158,120);
                    color: rgba(255,255,255,220);
                    padding: 0 18px;
                    font-family: 'Segoe UI';
                    font-size: 12px;
                    font-weight: 750;
                    border-radius: 10px;
                }
                QPushButton:hover {
                    background-color: rgba(124,255,158,8);
                    border: 1px solid rgba(124,255,158,160);
                }
                QPushButton:pressed {
                    background-color: rgba(124,255,158,14);
                    border: 1px solid rgba(124,255,158,200);
                }
                QPushButton:disabled {
                    border: 1px solid rgba(255,255,255,18);
                    color: rgba(255,255,255,90);
                }
            """
        return """
            QPushButton {
                background-color: rgba(124,255,158,16);
                border: 1px solid rgba(124,255,158,200);
                color: rgba(255,255,255,235);
                padding: 0 18px;
                font-family: 'Segoe UI';
                font-size: 12px;
                font-weight: 850;
                border-radius: 10px;
            }
            QPushButton:hover {
                background-color: rgba(124,255,158,22);
                border: 1px solid rgba(124,255,158,230);
            }
            QPushButton:pressed {
                background-color: rgba(124,255,158,28);
                border: 1px solid rgba(124,255,158,245);
            }
            QPushButton:disabled {
                border: 1px solid rgba(255,255,255,18);
                color: rgba(255,255,255,90);
                background-color: rgba(0,0,0,0);
            }
        """

    def _input_style(self) -> str:
        # IMPORTANT: startup_combo fully filled and no internal divider line
        return """
            QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {
                background-color: rgba(0,0,0,18);
                border: 1px solid rgba(255,255,255,18);
                border-radius: 10px;
                padding: 7px 10px;
                color: rgba(255,255,255,220);
                font-family: 'Segoe UI';
                font-size: 12px;
                min-height: 34px;
            }
            QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {
                border: 1px solid rgba(124,255,158,160);
            }

            QComboBox#startup_combo {
                border: 1px solid rgba(124,255,158,165);
                background-color: rgba(124,255,158,18);
                padding-right: 34px; /* room for arrow area */
            }
            QComboBox#startup_combo:hover {
                border: 1px solid rgba(124,255,158,200);
                background-color: rgba(124,255,158,22);
            }
            QComboBox#startup_combo:focus {
                border: 1px solid rgba(124,255,158,235);
                background-color: rgba(124,255,158,24);
            }
            QComboBox#startup_combo::drop-down {
                width: 34px;
                border: none;
                border-left: 0px solid rgba(0,0,0,0); /* kill separator */
                background-color: rgba(124,255,158,18);
                border-top-right-radius: 10px;
                border-bottom-right-radius: 10px;
            }
            QComboBox#startup_combo:hover::drop-down {
                background-color: rgba(124,255,158,22);
            }
            QComboBox#startup_combo:focus::drop-down {
                background-color: rgba(124,255,158,24);
            }
            QComboBox#startup_combo::down-arrow {
                width: 0px;
                height: 0px;
                image: none;
            }

            QSpinBox, QDoubleSpinBox {
                border: 1px solid rgba(124,255,158,85);
            }
            QSpinBox:hover, QDoubleSpinBox:hover {
                border: 1px solid rgba(124,255,158,120);
            }

            QComboBox QAbstractItemView {
                background-color: rgba(0,0,0,235);
                border: 1px solid rgba(124,255,158,90);
                color: rgba(255,255,255,220);
                padding: 6px;
                outline: none;
            }
            QComboBox QAbstractItemView::item { padding: 6px 10px; }
            QComboBox QAbstractItemView::item:selected {
                background-color: rgba(124,255,158,35);
                color: rgba(255,255,255,235);
            }
            QComboBox QAbstractItemView::item:hover { background-color: rgba(124,255,158,22); }
        """

    def _label_style(self) -> str:
        return "color: rgba(255,255,255,195); font-family: 'Segoe UI'; font-size: 12px; font-weight: 650;"

    def _muted_style(self) -> str:
        return "color: rgba(255,255,255,130); font-family: 'Segoe UI'; font-size: 11px;"

    def _muted_value_style(self) -> str:
        return "color: rgba(255,255,255,155); font-family: 'Segoe UI'; font-size: 12px;"

    def _section_frame(self, title: str) -> QFrame:
        box = QFrame()
        box.setStyleSheet("""
            QFrame {
                background-color: rgba(0,0,0,0);
                border: 0px;
            }
        """)
        v = QVBoxLayout()
        v.setContentsMargins(18, 16, 18, 16)
        v.setSpacing(10)

        t = QLabel(title)
        f = QFont("Segoe UI")
        f.setPixelSize(12)
        f.setWeight(QFont.DemiBold)
        t.setFont(f)
        t.setStyleSheet("color: rgba(255,255,255,215);")
        v.addWidget(t)

        box.setLayout(v)
        return box

    # ==============================
    # Section state management (UI-only)
    # ==============================
    def _clear_section_state(self) -> None:
        self._ui_general = {}
        self._ui_scan = {}
        self._ui_attack = {}
        self._diag_badges = {}
        self._diag_vals = {}

    # ==============================
    # Persistence (unchanged logic)
    # ==============================
    def _load_settings(self) -> None:
        loaded, ok = _safe_read_json(SETTINGS_PATH)
        self._raw_loaded = loaded if ok else {}

        merged = _deep_merge_preserve_unknown(DEFAULTS, self._raw_loaded)

        merged.setdefault("version", "v1")
        g = merged.setdefault("general", {})
        g["startup_view"] = str(g.get("startup_view", "READY")).upper()
        if g["startup_view"] not in {"READY", "FULL_SCAN", "ATTACK_PATHS", "TARGETS", "REPORTS", "ABOUT"}:
            g["startup_view"] = "READY"
        g["confirm_destructive_actions"] = bool(g.get("confirm_destructive_actions", True))
        g["reduce_motion"] = bool(g.get("reduce_motion", False))

        s = merged.setdefault("scan_defaults", {})
        s["timeout_sec"] = _clamp_int(int(s.get("timeout_sec", 15)), 1, 120)
        s["concurrency"] = _clamp_int(int(s.get("concurrency", 6)), 1, 64)
        ua = str(s.get("user_agent", "SpektronScanner/1.0")).strip()
        s["user_agent"] = ua if ua else "SpektronScanner/1.0"
        s["auto_save_evidence"] = bool(s.get("auto_save_evidence", True))

        a = merged.setdefault("attack_engine", {})
        a["impact_weight"] = _clamp_float(float(a.get("impact_weight", 1.0)), 0.1, 3.0)
        a["feasibility_weight"] = _clamp_float(float(a.get("feasibility_weight", 1.0)), 0.1, 3.0)
        a["control_coverage_weight"] = _clamp_float(float(a.get("control_coverage_weight", 1.0)), 0.1, 3.0)
        a["overwrite_attack_outputs"] = bool(a.get("overwrite_attack_outputs", False))

        self._settings = merged

        if not SETTINGS_PATH.exists():
            _atomic_write_json(SETTINGS_PATH, self._settings)
            self._raw_loaded = dict(self._settings)

    def _collect_ui_to_updates(self) -> Dict[str, Any]:
        updates: Dict[str, Any] = {}

        if self._ui_general:
            updates.setdefault("general", {})
            updates["general"]["startup_view"] = self._ui_general["startup_view"].currentData()
            updates["general"]["confirm_destructive_actions"] = bool(self._settings.get("general", {}).get("confirm_destructive_actions", True))
            updates["general"]["reduce_motion"] = bool(self._settings.get("general", {}).get("reduce_motion", False))

        if self._ui_scan:
            timeout = int(self._ui_scan["timeout_sec"].value())
            conc = int(self._ui_scan["concurrency"].value())
            ua = self._ui_scan["user_agent"].text().strip()

            updates.setdefault("scan_defaults", {})
            updates["scan_defaults"]["timeout_sec"] = _clamp_int(timeout, 1, 120)
            updates["scan_defaults"]["concurrency"] = _clamp_int(conc, 1, 64)
            updates["scan_defaults"]["user_agent"] = ua
            updates["scan_defaults"]["auto_save_evidence"] = bool(self._settings.get("scan_defaults", {}).get("auto_save_evidence", True))

        if self._ui_attack:
            updates.setdefault("attack_engine", {})
            updates["attack_engine"]["impact_weight"] = float(self._ui_attack["impact_weight"].value())
            updates["attack_engine"]["feasibility_weight"] = float(self._ui_attack["feasibility_weight"].value())
            updates["attack_engine"]["control_coverage_weight"] = float(self._ui_attack["control_coverage_weight"].value())
            updates["attack_engine"]["overwrite_attack_outputs"] = bool(self._settings.get("attack_engine", {}).get("overwrite_attack_outputs", False))

        updates["version"] = "v1"
        return updates

    def _show_saved_toast(self) -> None:
        self._toast.show()
        self._toast.raise_()
        QTimer.singleShot(1200, self._toast.hide)

    def _save_settings_from_ui(self) -> None:
        updates = self._collect_ui_to_updates()

        ua = updates.get("scan_defaults", {}).get("user_agent", None)
        if ua is not None and not str(ua).strip():
            QMessageBox.warning(self, "Settings", "User-Agent cannot be empty.")
            return

        merged = _deep_merge_preserve_unknown(self._raw_loaded if isinstance(self._raw_loaded, dict) else {}, updates)

        g = merged.setdefault("general", {})
        g["startup_view"] = str(g.get("startup_view", "READY")).upper()
        if g["startup_view"] not in {"READY", "FULL_SCAN", "ATTACK_PATHS", "TARGETS", "REPORTS", "ABOUT"}:
            g["startup_view"] = "READY"
        g["confirm_destructive_actions"] = bool(g.get("confirm_destructive_actions", True))
        g["reduce_motion"] = bool(g.get("reduce_motion", False))

        s = merged.setdefault("scan_defaults", {})
        s["timeout_sec"] = _clamp_int(int(s.get("timeout_sec", 15)), 1, 120)
        s["concurrency"] = _clamp_int(int(s.get("concurrency", 6)), 1, 64)
        ua2 = str(s.get("user_agent", "SpektronScanner/1.0")).strip()
        s["user_agent"] = ua2 if ua2 else "SpektronScanner/1.0"
        s["auto_save_evidence"] = bool(s.get("auto_save_evidence", True))

        a = merged.setdefault("attack_engine", {})
        a["impact_weight"] = _clamp_float(float(a.get("impact_weight", 1.0)), 0.1, 3.0)
        a["feasibility_weight"] = _clamp_float(float(a.get("feasibility_weight", 1.0)), 0.1, 3.0)
        a["control_coverage_weight"] = _clamp_float(float(a.get("control_coverage_weight", 1.0)), 0.1, 3.0)
        a["overwrite_attack_outputs"] = bool(a.get("overwrite_attack_outputs", False))

        merged["version"] = "v1"

        try:
            _atomic_write_json(SETTINGS_PATH, merged)
            self._raw_loaded = dict(merged)
            self._settings = dict(merged)
            self._show_saved_toast()
        except Exception as e:
            QMessageBox.critical(self, "Settings", f"Failed to save settings.\n\n{e}")

    # ==============================
    # Content renderers (same content, different target layout)
    # ==============================
    def _row(self, left: QWidget, right: QWidget, right_stretch: bool = False) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(12)
        row.addWidget(left)
        row.addStretch(1)
        if right_stretch:
            row.addWidget(right, 1)
        else:
            row.addWidget(right)
        return row

    def _render_general(self, target_layout: QVBoxLayout) -> None:
        frame = self._section_frame("Startup")
        v = frame.layout()

        desc = QLabel("Default view when Spektron opens.")
        desc.setStyleSheet(self._muted_style())
        v.addWidget(desc)

        lbl = QLabel("Start on")
        lbl.setStyleSheet(self._label_style())

        dd = QComboBox()
        dd.setObjectName("startup_combo")
        dd.setStyleSheet(self._input_style())
        dd.setFixedWidth(320)

        options = [
            ("Ready (Home)", "READY"),
            ("Full Scan", "FULL_SCAN"),
            ("Attack Paths", "ATTACK_PATHS"),
            ("Targets", "TARGETS"),
            ("Reports", "REPORTS"),
            ("About", "ABOUT"),
        ]
        for text, value in options:
            dd.addItem(text, userData=value)

        current = self._settings.get("general", {}).get("startup_view", "READY")
        idx = max(0, dd.findData(current))
        dd.setCurrentIndex(idx)

        v.addLayout(self._row(lbl, dd))
        target_layout.addWidget(frame)

        self._ui_general = {"startup_view": dd}

    def _render_paths_storage(self, target_layout: QVBoxLayout) -> None:
        frame = self._section_frame("Paths & Storage")
        v = frame.layout()

        for label, relpath in FIXED_PATHS.items():
            l = QLabel(label)
            l.setStyleSheet(self._label_style())
            p = QLabel(relpath)
            p.setStyleSheet(self._muted_value_style())
            v.addLayout(self._row(l, p))

        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        open_btn = QPushButton("Open folders")
        open_btn.setCursor(Qt.PointingHandCursor)
        open_btn.setFixedHeight(38)
        open_btn.setStyleSheet(self._button_style(kind="secondary"))
        self._apply_button_depth(open_btn, strong=False)
        open_btn.clicked.connect(self._open_output_folders)

        reset_btn = QPushButton("Reset defaults")
        reset_btn.setCursor(Qt.PointingHandCursor)
        reset_btn.setFixedHeight(38)
        reset_btn.setStyleSheet(self._button_style(kind="secondary"))
        self._apply_button_depth(reset_btn, strong=False)
        reset_btn.clicked.connect(self._reset_defaults)

        btn_row.addWidget(open_btn)
        btn_row.addStretch(1)
        btn_row.addWidget(reset_btn)

        v.addSpacing(6)
        v.addLayout(btn_row)

        target_layout.addWidget(frame)

    def _render_scan_defaults(self, target_layout: QVBoxLayout) -> None:
        frame = self._section_frame("Scan Defaults")
        v = frame.layout()

        lbl1 = QLabel("Timeout (sec)")
        lbl1.setStyleSheet(self._label_style())
        sp_timeout = QSpinBox()
        sp_timeout.setRange(1, 120)
        sp_timeout.setStyleSheet(self._input_style())
        sp_timeout.setFixedWidth(320)
        sp_timeout.setValue(int(self._settings.get("scan_defaults", {}).get("timeout_sec", 15)))
        v.addLayout(self._row(lbl1, sp_timeout))

        lbl2 = QLabel("Concurrency")
        lbl2.setStyleSheet(self._label_style())
        sp_conc = QSpinBox()
        sp_conc.setRange(1, 64)
        sp_conc.setStyleSheet(self._input_style())
        sp_conc.setFixedWidth(320)
        sp_conc.setValue(int(self._settings.get("scan_defaults", {}).get("concurrency", 6)))
        v.addLayout(self._row(lbl2, sp_conc))

        lbl3 = QLabel("User-Agent")
        lbl3.setStyleSheet(self._label_style())
        ua = QLineEdit()
        ua.setStyleSheet(self._input_style())
        ua.setText(str(self._settings.get("scan_defaults", {}).get("user_agent", "SpektronScanner/1.0")))
        v.addLayout(self._row(lbl3, ua, right_stretch=True))

        target_layout.addWidget(frame)

        self._ui_scan = {
            "timeout_sec": sp_timeout,
            "concurrency": sp_conc,
            "user_agent": ua,
        }

    def _render_attack_engine(self, target_layout: QVBoxLayout) -> None:
        frame = self._section_frame("Attack Engine")
        v = frame.layout()

        l0 = QLabel("Engine mode")
        l0.setStyleSheet(self._label_style())
        mode = QLabel("Deterministic v1 (offline)")
        mode.setStyleSheet(self._muted_value_style())
        v.addLayout(self._row(l0, mode))

        def _dbl_row(label: str, key: str) -> QDoubleSpinBox:
            l = QLabel(label)
            l.setStyleSheet(self._label_style())
            sp = QDoubleSpinBox()
            sp.setDecimals(2)
            sp.setRange(0.1, 3.0)
            sp.setSingleStep(0.05)
            sp.setFixedWidth(320)
            sp.setStyleSheet(self._input_style())
            sp.setValue(float(self._settings.get("attack_engine", {}).get(key, 1.0)))
            v.addLayout(self._row(l, sp))
            return sp

        sp_impact = _dbl_row("Impact weight", "impact_weight")
        sp_feas = _dbl_row("Feasibility weight", "feasibility_weight")
        sp_ctrl = _dbl_row("Control coverage weight", "control_coverage_weight")

        target_layout.addWidget(frame)

        self._ui_attack = {
            "impact_weight": sp_impact,
            "feasibility_weight": sp_feas,
            "control_coverage_weight": sp_ctrl,
        }

    def _render_diagnostics(self, target_layout: QVBoxLayout) -> None:
        frame = self._section_frame("Diagnostics")
        v = frame.layout()

        self._diag_items = [
            ("core", "CORE modules loaded"),
            ("folders", "Output folders present"),
            ("json", "Settings JSON parse"),
            ("write", "Write access to output"),
        ]

        for key, text in self._diag_items:
            row = QHBoxLayout()
            row.setSpacing(10)

            name = QLabel(text)
            name.setStyleSheet("color: rgba(255,255,255,205); font-family: 'Segoe UI'; font-size: 12px; font-weight: 650;")

            value = QLabel("—")
            value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            value.setFixedWidth(220)
            value.setStyleSheet("color: rgba(255,255,255,140); font-family: 'Segoe UI'; font-size: 12px;")

            badge = QLabel("pending")
            badge.setAlignment(Qt.AlignCenter)
            badge.setFixedHeight(22)
            badge.setFixedWidth(88)
            badge.setStyleSheet(self._badge_style(kind="pending"))

            row.addWidget(name)
            row.addStretch(1)
            row.addWidget(value)
            row.addSpacing(10)
            row.addWidget(badge)

            v.addLayout(row)

            self._diag_vals[key] = value
            self._diag_badges[key] = badge

        target_layout.addWidget(frame)
        self._run_validation()

    def _badge_style(self, kind: str) -> str:
        if kind == "ok":
            return """
                QLabel {
                    background-color: rgba(124,255,158,10);
                    border: 1px solid rgba(124,255,158,140);
                    color: rgba(255,255,255,220);
                    border-radius: 10px;
                    font-family: 'Segoe UI';
                    font-size: 11px;
                    font-weight: 800;
                }
            """
        if kind == "warn":
            return """
                QLabel {
                    background-color: rgba(255,206,120,10);
                    border: 1px solid rgba(255,206,120,170);
                    color: rgba(255,255,255,215);
                    border-radius: 10px;
                    font-family: 'Segoe UI';
                    font-size: 11px;
                    font-weight: 800;
                }
            """
        return """
            QLabel {
                background-color: rgba(255,255,255,8);
                border: 1px solid rgba(255,255,255,18);
                color: rgba(255,255,255,160);
                border-radius: 10px;
                font-family: 'Segoe UI';
                font-size: 11px;
                font-weight: 800;
            }
        """

    # ==============================
    # Actions (unchanged)
    # ==============================
    def _open_output_folders(self) -> None:
        base = OUTPUT_DIR
        try:
            if base.exists():
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(base.resolve())))
        except Exception:
            pass

    def _reset_defaults(self) -> None:
        confirm = bool(self._settings.get("general", {}).get("confirm_destructive_actions", True))
        if confirm:
            res = QMessageBox.question(
                self,
                "Reset defaults",
                "Reset settings to defaults?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if res != QMessageBox.Yes:
                return

        try:
            _atomic_write_json(SETTINGS_PATH, dict(DEFAULTS))
            self._raw_loaded = dict(DEFAULTS)
            self._settings = dict(DEFAULTS)

            # Rebuild pages so controls refresh
            self._stack.blockSignals(True)
            self._stack.setCurrentWidget(self._pages["HUB"])
            for k in ["General", "Paths & Storage", "Scan Defaults", "Attack Engine", "Diagnostics"]:
                w = self._pages.get(k)
                if w is not None:
                    self._stack.removeWidget(w)
            self._pages = {"HUB": self._pages["HUB"]}
            self._build_section_pages()
            self._stack.blockSignals(False)
            self._go_hub()

        except Exception as e:
            QMessageBox.critical(self, "Reset defaults", f"Failed to reset settings.\n\n{e}")

    def _find_core_dir(self) -> Optional[Path]:
        candidates = [
            ROOT / "core",
            ROOT / "SPEKTRON" / "CORE",
        ]
        for c in candidates:
            try:
                if c.exists() and c.is_dir():
                    return c
            except Exception:
                continue
        return None

    def _run_validation(self) -> None:
        def set_row(key: str, ok: bool, badge_text: str, value_text: str) -> None:
            badge = self._diag_badges.get(key)
            val = self._diag_vals.get(key)
            if badge is None or val is None:
                return

            badge.setStyleSheet(self._badge_style("ok" if ok else "warn"))
            badge.setText(badge_text)
            val.setText(value_text)

        # CORE modules loaded
        core_ok = False
        core_badge = "MISSING"
        core_val = "not found"
        try:
            core_dir = self._find_core_dir()
            if core_dir is not None:
                jsons = list(core_dir.glob("*.json"))
                count = len(jsons)
                if count > 0:
                    core_val = f"{count} jsons"
                    if count == 11:
                        core_ok = True
                        core_badge = "OK"
                    else:
                        core_ok = False
                        core_badge = "WARN"
                        core_val = f"{count} jsons (expected 11)"
        except Exception:
            core_ok = False
            core_badge = "WARN"
            core_val = "error"
        set_row("core", core_ok, core_badge, core_val)

        # output folders present
        folders_ok = True
        try:
            needed = [
                OUTPUT_DIR / "evidence",
                OUTPUT_DIR / "attack",
                OUTPUT_DIR / "targets",
                OUTPUT_DIR / "settings",
            ]
            for p in needed:
                if not p.exists() or not p.is_dir():
                    folders_ok = False
        except Exception:
            folders_ok = False
        set_row("folders", folders_ok, "OK" if folders_ok else "MISSING", "evidence/attack/targets/settings")

        # settings json parse
        json_ok = False
        try:
            _, ok = _safe_read_json(SETTINGS_PATH)
            json_ok = ok
        except Exception:
            json_ok = False
        set_row("json", json_ok, "OK" if json_ok else "WARN", "parse")

        # write access to output
        write_ok = False
        try:
            test = OUTPUT_DIR / ".write_test.tmp"
            test.write_text("ok", encoding="utf-8")
            try:
                test.unlink()
            except Exception:
                pass
            write_ok = True
        except Exception:
            write_ok = False
        set_row("write", write_ok, "OK" if write_ok else "WARN", "temp write")
