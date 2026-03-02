# main_menu.py

import sys
import json
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import Qt, QRect, QSize, QTimer, QProcess
from PySide6.QtGui import (
    QPixmap,
    QPainter,
    QFont,
    QColor,
    QIcon,
    QRadialGradient,
)
from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QGraphicsOpacityEffect,
    QGraphicsDropShadowEffect,
    QButtonGroup,
    QMessageBox,
    QSizePolicy,
)

from about import AboutView
from settings import SettingsView
from full_scan import FullScanWidget

# ✅ Targets
from targets import TargetsWidget


ROOT = Path(__file__).resolve().parent
ASSETS = ROOT / "assets"
ICONS = ASSETS / "icons"


class SidebarButton(QPushButton):
    def __init__(self, text: str, icon_path: Path, parent=None):
        super().__init__(text, parent)

        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(74)
        self.setMaximumHeight(88)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.setFlat(True)
        self.setCheckable(True)

        self.setIcon(QIcon(str(icon_path)))
        self.setIconSize(QSize(38, 38))

        self._opacity_effect = QGraphicsOpacityEffect(self)
        self._opacity_effect.setOpacity(0.95)
        self.setGraphicsEffect(self._opacity_effect)

        self._glow = QGraphicsDropShadowEffect(self)
        self._glow.setBlurRadius(18)
        self._glow.setOffset(0, 0)
        self._glow.setColor(QColor(124, 255, 158, 180))

        self.setStyleSheet("""
            QPushButton {
                background: transparent;
                border: none;
                color: rgba(255,255,255,205);
                text-align: left;
                padding-left: 20px;
                padding-right: 18px;
                font-family: 'Segoe UI';
                font-size: 17px;
                font-weight: 500;
            }

            QPushButton:hover {
                background-color: rgba(255,255,255,14);
                color: rgba(255,255,255,230);
                border-left: 4px solid rgb(124,255,158);
                padding-left: 16px;
            }

            QPushButton:checked {
                background-color: rgba(0,0,0,65);
                color: rgba(255,255,255,230);
                border-left: 4px solid rgb(124,255,158);
                padding-left: 16px;
            }

            QPushButton:pressed {
                background-color: rgba(255,255,255,20);
            }
        """)

    def enterEvent(self, event):
        if not self.isChecked():
            self._opacity_effect.setOpacity(1.0)
            self.setGraphicsEffect(self._glow)
        super().enterEvent(event)

    def leaveEvent(self, event):
        if not self.isChecked():
            self._opacity_effect.setOpacity(0.95)
            self.setGraphicsEffect(self._opacity_effect)
        super().leaveEvent(event)

    def setChecked(self, checked: bool):
        super().setChecked(checked)
        if checked:
            self._opacity_effect.setOpacity(1.0)
            self.setGraphicsEffect(self._glow)
        else:
            self._opacity_effect.setOpacity(0.95)
            self.setGraphicsEffect(self._opacity_effect)


class MainMenu(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Spektron v1")
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground, False)

        self._button_group = QButtonGroup(self)
        self._button_group.setExclusive(True)

        self._about_view = None
        self._about_button = None
        self._settings_view = None
        self._reports_view = None
        self._full_scan_view = None
        self._attack_paths_view = None

        # ✅ Targets
        self._targets_view = None

        self._active_scan_id = None  # last known scan_id (from Full Scan)
        self._sidebar_buttons = {}
        self._placeholder_card = None
        self._content_layout = None

        # Topbar dynamic label (existing QLabel only)
        self._topbar_center_label = None
        self._last_scan_host = None
        self._last_scan_generated_at = None  # datetime
        self._topbar_timer = None

        # Full scan hook state
        self._full_scan_hooks_installed = False
        self._scan_refresh_retries_left = 0

        self._load_background()
        self._build_ui()
        self._init_topbar_dynamic_labels()

        self.showFullScreen()

    def _load_background(self):
        screen_width = QApplication.primaryScreen().size().width()
        if screen_width >= 2300:
            bg_path = ASSETS / "launcher_bg_2560x1440.png"
        else:
            bg_path = ASSETS / "launcher_bg.png"
        self._bg = QPixmap(str(bg_path))

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.SmoothPixmapTransform)

        if not self._bg.isNull():
            scaled = self._bg.scaled(
                self.size(),
                Qt.KeepAspectRatioByExpanding,
                Qt.SmoothTransformation
            )
            x = (scaled.width() - self.width()) // 2
            y = (scaled.height() - self.height()) // 2
            painter.drawPixmap(
                QRect(0, 0, self.width(), self.height()),
                scaled,
                QRect(x, y, self.width(), self.height())
            )

        painter.fillRect(self.rect(), QColor(0, 0, 0, 60))

        gradient = QRadialGradient(
            self.rect().center(),
            max(self.width(), self.height()) * 0.7
        )
        gradient.setColorAt(0.7, QColor(0, 0, 0, 0))
        gradient.setColorAt(1.0, QColor(0, 0, 0, 160))
        painter.fillRect(self.rect(), gradient)

        super().paintEvent(event)

    def _build_ui(self):
        root = QVBoxLayout()
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_topbar())
        root.addLayout(self._build_body())
        root.addWidget(self._build_footer())

        self.setLayout(root)

    def _build_topbar(self):
        top = QFrame()
        top.setFixedHeight(78)
        top.setStyleSheet("""
            QFrame {
                background-color: rgba(0,0,0,140);
                border-bottom: 1px solid rgba(255,255,255,18);
            }
        """)

        layout = QHBoxLayout()
        layout.setContentsMargins(28, 0, 28, 0)

        left = QHBoxLayout()

        logo = QLabel()
        pix = QPixmap(str(ASSETS / "spektron_cat.png"))
        logo.setPixmap(pix.scaled(70, 70, Qt.KeepAspectRatio, Qt.SmoothTransformation))

        title = QLabel("SPEKTRON")
        font = QFont("Segoe UI", 20)
        font.setWeight(QFont.Bold)
        title.setFont(font)
        title.setStyleSheet("color: rgba(255,255,255,230); margin-top: -2px;")

        left.addWidget(logo)
        left.addSpacing(0)
        left.addWidget(title)

        left_w = QWidget()
        left_w.setLayout(left)
        left_w.setStyleSheet("background: transparent;")

        center = QLabel("TARGET: —   |   SCAN: —")
        self._topbar_center_label = center
        center.setFont(QFont("Segoe UI", 13))
        center.setStyleSheet("color: rgba(255,255,255,150);")

        right = QHBoxLayout()

        engine = QLabel("ENGINE READY")
        engine.setFont(QFont("Segoe UI", 13))
        engine.setStyleSheet("color: rgb(124,255,158);")

        back = QPushButton("EXIT")
        back.setCursor(Qt.PointingHandCursor)
        back.setFixedHeight(36)
        back.setStyleSheet("""
            QPushButton {
                background: transparent;
                border: 1px solid rgba(124,255,158,160);
                color: rgba(255,255,255,200);
                padding: 0 18px;
                font-family: 'Segoe UI';
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: rgba(124,255,158,20);
            }
        """)
        back.clicked.connect(self.close)

        right.addWidget(engine)
        right.addSpacing(18)
        right.addWidget(back)

        right_w = QWidget()
        right_w.setLayout(right)
        right_w.setStyleSheet("background: transparent;")

        layout.addWidget(left_w)
        layout.addStretch()
        layout.addWidget(center)
        layout.addStretch()
        layout.addWidget(right_w)

        top.setLayout(layout)
        return top

    def _build_body(self):
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        body.addWidget(self._build_sidebar())
        body.addWidget(self._build_content())

        return body

    def _build_sidebar(self):
        sidebar = QFrame()
        sidebar.setFixedWidth(320)
        sidebar.setStyleSheet("""
            QFrame {
                background-color: rgba(0,0,0,120);
            }
        """)

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(18, 24, 18, 18)
        main_layout.setSpacing(0)

        menu_container = QWidget()
        menu_layout = QVBoxLayout()
        menu_layout.setSpacing(12)
        menu_layout.setContentsMargins(0, 0, 0, 0)

        items = {
            "Full Scan": "icon_run_full_scan.png",
            "Attack Paths": "icon_attack_paths.png",
            "Targets": "icon_quick_scan.png",
            "Reports": "icon_reports.png",
            "Settings": "icon_settings.png",
        }

        for text, icon in items.items():
            btn = SidebarButton(text, ICONS / icon)
            self._sidebar_buttons[text] = btn
            self._button_group.addButton(btn)

            if text == "Settings":
                btn.clicked.connect(self._on_sidebar_settings_clicked)
            elif text == "Full Scan":
                btn.clicked.connect(self._on_sidebar_full_scan_clicked)
            elif text == "Attack Paths":
                btn.clicked.connect(self._on_sidebar_attack_paths_clicked)
            elif text == "Reports":
                btn.clicked.connect(self._on_sidebar_reports_clicked)
            elif text == "Targets":
                btn.clicked.connect(self._on_sidebar_targets_clicked)
            else:
                btn.clicked.connect(self._on_sidebar_menu_clicked)

            menu_layout.addWidget(btn)

        menu_container.setLayout(menu_layout)
        menu_container.setStyleSheet("background: transparent;")

        about_button = SidebarButton("About", ICONS / "icon_about.png")
        self._sidebar_buttons["About"] = about_button
        self._button_group.addButton(about_button)
        about_button.clicked.connect(self._on_sidebar_about_clicked)
        self._about_button = about_button

        main_layout.addWidget(menu_container)
        main_layout.addStretch(1)
        main_layout.addWidget(about_button)

        sidebar.setLayout(main_layout)
        return sidebar

    def _build_content(self):
        content = QFrame()
        content.setStyleSheet("background: transparent;")

        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)

        card = QFrame()
        card.setFixedSize(360, 140)
        card.setStyleSheet("""
            QFrame {
                background-color: rgba(0,0,0,40);
                border-radius: 14px;
            }
        """)

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(40)
        shadow.setOffset(0, 4)
        shadow.setColor(QColor(0, 0, 0, 160))
        card.setGraphicsEffect(shadow)

        card_layout = QVBoxLayout()
        card_layout.setAlignment(Qt.AlignCenter)
        card_layout.setContentsMargins(0, 0, 0, 0)
        card_layout.setSpacing(6)

        title = QLabel("READY TO USE")
        font = QFont("Segoe UI", 18)
        font.setWeight(QFont.Bold)
        title.setFont(font)
        title.setStyleSheet("color: rgba(255,255,255,220);")

        subtitle = QLabel("Spektron v1 Engine Initialized")
        subtitle.setFont(QFont("Segoe UI", 12))
        subtitle.setStyleSheet("color: rgba(255,255,255,150);")

        card_layout.addWidget(title, alignment=Qt.AlignHCenter)
        card_layout.addWidget(subtitle, alignment=Qt.AlignHCenter)
        card.setLayout(card_layout)

        layout.addWidget(card)
        content.setLayout(layout)

        self._placeholder_card = card
        self._content_layout = layout

        return content

    def _build_footer(self):
        footer = QFrame()
        footer.setFixedHeight(28)
        footer.setStyleSheet("background: transparent;")

        layout = QHBoxLayout()
        layout.setContentsMargins(18, 0, 0, 6)

        label = QLabel("v0.9.3 | offline | engine ready")
        label.setFont(QFont("Segoe UI", 10))
        label.setStyleSheet("color: rgba(255,255,255,120);")

        layout.addWidget(label)
        layout.addStretch()

        footer.setLayout(layout)
        return footer

    def _hide_all_views(self):
        if self._about_view is not None:
            self._about_view.hide()
        if self._settings_view is not None:
            self._settings_view.hide()
        if self._reports_view is not None:
            self._reports_view.hide()
        if self._full_scan_view is not None:
            self._full_scan_view.hide()
        if self._attack_paths_view is not None:
            self._attack_paths_view.hide()
        if self._targets_view is not None:
            self._targets_view.hide()

    def _on_sidebar_about_clicked(self):
        if self._settings_view is not None:
            self._settings_view.hide()
        if self._reports_view is not None:
            self._reports_view.hide()
        if self._full_scan_view is not None:
            self._full_scan_view.hide()
        if self._attack_paths_view is not None:
            self._attack_paths_view.hide()
        if self._targets_view is not None:
            self._targets_view.hide()

        if self._about_view is None:
            self._about_view = AboutView()
        if self._placeholder_card is not None:
            self._placeholder_card.hide()

        if self._about_button is not None:
            self._about_button.show()
        if self._content_layout is not None:
            if self._about_view.parent() is None:
                self._content_layout.addWidget(self._about_view)
            self._about_view.show()

    def _on_sidebar_settings_clicked(self):
        if self._about_view is not None:
            self._about_view.hide()
        if self._reports_view is not None:
            self._reports_view.hide()
        if self._full_scan_view is not None:
            self._full_scan_view.hide()
        if self._attack_paths_view is not None:
            self._attack_paths_view.hide()
        if self._targets_view is not None:
            self._targets_view.hide()

        if self._settings_view is None:
            self._settings_view = SettingsView()
        if self._placeholder_card is not None:
            self._placeholder_card.hide()

        if self._about_button is not None:
            self._about_button.show()
        if self._content_layout is not None:
            if self._settings_view.parent() is None:
                self._content_layout.addWidget(self._settings_view)
            self._settings_view.show()

    def _on_sidebar_attack_paths_clicked(self):
        if self._about_view is not None:
            self._about_view.hide()
        if self._settings_view is not None:
            self._settings_view.hide()
        if self._reports_view is not None:
            self._reports_view.hide()
        if self._full_scan_view is not None:
            self._full_scan_view.hide()
        if self._targets_view is not None:
            self._targets_view.hide()

        if self._attack_paths_view is None:
            try:
                try:
                    from attack_paths import AttackPathsWidget  # type: ignore
                except Exception:
                    from ui.attack_paths import AttackPathsWidget  # type: ignore
                self._attack_paths_view = AttackPathsWidget()
            except Exception as e:
                QMessageBox.critical(self, "Attack Paths", f"Failed to load Attack Paths.\n\n{e}")
                return

        if self._placeholder_card is not None:
            self._placeholder_card.hide()

        if self._about_button is not None:
            self._about_button.show()

        if self._content_layout is not None:
            if self._attack_paths_view.parent() is None:
                self._content_layout.addWidget(self._attack_paths_view)

            if hasattr(self._attack_paths_view, "set_scan_id"):
                try:
                    self._attack_paths_view.set_scan_id(self._active_scan_id)
                except Exception:
                    pass

            if hasattr(self._attack_paths_view, "open_browser"):
                try:
                    self._attack_paths_view.open_browser("")
                except Exception:
                    pass

            self._attack_paths_view.show()

    def _on_sidebar_reports_clicked(self):
        if self._about_view is not None:
            self._about_view.hide()
        if self._settings_view is not None:
            self._settings_view.hide()
        if self._full_scan_view is not None:
            self._full_scan_view.hide()
        if self._attack_paths_view is not None:
            self._attack_paths_view.hide()
        if self._targets_view is not None:
            self._targets_view.hide()

        if self._reports_view is None:
            try:
                try:
                    from reports import ReportsWidget  # type: ignore
                except Exception:
                    from ui.reports import ReportsWidget  # type: ignore
                self._reports_view = ReportsWidget()
            except Exception as e:
                QMessageBox.critical(self, "Reports", f"Failed to load Reports.\n\n{e}")
                return

        if self._placeholder_card is not None:
            self._placeholder_card.hide()

        if self._about_button is not None:
            self._about_button.show()
        if self._content_layout is not None:
            if self._reports_view.parent() is None:
                self._content_layout.addWidget(self._reports_view)
            self._reports_view.show()

    def _on_sidebar_full_scan_clicked(self):
        if self._about_view is not None:
            self._about_view.hide()
        if self._settings_view is not None:
            self._settings_view.hide()
        if self._reports_view is not None:
            self._reports_view.hide()
        if self._attack_paths_view is not None:
            self._attack_paths_view.hide()
        if self._targets_view is not None:
            self._targets_view.hide()

        if self._full_scan_view is None:
            try:
                self._full_scan_view = FullScanWidget()
                try:
                    self._full_scan_view.viewAttackPathsRequested.connect(self.go_attack_paths_last)
                    self._full_scan_view.viewTopRiskRequested.connect(self.go_attack_paths_top)
                    self._full_scan_view.openReportsRequested.connect(self.go_reports_export)
                except Exception:
                    pass

                self._wire_full_scan_dynamic_hooks()

            except Exception as e:
                QMessageBox.critical(self, "Full Scan", f"Failed to load Full Scan.\n\n{e}")
                return

        if self._placeholder_card is not None:
            self._placeholder_card.hide()

        if self._about_button is not None:
            self._about_button.show()

        if self._content_layout is not None:
            if self._full_scan_view.parent() is None:
                self._content_layout.addWidget(self._full_scan_view)
            self._full_scan_view.show()

    # ✅ Targets hook
    def _on_sidebar_targets_clicked(self):
        if self._about_view is not None:
            self._about_view.hide()
        if self._settings_view is not None:
            self._settings_view.hide()
        if self._reports_view is not None:
            self._reports_view.hide()
        if self._full_scan_view is not None:
            self._full_scan_view.hide()
        if self._attack_paths_view is not None:
            self._attack_paths_view.hide()

        if self._targets_view is None:
            try:
                self._targets_view = TargetsWidget()
            except Exception as e:
                QMessageBox.critical(self, "Targets", f"Failed to load Targets.\n\n{e}")
                return

        if self._placeholder_card is not None:
            self._placeholder_card.hide()

        if self._about_button is not None:
            self._about_button.show()

        if self._content_layout is not None:
            if self._targets_view.parent() is None:
                self._content_layout.addWidget(self._targets_view)
            self._targets_view.show()

    def _on_sidebar_menu_clicked(self):
        if self._about_view is not None:
            self._about_view.hide()
        if self._settings_view is not None:
            self._settings_view.hide()
        if self._reports_view is not None:
            self._reports_view.hide()
        if self._full_scan_view is not None:
            self._full_scan_view.hide()
        if self._attack_paths_view is not None:
            self._attack_paths_view.hide()
        if self._targets_view is not None:
            self._targets_view.hide()
        if self._placeholder_card is not None:
            self._placeholder_card.show()

    # =========================
    # External navigation hooks
    # =========================
    def go_full_scan(self, scan_id: str):
        sid = (scan_id or "").strip()
        if sid:
            self._active_scan_id = sid

        btn = self._sidebar_buttons.get("Full Scan")
        if btn is not None:
            btn.click()
        else:
            self._on_sidebar_full_scan_clicked()

        if self._full_scan_view is not None and sid:
            t = sid
            if "_" in sid:
                t = sid.rsplit("_", 1)[0].strip() or sid
            for attr in ("in_target",):
                if hasattr(self._full_scan_view, attr):
                    try:
                        getattr(self._full_scan_view, attr).setText(t)
                    except Exception:
                        pass

    def go_attack_paths_last(self, scan_id: str):
        sid = (scan_id or "").strip()
        if sid:
            self._active_scan_id = sid

        btn = self._sidebar_buttons.get("Attack Paths")
        if btn is not None:
            btn.click()
        else:
            self._on_sidebar_attack_paths_clicked()

        if self._attack_paths_view is not None:
            try:
                self._attack_paths_view.open_last_attack_path(sid)
            except Exception as e:
                QMessageBox.critical(self, "Attack Paths", f"Failed to open Last Attack Path.\n\n{e}")

    def go_attack_paths_top(self, scan_id: str):
        sid = (scan_id or "").strip()
        if sid:
            self._active_scan_id = sid

        btn = self._sidebar_buttons.get("Attack Paths")
        if btn is not None:
            btn.click()
        else:
            self._on_sidebar_attack_paths_clicked()

        if self._attack_paths_view is not None:
            try:
                self._attack_paths_view.open_top_risk(sid)
            except Exception as e:
                QMessageBox.critical(self, "Attack Paths", f"Failed to open Top Risk.\n\n{e}")

    def go_reports_export(self, scan_id: str):
        sid = (scan_id or "").strip()
        if sid:
            self._active_scan_id = sid

        btn = self._sidebar_buttons.get("Reports")
        if btn is not None:
            btn.click()
        else:
            self._on_sidebar_reports_clicked()

        if self._reports_view is not None and sid:
            for meth in ("open_export", "open_export_tab", "open_export_view", "go_export"):
                if hasattr(self._reports_view, meth):
                    try:
                        getattr(self._reports_view, meth)(sid)
                        break
                    except Exception:
                        pass
            if hasattr(self._reports_view, "set_scan_id"):
                try:
                    self._reports_view.set_scan_id(sid)
                except Exception:
                    pass

    # =========================
    # Topbar dynamic scan labels
    # =========================
    def _init_topbar_dynamic_labels(self):
        self._load_last_scan_from_filesystem()
        self._update_topbar_text()

        self._topbar_timer = QTimer(self)
        self._topbar_timer.setInterval(60 * 1000)
        self._topbar_timer.timeout.connect(self._update_topbar_text)
        self._topbar_timer.start()

    def _set_topbar_label_text(self, host, scan_text):
        if self._topbar_center_label is None:
            return
        h = (host or "—").strip() or "—"
        s = (scan_text or "—").strip() or "—"
        self._topbar_center_label.setText(f"TARGET: {h}   |   SCAN: {s}")

    def _update_topbar_text(self):
        self._set_topbar_label_text(self._last_scan_host, self._format_relative_time(self._last_scan_generated_at))

    def _format_relative_time(self, dt):
        if dt is None:
            return "—"

        try:
            now = datetime.now(dt.tzinfo or timezone.utc)
            delta = now - dt
            seconds = int(delta.total_seconds())
        except Exception:
            return "—"

        if seconds < 0:
            seconds = 0

        if seconds < 60:
            return "just now"
        if seconds < 60 * 60:
            mins = seconds // 60
            return f"{mins}m ago"
        if seconds < 24 * 60 * 60:
            hrs = seconds // (60 * 60)
            return f"{hrs}h ago"
        if seconds < 7 * 24 * 60 * 60:
            days = seconds // (24 * 60 * 60)
            return f"{days}d ago"

        try:
            return dt.strftime("%d %b %Y")
        except Exception:
            return "—"

    def _parse_generated_at(self, value):
        if not value:
            return None
        if not isinstance(value, str):
            try:
                value = str(value)
            except Exception:
                return None

        s = value.strip()
        if not s:
            return None

        try:
            if s.endswith("Z"):
                return datetime.fromisoformat(s[:-1]).replace(tzinfo=timezone.utc)
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    def _normalize_host(self, raw: str):
        if raw is None:
            return None
        s = str(raw).strip()
        if not s:
            return None

        low = s.lower()
        if low.startswith("http://"):
            s = s[7:]
        elif low.startswith("https://"):
            s = s[8:]

        s = s.strip()
        if not s:
            return None

        # strip path/query/fragment
        for sep in ("/", "?", "#"):
            if sep in s:
                s = s.split(sep, 1)[0].strip()

        # strip trailing port if empty or spaces (keep normal ports)
        s = s.strip()
        return s or None

    def _load_last_scan_from_filesystem(self):
        scans_dir = ROOT / "output" / "scan"
        if not scans_dir.exists():
            self._last_scan_host = None
            self._last_scan_generated_at = None
            return

        best_dt = None
        best_host = None

        try:
            files = list(scans_dir.glob("scan_*.json"))
        except Exception:
            files = []

        for fp in files:
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                continue

            dt = self._parse_generated_at(data.get("generated_at"))
            if dt is None:
                continue

            host = None
            try:
                tgt = data.get("target") or {}
                if isinstance(tgt, dict):
                    host = self._normalize_host(tgt.get("host") or "")
            except Exception:
                host = None

            if best_dt is None or dt > best_dt:
                best_dt = dt
                best_host = host

        self._last_scan_host = best_host
        self._last_scan_generated_at = best_dt

    # =========================
    # Full Scan -> Topbar hooks
    # =========================
    def _wire_full_scan_dynamic_hooks(self):
        if self._full_scan_view is None or self._full_scan_hooks_installed:
            return

        self._full_scan_hooks_installed = True

        # 1) Hook "start scan" button (best-effort)
        start_btn = None
        for name in ("btn_scan", "btn_run", "btn_start", "btn_full_scan", "run_btn", "start_btn", "b_start", "b_run"):
            if hasattr(self._full_scan_view, name):
                obj = getattr(self._full_scan_view, name, None)
                if isinstance(obj, QPushButton):
                    start_btn = obj
                    break

        if start_btn is None:
            try:
                for b in self._full_scan_view.findChildren(QPushButton):
                    t = (b.text() or "").strip().lower()
                    if not t:
                        continue
                    if t in ("scan", "run", "start", "full scan", "start scan"):
                        start_btn = b
                        break
                    if "full" in t and "scan" in t:
                        start_btn = b
                        break
            except Exception:
                start_btn = None

        if start_btn is not None:
            try:
                start_btn.clicked.connect(self._on_full_scan_started)
            except Exception:
                pass

        # 2) Hook "scan finished" (signals + QProcess)
        for sig_name in (
            "scanCompleted", "scanFinished", "scanSucceeded", "scanSuccess",
            "completed", "finished", "success",
            "done", "runFinished", "pipelineFinished",
        ):
            try:
                sig = getattr(self._full_scan_view, sig_name, None)
                if sig is not None and hasattr(sig, "connect"):
                    sig.connect(self._on_full_scan_finished)
            except Exception:
                pass

        try:
            for attr in dir(self._full_scan_view):
                if attr.startswith("_"):
                    continue
                try:
                    v = getattr(self._full_scan_view, attr, None)
                except Exception:
                    continue
                if isinstance(v, QProcess):
                    try:
                        v.finished.connect(lambda *_: self._on_full_scan_finished())
                    except Exception:
                        pass
        except Exception:
            pass

    def _on_full_scan_started(self, *args, **kwargs):
        host = None
        try:
            if self._full_scan_view is not None and hasattr(self._full_scan_view, "in_target"):
                host = self._normalize_host(getattr(self._full_scan_view, "in_target").text())
        except Exception:
            host = None

        if host:
            self._last_scan_host = host
            self._last_scan_generated_at = datetime.now(timezone.utc)
            self._update_topbar_text()

    def _on_full_scan_finished(self, *args, **kwargs):
        # files can land a bit later; retry a few times quickly
        self._scan_refresh_retries_left = 10
        self._refresh_last_scan_with_retries()

    def _refresh_last_scan_with_retries(self):
        prev_dt = self._last_scan_generated_at

        self._load_last_scan_from_filesystem()
        self._update_topbar_text()

        # stop early if we got something newer than "just now" placeholder
        if prev_dt is None and self._last_scan_generated_at is not None:
            return
        if prev_dt is not None and self._last_scan_generated_at is not None:
            try:
                if self._last_scan_generated_at > prev_dt:
                    return
            except Exception:
                pass

        self._scan_refresh_retries_left -= 1
        if self._scan_refresh_retries_left > 0:
            QTimer.singleShot(600, self._refresh_last_scan_with_retries)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.close()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainMenu()
    window.show()
    sys.exit(app.exec())
