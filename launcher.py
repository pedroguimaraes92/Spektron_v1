# pip install pyside6
#
# Assets expected (relative to this file):
#   assets/launcher_bg.png                  (1280x720)
#   assets/launcher_bg_2560x1440.png        (2560x1440)  <-- usado quando disponível
#   assets/spektron_cat.png
#   assets/spektron_cat_red_eyes.png        <-- NOVO (olhos vermelhos)
#   assets/spektron_cat_outline.json        (recomendado)
#
#   assets/icons/icon_main_menu.png
#   assets/icons/icon_quick_scan.png
#   assets/icons/icon_settings.png
#
# Run:
#   python launcher.py

import json
import math
import sys
from pathlib import Path
from typing import List, Tuple, Optional, Dict

from PySide6.QtCore import (
    Qt,
    QProcess,
    QRectF,
    QSize,
    QPointF,
    QTimer,
    QEasingCurve,
    QPropertyAnimation,
    Signal,
)

from PySide6.QtGui import (
    QColor,
    QFont,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QLinearGradient,
    QBrush,
    QRadialGradient,
)

from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QVBoxLayout,
    QHBoxLayout,
    QGraphicsDropShadowEffect,
)


ROOT = Path(__file__).resolve().parent
ASSETS = ROOT / "assets"
ICONS = ASSETS / "icons"

# Backgrounds (dois tamanhos)
BG_PATH = ASSETS / "launcher_bg.png"
BG_PATH_HI = ASSETS / "launcher_bg_2560x1440.png"

CAT_PATH = ASSETS / "spektron_cat.png"
CAT_RED_EYES_PATH = ASSETS / "spektron_cat_red_eyes.png"
OUTLINE_PATH = ASSETS / "spektron_cat_outline.json"

LOGO_NEON = QColor(0x7A, 0xFF, 0x4D)


def load_outline_paths(path: Path) -> Optional[List[List[QPointF]]]:
    if not path.exists():
        return None

    data = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(data, dict):
        for k in ("paths", "polylines", "outline", "lines"):
            if k in data and isinstance(data[k], list):
                raw = data[k]
                break
        else:
            return None
    elif isinstance(data, list):
        raw = data
    else:
        return None

    polylines: List[List[Tuple[float, float]]] = []
    for poly in raw:
        if not isinstance(poly, list) or len(poly) < 2:
            continue
        pts: List[Tuple[float, float]] = []
        ok = True
        for p in poly:
            if (
                isinstance(p, (list, tuple))
                and len(p) == 2
                and isinstance(p[0], (int, float))
                and isinstance(p[1], (int, float))
            ):
                pts.append((float(p[0]), float(p[1])))
            else:
                ok = False
                break
        if ok and len(pts) >= 2:
            polylines.append(pts)

    if not polylines:
        return None

    xs = [x for poly in polylines for (x, _) in poly]
    ys = [y for poly in polylines for (_, y) in poly]
    minx, maxx = min(xs), max(xs)
    miny, maxy = min(ys), max(ys)

    already_norm = (minx >= -0.02 and miny >= -0.02 and maxx <= 1.02 and maxy <= 1.02)

    norm_paths: List[List[QPointF]] = []
    if already_norm:
        for poly in polylines:
            norm_paths.append([QPointF(x, y) for x, y in poly])
        return norm_paths

    w = max(1e-9, maxx - minx)
    h = max(1e-9, maxy - miny)
    for poly in polylines:
        norm_paths.append([QPointF((x - minx) / w, (y - miny) / h) for x, y in poly])

    return norm_paths


class Background(QWidget):
    def __init__(self, bg_path_lo: Path, bg_path_hi: Optional[Path] = None):
        super().__init__()
        self._bg_lo_path = bg_path_lo
        self._bg_hi_path = bg_path_hi

        if not self._bg_lo_path.exists():
            raise FileNotFoundError(f"Missing background: {self._bg_lo_path}")

        self._pix_lo = QPixmap(str(self._bg_lo_path))
        self._pix_hi = QPixmap(str(self._bg_hi_path)) if (self._bg_hi_path and self._bg_hi_path.exists()) else None

        self._scaled: Optional[QPixmap] = None
        self._last_size: Optional[QSize] = None
        self._last_used_hi: Optional[bool] = None

    def _choose_source(self, w: int, h: int) -> QPixmap:
        if self._pix_hi and not self._pix_hi.isNull():
            if w >= 1500 or h >= 900:
                return self._pix_hi
        return self._pix_lo

    def paintEvent(self, _):
        w, h = self.width(), self.height()
        if w <= 0 or h <= 0:
            return

        src = self._choose_source(w, h)
        use_hi = (src is self._pix_hi)

        size = QSize(w, h)
        if self._scaled is None or self._last_size != size or self._last_used_hi != use_hi:
            self._scaled = src.scaled(w, h, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation)
            self._last_size = size
            self._last_used_hi = use_hi

        p = QPainter(self)
        p.setRenderHint(QPainter.SmoothPixmapTransform, True)

        sx, sy = self._scaled.width(), self._scaled.height()
        x0 = (sx - w) // 2
        y0 = (sy - h) // 2
        p.drawPixmap(0, 0, self._scaled, x0, y0, w, h)
        p.end()


class LogoTraceWidget(QWidget):
    """
    Logo + glow/pulse.
    Olhos vermelhos: piscam 1 vez e depois ficam vermelhos
    (via imagem spektron_cat_red_eyes.png).
    SEM glow extra.
    SEM trace MSPaint.
    """

    def __init__(self, cat_path: Path, outline_path: Optional[Path] = None, parent: Optional[QWidget] = None):
        super().__init__(parent)

        self._pix_green = QPixmap(str(cat_path))
        self._pix_red = QPixmap(str(CAT_RED_EYES_PATH)) if CAT_RED_EYES_PATH.exists() else QPixmap()

        if self._pix_red.isNull():
            self._pix_red = self._pix_green

        # Glow principal do logo (mantido)
        self._glow = QGraphicsDropShadowEffect(self)
        self._glow.setOffset(0, 0)
        self._glow.setBlurRadius(0)
        c = QColor(LOGO_NEON)
        c.setAlpha(0)
        self._glow.setColor(c)
        self.setGraphicsEffect(self._glow)

        self._anim_in = QPropertyAnimation(self._glow, b"blurRadius", self)
        self._anim_in.setEasingCurve(QEasingCurve.OutCubic)
        self._anim_in.setDuration(520)
        self._anim_in.setStartValue(0)
        self._anim_in.setEndValue(34)

        self._anim_pulse = QPropertyAnimation(self._glow, b"blurRadius", self)
        self._anim_pulse.setEasingCurve(QEasingCurve.InOutSine)
        self._anim_pulse.setDuration(1600)
        self._anim_pulse.setStartValue(22)
        self._anim_pulse.setEndValue(36)
        self._anim_pulse.setLoopCount(-1)

        self._t = 0.0
        self._running = False

        self._eyes_latched = False

        self.timer = QTimer(self)
        self.timer.setInterval(32)
        self.timer.timeout.connect(self._tick)

        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(560, 300)

    def start_trace(self) -> None:
        self._running = True
        self._t = 0.0
        self._eyes_latched = False

        c = QColor(LOGO_NEON)
        c.setAlpha(200)
        self._glow.setColor(c)

        self._anim_in.start()
        QTimer.singleShot(520, self._anim_pulse.start)
        self.timer.start()
        self.update()

    def _tick(self) -> None:
        if not self._running:
            return

        self._t += 0.10

        # Flicker suave do glow principal
        a = 170 + int(30 * math.sin(self._t) + 18 * math.sin(self._t * 2.6))
        a = max(110, min(230, a))
        c = QColor(LOGO_NEON)
        c.setAlpha(a)
        self._glow.setColor(c)

        # dispara olhos vermelhos UMA vez
        if not self._eyes_latched:
            s = 0.5 + 0.5 * math.sin(self._t * 0.55)
            blink = max(0.0, min(1.0, (s - 0.72) / 0.28))
            if blink >= 0.98:
                self._eyes_latched = True

        self.update()

    def _current_logo_rect(self) -> QRectF:
        pix = self._pix_green
        if pix.isNull():
            return QRectF(0, 0, self.width(), self.height())

        pw, ph = pix.width(), pix.height()
        scale = min(self.width() / pw, self.height() / ph)
        w = pw * scale
        h = ph * scale
        x = (self.width() - w) / 2.0
        y = (self.height() - h) / 2.0
        return QRectF(x, y, w, h)

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        p.setRenderHint(QPainter.SmoothPixmapTransform, True)

        r = self._current_logo_rect()

        pix = self._pix_red if self._eyes_latched else self._pix_green

        if not pix.isNull():
            src = QRectF(0, 0, pix.width(), pix.height())
            p.drawPixmap(r, pix, src)

        p.end()


def make_icon_from_file(name: str, px: int) -> QPixmap:
    pth = Path(name)
    if not pth.is_absolute():
        pth = ICONS / name
    pix = QPixmap(str(pth)) if pth.exists() else QPixmap()
    if pix.isNull():
        pix = QPixmap(px, px)
        pix.fill(Qt.transparent)
    return pix.scaled(QSize(px, px), Qt.KeepAspectRatio, Qt.SmoothTransformation)


def tint_pixmap(src: QPixmap, color: QColor) -> QPixmap:
    if src.isNull():
        return src
    out = QPixmap(src.size())
    out.fill(Qt.transparent)
    p = QPainter(out)
    p.setRenderHint(QPainter.Antialiasing, True)
    p.setRenderHint(QPainter.SmoothPixmapTransform, True)
    p.drawPixmap(0, 0, src)
    p.setCompositionMode(QPainter.CompositionMode_SourceIn)
    p.fillRect(out.rect(), color)
    p.end()
    return out


class IconTile(QWidget):
    clicked = Signal()

    def __init__(self, text: str, icon_file: str, icon_px: int = 84):
        super().__init__()
        self.setCursor(Qt.PointingHandCursor)
        self.setAttribute(Qt.WA_TranslucentBackground, True)

        self.text = text
        self._icon_px = int(icon_px)

        self._hover = False
        self._pressed = False
        self._active = False

        self._cache: Dict[str, QPixmap] = {}

        layout = QVBoxLayout(self)
        layout.setSpacing(7)
        layout.setContentsMargins(16, 12, 16, 10)
        layout.setAlignment(Qt.AlignCenter)

        self.icon = QLabel()
        self.icon.setAlignment(Qt.AlignCenter)
        self.icon.setAttribute(Qt.WA_TranslucentBackground, True)

        # glow SÓ no ícone
        self.icon_shadow = QGraphicsDropShadowEffect(self.icon)
        self.icon_shadow.setOffset(0, 0)
        self.icon_shadow.setBlurRadius(0)
        c = QColor(LOGO_NEON)
        c.setAlpha(0)
        self.icon_shadow.setColor(c)
        self.icon.setGraphicsEffect(self.icon_shadow)

        self.icon_anim = QPropertyAnimation(self.icon_shadow, b"blurRadius", self)
        self.icon_anim.setEasingCurve(QEasingCurve.InOutSine)
        self.icon_anim.setDuration(170)

        self.label = QLabel(text)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setAttribute(Qt.WA_TranslucentBackground, True)

        layout.addWidget(self.icon)
        layout.addWidget(self.label)

        self._icon_base_path = icon_file
        self._icon_base = make_icon_from_file(self._icon_base_path, self._icon_px)

        self.setFixedSize(240, 120)
        self._apply_label_style()
        self._apply_icon_glow()

    def set_icon_base_px(self, px: int) -> None:
        px = int(px)
        px = max(54, min(px, 140))
        if px == self._icon_px:
            return
        self._icon_px = px
        self._icon_base = make_icon_from_file(self._icon_base_path, self._icon_px)
        self._cache.clear()
        self.update()

    def set_active(self, active: bool) -> None:
        self._active = bool(active)
        self.update()

    def _state_key(self) -> str:
        if self._pressed or self._active:
            return "on"
        if self._hover:
            return "hover"
        return "off"

    def _icon_for_state(self, state: str) -> QPixmap:
        key = f"icon_{state}_{self.width()}x{self.height()}_{self._icon_px}"
        if key in self._cache:
            return self._cache[key]

        icon_px = int(min(self.width() * 0.33, self._icon_px))
        base = self._icon_base.scaled(icon_px, icon_px, Qt.KeepAspectRatio, Qt.SmoothTransformation)

        if state == "off":
            col = QColor(255, 255, 255, 80)
            pix = tint_pixmap(base, col)
        elif state == "hover":
            col = QColor(LOGO_NEON)
            col.setAlpha(155)
            pix = tint_pixmap(base, col)
        else:
            col = QColor(LOGO_NEON)
            col.setAlpha(220)
            pix = tint_pixmap(base, col)

        self._cache[key] = pix
        return pix

    def _apply_label_style(self):
        if self._pressed or self._active:
            self.label.setStyleSheet("""
                color: rgba(122,255,77,0.92);
                font-size: 12px;
                letter-spacing: 2px;
                font-weight: 900;
            """)
        elif self._hover:
            self.label.setStyleSheet("""
                color: rgba(255,255,255,0.62);
                font-size: 12px;
                letter-spacing: 2px;
                font-weight: 850;
            """)
        else:
            self.label.setStyleSheet("""
                color: rgba(255,255,255,0.36);
                font-size: 12px;
                letter-spacing: 2px;
                font-weight: 800;
            """)

    def _apply_icon_glow(self):
        state = self._state_key()
        if state == "on":
            c = QColor(LOGO_NEON); c.setAlpha(190)
            self.icon_shadow.setColor(c)
            self.icon_anim.stop()
            self.icon_anim.setStartValue(self.icon_shadow.blurRadius())
            self.icon_anim.setEndValue(18)
            self.icon_anim.start()
        elif state == "hover":
            c = QColor(LOGO_NEON); c.setAlpha(130)
            self.icon_shadow.setColor(c)
            self.icon_anim.stop()
            self.icon_anim.setStartValue(self.icon_shadow.blurRadius())
            self.icon_anim.setEndValue(12)
            self.icon_anim.start()
        else:
            c = QColor(LOGO_NEON); c.setAlpha(0)
            self.icon_shadow.setColor(c)
            self.icon_anim.stop()
            self.icon_anim.setStartValue(self.icon_shadow.blurRadius())
            self.icon_anim.setEndValue(0)
            self.icon_anim.start()

    def _strength(self) -> float:
        if self._pressed or self._active:
            return 1.0
        if self._hover:
            return 0.70
        return 0.0

    def _draw_bottom_lamp_glow(self, p: QPainter):
        s = self._strength()
        if s <= 0.001:
            return

        r = QRectF(self.rect())
        glow = QRectF(
            r.x() + r.width() * 0.22,
            r.y() + r.height() * 0.70,
            r.width() * 0.56,
            r.height() * 0.26,
        )

        grad = QRadialGradient(glow.center().x(), glow.bottom(), glow.width() * 0.62)
        c0 = QColor(LOGO_NEON); c0.setAlpha(int(165 * s))
        c1 = QColor(LOGO_NEON); c1.setAlpha(int(55 * s))
        c2 = QColor(LOGO_NEON); c2.setAlpha(0)
        grad.setColorAt(0.00, c0)
        grad.setColorAt(0.55, c1)
        grad.setColorAt(1.00, c2)

        p.save()
        p.setRenderHint(QPainter.Antialiasing, True)
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(grad))
        p.drawRoundedRect(glow, 18, 18)
        p.restore()

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        p.setRenderHint(QPainter.SmoothPixmapTransform, True)

        self._draw_bottom_lamp_glow(p)

        st = self._state_key()
        self.icon.setPixmap(self._icon_for_state(st))

        self._apply_label_style()
        self._apply_icon_glow()

        p.end()

    def enterEvent(self, e):
        self._hover = True
        self.update()
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._hover = False
        self._pressed = False
        self.update()
        super().leaveEvent(e)

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self._pressed = True
            self.clicked.emit()
            self.update()
        super().mousePressEvent(e)

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.LeftButton:
            self._pressed = False
            self.update()
        super().mouseReleaseEvent(e)


class Launcher(Background):
    def __init__(self):
        super().__init__(BG_PATH, BG_PATH_HI)

        # Fullscreen, frameless launcher (no minimize/maximize/close buttons)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)

        self.setWindowTitle("Spektron")
        self.resize(1280, 720)

        container = QWidget(self)
        container.setAttribute(Qt.WA_TranslucentBackground, True)

        self.setStyleSheet("""
            QLabel#title {
                font-size: 64px;
                letter-spacing: 8px;
                font-weight: 900;
                color: rgba(230,230,230,0.92);
            }
            QLabel#subtitle {
                color: rgba(255,255,255,0.45);
                font-size: 15px;
                letter-spacing: 3px;
            }
            QLabel#status { color: rgba(255,255,255,0.55); font-size: 12px; }
        """)

        self.logo = LogoTraceWidget(CAT_PATH, OUTLINE_PATH if OUTLINE_PATH.exists() else None)

        title = QLabel("SPEKTRON")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignCenter)

        subtitle = QLabel("adversarial attack path engine")
        subtitle.setObjectName("subtitle")
        subtitle.setAlignment(Qt.AlignCenter)

        btn_row = QHBoxLayout()
        btn_row.setAlignment(Qt.AlignCenter)
        btn_row.setSpacing(26)

        self.tile_main = IconTile("MAIN MENU", "icon_main_menu.png", icon_px=84)
        self.tile_quick = IconTile("QUICK SCAN", "icon_quick_scan.png", icon_px=84)
        self.tile_settings = IconTile("EXIT", "icon_exit.png", icon_px=84)

        for t in (self.tile_main, self.tile_quick, self.tile_settings):
            btn_row.addWidget(t)

        status = QLabel("v1.0.3 | online | engine ready")
        status.setObjectName("status")

        layout = QVBoxLayout(container)
        layout.setContentsMargins(40, 24, 40, 18)
        layout.setSpacing(10)
        layout.addStretch(3)
        layout.addWidget(self.logo, 0, Qt.AlignCenter)
        layout.addSpacing(0)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(26)
        layout.addLayout(btn_row)
        layout.addStretch(4)
        layout.addWidget(status, 0, Qt.AlignLeft)

        self._container = container

        self.tile_main.clicked.connect(lambda: print("MAIN MENU"))
        self.tile_quick.clicked.connect(self._open_quickscan)

        # ALTERAÇÃO ÚNICA: botão EXIT fecha o launcher
        self.tile_settings.clicked.connect(self.close)

        QTimer.singleShot(260, self.logo.start_trace)

    def _open_quickscan(self) -> None:
        """Launch quickscan.py in a separate process (launcher stays open)."""
        try:
            script = ROOT / "quickscan.py"
            if not script.exists():
                print("quickscan.py not found in project root")
                return
            # Use a detached process so the launcher keeps running independently.
            QProcess.startDetached(sys.executable, [str(script)], str(ROOT))
        except Exception as e:
            print(f"Failed to launch quickscan: {e}")

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._container.setGeometry(0, 0, self.width(), self.height())

        w, h = self.width(), self.height()

        logo_w = max(420, min(int(w * 0.36), 820))
        logo_h = int(logo_w * 0.60)
        self.logo.setFixedSize(logo_w, logo_h)

        tile_w = max(170, min(int(w * 0.135), 240))
        tile_h = max(98,  min(int(h * 0.125), 128))

        for t in (self.tile_main, self.tile_quick, self.tile_settings):
            t.setFixedSize(tile_w, tile_h)

        icon_base = int(min(tile_w, tile_h) * 0.68)
        for t in (self.tile_main, self.tile_quick, self.tile_settings):
            t.set_icon_base_px(icon_base)


def main():
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    w = Launcher()
    # Launcher is frameless; keep it fullscreen.
    w.showFullScreen()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
