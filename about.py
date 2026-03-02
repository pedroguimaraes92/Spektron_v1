# about.py

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor, QPixmap
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QFrame,
    QGraphicsDropShadowEffect,
)


ROOT = Path(__file__).resolve().parent
ASSETS = ROOT / "assets"
ICONS = ASSETS / "icons"


class AboutView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setStyleSheet("background: transparent;")

        root = QVBoxLayout()
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.setAlignment(Qt.AlignTop)  # <-- ALTERADO (antes era AlignCenter)

        # ==============================
        # Ícone
        # ==============================
        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignHCenter)

        icon_pix = QPixmap(str(ICONS / "icon_about.png"))
        icon_label.setPixmap(
            icon_pix.scaled(124, 124, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        )
        icon_label.setStyleSheet("background: transparent;")

        icon_glow = QGraphicsDropShadowEffect()
        icon_glow.setBlurRadius(30)
        icon_glow.setOffset(0, 0)
        icon_glow.setColor(QColor(124, 255, 158, 95))
        icon_label.setGraphicsEffect(icon_glow)

        # ==============================
        # Card único
        # ==============================
        card = QFrame()
        card.setMinimumWidth(960)
        card.setMaximumWidth(1020)
        card.setMinimumHeight(560)

        card.setObjectName("about_card")
        card.setStyleSheet("""
            QFrame {
                background-color: rgba(0,0,0,55);
                border: 1px solid rgba(120,255,120,25);
                border-radius: 18px;
            }
            #about_card QLabel {
                background: transparent;
                border: none;
                border-radius: 0px;
                padding: 0px;
                margin: 0px;
            }
        """)

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(26)
        shadow.setOffset(0, 8)
        shadow.setColor(QColor(0, 0, 0, 110))
        card.setGraphicsEffect(shadow)

        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(36, 36, 36, 36)
        content_layout.setSpacing(0)

        # ------------------------------
        # Título
        # ------------------------------
        title = QLabel("Spektron v1 - Adversarial Attack Path Engine")
        title_font = QFont("Segoe UI")
        title_font.setPixelSize(20)
        title_font.setWeight(QFont.DemiBold)
        title.setFont(title_font)
        title.setStyleSheet("color: rgba(255,255,255,235);")
        title.setAlignment(Qt.AlignLeft)

        content_layout.addWidget(title)
        content_layout.addSpacing(20)

        # ------------------------------
        # Parágrafos
        # ------------------------------
        body_font = QFont("Segoe UI")
        body_font.setPixelSize(15)

        paragraphs = [
            "Spektron is a deterministic attack path engine designed to transform passive web reconnaissance into structured adversarial analysis.",
            "Instead of listing isolated findings, Spektron correlates evidence into linear attack paths following a strict model:",
            "Entry → Weakness → Technique → Impact → Controls",
            "The engine evaluates real exploit chains using passive data only, prioritizing paths based on structural risk and impact feasibility.",
        ]

        for text in paragraphs:
            lbl = QLabel(text)
            lbl.setFont(body_font)
            lbl.setWordWrap(True)
            lbl.setAlignment(Qt.AlignLeft)
            lbl.setStyleSheet("color: rgba(255,255,255,215);")
            content_layout.addWidget(lbl)
            content_layout.addSpacing(14)

        # ------------------------------
        # Core Capabilities
        # ------------------------------
        section = QLabel("Core Capabilities")
        section_font = QFont("Segoe UI")
        section_font.setPixelSize(16)
        section_font.setWeight(QFont.DemiBold)
        section.setFont(section_font)
        section.setStyleSheet("color: rgba(255,255,255,230);")
        section.setAlignment(Qt.AlignLeft)

        content_layout.addSpacing(8)
        content_layout.addWidget(section)
        content_layout.addSpacing(14)

        capabilities = [
            "Passive web reconnaissance correlation",
            "Deterministic attack path modeling",
            "Offline local engine (JSON-based outputs)",
            "Attack Path Score as primary risk metric",
            "Structured outputs: Evidence, Attack Paths, Graph, Summary",
        ]

        for text in capabilities:
            lbl = QLabel(text)
            lbl.setFont(body_font)
            lbl.setWordWrap(True)
            lbl.setAlignment(Qt.AlignLeft)
            lbl.setStyleSheet("color: rgba(255,255,255,215);")
            content_layout.addWidget(lbl)
            content_layout.addSpacing(10)

        content_layout.addSpacing(12)

        # ------------------------------
        # Encerramento
        # ------------------------------
        closing = QLabel(
            "Spektron is built for clarity, precision and operational decision-making, enabling security teams to eliminate attack chains instead of chasing individual vulnerabilities."
        )
        closing.setFont(body_font)
        closing.setWordWrap(True)
        closing.setAlignment(Qt.AlignLeft)
        closing.setStyleSheet("color: rgba(255,255,255,215);")

        content_layout.addWidget(closing)
        content_layout.addSpacing(26)

        # ------------------------------
        # Footer
        # ------------------------------
        footer_font = QFont("Segoe UI")
        footer_font.setPixelSize(11)

        footer = QLabel("v0.9.3 | offline | engine ready")
        footer.setFont(footer_font)
        footer.setStyleSheet("color: rgba(255,255,255,105);")
        footer.setAlignment(Qt.AlignCenter)

        content_layout.addWidget(footer)

        card.setLayout(content_layout)

        # ==============================
        # Layout principal ajustado
        # ==============================
        root.addSpacing(60)  # controla o quanto sobe (ajuste fino aqui)
        root.addWidget(icon_label, alignment=Qt.AlignHCenter)
        root.addSpacing(24)
        root.addWidget(card, alignment=Qt.AlignHCenter)
        root.addStretch()  # empurra levemente para cima

        self.setLayout(root)
