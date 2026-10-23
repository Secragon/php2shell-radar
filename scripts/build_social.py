"""Render the repository's 1280x640 social preview from the product icon."""

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import (QColor, QFont, QGuiApplication, QImage, QLinearGradient,
                           QFontDatabase, QPainter, QPen, QRadialGradient)
from PySide6.QtSvg import QSvgRenderer


def main():
    root = Path(__file__).resolve().parents[1]
    output = root / "assets" / "social-preview.png"
    output.parent.mkdir(exist_ok=True)
    app = QGuiApplication.instance() or QGuiApplication([])
    if not QFontDatabase.families():
        for name in ("segoeui.ttf", "segoeuib.ttf"):
            path = Path("C:/Windows/Fonts") / name
            if path.is_file():
                QFontDatabase.addApplicationFont(str(path))
    icon = QSvgRenderer(str(root / "hunter" / "data" / "app-icon.svg"))
    if not icon.isValid():
        raise RuntimeError("Invalid product icon SVG")

    image = QImage(1280, 640, QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(Qt.GlobalColor.white)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    background = QLinearGradient(0, 0, 1280, 640)
    background.setColorAt(0, QColor("#fbfdff"))
    background.setColorAt(0.56, QColor("#eff8ff"))
    background.setColorAt(1, QColor("#e8ecff"))
    painter.fillRect(image.rect(), background)

    for x, y, radius, color in ((70, 615, 330, QColor(114, 203, 212, 38)),
                                 (1190, 70, 400, QColor(123, 151, 247, 30))):
        glow = QRadialGradient(x, y, radius)
        glow.setColorAt(0, color)
        glow.setColorAt(1, QColor(color.red(), color.green(), color.blue(), 0))
        painter.setBrush(glow)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(QRectF(x - radius, y - radius, radius * 2, radius * 2))

    painter.setBrush(Qt.BrushStyle.NoBrush)
    for radius, alpha in ((180, 35), (260, 31), (340, 24), (420, 18)):
        painter.setPen(QPen(QColor(55, 113, 174, alpha), 3))
        painter.drawEllipse(QRectF(1150 - radius, 320 - radius, radius * 2, radius * 2))

    for offset, alpha in ((14, 11), (9, 17), (5, 23)):
        painter.setBrush(QColor(23, 42, 69, alpha))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(QRectF(104 + offset, 169 + offset, 300, 300), 70, 70)
    icon.render(painter, QRectF(104, 169, 300, 300))

    painter.setPen(QColor("#18334e"))
    title = QFont("Segoe UI")
    title.setWeight(QFont.Weight.Bold)
    title.setPixelSize(82)
    painter.setFont(title)
    painter.drawText(QRectF(455, 187, 730, 110),
                     Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, "PHP2Shell")
    title.setPixelSize(100)
    painter.setFont(title)
    painter.drawText(QRectF(451, 278, 680, 125),
                     Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, "Radar")

    painter.setPen(QColor("#577086"))
    subtitle = QFont("Segoe UI")
    subtitle.setPixelSize(30)
    painter.setFont(subtitle)
    painter.drawText(QRectF(460, 411, 700, 66),
                     Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                     "Find PHP sites. Prioritize exposure.")
    painter.setBrush(QColor("#75cad6"))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawRoundedRect(QRectF(460, 507, 124, 8), 4, 4)
    painter.setBrush(QColor("#ef526e"))
    painter.drawEllipse(QRectF(598, 503, 16, 16))
    painter.end()
    if not image.save(str(output), "PNG"):
        raise RuntimeError("Could not save social preview")
    app.quit()
    print(output)


if __name__ == "__main__":
    main()
