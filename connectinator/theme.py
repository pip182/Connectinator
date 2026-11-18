"""Shared dark controls, with QtAwesome glyphs for stylesheet subcontrols."""

from pathlib import Path
import tempfile

from PySide6.QtCore import QTemporaryDir, Qt
from PySide6.QtWidgets import QCheckBox, QComboBox, QHBoxLayout, QLabel, QMessageBox, QStyledItemDelegate, QToolButton, QWidget

from .icons import icon


class HelpButton(QToolButton):
    """Small ? icon: hover shows a tooltip; click opens fuller help."""

    def __init__(self, tooltip: str, parent=None, *, title: str = "", detail: str = ""):
        super().__init__(parent)
        self._title = title or "Help"
        self._detail = detail or tooltip
        self.setObjectName("help")
        self.setIcon(icon("circle-question", "#8ea2ff"))
        self.setToolTip(tooltip)
        self.setAutoRaise(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.clicked.connect(self._show_detail)

    def _show_detail(self):
        QMessageBox.information(self.window(), self._title, self._detail)


def form_label(text: str, tooltip: str, parent=None, *, title: str = "", detail: str = "") -> QWidget:
    row = QWidget(parent)
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(6)
    layout.addWidget(QLabel(text))
    layout.addWidget(HelpButton(tooltip, row, title=title or text, detail=detail or tooltip))
    return row


def checkbox_with_help(checkbox: QCheckBox, tooltip: str, parent=None, *, title: str = "", detail: str = "") -> QWidget:
    row = QWidget(parent)
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(6)
    layout.addWidget(checkbox)
    layout.addWidget(HelpButton(tooltip, row, title=title or checkbox.text(), detail=detail or tooltip))
    layout.addStretch()
    return row


class ComboBox(QComboBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        # The default menu delegate can bypass item spacing and hover styling.
        self.setItemDelegate(QStyledItemDelegate(self))
        self.setMaxVisibleItems(10)
        self.view().setUniformItemSizes(True)


STYLE = """
QWidget { background: #0c0c0e; color: #e8e8e8; font-size: 13px; }
QLabel#title { font-size: 30px; font-weight: 700; }
QLabel#muted { color: #9a9aa3; }
QLabel#summary { color: #8ea2ff; font-size: 15px; padding: 3px 0; }
QFrame#panel { background: #161619; border: 1px solid #2c2c32; border-radius: 10px; }
QFrame#panel QLabel, QFrame#panel QCheckBox { background: transparent; }
QPushButton { background: #232329; border: 1px solid #3a3a42; border-radius: 6px; padding: 9px 14px; }
QPushButton:hover { background: #2f2f38; border-color: #55555f; }
QPushButton:pressed { background: #1a1a1f; }
QPushButton:focus { border-color: #5ccfe6; }
QPushButton#primary { background: #1f7a2e; border-color: #34a047; color: white; font-weight: 600; }
QPushButton#primary:hover { background: #2a9040; }
QPushButton#primary:pressed { background: #195f26; }
QPushButton:disabled, QPushButton#primary:disabled { background: #1a1a1e; color: #5f5f68; border-color: #2a2a30; }
QLineEdit, QComboBox, QDoubleSpinBox, QPlainTextEdit { background: #101012; border: 1px solid #38383f; border-radius: 6px; padding: 7px; selection-background-color: #2a3f73; selection-color: #ffffff; }
QLineEdit:hover, QComboBox:hover, QDoubleSpinBox:hover { border-color: #55555f; }
QLineEdit:focus, QComboBox:focus, QDoubleSpinBox:focus, QPlainTextEdit:focus { border-color: #5ccfe6; }
QLineEdit:disabled, QComboBox:disabled, QDoubleSpinBox:disabled { background: #141417; color: #5f5f68; border-color: #2a2a30; }
QComboBox { padding-right: 36px; min-height: 18px; }
QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: top right; width: 28px; background: #1e1e24; border: none; border-left: 1px solid #38383f; border-top-right-radius: 5px; border-bottom-right-radius: 5px; }
QComboBox::drop-down:hover, QComboBox::drop-down:on { background: #2b2b33; }
QComboBox::drop-down:disabled { background: #18181c; border-left-color: #2a2a30; }
QComboBox::down-arrow { image: url("@DOWN@"); width: 12px; height: 12px; }
QComboBox::down-arrow:on { image: url("@UP@"); }
QComboBox::down-arrow:disabled { image: url("@DOWN_DISABLED@"); }
QComboBox QAbstractItemView { background: #141418; color: #e8e8e8; border: 1px solid #4a4a55; border-radius: 6px; padding: 4px; outline: 0; selection-background-color: #26345c; selection-color: #ffffff; }
QComboBox QAbstractItemView::item { min-height: 26px; padding: 5px 10px; border: none; border-radius: 4px; }
QComboBox QAbstractItemView::item:hover, QComboBox QAbstractItemView::item:selected { background: #26345c; color: #ffffff; }
QDoubleSpinBox { padding-right: 29px; min-height: 18px; }
QDoubleSpinBox::up-button { subcontrol-origin: border; subcontrol-position: top right; width: 22px; background: #1e1e24; border-left: 1px solid #38383f; border-bottom: 1px solid #38383f; border-top-right-radius: 5px; }
QDoubleSpinBox::down-button { subcontrol-origin: border; subcontrol-position: bottom right; width: 22px; background: #1e1e24; border-left: 1px solid #38383f; border-bottom-right-radius: 5px; }
QDoubleSpinBox::up-button:hover, QDoubleSpinBox::down-button:hover { background: #2b2b33; }
QDoubleSpinBox::up-button:pressed, QDoubleSpinBox::down-button:pressed { background: #1f5a2c; }
QDoubleSpinBox::up-arrow { image: url("@UP@"); width: 9px; height: 9px; }
QDoubleSpinBox::down-arrow { image: url("@DOWN@"); width: 9px; height: 9px; }
QDoubleSpinBox::up-arrow:disabled, QDoubleSpinBox::up-arrow:off { image: url("@UP_DISABLED@"); }
QDoubleSpinBox::down-arrow:disabled, QDoubleSpinBox::down-arrow:off { image: url("@DOWN_DISABLED@"); }
QCheckBox { spacing: 7px; }
QCheckBox::indicator { width: 15px; height: 15px; border: 1px solid #4a4a56; border-radius: 4px; background: #101012; }
QCheckBox::indicator:hover { border-color: #5ccfe6; }
QCheckBox::indicator:checked { background: #1f7a2e; border-color: #34a047; image: url("@CHECK@"); }
QCheckBox::indicator:disabled { background: #18181c; border-color: #2a2a30; }
QCheckBox:disabled { color: #5f5f68; }
QTableView { background: #101012; alternate-background-color: #141418; gridline-color: #26262c; border: 1px solid #2e2e35; border-radius: 6px; }
QTableView::item { padding: 7px; }
QTableView::item:selected { background: #263a6b; }
QTableView::item:selected:!active { background: #1f2a4a; }
QHeaderView::section { background: #1e1e24; padding: 10px; border: none; font-weight: 600; }
QHeaderView::up-arrow { image: url("@UP@"); width: 9px; height: 9px; }
QHeaderView::down-arrow { image: url("@DOWN@"); width: 9px; height: 9px; }
QTableCornerButton::section { background: #1e1e24; border: none; }
QScrollBar:vertical { background: #101012; width: 12px; margin: 2px 0; border: none; }
QScrollBar:horizontal { background: #101012; height: 12px; margin: 0 2px; border: none; }
QScrollBar::handle:vertical { background: #45454f; min-height: 30px; border: 3px solid #101012; border-radius: 6px; }
QScrollBar::handle:horizontal { background: #45454f; min-width: 30px; border: 3px solid #101012; border-radius: 6px; }
QScrollBar::handle:hover { background: #5ccfe6; }
QScrollBar::handle:pressed { background: #8ea2ff; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; border: none; background: transparent; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; border: none; background: transparent; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QAbstractScrollArea::corner { background: #101012; border: none; }
QSplitter::handle { background: #1c1c22; }
QSplitter::handle:vertical { height: 5px; margin: 2px 0; }
QSplitter::handle:hover { background: #3a8a99; }
QProgressBar { background: #25252b; border: none; border-radius: 3px; }
QProgressBar::chunk { background: #5ccfe6; border-radius: 3px; }
QToolTip { background: #232329; color: #e8e8e8; border: 1px solid #55555f; padding: 5px; }
QToolButton#help { background: transparent; border: none; padding: 2px; }
QToolButton#help:hover { background: #2f2f38; border-radius: 9px; }
"""


def apply_theme(app):
    # QSS requires image URLs. Render the existing icon system once at 2x size;
    # keep the temporary directory alive for the application's lifetime.
    assets = getattr(app, "_theme_assets", None)
    if assets is None:
        assets = QTemporaryDir(str(Path(tempfile.gettempdir()) / "connectinator-theme-XXXXXX"))
        if not assets.isValid():
            raise OSError("Could not create theme image directory")
        app._theme_assets = assets
    stylesheet = STYLE
    for token, name, color in (
        ("DOWN", "chevron-down", "#c8c8d0"),
        ("UP", "chevron-up", "#c8c8d0"),
        ("DOWN_DISABLED", "chevron-down", "#5f5f68"),
        ("UP_DISABLED", "chevron-up", "#5f5f68"),
        ("CHECK", "check", "#ffffff"),
    ):
        path = Path(assets.path()) / f"{token.lower()}.png"
        if not path.exists() and not icon(name, color).pixmap(24, 24).save(str(path)):
            raise OSError(f"Could not create theme icon: {token}")
        stylesheet = stylesheet.replace(f"@{token}@", path.resolve().as_posix())
    app.setStyle("Fusion")
    app.setStyleSheet(stylesheet)
