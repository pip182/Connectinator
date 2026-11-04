"""Shared dark controls, with QtAwesome glyphs for stylesheet subcontrols."""

from pathlib import Path
import tempfile

from PySide6.QtCore import QTemporaryDir
from PySide6.QtWidgets import QComboBox, QStyledItemDelegate

from .icons import icon


class ComboBox(QComboBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        # The default menu delegate can bypass item spacing and hover styling.
        self.setItemDelegate(QStyledItemDelegate(self))
        self.setMaxVisibleItems(10)
        self.view().setUniformItemSizes(True)


STYLE = """
QWidget { background: #111923; color: #e5edf5; font-size: 13px; }
QLabel#title { font-size: 30px; font-weight: 700; }
QLabel#muted { color: #9baec3; }
QLabel#summary { color: #70dfbd; font-size: 15px; padding: 3px 0; }
QFrame#panel { background: #192432; border: 1px solid #2a3b50; border-radius: 10px; }
QFrame#panel QLabel, QFrame#panel QCheckBox { background: transparent; }
QPushButton { background: #25354a; border: 1px solid #354a64; border-radius: 6px; padding: 9px 14px; }
QPushButton:hover { background: #324960; border-color: #4b6582; }
QPushButton:pressed { background: #1c2b3c; }
QPushButton:focus { border-color: #56d6ac; }
QPushButton#primary { background: #248365; border-color: #319c7b; color: white; font-weight: 600; }
QPushButton#primary:hover { background: #2b9875; }
QPushButton#primary:pressed { background: #1b6c53; }
QPushButton:disabled, QPushButton#primary:disabled { background: #1d2937; color: #64758b; border-color: #293747; }
QLineEdit, QComboBox, QDoubleSpinBox, QPlainTextEdit { background: #131e2b; border: 1px solid #34465b; border-radius: 6px; padding: 7px; selection-background-color: #285c77; selection-color: #ffffff; }
QLineEdit:hover, QComboBox:hover, QDoubleSpinBox:hover { border-color: #4b6582; }
QLineEdit:focus, QComboBox:focus, QDoubleSpinBox:focus, QPlainTextEdit:focus { border-color: #56d6ac; }
QLineEdit:disabled, QComboBox:disabled, QDoubleSpinBox:disabled { background: #16212e; color: #64758b; border-color: #293747; }
QComboBox { padding-right: 36px; min-height: 18px; }
QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: top right; width: 28px; background: #203044; border: none; border-left: 1px solid #34465b; border-top-right-radius: 5px; border-bottom-right-radius: 5px; }
QComboBox::drop-down:hover, QComboBox::drop-down:on { background: #2c4358; }
QComboBox::drop-down:disabled { background: #1b2837; border-left-color: #293747; }
QComboBox::down-arrow { image: url("@DOWN@"); width: 12px; height: 12px; }
QComboBox::down-arrow:on { image: url("@UP@"); }
QComboBox::down-arrow:disabled { image: url("@DOWN_DISABLED@"); }
QComboBox QAbstractItemView { background: #182432; color: #e5edf5; border: 1px solid #426079; border-radius: 6px; padding: 4px; outline: 0; selection-background-color: #2b5165; selection-color: #ffffff; }
QComboBox QAbstractItemView::item { min-height: 26px; padding: 5px 10px; border: none; border-radius: 4px; }
QComboBox QAbstractItemView::item:hover, QComboBox QAbstractItemView::item:selected { background: #2b5165; color: #ffffff; }
QDoubleSpinBox { padding-right: 29px; min-height: 18px; }
QDoubleSpinBox::up-button { subcontrol-origin: border; subcontrol-position: top right; width: 22px; background: #203044; border-left: 1px solid #34465b; border-bottom: 1px solid #34465b; border-top-right-radius: 5px; }
QDoubleSpinBox::down-button { subcontrol-origin: border; subcontrol-position: bottom right; width: 22px; background: #203044; border-left: 1px solid #34465b; border-bottom-right-radius: 5px; }
QDoubleSpinBox::up-button:hover, QDoubleSpinBox::down-button:hover { background: #2c4358; }
QDoubleSpinBox::up-button:pressed, QDoubleSpinBox::down-button:pressed { background: #285847; }
QDoubleSpinBox::up-arrow { image: url("@UP@"); width: 9px; height: 9px; }
QDoubleSpinBox::down-arrow { image: url("@DOWN@"); width: 9px; height: 9px; }
QDoubleSpinBox::up-arrow:disabled, QDoubleSpinBox::up-arrow:off { image: url("@UP_DISABLED@"); }
QDoubleSpinBox::down-arrow:disabled, QDoubleSpinBox::down-arrow:off { image: url("@DOWN_DISABLED@"); }
QCheckBox { spacing: 7px; }
QCheckBox::indicator { width: 15px; height: 15px; border: 1px solid #425b75; border-radius: 4px; background: #131e2b; }
QCheckBox::indicator:hover { border-color: #56d6ac; }
QCheckBox::indicator:checked { background: #248365; border-color: #319c7b; image: url("@CHECK@"); }
QCheckBox::indicator:disabled { background: #1b2837; border-color: #293747; }
QCheckBox:disabled { color: #64758b; }
QTableView { background: #131e2b; alternate-background-color: #182432; gridline-color: #28394b; border: 1px solid #304256; border-radius: 6px; }
QTableView::item { padding: 7px; }
QTableView::item:selected { background: #25536a; }
QTableView::item:selected:!active { background: #234353; }
QHeaderView::section { background: #203044; padding: 10px; border: none; font-weight: 600; }
QHeaderView::up-arrow { image: url("@UP@"); width: 9px; height: 9px; }
QHeaderView::down-arrow { image: url("@DOWN@"); width: 9px; height: 9px; }
QTableCornerButton::section { background: #203044; border: none; }
QScrollBar:vertical { background: #131e2b; width: 12px; margin: 2px 0; border: none; }
QScrollBar:horizontal { background: #131e2b; height: 12px; margin: 0 2px; border: none; }
QScrollBar::handle:vertical { background: #425b73; min-height: 30px; border: 3px solid #131e2b; border-radius: 6px; }
QScrollBar::handle:horizontal { background: #425b73; min-width: 30px; border: 3px solid #131e2b; border-radius: 6px; }
QScrollBar::handle:hover { background: #60bda5; }
QScrollBar::handle:pressed { background: #70dfbd; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; border: none; background: transparent; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; border: none; background: transparent; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QAbstractScrollArea::corner { background: #131e2b; border: none; }
QSplitter::handle { background: #1c2c3d; }
QSplitter::handle:vertical { height: 5px; margin: 2px 0; }
QSplitter::handle:hover { background: #3b786d; }
QProgressBar { background: #243447; border: none; border-radius: 3px; }
QProgressBar::chunk { background: #56d6ac; border-radius: 3px; }
QToolTip { background: #25354a; color: #e5edf5; border: 1px solid #526981; padding: 5px; }
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
        ("DOWN", "chevron-down", "#b5c9dd"),
        ("UP", "chevron-up", "#b5c9dd"),
        ("DOWN_DISABLED", "chevron-down", "#64758b"),
        ("UP_DISABLED", "chevron-up", "#64758b"),
        ("CHECK", "check", "#ffffff"),
    ):
        path = Path(assets.path()) / f"{token.lower()}.png"
        if not path.exists() and not icon(name, color).pixmap(24, 24).save(str(path)):
            raise OSError(f"Could not create theme icon: {token}")
        stylesheet = stylesheet.replace(f"@{token}@", path.resolve().as_posix())
    app.setStyle("Fusion")
    app.setStyleSheet(stylesheet)
