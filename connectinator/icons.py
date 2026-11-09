"""Shared QtAwesome icons; create only after a QApplication exists."""

from functools import lru_cache

# Load our Qt binding before QtAwesome/QtPy choose a binding.
from PySide6 import QtGui  # noqa: F401
import qtawesome as qta


@lru_cache(maxsize=64)
def icon(name: str, color: str = "#d0d0d8"):
    return qta.icon(name if "." in name else f"fa6s.{name}",
                    color=color, color_disabled="#5f5f68")
