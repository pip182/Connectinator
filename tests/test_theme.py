import os

os.environ["QT_QPA_PLATFORM"] = "offscreen"

import unittest
from unittest.mock import patch

from PySide6.QtWidgets import QApplication, QMessageBox

from connectinator.theme import HelpButton


class ThemeHelpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_help_button_tooltip_and_detail_dialog(self):
        button = HelpButton("Short tip", detail="Longer help body.")
        self.assertEqual(button.toolTip(), "Short tip")
        with patch.object(QMessageBox, "information") as shown:
            button.clicked.emit()
            shown.assert_called_once()
            self.assertEqual(shown.call_args[0][2], "Longer help body.")