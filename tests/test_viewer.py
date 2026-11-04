from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from connectinator.viewer import launch, viewer_command


class ViewerTests(unittest.TestCase):
    def test_port_syntax_and_paths_with_spaces(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fake viewer.exe"
            path.touch()
            self.assertEqual(viewer_command(str(path), "10.0.0.4", 5907), [str(path), "10.0.0.4::5907"])
            self.assertEqual(viewer_command(str(path), "10.0.0.4", 5907, "Single colon")[-1], "10.0.0.4:5907")
            with patch("connectinator.viewer.subprocess.Popen") as popen:
                launch(str(path), "10.0.0.4", 5907, "Double colon")
                popen.assert_called_once_with([str(path), "10.0.0.4::5907"], shell=False)

    def test_missing_executable(self):
        with self.assertRaises(ValueError):
            viewer_command("/missing-viewer", "10.0.0.1", 5900)
