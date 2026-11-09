from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch

from connectinator.viewer import launch, viewer_command


class ViewerTests(unittest.TestCase):
    def test_frozen_launch_restores_dll_lookup_even_on_failure(self):
        dll = MagicMock()
        dll.SetDllDirectoryW.return_value = 1
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "viewer.exe"
            executable.touch()
            with patch("connectinator.viewer.sys.platform", "win32"), \
                 patch("connectinator.viewer.sys.frozen", True, create=True), \
                 patch("connectinator.viewer.sys._MEIPASS", "C:/bundle", create=True), \
                 patch("ctypes.WinDLL", return_value=dll, create=True), \
                 patch("connectinator.viewer.subprocess.Popen", side_effect=OSError):
                with self.assertRaises(OSError):
                    launch(str(executable), "10.0.0.1", 5900, "Double colon")
        self.assertEqual(dll.SetDllDirectoryW.call_args_list, [call(None), call("C:/bundle")])

    def test_port_syntax_and_paths_with_spaces(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fake viewer.exe"
            path.touch()
            self.assertEqual(viewer_command(str(path), "10.0.0.4", 5907), [str(path), "10.0.0.4::5907"])
            self.assertEqual(viewer_command(str(path), "10.0.0.4", 5907, "Single colon")[-1], "10.0.0.4:5907")
            with patch("connectinator.viewer.subprocess.Popen") as popen:
                launch(str(path), "10.0.0.4", 5907, "Double colon")
                popen.assert_called_once_with([str(path), "10.0.0.4::5907"], shell=False)

    def test_view_only_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            tiger = Path(directory) / "vncviewer.exe"
            tight = Path(directory) / "tvnviewer.exe"
            tiger.touch()
            tight.touch()
            self.assertEqual(viewer_command(str(tiger), "10.0.0.4", 5900, view_only=True),
                             [str(tiger), "-ViewOnly", "10.0.0.4::5900"])
            self.assertEqual(viewer_command(str(tight), "10.0.0.4", 5900, view_only=True),
                             [str(tight), "10.0.0.4::5900", "-viewonly=yes"])

    def test_missing_executable(self):
        with self.assertRaises(ValueError):
            viewer_command("/missing-viewer", "10.0.0.1", 5900)
