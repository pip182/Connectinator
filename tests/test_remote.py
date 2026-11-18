import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from connectinator.remote import (
    browser_url,
    client_command,
    find_client,
    parse_favorite_ref,
    service_kind,
)
from connectinator.scanner import Service


class RemoteTests(unittest.TestCase):
    def test_service_kind(self):
        self.assertEqual(service_kind(Service(5900, "VNC", True)), "VNC")
        self.assertEqual(service_kind(Service(22, "SSH", True)), "SSH")
        self.assertEqual(service_kind(Service(3389, "RDP")), "RDP")
        self.assertEqual(service_kind(Service(80, "HTTP")), "HTTP")
        self.assertEqual(service_kind(Service(443, "HTTPS")), "HTTPS")
        self.assertEqual(service_kind(Service(8080, "HTTP alternate")), "HTTP")

    def test_favorite_ref_migration(self):
        self.assertEqual(parse_favorite_ref("SSH:2222"), ("SSH", 2222))
        self.assertEqual(parse_favorite_ref(5907), ("VNC", 5907))

    def test_browser_url(self):
        self.assertEqual(browser_url("HTTP", "10.0.0.4", 80), "http://10.0.0.4")
        self.assertEqual(browser_url("HTTPS", "10.0.0.4", 8443), "https://10.0.0.4:8443")

    def test_ssh_command(self):
        with tempfile.TemporaryDirectory() as directory:
            ssh = Path(directory) / "ssh"
            ssh.touch()
            self.assertEqual(
                client_command("SSH", str(ssh), "10.0.0.5", 22, ssh_user="admin"),
                [str(ssh), "-p", "22", "admin@10.0.0.5"],
            )

    def test_rdp_mstsc_command(self):
        with tempfile.TemporaryDirectory() as directory:
            mstsc = Path(directory) / "mstsc.exe"
            mstsc.touch()
            self.assertEqual(
                client_command("RDP", str(mstsc), "10.0.0.5", 3389),
                [str(mstsc), "/v:10.0.0.5"],
            )
            self.assertEqual(
                client_command("RDP", str(mstsc), "10.0.0.5", 3390),
                [str(mstsc), "/v:10.0.0.5:3390"],
            )

    def test_vnc_delegates_to_viewer(self):
        with tempfile.TemporaryDirectory() as directory:
            viewer = Path(directory) / "vncviewer.exe"
            viewer.touch()
            self.assertEqual(
                client_command("VNC", str(viewer), "10.0.0.4", 5907),
                [str(viewer), "10.0.0.4::5907"],
            )

    def test_browser_launch(self):
        with patch("connectinator.remote.webbrowser.open", return_value=True) as opened:
            from connectinator.remote import launch_client

            launch_client("HTTPS", "", "10.0.0.4", 443)
            opened.assert_called_once_with("https://10.0.0.4")

    def test_launch_without_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            ssh = Path(directory) / "ssh"
            ssh.touch()
            with patch("connectinator.remote.subprocess.Popen") as popen:
                from connectinator.remote import launch_client

                launch_client("SSH", str(ssh), "10.0.0.4", 2222, ssh_user="ops")
                popen.assert_called_once_with(
                    [str(ssh), "-p", "2222", "ops@10.0.0.4"], shell=False
                )

    def test_find_client_requires_kind(self):
        self.assertEqual(find_client("HTTP"), "")
        with self.assertRaises(ValueError):
            find_client("FTP")