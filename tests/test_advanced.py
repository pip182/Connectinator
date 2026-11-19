import asyncio
import socketserver
import threading
import time
import unittest
from unittest.mock import patch

from connectinator import advanced
from connectinator.advanced import AdvancedReport, Finding, advanced_scan
from connectinator.scanner import Service


class _Responder(socketserver.BaseRequestHandler):
    payload = b""
    chunks: tuple[bytes, ...] = ()
    wait_for_request = True

    def handle(self):
        try:
            if self.wait_for_request:
                self.request.recv(4096)
        except OSError:
            pass
        for chunk in self.chunks or (self.payload,):
            if not chunk:
                continue
            self.request.sendall(chunk)
            time.sleep(0.02)


def _serve(payload, *, wait_for_request=True, chunks=()):
    class Handler(_Responder):
        pass

    Handler.payload = payload
    Handler.chunks = tuple(chunks)
    Handler.wait_for_request = wait_for_request
    server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, server.server_address[1]


class AdvancedScanTests(unittest.TestCase):
    def scan(self, group, payload, *, wait_for_request=True, chunks=(), service_name="SSH"):
        server, thread, port = _serve(payload, wait_for_request=wait_for_request, chunks=chunks)
        replacement = {port: service_name} if group == "GREETING_PORTS" else frozenset({port})
        try:
            with patch.object(advanced, group, replacement), \
                 patch("connectinator.advanced.ping_ttl", return_value=64):
                return asyncio.run(advanced_scan("127.0.0.1", 0.5, lambda: False, ports=(port,)))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_http_banner_and_access_findings(self):
        report = self.scan(
            "HTTP_PORTS",
            b"HTTP/1.1 200 OK\r\nServer: Apache/2.2.34\r\n"
            b"WWW-Authenticate: Basic realm=\"test\"\r\n\r\n<html>Index of /</html>",
        )
        http = next(service for service in report.services if service.name == "HTTP")
        self.assertTrue(http.verified)
        self.assertEqual(http.source, "advanced")
        self.assertIn("Apache/2.2.34", http.banner)
        titles = {finding.title for finding in report.findings}
        self.assertIn("HTTP directory listing at /", titles)
        self.assertIn("HTTP root requires authentication", titles)
        self.assertIn("Old web server version in banner", titles)
        port_findings = [finding for finding in report.findings if finding.port]
        self.assertEqual(port_findings[0].severity, "warning")
        self.assertEqual(port_findings[-1].severity, "info")
        self.assertTrue(report.reachable)

    def test_vnc_no_auth_is_reported_without_opening_a_session(self):
        report = self.scan("VNC_PORTS", b"RFB 003.008\n\x01\x01",
                           wait_for_request=False)
        vnc = next(service for service in report.services if service.name == "VNC")
        self.assertTrue(vnc.verified)
        self.assertIn("None", vnc.banner)
        self.assertTrue(any(f.severity == "warning" and "unauthenticated" in f.title
                            for f in report.findings))

    def test_ssh_banner_and_ttl_fingerprint(self):
        report = self.scan("GREETING_PORTS",
                           b"SSH-1.99-OpenSSH_5.9p1\r\n", wait_for_request=False)
        ssh = next(service for service in report.services if service.name == "SSH")
        self.assertTrue(ssh.verified)
        self.assertTrue(any(f.category == "Version" for f in report.findings))
        self.assertIn("Linux/macOS", report.fingerprint)
        self.assertTrue(any(f.category == "Fingerprint" for f in report.findings))

    def test_fragmented_http_headers_and_vnc_banner(self):
        http_report = self.scan(
            "HTTP_PORTS", b"",
            chunks=(b"HTTP/1.1 200 OK\r\nServer: nginx/1.2\r\n",
                    b"\r\n<body>Welcome</body>"),
        )
        http = http_report.services[0]
        self.assertTrue(http.verified)
        self.assertIn("nginx/1.2", http.banner)

        vnc_report = self.scan(
            "VNC_PORTS", b"", wait_for_request=False,
            chunks=(b"RFB 003", b".008\n\x01", b"\x01"),
        )
        vnc = vnc_report.services[0]
        self.assertTrue(vnc.verified)
        self.assertIn("None", vnc.banner)

    def test_unverified_port_23_does_not_warn_about_telnet(self):
        report = self.scan(
            "GREETING_PORTS", b"unrecognized banner\n",
            wait_for_request=False, service_name="Telnet",
        )
        telnet = report.services[0]
        self.assertEqual(telnet.name, "Telnet")
        self.assertFalse(telnet.verified)
        self.assertFalse(any(f.severity == "warning" for f in report.findings))

    def test_progress_snapshots_carry_coverage(self):
        snapshots = []
        with patch("connectinator.advanced.ping_ttl", return_value=None):
            report = asyncio.run(advanced_scan(
                "127.0.0.1", 0.2, lambda: False, ports=(1,),
                on_update=snapshots.append,
            ))
        self.assertTrue(snapshots)
        snapshot = snapshots[-1]
        self.assertEqual(snapshot.completed_ports, 1)
        self.assertEqual(snapshot.checked_ports, (1,))
        self.assertTrue(snapshot.partial)
        self.assertEqual(report.completed_ports, 1)

    def test_cancel_returns_a_partial_report(self):
        with patch("connectinator.advanced.ping_ttl", return_value=None):
            report = asyncio.run(advanced_scan(
                "127.0.0.1", 0.2, lambda: True, ports=(1,),
            ))
        self.assertTrue(report.partial)
        self.assertFalse(report.reachable)

    def test_report_serializes_findings(self):
        report = AdvancedReport(
            "10.0.0.5",
            services=[Service(22, "SSH", True, "SSH-2.0")],
            findings=[Finding("Access", "Plaintext Telnet service reachable", "detail", 23, "warning")],
            fingerprint="TTL suggests a Windows host",
            ports_scanned=2,
        )
        data = report.to_dict()
        self.assertEqual(data["findings"][0]["severity"], "warning")
        self.assertEqual(data["services"][0]["port"], 22)
        self.assertEqual(data["ports_scanned"], 2)
        self.assertEqual(data["checked_ports"], [])
        self.assertEqual(data["completed_ports"], 0)


if __name__ == "__main__":
    unittest.main()
