import hashlib
import http.client
import json
import os
import socket
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import quote

from evidencelab.case import INTAKE_ACTION, run_case
from evidencelab.gui import server as gui_server
from evidencelab.gui.server import EvidenceLabServer, sanitize_filename
from evidencelab.gui.view import neutralize

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "samples" / "email_suspeito.eml"
STATIC = ROOT / "evidencelab" / "gui" / "static"


class GuiServerTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.server = EvidenceLabServer(self.tmp / "casos")
        self.server.quiet = True
        self.port = self.server.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        for root, _, files in os.walk(self.tmp):
            for name in files:
                os.chmod(Path(root) / name, stat.S_IRUSR | stat.S_IWUSR)
        self._tmp.cleanup()

    # ----- utilitários -----------------------------------------------------------
    def request(self, method, path, body=None, headers=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", host or f"127.0.0.1:{self.port}")
        for key, value in (headers or {}).items():
            conn.putheader(key, value)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        if body:
            conn.send(body)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def analyze(self, raw=None, filename="email_suspeito.eml", examiner="Analista", authserv="",
                extra=None, drop=()):
        raw = SAMPLE.read_bytes() if raw is None else raw
        headers = {
            "Origin": self.origin,
            "Content-Type": "application/octet-stream",
            "X-DEL-Token": self.server.token,
            "X-DEL-Filename": quote(filename),
            "X-DEL-Examiner": quote(examiner),
            "X-DEL-Authserv-Id": quote(authserv),
            "X-DEL-Client-SHA256": hashlib.sha256(raw).hexdigest(),
            **(extra or {}),
        }
        for key in drop:
            headers.pop(key)
        return self.request("POST", "/api/analyze", raw, headers)

    def case_dirs(self):
        root = self.tmp / "casos"
        return sorted(p.name for p in root.iterdir()) if root.exists() else []


class PageAndStaticTests(GuiServerTest):
    def test_page_requires_token(self):
        resp, _ = self.request("GET", "/")
        self.assertEqual(resp.status, 403)
        resp, body = self.request("GET", f"/?t={self.server.token}")
        self.assertEqual(resp.status, 200)
        self.assertIn(self.server.token.encode(), body)
        self.assertNotIn(gui_server.TOKEN_PLACEHOLDER.encode(), body)

    def test_security_headers(self):
        resp, _ = self.request("GET", f"/?t={self.server.token}")
        csp = resp.getheader("Content-Security-Policy")
        self.assertIn("default-src 'none'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.getheader("Referrer-Policy"), "no-referrer")
        self.assertEqual(resp.getheader("Server"), "EvidenceLab")

    def test_host_header_rejected_against_dns_rebinding(self):
        resp, _ = self.request("GET", f"/?t={self.server.token}", host="evil.example")
        self.assertEqual(resp.status, 403)
        resp, _ = self.request("GET", "/static/app.js", host=f"evil.example:{self.port}")
        self.assertEqual(resp.status, 403)

    def test_static_allowlist_and_traversal(self):
        resp, body = self.request("GET", "/static/app.js")
        self.assertEqual(resp.status, 200)
        self.assertTrue(resp.getheader("Content-Type").startswith("text/javascript"))
        for path in ("/static/../server.py", "/static/%2e%2e/server.py", "/static/index.html", "/../../etc/passwd"):
            self.assertEqual(self.request("GET", path)[0].status, 404, path)

    def test_unsupported_methods(self):
        for method in ("PUT", "DELETE", "OPTIONS", "PATCH"):
            self.assertEqual(self.request(method, "/api/analyze")[0].status, 405, method)

    def test_server_binds_only_loopback(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_frontend_never_writes_html(self):
        js = (STATIC / "app.js").read_text(encoding="utf-8")
        for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
                          "new Function", ".href = l", "window.open"):
            self.assertNotIn(forbidden, js, forbidden)
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        self.assertNotRegex(html, r"<script>(?!</script>)|<style>|\son[a-z]+=\"|https?://")


class AnalyzeTests(GuiServerTest):
    def test_analyze_sample_end_to_end(self):
        resp, body = self.analyze(examiner="Maria", authserv="mx.vitima.example")
        self.assertEqual(resp.status, 200, body)
        data = json.loads(body)
        self.assertEqual(data["sha256"], hashlib.sha256(SAMPLE.read_bytes()).hexdigest())
        self.assertTrue(data["integridade_ok"])
        self.assertEqual(data["nivel_suspeita"], "ALTO")
        self.assertTrue(data["autenticacao_selecionado"])
        events = data["cadeia_custodia"]["eventos"]
        self.assertEqual([e["action"] for e in events][:3], [INTAKE_ACTION, "Coleta", "Hash inicial"])
        self.assertEqual(events[0]["sha256"], data["sha256"])
        self.assertTrue(data["cadeia_custodia"]["encadeamento_integro"])
        self.assertEqual(set(data["avisos"]), {"heuristico", "hash", "autenticacao", "custodia"})
        self.assertNotIn("caminho", data)

        # Downloads dos relatórios do caso criado nesta sessão.
        for kind, ctype in (("json", "application/json"), ("md", "text/markdown")):
            resp, report = self.request("GET", f"/api/report/{data['caso']}/{kind}?t={self.server.token}")
            self.assertEqual(resp.status, 200)
            self.assertTrue(resp.getheader("Content-Type").startswith(ctype))
            self.assertIn("attachment", resp.getheader("Content-Disposition"))
            self.assertGreater(len(report), 100)

    def test_no_url_reaches_browser_intact(self):
        _, body = self.analyze()
        text = body.decode("utf-8")
        self.assertNotRegex(text, r"(?i)https?://")
        self.assertIn("hxxp://203[.]0[.]113[.]45", text)
        data = json.loads(body)
        self.assertTrue(all("url" not in link for link in data["links"]))

    def test_attachments_never_served_or_written(self):
        _, body = self.analyze()
        data = json.loads(body)
        case_dir = self.tmp / "casos" / data["caso"]
        files = sorted(p.relative_to(case_dir).as_posix() for p in case_dir.rglob("*") if p.is_file())
        self.assertEqual(files, [
            "cadeia_custodia.json", "evidencia/email_suspeito.eml", "recebido/email_suspeito.eml",
            "relatorio_email_suspeito.json", "relatorio_email_suspeito.md",
        ])
        self.assertTrue(all("download" not in key for att in data["anexos"] for key in att))

    def test_hostile_content_neutralized(self):
        raw = ("From: a@x.example\nMessage-ID: <1@x>\n"
               "Subject: =?UTF-8?Q?ol=1B[2J_<img_src=3Dx_onerror=3Dalert(1)>_=E2=80=AE?=\n\nhi\n").encode()
        resp, body = self.analyze(raw, filename="hostil.eml")
        self.assertEqual(resp.status, 200)
        subject = json.loads(body)["cabecalhos"]["Subject"]
        self.assertNotIn("\x1b", subject)
        self.assertNotIn("\u202e", subject)
        self.assertIn("\\x1b", subject)

    def test_neutralize_is_recursive(self):
        out = neutralize({"a": ["x\x1by", {"b": "https://e.example/p"}], "n": 3, "ok": True})
        self.assertEqual(out, {"a": ["x\\x1by", {"b": "hxxps://e[.]example/p"}], "n": 3, "ok": True})

    def test_no_outbound_connection_during_analysis(self):
        real_connect = socket.socket.connect
        targets = []

        def guarded(sock, address):
            targets.append(address)
            if address[0] != "127.0.0.1":
                raise AssertionError(f"conexão externa: {address}")
            return real_connect(sock, address)

        with mock.patch.object(socket.socket, "connect", guarded):
            resp, _ = self.analyze()
        self.assertEqual(resp.status, 200)
        self.assertTrue(targets and all(a[0] == "127.0.0.1" for a in targets))


class RejectionTests(GuiServerTest):
    def test_missing_or_wrong_token(self):
        self.assertEqual(self.analyze(drop=("X-DEL-Token",))[0].status, 403)
        self.assertEqual(self.analyze(extra={"X-DEL-Token": "x" * 43})[0].status, 403)
        self.assertEqual(self.case_dirs(), [])

    def test_origin_required_and_checked(self):
        self.assertEqual(self.analyze(drop=("Origin",))[0].status, 403)
        self.assertEqual(self.analyze(extra={"Origin": "http://evil.example"})[0].status, 403)
        self.assertEqual(self.analyze(extra={"Origin": "null"})[0].status, 403)
        self.assertEqual(self.case_dirs(), [])

    def test_client_hash_mismatch_discards_upload(self):
        resp, body = self.analyze(extra={"X-DEL-Client-SHA256": "0" * 64})
        self.assertEqual(resp.status, 400)
        self.assertIn("difere", json.loads(body)["erro"])
        self.assertEqual(self.case_dirs(), [])

    def test_oversized_body_rejected_before_reading(self):
        with mock.patch.object(gui_server, "MAX_EML_BYTES", 100):
            resp, _ = self.analyze()
        self.assertEqual(resp.status, 413)
        self.assertEqual(self.case_dirs(), [])

    def test_transfer_encoding_rejected(self):
        self.assertEqual(self.analyze(extra={"Transfer-Encoding": "chunked"})[0].status, 400)
        self.assertEqual(self.case_dirs(), [])

    def test_unexpected_error_returns_generic_500(self):
        with mock.patch.object(gui_server, "run_case", side_effect=RuntimeError("detalhe interno /x/y")):
            resp, body = self.analyze()
        self.assertEqual(resp.status, 500)
        self.assertNotIn(b"detalhe interno", body)

    def test_wrong_content_type_and_empty_body(self):
        self.assertEqual(self.analyze(extra={"Content-Type": "multipart/form-data"})[0].status, 415)
        self.assertEqual(self.analyze(raw=b"")[0].status, 400)

    def test_invalid_fields(self):
        self.assertEqual(self.analyze(filename="nota.txt")[0].status, 400)
        self.assertEqual(self.analyze(examiner="")[0].status, 400)
        self.assertEqual(self.analyze(examiner="a\x1bb")[0].status, 400)
        self.assertEqual(self.analyze(authserv="mx;evil")[0].status, 400)
        self.assertEqual(self.analyze(extra={"X-DEL-Filename": "%ff%fe.eml"})[0].status, 400)
        self.assertEqual(self.case_dirs(), [])

    def test_hostile_filename_stays_inside_cases_dir(self):
        resp, body = self.analyze(filename="../../../etc/passwd .eml")
        self.assertEqual(resp.status, 200)
        case = json.loads(body)["caso"]
        self.assertRegex(case, r"^passwd-\d{8}T\d{6}Z-[0-9a-f]{6}$")
        self.assertTrue((self.tmp / "casos" / case / "evidencia" / "passwd.eml").is_file())
        self.assertFalse((self.tmp / "etc").exists())

    def test_sanitize_filename(self):
        self.assertEqual(sanitize_filename("C:\\Users\\x\\fat ura (1).EML"), "fat_ura__1.eml")
        self.assertEqual(sanitize_filename("...eml"), "evidencia.eml")
        self.assertEqual(sanitize_filename("a" * 300 + ".eml"), "a" * 80 + ".eml")
        with self.assertRaises(gui_server.RequestError):
            sanitize_filename("x.eml.exe")

    def test_report_download_restrictions(self):
        _, body = self.analyze()
        case = json.loads(body)["caso"]
        token = self.server.token
        self.assertEqual(self.request("GET", f"/api/report/{case}/json")[0].status, 403)
        for path in (f"/api/report/outro-caso/json?t={token}", f"/api/report/{case}/exe?t={token}",
                     f"/api/report/..%2f..%2fetc/json?t={token}", f"/api/report/{case}/json/x?t={token}"):
            self.assertEqual(self.request("GET", path)[0].status, 404, path)


class IntakeNoteTests(unittest.TestCase):
    def test_run_case_without_intake_note_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_case(SAMPLE, Path(tmp) / "c")
            self.assertEqual([e.action for e in result.custody.events][:2], ["Coleta", "Hash inicial"])
            for p in Path(tmp).rglob("*"):
                if p.is_file():
                    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)

    def test_run_case_with_intake_note_records_first_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_case(SAMPLE, Path(tmp) / "c", intake_note="via teste", intake_sha256="ab" * 32)
            first = result.custody.events[0]
            self.assertEqual((first.action, first.details, first.sha256), (INTAKE_ACTION, "via teste", "ab" * 32))
            self.assertTrue(result.custody.verify_chain())
            for p in Path(tmp).rglob("*"):
                if p.is_file():
                    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)


if __name__ == "__main__":
    unittest.main()
