import os
import stat
import tempfile
import unittest
from pathlib import Path

from evidencelab.case import IntegrityError, run_case, verify
from evidencelab.cli import main
from evidencelab.email_analysis import analyze_email, parse_received
from evidencelab.hashing import sha256_file, short_hash
from evidencelab.report import render_panel, write_reports

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "email_suspeito.eml"

BENIGN = b"""From: Ana <ana@empresa.example>
To: <bruno@empresa.example>
Subject: Ata da reuniao
Date: Tue, 06 Oct 2026 09:00:00 -0300
Message-ID: <abc123@empresa.example>
Received: from mail.empresa.example (mail.empresa.example [192.0.2.5])
\tby mx.empresa.example with ESMTPS id 1; Tue, 06 Oct 2026 09:00:02 -0300
Authentication-Results: mx.empresa.example; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset="UTF-8"

Segue a ata: https://intranet.empresa.example/atas/42
"""


class HashingTests(unittest.TestCase):
    def test_short_hash(self):
        self.assertEqual(short_hash("8e91c4a2" + "0" * 52 + "71fd"), "8e91c4a2...71fd")


class EmailAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.analysis = analyze_email(SAMPLE)
        self.descriptions = " | ".join(i.description for i in self.analysis.indicators)

    def test_headers(self):
        h = self.analysis.headers
        self.assertIn("banco-seguro.example", h["From"])
        self.assertEqual(h["Subject"], "URGENTE: Sua conta será bloqueada em 24h")

    def test_received_hops_in_chronological_order(self):
        hops = self.analysis.hops
        self.assertEqual(len(hops), 3)
        self.assertEqual(hops[1].ip, "203.0.113.45")
        self.assertEqual(hops[-1].by_host, "mail.vitima.example")
        stamps = [h.timestamp for h in hops]
        self.assertEqual(stamps, sorted(stamps))

    def test_authentication_results(self):
        self.assertEqual(
            self.analysis.authentication, {"spf": "fail", "dkim": "none", "dmarc": "fail"}
        )

    def test_attachment_hashed(self):
        (att,) = self.analysis.attachments
        self.assertEqual(att.filename, "Comprovante_Bloqueio.pdf.exe")
        self.assertEqual(len(att.sha256), 64)

    def test_phishing_indicators(self):
        for expected in ("Reply-To", "endereço IP", "Texto do link", "Extensão dupla", "urgência"):
            self.assertIn(expected, self.descriptions)
        self.assertEqual(self.analysis.risk_level, "ALTO")

    def test_benign_email_is_low_risk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ok.eml"
            path.write_bytes(BENIGN)
            analysis = analyze_email(path)
        self.assertEqual(analysis.indicators, [])
        self.assertEqual(analysis.risk_level, "BAIXO")

    def test_parse_received_without_date(self):
        (hop,) = parse_received(["from a.example ([192.0.2.1]) by b.example with SMTP"])
        self.assertEqual((hop.by_host, hop.ip, hop.timestamp), ("b.example", "192.0.2.1", None))


class CaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.case_dir = Path(self.tmp.name) / "caso"

    def tearDown(self):
        for root, _, files in os.walk(self.tmp.name):
            for name in files:
                os.chmod(Path(root) / name, stat.S_IWUSR | stat.S_IRUSR)
        self.tmp.cleanup()

    def test_full_workflow(self):
        result = run_case(SAMPLE, self.case_dir, examiner="Perita")
        self.assertEqual(result.sha256, sha256_file(SAMPLE))
        self.assertTrue(result.integrity_ok)
        self.assertEqual(len(result.steps), 5)
        self.assertFalse(result.evidence_path.stat().st_mode & stat.S_IWUSR)

        paths = write_reports(result)
        self.assertTrue(all(p.is_file() for p in paths))
        actions = [e.action for e in result.custody.events]
        self.assertEqual(actions[0], "Coleta")
        self.assertEqual(actions[-1], "Relatório")

        panel = render_panel(result)
        self.assertIn("● VERIFICADA", panel)
        self.assertIn(short_hash(result.sha256), panel)

    def test_refuses_to_reacquire(self):
        run_case(SAMPLE, self.case_dir)
        with self.assertRaises(FileExistsError):
            run_case(SAMPLE, self.case_dir)

    def test_verify_detects_tampering(self):
        result = run_case(SAMPLE, self.case_dir)
        write_reports(result)
        self.assertEqual(main(["verify", str(self.case_dir)]), 0)

        os.chmod(result.evidence_path, stat.S_IWUSR | stat.S_IRUSR)
        with open(result.evidence_path, "ab") as fh:
            fh.write(b"\nadulterado")
        self.assertFalse(verify(result.evidence_path, result.sha256))
        self.assertEqual(main(["verify", str(self.case_dir)]), 1)


if __name__ == "__main__":
    unittest.main()
