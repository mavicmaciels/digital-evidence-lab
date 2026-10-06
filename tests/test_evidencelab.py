import io
import json
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from evidencelab.case import CUSTODY_FILE, run_case, verify
from evidencelab.cli import main as cli_main
from evidencelab.custody import ChainOfCustody
from evidencelab.email_analysis import (
    analyze_email,
    parse_date,
    parse_received,
    registrable_domain,
)
from evidencelab.hashing import sha256_file, short_hash
from evidencelab.report import render_panel, to_markdown, write_reports
from evidencelab.sanitize import defang, md, safe



def main(argv):
    with redirect_stdout(io.StringIO()):
        return cli_main(argv)


SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "email_suspeito.eml"


def headers(*lines: str, body: str = "ola\n") -> bytes:
    return ("\n".join(lines) + "\n\n" + body).encode("utf-8")


BENIGN = headers(
    "From: TI <ti@empresa.example>",
    "Reply-To: chamados@helpdesk.example",
    "Return-Path: <bounce@envios.esp.example>",
    "To: <bruno@empresa.example>",
    "Subject: Sua senha expira na sexta",
    "Date: Tue, 06 Oct 2026 09:00:00 -0300",
    "Message-ID: <abc123@empresa.example>",
    "Received: from mail.empresa.example (mail.empresa.example [192.0.2.5])",
    "\tby mx.empresa.example with ESMTPS id 1; Tue, 06 Oct 2026 09:00:02 -0300",
    "Authentication-Results: mx.empresa.example; spf=pass; dkim=pass; dmarc=pass",
    "Content-Type: text/plain; charset=UTF-8",
    body="Lembrete: troque sua senha. Leia o artigo sobre o filme de suspense.\n"
    "https://intranet.empresa.example/senha\n",
)


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        for root, _, files in os.walk(self.tmp):
            for name in files:
                os.chmod(Path(root) / name, stat.S_IRUSR | stat.S_IWUSR)
        self._tmp.cleanup()

    def eml(self, raw: bytes, name: str = "m.eml") -> Path:
        path = self.tmp / name
        path.write_bytes(raw)
        return path


class HashingTests(TempDirTest):
    def test_sha256_known_value(self):
        path = self.eml(b"abc")
        self.assertEqual(
            sha256_file(path), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )

    def test_short_hash(self):
        self.assertEqual(short_hash("8e91c4a2" + "0" * 52 + "71fd"), "8e91c4a2...71fd")


class SanitizeTests(unittest.TestCase):
    def test_control_and_bidi_characters_escaped(self):
        self.assertEqual(safe("a\x1b[2Jb‮"), "a\\x1b[2Jb\\u202e")

    def test_defang(self):
        self.assertEqual(defang("https://evil.example/x.y"), "hxxps://evil[.]example/x.y")
        self.assertEqual(defang("evil.example"), "evil[.]example")

    def test_markdown_injection_neutralized(self):
        self.assertNotIn("<script>", md("<script>x</script> | [a](b)"))


class SampleAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.analysis = analyze_email(SAMPLE)
        cls.text = " | ".join(i.description for i in cls.analysis.indicators)

    def test_headers_decoded(self):
        self.assertEqual(self.analysis.headers["Subject"], "URGENTE: Sua conta será bloqueada em 24h")

    def test_received_hops_chronological_and_utc(self):
        hops = self.analysis.hops
        self.assertEqual([h.ip for h in hops], ["10.13.37.2", "203.0.113.45", "198.51.100.10"])
        self.assertTrue(all(h.timestamp.utcoffset().total_seconds() == 0 for h in hops))
        self.assertEqual(hops[1].timestamp.isoformat(), "2026-10-05T13:14:05+00:00")
        self.assertEqual(hops[1].raw_date, "Mon, 05 Oct 2026 10:14:05 -0300")

    def test_authentication_status(self):
        r = self.analysis.authentication.results
        self.assertEqual(self.analysis.authentication.authserv_id, "mx.vitima.example")
        self.assertEqual(
            {k: (v.result, v.status) for k, v in r.items()},
            {"spf": ("fail", "falha"), "dkim": ("none", "ausente"), "dmarc": ("fail", "falha")},
        )

    def test_attachment_hash_and_not_written(self):
        (att,) = self.analysis.attachments
        self.assertEqual(att.filename, "Comprovante_Bloqueio.pdf.exe")
        self.assertEqual(len(att.sha256), 64)

    def test_indicators(self):
        for expected in ("Reply-To", "endereço IP", "Texto do link", "executável com extensão dupla", "urgência"):
            self.assertIn(expected, self.text)
        self.assertEqual(self.analysis.suspicion_level, "ALTO")

    def test_urls_in_indicators_are_defanged(self):
        self.assertNotIn("http://", self.text)
        self.assertIn("hxxp://203[.]0[.]113[.]45", self.text)


class AuthenticationTests(TempDirTest):
    def auth(self, *ar_lines, trusted=None):
        raw = headers(*ar_lines, "From: a@x.example", "Message-ID: <1@x>")
        return analyze_email(self.eml(raw), trusted)

    def test_absent_header_is_informational_only(self):
        a = self.auth()
        self.assertEqual({r.status for r in a.authentication.results.values()}, {"ausente"})
        self.assertEqual([i.severity for i in a.indicators], ["info"])
        self.assertEqual(a.suspicion_level, "BAIXO")

    def test_none_is_absence_not_failure(self):
        a = self.auth("Authentication-Results: mx.example; spf=none; dkim=none; dmarc=none")
        self.assertTrue(all(i.severity == "info" for i in a.indicators))
        self.assertEqual(a.score, 0)

    def test_temperror_and_neutral_are_inconclusive(self):
        a = self.auth("Authentication-Results: mx.example; spf=temperror; dkim=neutral; dmarc=permerror")
        self.assertEqual({r.status for r in a.authentication.results.values()}, {"inconclusivo"})
        self.assertEqual(a.score, 0)

    def test_failures_are_scored(self):
        a = self.auth("Authentication-Results: mx.example; spf=softfail; dkim=fail; dmarc=fail")
        sev = {i.description.split(" ")[0]: i.severity for i in a.indicators}
        self.assertEqual(sev, {"SPF": "baixa", "DKIM": "média", "DMARC": "alta"})

    def test_comments_and_unrelated_keys_ignored(self):
        a = self.auth("Authentication-Results: mx.example; spf=pass (nota: dmarc=fail) x-dkim=fail")
        r = a.authentication.results
        self.assertEqual((r["spf"].result, r["dkim"].result, r["dmarc"].result), ("pass", None, None))

    def test_only_topmost_header_used_against_forgery(self):
        a = self.auth(
            "Authentication-Results: mx.real.example; spf=fail",
            "Authentication-Results: forjado.example; spf=pass; dkim=pass; dmarc=pass",
        )
        r = a.authentication.results
        self.assertEqual((r["spf"].result, r["dkim"].result), ("fail", None))
        self.assertEqual(a.authentication.headers_found, 2)

    def test_trusted_authserv_id(self):
        a = self.auth(
            "Authentication-Results: forjado.example; dmarc=pass",
            "Authentication-Results: mx.real.example; dmarc=fail",
            trusted="mx.real.example",
        )
        self.assertEqual(a.authentication.results["dmarc"].result, "fail")

    def test_multiple_dkim_signatures_any_pass(self):
        a = self.auth("Authentication-Results: mx.example; dkim=fail header.d=a; dkim=pass header.d=b")
        self.assertEqual(a.authentication.results["dkim"].result, "pass")


class FalsePositiveTests(TempDirTest):
    def test_benign_email_low_suspicion(self):
        a = analyze_email(self.eml(BENIGN))
        self.assertEqual(a.suspicion_level, "BAIXO", a.indicators)
        self.assertNotIn("urgência", " ".join(i.description for i in a.indicators))

    def test_registrable_domain_multilabel_suffix(self):
        self.assertEqual(registrable_domain("mail.banco.com.br"), "banco.com.br")
        self.assertNotEqual(registrable_domain("golpe.com.br"), registrable_domain("banco.com.br"))

    def test_subdomain_of_same_organization_not_flagged(self):
        raw = headers(
            "From: a@banco.com.br", "Reply-To: b@atendimento.banco.com.br", "Message-ID: <1@x>",
            "Content-Type: text/html",
            body='<a href="https://www.banco.com.br/x">https://banco.com.br/x</a>',
        )
        a = analyze_email(self.eml(raw))
        self.assertEqual([i for i in a.indicators if i.severity != "info"], [])


class RobustnessTests(TempDirTest):
    def test_naive_date_does_not_crash(self):
        raw = headers(
            "From: a@x.example", "Message-ID: <1@x>",
            "Date: Mon, 05 Oct 2026 10:00:00 -0000",
            "Received: from a by b; Mon, 05 Oct 2026 13:00:00 +0000",
        )
        a = analyze_email(self.eml(raw))
        self.assertIn("Diferença > 1h", " ".join(i.description for i in a.indicators))

    def test_parse_date_utc(self):
        self.assertEqual(parse_date("Mon, 05 Oct 2026 10:14:05 -0300").isoformat(), "2026-10-05T13:14:05+00:00")
        self.assertIsNone(parse_date("data inválida"))

    def test_malformed_url_does_not_crash(self):
        raw = headers("From: a@x.example", "Message-ID: <1@x>", body="veja http://[::1 agora\n")
        analyze_email(self.eml(raw))

    def test_parse_received_without_date_and_ipv6(self):
        (hop,) = parse_received(["from a.example ([IPv6:2001:db8::1]) by b.example with SMTP"])
        self.assertEqual((hop.by_host, hop.ip, hop.timestamp), ("b.example", "2001:db8::1", None))

    def test_nested_attachment_in_forwarded_message(self):
        raw = (
            b"From: a@x.example\nMessage-ID: <1@x>\nContent-Type: multipart/mixed; boundary=B\n\n"
            b"--B\nContent-Type: text/plain\n\nfwd\n--B\nContent-Type: message/rfc822\n\n"
            b"From: c@y.example\nContent-Type: multipart/mixed; boundary=C\n\n"
            b"--C\nContent-Type: text/plain\n\nx\n--C\nContent-Type: application/octet-stream\n"
            b'Content-Disposition: attachment; filename="fatura.exe"\n\nMZ\n--C--\n--B--\n'
        )
        a = analyze_email(self.eml(raw))
        self.assertEqual([att.filename for att in a.attachments], ["fatura.exe"])

    def test_bidi_filename_flagged(self):
        raw = (
            "From: a@x.example\nMessage-ID: <1@x>\nContent-Type: multipart/mixed; boundary=B\n\n"
            "--B\nContent-Type: application/octet-stream\n"
            'Content-Disposition: attachment; filename="fatura‮fdp.exe"\n\nMZ\n--B--\n'
        ).encode("utf-8")
        a = analyze_email(self.eml(raw))
        self.assertIn("bidirecional", " ".join(i.description for i in a.indicators))

    def test_dangerous_scheme(self):
        raw = headers("From: a@x.example", "Message-ID: <1@x>", "Content-Type: text/html",
                      body='<a href="javascript:alert(1)">abrir</a>')
        a = analyze_email(self.eml(raw))
        self.assertIn("esquema perigoso", " ".join(i.description for i in a.indicators))


class CaseWorkflowTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.source = self.tmp / "origem" / "email_suspeito.eml"
        self.source.parent.mkdir()
        shutil.copy2(SAMPLE, self.source)
        self.case_dir = self.tmp / "caso"

    def test_full_workflow_and_original_preserved(self):
        before = (sha256_file(self.source), self.source.stat().st_mtime_ns, self.source.stat().st_mode)
        result = run_case(self.source, self.case_dir, examiner="Perita")
        write_reports(result)
        after = (sha256_file(self.source), self.source.stat().st_mtime_ns, self.source.stat().st_mode)

        self.assertEqual(before, after)
        self.assertEqual(result.sha256, before[0])
        self.assertTrue(result.integrity_ok)
        self.assertFalse(result.evidence_path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        self.assertEqual(result.evidence_path.stat().st_mtime_ns, before[1])

        actions = [e.action for e in result.custody.events]
        self.assertEqual(actions, ["Coleta", "Hash inicial", "Análise", "Verificação de integridade", "Relatório"])
        self.assertTrue(result.custody.verify_chain())
        self.assertTrue(all(e.timestamp.endswith("+00:00") for e in result.custody.events))

        panel = render_panel(result)
        self.assertIn("● VERIFICADA", panel)
        self.assertIn(short_hash(result.sha256), panel)
        self.assertIn("Não comprova a autenticidade", panel)

    def test_case_dir_contains_no_extracted_attachment(self):
        write_reports(run_case(self.source, self.case_dir))
        files = sorted(p.relative_to(self.case_dir).as_posix() for p in self.case_dir.rglob("*") if p.is_file())
        self.assertEqual(files, [
            "cadeia_custodia.json", "evidencia/email_suspeito.eml",
            "relatorio_email_suspeito.json", "relatorio_email_suspeito.md",
        ])

    def test_no_network_or_process_execution(self):
        blocked = mock.Mock(side_effect=AssertionError("acesso proibido"))
        with mock.patch.object(socket.socket, "connect", blocked), \
             mock.patch.object(socket, "create_connection", blocked), \
             mock.patch.object(subprocess, "Popen", blocked), \
             mock.patch.object(os, "system", blocked):
            write_reports(run_case(self.source, self.case_dir))
        blocked.assert_not_called()

    def test_refuses_to_reacquire(self):
        run_case(self.source, self.case_dir)
        with self.assertRaises(FileExistsError):
            run_case(self.source, self.case_dir)

    def test_second_evidence_does_not_overwrite_custody(self):
        run_case(self.source, self.case_dir)
        other = self.eml(b"From: a@x.example\n\nhi\n", "outro.eml")
        with self.assertRaises(FileExistsError):
            run_case(other, self.case_dir)
        self.assertEqual(ChainOfCustody.load(self.case_dir / CUSTODY_FILE).evidence, "email_suspeito.eml")

    def test_verify_detects_evidence_tampering(self):
        result = run_case(self.source, self.case_dir)
        write_reports(result)
        self.assertEqual(main(["verify", str(self.case_dir)]), 0)

        os.chmod(result.evidence_path, stat.S_IRUSR | stat.S_IWUSR)
        with open(result.evidence_path, "ab") as fh:
            fh.write(b"\nadulterado")
        self.assertFalse(verify(result.evidence_path, result.sha256))
        self.assertEqual(main(["verify", str(self.case_dir)]), 1)

    def test_verify_detects_custody_log_tampering(self):
        write_reports(run_case(self.source, self.case_dir))
        path = self.case_dir / CUSTODY_FILE
        data = json.loads(path.read_text(encoding="utf-8"))
        data["events"][0]["examiner"] = "outra pessoa"
        path.write_text(json.dumps(data), encoding="utf-8")
        self.assertFalse(ChainOfCustody.load(path).verify_chain())
        self.assertEqual(main(["verify", str(self.case_dir)]), 1)

    def test_terminal_and_markdown_escape_hostile_content(self):
        raw = "From: a@x.example\nMessage-ID: <1@x>\nSubject: =?UTF-8?Q?ol=1B[2J_<img_src=3Dx>?=\n\nhi\n"
        src = self.eml(raw.encode(), "hostil.eml")
        result = run_case(src, self.tmp / "caso2")
        self.assertNotIn("\x1b", render_panel(result) + to_markdown(result))
        self.assertNotRegex(to_markdown(result), r"(?<!\\)<img")


if __name__ == "__main__":
    unittest.main()
