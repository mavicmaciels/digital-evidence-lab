"""Servidor HTTP local da interface (biblioteca padrão).

Superfície exposta e controles:
- escuta apenas em 127.0.0.1 (não há opção para outro endereço);
- cabeçalho Host restrito a 127.0.0.1/localhost na porta do servidor (anti DNS rebinding);
- token aleatório por sessão exigido na página, na API e nos downloads;
- POST exige Origin igual ao do próprio servidor e cabeçalho X-DEL-Token (o que força
  preflight CORS, nunca respondido) — bloqueia CSRF a partir de outros sites;
- CSP restritiva (sem script inline, sem recursos externos) e cabeçalhos de segurança;
- arquivos estáticos por lista fixa; relatórios só de casos criados nesta sessão;
- corpo limitado ao tamanho máximo de .eml, lido por Content-Length exato.

A análise é feita pelo motor existente (`run_case` + `write_reports`). Nenhuma URL do
e-mail é acessada e nenhum anexo é gravado ou servido.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
import unicodedata
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from evidencelab.case import IntegrityError, run_case
from evidencelab.email_analysis import MAX_EML_BYTES
from evidencelab.gui.view import build_view
from evidencelab.report import write_reports
from evidencelab.sanitize import safe

HOST = "127.0.0.1"
STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_FILES = {
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
TOKEN_PLACEHOLDER = "__DEL_SESSION_TOKEN__"
INTAKE_DIR = "recebido"

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), clipboard-read=()",
}

SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")
CASE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,160}$")
AUTHSERV_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_EXAMINER = 120


class RequestError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def sanitize_filename(raw: str) -> str:
    """Reduz o nome informado pelo navegador a um nome seguro terminado em .eml."""
    name = unicodedata.normalize("NFKC", raw).replace("\\", "/").split("/")[-1].strip()
    if not name.lower().endswith(".eml"):
        raise RequestError(400, "Selecione um arquivo com extensão .eml.")
    stem = SAFE_NAME_RE.sub("_", name[:-4]).strip("._") or "evidencia"
    return stem[:80] + ".eml"


def _header_text(value: str | None, limit: int) -> str:
    text = unquote(value or "", errors="strict").strip()
    if len(text) > limit or any(not ch.isprintable() for ch in text):
        raise RequestError(400, "Campo de texto inválido.")
    return text


class EvidenceLabServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, cases_root: Path, port: int = 0, token: str | None = None):
        super().__init__((HOST, port), Handler)
        self.cases_root = Path(cases_root)
        self.token = token or secrets.token_urlsafe(32)
        self.cases: dict[str, Path] = {}
        self.lock = threading.Lock()
        self.quiet = False
        port = self.server_address[1]
        self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        self.allowed_origins = {f"http://{h}" for h in self.allowed_hosts}

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}/?t={self.token}"


class Handler(BaseHTTPRequestHandler):
    server: EvidenceLabServer
    server_version = "EvidenceLab"

    def version_string(self) -> str:  # sem versão do Python no cabeçalho Server
        return self.server_version
    timeout = 60  # evita conexões ociosas presas indefinidamente

    # ----- respostas -----------------------------------------------------------
    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in {**SECURITY_HEADERS, **(extra or {})}.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        if self.path.startswith("/api/"):
            self._json(status, {"erro": safe(message)})
        else:
            self._send(status, safe(message).encode("utf-8"), "text/plain; charset=utf-8")

    def log_message(self, fmt, *args):  # sem token nem query string nos logs
        if self.server.quiet:
            return
        path = urlsplit(self.path).path
        print(f"[evidencelab.gui] {self.command} {safe(path)} -> {args[1] if len(args) > 1 else ''}")

    # ----- verificações ----------------------------------------------------------
    def _check_host(self) -> None:
        if self.headers.get("Host", "") not in self.server.allowed_hosts:
            raise RequestError(403, "Host não permitido.")

    def _check_token(self, presented: str | None) -> None:
        if not presented or not hmac.compare_digest(presented.encode(), self.server.token.encode()):
            raise RequestError(403, "Token de sessão ausente ou inválido. Use o endereço exibido no terminal.")

    def _query_token(self) -> str | None:
        values = parse_qs(urlsplit(self.path).query).get("t")
        return values[0] if values else None

    # ----- métodos -----------------------------------------------------------------
    def do_GET(self):
        try:
            self._check_host()
            path = urlsplit(self.path).path
            if path == "/":
                self._check_token(self._query_token())
                html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
                self._send(200, html.replace(TOKEN_PLACEHOLDER, self.server.token).encode("utf-8"),
                           "text/html; charset=utf-8")
            elif path == "/favicon.ico":
                self._send(204, b"", "image/x-icon")
            elif path in STATIC_FILES:
                name, ctype = STATIC_FILES[path]
                self._send(200, (STATIC_DIR / name).read_bytes(), ctype)
            elif path.startswith("/api/report/"):
                self._check_token(self._query_token())
                self._download(path)
            else:
                raise RequestError(404, "Não encontrado.")
        except RequestError as exc:
            self._error(exc.status, str(exc))

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        try:
            self._check_host()
            if urlsplit(self.path).path != "/api/analyze":
                raise RequestError(404, "Não encontrado.")
            if self.headers.get("Origin") not in self.server.allowed_origins:
                raise RequestError(403, "Origem não permitida.")
            self._check_token(self.headers.get("X-DEL-Token"))
            self._json(200, self._analyze())
        except RequestError as exc:
            self.close_connection = True  # corpo possivelmente não lido: não reutilizar a conexão
            self._error(exc.status, str(exc))
        except Exception:  # falha inesperada: resposta genérica, sem detalhes internos
            self.close_connection = True
            self._error(500, "Erro interno ao processar a evidência.")

    def _method_not_allowed(self):
        self._error(405, "Método não permitido.")

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _method_not_allowed

    # ----- operações -------------------------------------------------------------
    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding"):  # só Content-Length exato; evita ambiguidade de corpo
            raise RequestError(400, "Transfer-Encoding não suportado.")
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/octet-stream":
            raise RequestError(415, "Envie o arquivo como application/octet-stream.")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise RequestError(411, "Content-Length obrigatório.") from None
        if length <= 0:
            raise RequestError(400, "Arquivo vazio.")
        if length > MAX_EML_BYTES:
            self.close_connection = True  # não lê o corpo excedente
            raise RequestError(413, f"Arquivo excede o limite de {MAX_EML_BYTES} bytes.")
        body = self.rfile.read(length)
        if len(body) != length:
            raise RequestError(400, "Corpo da requisição incompleto.")
        return body

    def _analyze(self) -> dict:
        try:
            original_name = _header_text(self.headers.get("X-DEL-Filename"), 255)
            examiner = _header_text(self.headers.get("X-DEL-Examiner"), MAX_EXAMINER)
            authserv = _header_text(self.headers.get("X-DEL-Authserv-Id"), 253) or None
        except UnicodeDecodeError:
            raise RequestError(400, "Campo de texto inválido.") from None
        if not examiner:
            raise RequestError(400, "Informe o examinador.")
        if authserv and not AUTHSERV_RE.match(authserv):
            raise RequestError(400, "authserv-id inválido: use apenas letras, números, '.', '-' e '_'.")
        client_hash = (self.headers.get("X-DEL-Client-SHA256") or "").lower()
        if not SHA256_RE.match(client_hash):
            raise RequestError(400, "SHA-256 calculado no navegador ausente ou inválido.")
        name = sanitize_filename(original_name)

        body = self._read_body()
        server_hash = hashlib.sha256(body).hexdigest()
        if not hmac.compare_digest(server_hash, client_hash):
            raise RequestError(400, "O SHA-256 recebido difere do calculado no navegador; transferência descartada.")

        with self.server.lock:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            case_id = f"{name[:-4]}-{stamp}-{secrets.token_hex(3)}"
            case_dir = self.server.cases_root / case_id
            intake = case_dir / INTAKE_DIR / name
            intake.parent.mkdir(parents=True)
            with open(intake, "xb") as fh:
                fh.write(body)
            os.chmod(intake, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            note = (
                f"Recebido pela interface local (127.0.0.1). Nome informado pelo navegador: "
                f"{original_name}; {len(body)} bytes; SHA-256 calculado no navegador e no "
                "servidor coincidem. O caminho original não é conhecido pela ferramenta."
            )
            try:
                result = run_case(intake, case_dir, examiner=examiner, trusted_authserv_id=authserv,
                                  intake_note=note, intake_sha256=server_hash)
                write_reports(result)
            except (IntegrityError, ValueError, OSError) as exc:
                raise RequestError(422, f"Falha na análise: {exc}") from None
            self.server.cases[case_id] = case_dir
        return build_view(result, case_id)

    def _download(self, path: str) -> None:
        parts = path.split("/")  # ["", "api", "report", case_id, kind]
        if len(parts) != 5 or not CASE_ID_RE.match(parts[3]) or parts[4] not in {"json", "md"}:
            raise RequestError(404, "Relatório não encontrado.")
        case_dir = self.server.cases.get(parts[3])
        if case_dir is None:
            raise RequestError(404, "Relatório não encontrado.")
        reports = sorted(case_dir.glob(f"relatorio_*.{parts[4]}"))
        if len(reports) != 1:
            raise RequestError(404, "Relatório não encontrado.")
        ctype = "application/json; charset=utf-8" if parts[4] == "json" else "text/markdown; charset=utf-8"
        filename = f"{parts[3]}_{reports[0].name}"
        self._send(200, reports[0].read_bytes(), ctype,
                   {"Content-Disposition": f'attachment; filename="{filename}"'})
