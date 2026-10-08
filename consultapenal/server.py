"""Servidor HTTP local do painel (biblioteca padrão, somente leitura).

- escuta apenas em 127.0.0.1;
- cabeçalho Host restrito a 127.0.0.1/localhost na porta do servidor;
- apenas GET/HEAD; arquivos estáticos por lista fixa;
- CSP restritiva (sem script inline, sem recursos externos).

Rotas:
  /                 página do painel
  /api/painel       conteúdo do painel, lido de `dados/` a cada requisição
  /api/busca?q=...  busca no conteúdo cadastrado
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from consultapenal.conteudo import DADOS_DIR, ConteudoInvalido, buscar, carregar_acervo

HOST = "127.0.0.1"
STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
}

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class ConsultaPenalServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int = 8765, dados_dir: Path = DADOS_DIR):
        super().__init__((HOST, port), Handler)
        self.dados_dir = Path(dados_dir)
        self.quiet = False
        porta = self.server_address[1]
        self.allowed_hosts = {f"127.0.0.1:{porta}", f"localhost:{porta}"}

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}/"


class Handler(BaseHTTPRequestHandler):
    server: ConsultaPenalServer
    server_version = "ConsultaPenal"

    def version_string(self) -> str:
        return self.server_version

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def log_message(self, fmt, *args):
        if not self.server.quiet:
            print(f"[consultapenal] {self.command} {urlsplit(self.path).path} -> {args[1] if len(args) > 1 else ''}")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if self.headers.get("Host", "") not in self.server.allowed_hosts:
            self._send(403, "Host não permitido.".encode("utf-8"), "text/plain; charset=utf-8")
            return
        partes = urlsplit(self.path)
        if partes.path in STATIC_FILES:
            nome, tipo = STATIC_FILES[partes.path]
            self._send(200, (STATIC_DIR / nome).read_bytes(), tipo)
            return
        if partes.path in ("/api/painel", "/api/busca"):
            try:
                acervo = carregar_acervo(self.server.dados_dir)
            except ConteudoInvalido as exc:
                self._json(500, {"erro": f"Arquivo de dados inválido: {exc}"})
                return
            if partes.path == "/api/painel":
                self._json(200, acervo)
            else:
                consulta = parse_qs(partes.query).get("q", [""])[0]
                self._json(200, {"consulta": consulta, "resultados": buscar(acervo, consulta)})
            return
        self._send(404, "Página não encontrada.".encode("utf-8"), "text/plain; charset=utf-8")

    def _metodo_nao_permitido(self):
        self._send(405, "Método não permitido.".encode("utf-8"), "text/plain; charset=utf-8")

    do_POST = do_PUT = do_DELETE = do_PATCH = _metodo_nao_permitido
