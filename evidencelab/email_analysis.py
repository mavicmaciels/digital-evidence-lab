"""Extração de metadados e indicadores heurísticos de um e-mail (.eml).

Segurança: este módulo apenas lê e interpreta bytes. Nenhum anexo é gravado em
disco ou executado e nenhuma URL é acessada; links são tratados como texto.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

from evidencelab.hashing import sha256_bytes
from evidencelab.sanitize import defang

MAX_EML_BYTES = 50 * 1024 * 1024

KEY_HEADERS = (
    "From",
    "Sender",
    "Reply-To",
    "Return-Path",
    "To",
    "Cc",
    "Subject",
    "Date",
    "Message-ID",
    "X-Mailer",
    "User-Agent",
    "X-Originating-IP",
)

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs", ".vbe",
    ".wsf", ".wsh", ".hta", ".msi", ".ps1", ".jar", ".lnk", ".dll", ".cpl",
}
CONTAINER_EXTENSIONS = {".iso", ".img", ".vhd", ".vhdx"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}
URGENCY_PATTERNS = (
    r"\burgente\b", r"\bimediatamente\b", r"\bbloquead[ao]s?\b", r"\bsuspens[ao]s?\b",
    r"\b24\s*(?:h|horas)\b", r"confirme seus dados", r"verifique sua conta",
    r"\burgent\b", r"\bimmediately\b", r"\bsuspended\b", r"verify your account",
)
URGENCY_RE = [re.compile(p, re.IGNORECASE) for p in URGENCY_PATTERNS]

# Sufixos públicos de dois rótulos mais comuns. Não substitui a Public Suffix List.
MULTI_LABEL_SUFFIXES = {
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "jus.br", "mil.br", "art.br",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "co.jp",
    "com.ar", "com.mx", "co.nz", "com.pt", "co.za", "com.cn", "com.tr", "co.in",
}

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
RECEIVED_RE = re.compile(
    r"^\s*(?:from\s+(?P<from>.+?))?\s*\bby\s+(?P<by>\S+)(?:.*?\bwith\s+(?P<with>\S+))?",
    re.IGNORECASE | re.DOTALL,
)
IPV4_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
IPV6_RE = re.compile(r"\[(?:IPv6:)?([0-9a-f:.]*:[0-9a-f:.]*)\]", re.IGNORECASE)
RESINFO_RE = re.compile(r"^([a-z0-9_-]+)(?:/\d+)?\s*=\s*([a-z]+)", re.IGNORECASE)

AUTH_MECHANISMS = ("spf", "dkim", "dmarc")
# Classificação dos resultados declarados (RFC 8601 / RFC 7208 / RFC 6376 / RFC 7489).
# "pass" é apenas o resultado declarado: não significa que o e-mail seja legítimo.
NOT_EVALUATED = "não avaliado"  # nenhum Authentication-Results selecionado
AUTH_STATUS = {
    None: "ausente",  # nenhum resultado registrado para o mecanismo
    "none": "ausente",  # sem registro SPF / mensagem sem assinatura DKIM / sem política DMARC
    "pass": "pass declarado",
    "fail": "falha",
    "softfail": "falha fraca",
    "neutral": "inconclusivo",
    "policy": "inconclusivo",
    "temperror": "inconclusivo",
    "permerror": "inconclusivo",
}

BIDI_CONTROLS = {chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A), 0x200E, 0x200F)}

SEVERITY_WEIGHT = {"alta": 3, "média": 2, "baixa": 1, "info": 0}


class EmailTooLargeError(ValueError):
    pass


@dataclass
class ReceivedHop:
    index: int
    from_host: str
    by_host: str
    protocol: str
    ip: str
    raw_date: str
    timestamp: datetime | None  # sempre em UTC


@dataclass
class AuthResult:
    mechanism: str
    result: str | None  # valor bruto declarado no cabeçalho selecionado, ou None
    status: str  # pass declarado / falha / falha fraca / inconclusivo / ausente / não avaliado


@dataclass
class AuthHeader:
    """Um cabeçalho Authentication-Results tal como declarado (posição 1 = topo)."""

    position: int
    authserv_id: str
    declared: dict[str, list[str]]
    selected: bool = False


@dataclass
class Authentication:
    requested_authserv_id: str | None  # informado pelo analista via --authserv-id
    authserv_id: str  # authserv-id do cabeçalho selecionado; "" se nenhum foi selecionado
    headers: list[AuthHeader]
    results: dict[str, AuthResult]
    duplicates_of_selected: int = 0  # outros cabeçalhos com o mesmo authserv-id

    @property
    def headers_found(self) -> int:
        return len(self.headers)

    @property
    def selected(self) -> bool:
        return bool(self.authserv_id)


@dataclass
class Link:
    url: str
    text: str = ""
    source: str = "text"


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class Indicator:
    severity: str  # "alta", "média", "baixa" ou "info" (informativo, não pontua)
    description: str


@dataclass
class EmailAnalysis:
    headers: dict[str, str]
    date: datetime | None
    hops: list[ReceivedHop]
    authentication: Authentication
    links: list[Link]
    attachments: list[Attachment]
    parse_defects: list[str] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(SEVERITY_WEIGHT[i.severity] for i in self.indicators)

    @property
    def suspicion_level(self) -> str:
        """Nível heurístico de suspeita. Não é prova de fraude nem de legitimidade."""
        if self.score >= 6:
            return "ALTO"
        if self.score >= 3:
            return "MÉDIO"
        return "BAIXO"


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            text = " ".join("".join(self._text).split())
            self.links.append(Link(url=self._href.strip(), text=text, source="html"))
            self._href = None


def load_message(path: Path) -> EmailMessage:
    size = path.stat().st_size
    if size > MAX_EML_BYTES:
        raise EmailTooLargeError(f"Arquivo com {size} bytes excede o limite de {MAX_EML_BYTES}")
    with open(path, "rb") as fh:
        return BytesParser(policy=policy.default).parse(fh)


def parse_date(value: str | None) -> datetime | None:
    """Converte uma data RFC 5322 para UTC. Datas sem fuso (-0000) são tratadas como UTC."""
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _header(msg: EmailMessage, name: str) -> str | None:
    try:
        value = msg[name]
    except Exception:  # cabeçalhos malformados não devem interromper a análise
        values = [v for k, v in msg.raw_items() if k.lower() == name.lower()]
        return str(values[0]) if values else None
    return None if value is None else str(value)


def _all_headers(msg: EmailMessage, name: str) -> list[str]:
    return [str(v) for k, v in msg.raw_items() if k.lower() == name.lower()]


def _domain(address: str) -> str:
    _, addr = parseaddr(address or "")
    return addr.rpartition("@")[2].lower().strip("<> .")


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def registrable_domain(domain: str) -> str:
    """Aproximação do domínio registrável (eTLD+1) sem a Public Suffix List completa."""
    parts = [p for p in domain.lower().strip(".").split(".") if p]
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def parse_received(values: list[str]) -> list[ReceivedHop]:
    """Converte os cabeçalhos Received (topo = mais recente) em saltos cronológicos."""
    hops = []
    for index, raw in enumerate(reversed(values), start=1):
        flat = " ".join(str(raw).split())
        route, sep, date_part = flat.rpartition(";")
        if not sep:
            route, date_part = flat, ""
        from_host = by_host = protocol = from_clause = ""
        match = RECEIVED_RE.search(route)
        if match:
            from_clause = match.group("from") or ""
            from_host = from_clause.split(" ")[0]
            by_host = match.group("by") or ""
            protocol = match.group("with") or ""
        ip = IPV4_RE.search(from_clause) or IPV6_RE.search(from_clause)
        hops.append(
            ReceivedHop(
                index=index,
                from_host=from_host,
                by_host=by_host,
                protocol=protocol,
                ip=ip.group(1) if ip else "",
                raw_date=date_part.strip(),
                timestamp=parse_date(date_part.strip()),
            )
        )
    return hops


def _strip_comments(value: str) -> str:
    previous = None
    while previous != value:
        previous = value
        value = re.sub(r"\([^()]*\)", " ", value)
    return value


def _parse_authentication_results(value: str) -> tuple[str, dict[str, list[str]]]:
    """Interpreta um cabeçalho Authentication-Results (RFC 8601), ignorando comentários."""
    clean = " ".join(_strip_comments(value).split())
    parts = [p.strip() for p in clean.split(";")]
    authserv_id = parts[0].split(" ")[0].lower() if parts and parts[0] else ""
    results: dict[str, list[str]] = {}
    for resinfo in parts[1:]:
        match = RESINFO_RE.match(resinfo)
        if match and match.group(1).lower() in AUTH_MECHANISMS:
            results.setdefault(match.group(1).lower(), []).append(match.group(2).lower())
    return authserv_id, results


def parse_authentication(msg: EmailMessage, trusted_authserv_id: str | None = None) -> Authentication:
    """Lê os cabeçalhos Authentication-Results e seleciona, se pedido, o de um authserv-id.

    O RFC 8601 alerta que esses cabeçalhos podem ser inseridos por qualquer
    participante do envio, inclusive o remetente, e que o consumidor precisa saber
    quais serviços de autenticação são confiáveis. A ferramenta não consegue
    estabelecer isso sozinha. A posição do cabeçalho não prova sua origem.

    - Sem `trusted_authserv_id`: todos os cabeçalhos são listados como declarados,
      nenhum é selecionado e os mecanismos ficam "não avaliado".
    - Com `trusted_authserv_id`: é selecionado o cabeçalho mais alto com esse
      authserv-id. A confiança nesse serviço é decisão do analista, com base externa.

    Em nenhum caso SPF/DKIM/DMARC são revalidados aqui.
    """
    headers = []
    for position, value in enumerate(_all_headers(msg, "Authentication-Results"), start=1):
        authserv_id, declared = _parse_authentication_results(value)
        headers.append(AuthHeader(position, authserv_id, declared))

    wanted = trusted_authserv_id.strip().lower() if trusted_authserv_id else None
    matching = [h for h in headers if wanted and h.authserv_id == wanted]
    chosen = matching[0] if matching else None
    if chosen:
        chosen.selected = True

    results = {}
    for mech in AUTH_MECHANISMS:
        if chosen is None:
            results[mech] = AuthResult(mech, None, NOT_EVALUATED)
            continue
        found = chosen.declared.get(mech, [])
        # Várias assinaturas DKIM: basta uma declarada como "pass" para o agregado ser "pass".
        result = "pass" if "pass" in found else (found[0] if found else None)
        results[mech] = AuthResult(mech, result, AUTH_STATUS.get(result, "inconclusivo"))
    return Authentication(
        requested_authserv_id=wanted,
        authserv_id=chosen.authserv_id if chosen else "",
        headers=headers,
        results=results,
        duplicates_of_selected=max(len(matching) - 1, 0),
    )


def _decoded_text(part: EmailMessage) -> str:
    try:
        content = part.get_content()
        return content if isinstance(content, str) else ""
    except Exception:  # charset desconhecido ou conteúdo malformado
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def _is_attachment(part: EmailMessage) -> bool:
    if part.is_multipart() or part.get_content_type() == "message/rfc822":
        return False
    return part.get_content_disposition() == "attachment" or bool(part.get_filename())


def extract_links(msg: EmailMessage) -> list[Link]:
    links: list[Link] = []
    seen: set[tuple[str, str]] = set()
    for part in msg.walk():
        if part.is_multipart() or _is_attachment(part):
            continue
        ctype = part.get_content_type()
        if ctype == "text/html":
            parser = _AnchorParser()
            try:
                parser.feed(_decoded_text(part))
                parser.close()
            except Exception:
                pass
            found = parser.links
        elif ctype == "text/plain":
            found = [Link(url=u.rstrip(".,;)")) for u in URL_RE.findall(_decoded_text(part))]
        else:
            continue
        for link in found:
            key = (link.url, link.source)
            if key not in seen:
                seen.add(key)
                links.append(link)
    return links


def extract_attachments(msg: EmailMessage) -> list[Attachment]:
    """Lista anexos (inclusive dentro de mensagens encaminhadas) e calcula o SHA-256
    do conteúdo decodificado. O conteúdo permanece em memória e nunca é gravado."""
    attachments = []
    for part in msg.walk():
        if not _is_attachment(part):
            continue
        payload = part.get_payload(decode=True) or b""
        attachments.append(
            Attachment(
                filename=part.get_filename() or "(sem nome)",
                content_type=part.get_content_type(),
                size=len(payload),
                sha256=sha256_bytes(payload),
            )
        )
    return attachments


def _body_text(msg: EmailMessage) -> str:
    chunks = [_header(msg, "Subject") or ""]
    for part in msg.walk():
        if part.get_content_maintype() == "text" and not _is_attachment(part):
            chunks.append(_decoded_text(part))
    return "\n".join(chunks)


def _auth_indicators(auth: Authentication) -> list[Indicator]:
    """Só resultados do cabeçalho selecionado pelo analista pontuam. "pass" nunca reduz
    a pontuação: um resultado declarado como aprovado não torna o e-mail legítimo."""
    ids = sorted({h.authserv_id or "(vazio)" for h in auth.headers})
    if not auth.headers:
        return [Indicator("info", "Sem cabeçalho Authentication-Results: SPF/DKIM/DMARC não avaliados")]
    if auth.requested_authserv_id is None:
        return [Indicator("info", f"{len(auth.headers)} Authentication-Results presente(s) (authserv-id: "
                                  f"{', '.join(ids)}), nenhum selecionado como confiável: resultados "
                                  "apenas listados, não pontuados (use --authserv-id)")]
    if not auth.selected:
        return [Indicator("info", f"Nenhum Authentication-Results com o authserv-id selecionado "
                                  f"({auth.requested_authserv_id}); encontrados: {', '.join(ids)}")]

    found = []
    source = f"declarado no Authentication-Results selecionado, authserv-id {auth.authserv_id}"
    others = sorted({h.authserv_id or "(vazio)" for h in auth.headers if h.authserv_id != auth.authserv_id})
    if others:
        found.append(Indicator("info", f"Authentication-Results de outro(s) authserv-id ignorado(s): {', '.join(others)}"))
    if auth.duplicates_of_selected:
        found.append(Indicator("info", f"{auth.duplicates_of_selected} cabeçalho(s) adicional(is) com o mesmo "
                                       "authserv-id; usado o mais alto. Possível falsificação ou falta de "
                                       "remoção pelo servidor de borda"))
    for mech, res in auth.results.items():
        name = mech.upper()
        if res.status == "falha":
            sev = "alta" if mech == "dmarc" else "média"
            found.append(Indicator(sev, f"{name} = fail ({source}); indício, não prova: "
                                        "encaminhamentos e listas podem causar falha legítima"))
        elif res.status == "falha fraca":
            found.append(Indicator("baixa", f"{name} = softfail ({source})"))
        elif res.status == "inconclusivo":
            found.append(Indicator("info", f"{name} = {res.result}: resultado inconclusivo ({source})"))
        elif res.status == "ausente":
            detail = f"= {res.result}" if res.result else "sem resultado declarado"
            found.append(Indicator("info", f"{name} {detail}: ausência não é prova de fraude"))
    return found


def find_indicators(analysis: EmailAnalysis, msg: EmailMessage) -> list[Indicator]:
    found = _auth_indicators(analysis.authentication)
    h = analysis.headers

    from_domain = _domain(h.get("From", ""))
    from_reg = registrable_domain(from_domain) if from_domain else ""
    reply_domain = _domain(h.get("Reply-To", ""))
    return_domain = _domain(h.get("Return-Path", ""))
    # Resultados declarados de autenticação não alteram a severidade destes indicadores.
    if reply_domain and from_reg and registrable_domain(reply_domain) != from_reg:
        found.append(Indicator("média", f"Reply-To ({reply_domain}) difere do domínio do From ({from_domain})"))
    if return_domain and from_reg and registrable_domain(return_domain) != from_reg:
        found.append(Indicator("info", f"Return-Path ({return_domain}) difere do From ({from_domain}); "
                                       "comum em serviços legítimos de envio em massa"))

    for link in analysis.links:
        host = _host(link.url)
        scheme = link.url.split(":", 1)[0].lower()
        if scheme in {"javascript", "data", "vbscript"}:
            found.append(Indicator("alta", f"Link com esquema perigoso: {scheme}:"))
            continue
        if not host:
            continue
        shown = URL_RE.findall(link.text)
        shown_host = _host(shown[0]) if shown else ""
        if _is_ip(host):
            found.append(Indicator("alta", f"Link aponta para endereço IP: {defang(link.url)}"))
        elif from_reg and host.startswith(from_reg + ".") and registrable_domain(host) != from_reg:
            found.append(Indicator("alta", f"Domínio do remetente usado como subdomínio de outro domínio: {defang(host)}"))
        if shown_host and registrable_domain(shown_host) != registrable_domain(host):
            found.append(Indicator("média", f"Texto do link exibe {defang(shown_host)}, mas o destino é {defang(host)}"))
        if any(label.startswith("xn--") for label in host.split(".")):
            found.append(Indicator("média", f"Domínio internacionalizado (punycode), possível homógrafo: {defang(host)}"))

    for att in analysis.attachments:
        name = att.filename.lower()
        if any(ch in BIDI_CONTROLS for ch in name):
            found.append(Indicator("alta", "Nome de anexo com caractere de controle bidirecional (disfarce de extensão)"))
        suffixes = [s for s in Path(name.replace("/", "_")).suffixes if 1 < len(s) <= 6]
        ext = suffixes[-1] if suffixes else ""
        double = " com extensão dupla" if len(suffixes) > 1 else ""
        if ext in EXECUTABLE_EXTENSIONS:
            found.append(Indicator("alta", f"Anexo executável{double}: {att.filename}"))
        elif ext in CONTAINER_EXTENSIONS:
            found.append(Indicator("média", f"Anexo em imagem de disco{double}: {att.filename}"))
        elif ext in MACRO_EXTENSIONS:
            found.append(Indicator("média", f"Anexo Office com macros{double}: {att.filename}"))

    body = _body_text(msg)
    terms = sorted({m.group(0).lower() for rx in URGENCY_RE for m in [rx.search(body)] if m})
    if len(terms) >= 2:
        found.append(Indicator("baixa", "Linguagem de urgência/pressão: " + ", ".join(terms)))

    first = next((hop.timestamp for hop in analysis.hops if hop.timestamp), None)
    if analysis.date and first and abs((first - analysis.date).total_seconds()) > 3600:
        found.append(Indicator("baixa", "Diferença > 1h entre Date e o salto Received mais antigo"))

    if not h.get("Message-ID"):
        found.append(Indicator("baixa", "Cabeçalho Message-ID ausente"))

    return found


def analyze_email(path: Path, trusted_authserv_id: str | None = None) -> EmailAnalysis:
    msg = load_message(path)
    headers = {}
    for name in KEY_HEADERS:
        value = _header(msg, name)
        if value is not None:
            headers[name] = value
    if "To" in headers:
        headers["To"] = ", ".join(addr for _, addr in getaddresses([headers["To"]]) if addr)

    defects = [f"{type(d).__name__}" for part in msg.walk() for d in part.defects]
    analysis = EmailAnalysis(
        headers=headers,
        date=parse_date(headers.get("Date")),
        hops=parse_received(_all_headers(msg, "Received")),
        authentication=parse_authentication(msg, trusted_authserv_id),
        links=extract_links(msg),
        attachments=extract_attachments(msg),
        parse_defects=defects,
    )
    analysis.indicators = find_indicators(analysis, msg)
    return analysis
