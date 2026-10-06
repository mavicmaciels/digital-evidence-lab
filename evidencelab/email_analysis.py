"""Extração de metadados e indicadores de um e-mail (.eml)."""

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

from evidencelab.hashing import sha256_bytes

KEY_HEADERS = (
    "From",
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
    ".wsf", ".hta", ".msi", ".ps1", ".jar", ".lnk", ".iso", ".img", ".dll",
}
URGENCY_TERMS = (
    "urgente", "imediatamente", "bloquead", "suspens", "24 horas", "24h",
    "confirme seus dados", "verifique sua conta", "senha", "urgent", "immediately",
    "suspended", "verify your account", "password",
)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
RECEIVED_RE = re.compile(
    r"^\s*(?:from\s+(?P<from>.+?))?\s*by\s+(?P<by>\S+)(?:\s+with\s+(?P<with>\S+))?",
    re.IGNORECASE | re.DOTALL,
)
IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE)


@dataclass
class ReceivedHop:
    index: int
    from_host: str
    by_host: str
    protocol: str
    ip: str
    timestamp: datetime | None


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
    severity: str  # "alta", "média", "baixa"
    description: str


@dataclass
class EmailAnalysis:
    headers: dict[str, str]
    date: datetime | None
    hops: list[ReceivedHop]
    authentication: dict[str, str]
    links: list[Link]
    attachments: list[Attachment]
    indicators: list[Indicator] = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        high = sum(1 for i in self.indicators if i.severity == "alta")
        if high >= 2:
            return "ALTO"
        if high or len(self.indicators) >= 2:
            return "MÉDIO"
        return "BAIXO"


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
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
            self.links.append(Link(url=self._href, text=text, source="html"))
            self._href = None


def load_message(path: Path) -> EmailMessage:
    with open(path, "rb") as fh:
        return BytesParser(policy=policy.default).parse(fh)


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None


def _domain(address: str) -> str:
    _, addr = parseaddr(address or "")
    return addr.rpartition("@")[2].lower().strip(">")


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _registrable(domain: str) -> str:
    """Aproximação simples do domínio registrável (últimos dois rótulos)."""
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def parse_received(values: list[str]) -> list[ReceivedHop]:
    """Converte os cabeçalhos Received (ordem do topo = mais recente) em saltos."""
    hops = []
    for index, raw in enumerate(reversed(values), start=1):
        flat = " ".join(str(raw).split())
        route, _, date_part = flat.rpartition(";")
        if not route:
            route, date_part = flat, ""
        match = RECEIVED_RE.search(route)
        from_host = by_host = protocol = ""
        if match:
            from_host = (match.group("from") or "").split(" ")[0]
            by_host = match.group("by") or ""
            protocol = match.group("with") or ""
        ip = IP_RE.search(route)
        hops.append(
            ReceivedHop(
                index=index,
                from_host=from_host,
                by_host=by_host,
                protocol=protocol,
                ip=ip.group(1) if ip else "",
                timestamp=_parse_date(date_part.strip()),
            )
        )
    return hops


def _decoded_text(part: EmailMessage) -> str:
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def extract_links(msg: EmailMessage) -> list[Link]:
    links: list[Link] = []
    seen: set[tuple[str, str]] = set()
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype == "text/html":
            parser = _AnchorParser()
            parser.feed(_decoded_text(part))
            found = parser.links
        elif ctype == "text/plain":
            found = [Link(url=u.rstrip(".,)")) for u in URL_RE.findall(_decoded_text(part))]
        else:
            continue
        for link in found:
            key = (link.url, link.source)
            if key not in seen:
                seen.add(key)
                links.append(link)
    return links


def extract_attachments(msg: EmailMessage) -> list[Attachment]:
    attachments = []
    for part in msg.iter_attachments():
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
    chunks = [str(msg.get("Subject", ""))]
    for part in msg.walk():
        if part.get_content_maintype() == "text" and part.get_content_disposition() != "attachment":
            chunks.append(_decoded_text(part))
    return "\n".join(chunks).lower()


def find_indicators(analysis: EmailAnalysis, msg: EmailMessage) -> list[Indicator]:
    found: list[Indicator] = []
    h = analysis.headers

    for mech in ("spf", "dkim", "dmarc"):
        result = analysis.authentication.get(mech)
        if result in {"fail", "softfail", "none", "permerror"}:
            sev = "alta" if result == "fail" else "média"
            found.append(Indicator(sev, f"{mech.upper()} = {result}"))

    from_domain = _domain(h.get("From", ""))
    reply_domain = _domain(h.get("Reply-To", ""))
    return_domain = _domain(h.get("Return-Path", ""))
    if reply_domain and from_domain and _registrable(reply_domain) != _registrable(from_domain):
        found.append(Indicator("alta", f"Reply-To ({reply_domain}) difere do remetente ({from_domain})"))
    if return_domain and from_domain and _registrable(return_domain) != _registrable(from_domain):
        found.append(Indicator("média", f"Return-Path ({return_domain}) difere do remetente ({from_domain})"))

    for link in analysis.links:
        host = _host(link.url)
        if _is_ip(host):
            found.append(Indicator("alta", f"Link aponta para endereço IP: {link.url}"))
        shown = URL_RE.findall(link.text)
        if shown and _host(shown[0]) and _host(shown[0]) != host:
            found.append(Indicator("alta", f"Texto do link exibe {_host(shown[0])}, mas aponta para {host}"))
        if from_domain and host and not _is_ip(host) and host.startswith(_registrable(from_domain) + "."):
            found.append(Indicator("alta", f"Domínio do remetente usado como subdomínio enganoso: {host}"))

    for att in analysis.attachments:
        name = att.filename.lower()
        suffixes = Path(name).suffixes
        if suffixes and suffixes[-1] in EXECUTABLE_EXTENSIONS:
            found.append(Indicator("alta", f"Anexo executável: {att.filename}"))
            if len(suffixes) > 1:
                found.append(Indicator("alta", f"Extensão dupla no anexo: {att.filename}"))

    body = _body_text(msg)
    terms = sorted({t for t in URGENCY_TERMS if t in body})
    if terms:
        found.append(Indicator("média", "Linguagem de urgência/pressão: " + ", ".join(terms)))

    date = analysis.date
    if date and analysis.hops:
        first = next((hop.timestamp for hop in analysis.hops if hop.timestamp), None)
        if first and abs((first - date).total_seconds()) > 3600:
            found.append(Indicator("baixa", "Diferença > 1h entre Date e o primeiro salto Received"))

    if not h.get("Message-ID"):
        found.append(Indicator("baixa", "Cabeçalho Message-ID ausente"))

    return found


def analyze_email(path: Path) -> EmailAnalysis:
    msg = load_message(path)
    headers = {name: str(msg[name]) for name in KEY_HEADERS if msg[name] is not None}
    if "To" in headers:
        headers["To"] = ", ".join(addr for _, addr in getaddresses([headers["To"]]))

    auth: dict[str, str] = {}
    for value in msg.get_all("Authentication-Results", []):
        for mech, result in AUTH_RE.findall(str(value)):
            auth.setdefault(mech.lower(), result.lower())

    analysis = EmailAnalysis(
        headers=headers,
        date=_parse_date(headers.get("Date")),
        hops=parse_received([str(v) for v in msg.get_all("Received", [])]),
        authentication=auth,
        links=extract_links(msg),
        attachments=extract_attachments(msg),
    )
    analysis.indicators = find_indicators(analysis, msg)
    return analysis
