"""Neutralização de conteúdo não confiável antes de exibi-lo.

Cabeçalhos, nomes de anexos e URLs vêm do atacante. Antes de irem para o
terminal ou para o Markdown, caracteres de controle (incluindo sequências ANSI e
controles bidirecionais) são escapados e URLs são "desarmadas" (defang).
"""

import re
from urllib.parse import urlsplit


def safe(text: object) -> str:
    """Escapa caracteres não imprimíveis (Cc, Cf, etc.) como \\xNN / \\uNNNN."""
    out = []
    for ch in str(text):
        if ch.isprintable():
            out.append(ch)
        elif ord(ch) <= 0xFF:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(f"\\u{ord(ch):04x}")
    return "".join(out)


def defang(value: str) -> str:
    """hxxp[s]://exemplo[.]com/... — impede que o link seja clicável por engano."""
    value = re.sub(r"^(?i:http)", "hxxp", value.strip())
    try:
        netloc = urlsplit(value).netloc
    except ValueError:
        netloc = ""
    if netloc:
        return value.replace(netloc, netloc.replace(".", "[.]"), 1)
    if "://" not in value:  # host isolado
        return value.replace(".", "[.]")
    return value


_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>|#!])")


def md(text: object) -> str:
    """Texto seguro para célula/linha Markdown (sem HTML, links ou tabelas injetadas)."""
    return _MD_SPECIAL.sub(r"\\\1", safe(text)).replace("\n", " ")


def md_code(text: object) -> str:
    """Conteúdo para code span; crases são substituídas para não fechar o span."""
    return "`" + safe(text).replace("`", "'") + "`"
