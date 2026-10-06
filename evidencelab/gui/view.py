"""Converte o resultado do motor de análise em dados para a interface.

Não há lógica de análise aqui: os dados vêm de `report.to_dict(result)`. Este módulo
apenas neutraliza o texto (todo valor textual passa por `sanitize.safe`), remove a
URL bruta dos links (fica só a versão desarmada) e acrescenta os avisos fixos.
"""

from collections import Counter

from evidencelab.case import CaseResult
from evidencelab.email_analysis import SEVERITY_WEIGHT, URL_RE
from evidencelab.report import AUTH_NOTE, HEURISTIC_NOTE, SCOPE_NOTE, _auth_title, to_dict
from evidencelab.sanitize import defang, safe

CUSTODY_NOTE = (
    "O encadeamento de hashes evidencia edições no registro de custódia, mas não "
    "equivale a assinatura digital nem a carimbo de tempo."
)


def neutralize(value):
    """Desarma URLs e aplica `safe` a todo texto, recursivamente.

    Inclui o texto exibido de links e cabeçalhos: nenhuma URL http(s) chega intacta
    ao navegador. Números e booleanos são preservados.
    """
    if isinstance(value, str):
        return safe(URL_RE.sub(lambda m: defang(m.group(0)), value))
    if isinstance(value, dict):
        return {safe(k): neutralize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [neutralize(v) for v in value]
    return value


def build_view(result: CaseResult, case_id: str) -> dict:
    data = to_dict(result)
    data.pop("caminho", None)  # caminho local do servidor: desnecessário na tela
    for link in data["links"]:
        link.pop("url", None)  # só a versão desarmada chega ao navegador
    counts = Counter(i.severity for i in result.analysis.indicators)
    data.update(
        caso=case_id,
        integridade_ok=result.integrity_ok,
        autenticacao_situacao=_auth_title(result.analysis.authentication),
        autenticacao_selecionado=result.analysis.authentication.selected,
        contagem_severidade={s: counts.get(s, 0) for s in SEVERITY_WEIGHT},
        etapas=result.steps,
        avisos={
            "heuristico": HEURISTIC_NOTE,
            "hash": SCOPE_NOTE,
            "autenticacao": AUTH_NOTE,
            "custodia": CUSTODY_NOTE,
        },
    )
    return neutralize(data)
