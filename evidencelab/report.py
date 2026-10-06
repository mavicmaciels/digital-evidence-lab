"""Geração de relatórios: painel no terminal, JSON e Markdown.

Todo conteúdo vindo do e-mail passa por `safe`/`md` antes de ser exibido, e URLs
são desarmadas (defang) nos relatórios legíveis por humanos.
"""

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from evidencelab.case import CUSTODY_FILE, CaseResult
from evidencelab.hashing import short_hash
from evidencelab.sanitize import defang, md, md_code, safe
from evidencelab.timeline import build_timeline

WIDTH = 64

SCOPE_NOTE = (
    "O hash atesta apenas que a cópia de trabalho não foi alterada desde a "
    "aquisição. Não comprova a autenticidade do conteúdo nem a autoria da mensagem."
)
HEURISTIC_NOTE = (
    "O nível de suspeita é heurístico: indica prioridade de análise, não prova "
    "fraude nem legitimidade."
)
AUTH_NOTE = (
    "Resultados SPF/DKIM/DMARC são os declarados pelo servidor receptor no "
    "cabeçalho Authentication-Results; não foram revalidados por esta ferramenta."
)


def _utc(dt: datetime | None) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else "-"


def _hm(iso: str) -> str:
    return datetime.fromisoformat(iso).astimezone(timezone.utc).strftime("%H:%M")


def render_panel(result: CaseResult) -> str:
    a = result.analysis
    auth = a.authentication
    lines = ["=" * WIDTH, "DIGITAL EVIDENCE LAB".center(WIDTH), "=" * WIDTH, ""]
    lines += [f"Evidência: {safe(result.evidence_path.name)}", ""]
    lines += [f"[✓] {step}" for step in result.steps]
    lines += ["", "SHA-256", short_hash(result.sha256), ""]
    lines.append("CADEIA DE CUSTÓDIA (UTC)")
    lines += [f"{_hm(e.timestamp)}  {e.action}" for e in result.custody.events]
    lines += ["", "INTEGRIDADE DA CÓPIA DE TRABALHO"]
    lines.append("● VERIFICADA (hash inalterado)" if result.integrity_ok else "● FALHA (hash divergente)")
    lines += ["", f"AUTENTICAÇÃO ({'declarada por ' + safe(auth.authserv_id) if auth.authserv_id else 'sem Authentication-Results'})"]
    for res in auth.results.values():
        raw = f" ({safe(res.result)})" if res.result else ""
        lines.append(f"  {res.mechanism.upper():<6}{res.status}{raw}")
    lines += ["", f"NÍVEL DE SUSPEITA (heurístico): {a.suspicion_level}  [pontuação {a.score}]"]
    for ind in a.indicators:
        lines.append(f"  [{ind.severity:^5}] {safe(ind.description)}")
    lines += ["", "Notas:", f"- {SCOPE_NOTE}", f"- {HEURISTIC_NOTE}", "=" * WIDTH]
    return "\n".join(lines)


def to_dict(result: CaseResult) -> dict:
    a = result.analysis
    return {
        "evidencia": result.evidence_path.name,
        "caminho": str(result.evidence_path),
        "sha256": result.sha256,
        "integridade_copia": "hash inalterado" if result.integrity_ok else "hash divergente",
        "nivel_suspeita": a.suspicion_level,
        "pontuacao": a.score,
        "cabecalhos": a.headers,
        "autenticacao": {
            "authserv_id": a.authentication.authserv_id,
            "cabecalhos_encontrados": a.authentication.headers_found,
            "resultados": {k: asdict(v) for k, v in a.authentication.results.items()},
        },
        "saltos_received": [{**asdict(h), "timestamp": _utc(h.timestamp)} for h in a.hops],
        "links": [{**asdict(link), "url_defanged": defang(link.url)} for link in a.links],
        "anexos": [asdict(att) for att in a.attachments],
        "defeitos_parsing": a.parse_defects,
        "indicadores": [asdict(i) for i in a.indicators],
        "timeline_utc": [
            {"timestamp": _utc(t.timestamp), "fonte": t.source, "descricao": t.description}
            for t in result.timeline
        ],
        "cadeia_custodia": {
            "encadeamento_integro": result.custody.verify_chain(),
            "eventos": [asdict(e) for e in result.custody.events],
        },
        "notas": [SCOPE_NOTE, HEURISTIC_NOTE, AUTH_NOTE],
    }


def to_markdown(result: CaseResult) -> str:
    a = result.analysis
    auth = a.authentication
    out = [
        f"# Relatório de análise — {md(result.evidence_path.name)}",
        "",
        f"- **SHA-256 da cópia de trabalho:** `{result.sha256}`",
        f"- **Integridade da cópia:** {'hash inalterado desde a aquisição' if result.integrity_ok else 'HASH DIVERGENTE'}",
        f"- **Nível de suspeita (heurístico):** {a.suspicion_level} (pontuação {a.score})",
        f"- **Examinador:** {md(result.custody.examiner)}",
        "",
        f"> {SCOPE_NOTE} {HEURISTIC_NOTE}",
        "",
        "## Cabeçalhos",
        "",
        "| Campo | Valor |",
        "|---|---|",
    ]
    out += [f"| {k} | {md(v)} |" for k, v in a.headers.items()]
    out += ["", "## Autenticação (SPF / DKIM / DMARC)", "", f"> {AUTH_NOTE}", ""]
    out.append(f"- **authserv-id:** {md(auth.authserv_id) or '(nenhum cabeçalho Authentication-Results)'}")
    out += [
        f"- **{r.mechanism.upper()}:** {r.status}" + (f" (`{md(r.result)}`)" if r.result else "")
        for r in auth.results.values()
    ]
    out += [
        "", "## Rota de entrega (Received)", "",
        "> Saltos anteriores à entrada na infraestrutura do destinatário podem ser forjados pelo remetente.",
        "", "| # | De | IP | Por | Protocolo | Horário (UTC) | Data original |", "|---|---|---|---|---|---|---|",
    ]
    out += [
        f"| {h.index} | {md(h.from_host)} | {md(h.ip)} | {md(h.by_host)} | {md(h.protocol)} | {_utc(h.timestamp)} | {md(h.raw_date)} |"
        for h in a.hops
    ]
    out += ["", "## Links (desarmados; não acessados)", ""]
    out += [
        f"- {md_code(defang(link.url))}" + (f" — texto exibido: “{md(link.text)}”" if link.text else "")
        for link in a.links
    ] or ["- (nenhum)"]
    out += ["", "## Anexos (não extraídos nem executados)", ""]
    out += [
        f"- {md_code(att.filename)} ({md(att.content_type)}, {att.size} bytes) — SHA-256 `{att.sha256}`"
        for att in a.attachments
    ] or ["- (nenhum)"]
    out += ["", "## Indicadores de suspeita (heurísticos)", ""]
    out += [f"- **[{i.severity}]** {md(i.description)}" for i in a.indicators] or ["- (nenhum)"]
    if a.parse_defects:
        out += ["", "## Defeitos de parsing (estrutura MIME/cabeçalhos fora do padrão)", ""]
        out += [f"- {md(d)}" for d in a.parse_defects]
    out += ["", "## Timeline (UTC)", "", "| Horário | Fonte | Evento |", "|---|---|---|"]
    out += [f"| {_utc(t.timestamp)} | {t.source} | {md(t.description)} |" for t in result.timeline]
    chain = "íntegro" if result.custody.verify_chain() else "INCONSISTENTE"
    out += [
        "", "## Cadeia de custódia", "",
        f"Encadeamento de hashes dos eventos: **{chain}**. O encadeamento evidencia edições "
        "no registro, mas não substitui assinatura digital ou carimbo de tempo.",
        "", "| Horário (UTC) | Ação | Examinador | Detalhes | SHA-256 |", "|---|---|---|---|---|",
    ]
    out += [
        f"| {e.timestamp} | {md(e.action)} | {md(e.examiner)} | {md(e.details)} | {e.sha256 or '-'} |"
        for e in result.custody.events
    ]
    return "\n".join(out) + "\n"


def write_reports(result: CaseResult) -> list[Path]:
    """Registra a emissão do relatório na cadeia de custódia e grava os arquivos."""
    result.custody.record("Relatório", "Relatórios JSON e Markdown emitidos", result.sha256)
    result.timeline = build_timeline(result.analysis, result.custody)

    stem = result.evidence_path.stem
    json_path = result.case_dir / f"relatorio_{stem}.json"
    md_path = result.case_dir / f"relatorio_{stem}.md"
    custody_path = result.case_dir / CUSTODY_FILE

    json_path.write_text(json.dumps(to_dict(result), indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(to_markdown(result), encoding="utf-8")
    result.custody.save(custody_path)
    return [json_path, md_path, custody_path]
