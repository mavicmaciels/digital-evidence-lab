"""Geração de relatórios: painel no terminal, JSON e Markdown."""

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from evidencelab.case import CUSTODY_FILE, CaseResult
from evidencelab.hashing import short_hash
from evidencelab.timeline import build_timeline

WIDTH = 60


def _hm(iso: str) -> str:
    return datetime.fromisoformat(iso).strftime("%H:%M")


def _fmt(dt: datetime | None) -> str:
    return dt.isoformat() if dt else "-"


def render_panel(result: CaseResult) -> str:
    a = result.analysis
    lines = ["=" * WIDTH, "DIGITAL EVIDENCE LAB".center(WIDTH), "=" * WIDTH, ""]
    lines.append(f"Evidência: {result.evidence_path.name}")
    lines.append("")
    lines += [f"[✓] {step}" for step in result.steps]
    lines += ["", "SHA-256", short_hash(result.sha256), ""]
    lines.append("CADEIA DE CUSTÓDIA")
    lines += [f"{_hm(e.timestamp)}  {e.action}" for e in result.custody.events]
    lines += ["", "INTEGRIDADE", "● VERIFICADA" if result.integrity_ok else "● COMPROMETIDA", ""]
    lines.append(f"RISCO: {a.risk_level} ({len(a.indicators)} indicadores)")
    for ind in a.indicators:
        lines.append(f"  [{ind.severity:^5}] {ind.description}")
    lines.append("=" * WIDTH)
    return "\n".join(lines)


def to_dict(result: CaseResult) -> dict:
    a = result.analysis
    return {
        "evidencia": result.evidence_path.name,
        "caminho": str(result.evidence_path),
        "sha256": result.sha256,
        "integridade": "verificada" if result.integrity_ok else "comprometida",
        "risco": a.risk_level,
        "cabecalhos": a.headers,
        "autenticacao": a.authentication,
        "saltos": [{**asdict(h), "timestamp": _fmt(h.timestamp)} for h in a.hops],
        "links": [asdict(link) for link in a.links],
        "anexos": [asdict(att) for att in a.attachments],
        "indicadores": [asdict(i) for i in a.indicators],
        "timeline": [
            {"timestamp": _fmt(t.timestamp), "fonte": t.source, "descricao": t.description}
            for t in result.timeline
        ],
        "cadeia_custodia": [asdict(e) for e in result.custody.events],
    }


def _md_escape(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def to_markdown(result: CaseResult) -> str:
    a = result.analysis
    out = [
        f"# Relatório de análise — {result.evidence_path.name}",
        "",
        f"- **SHA-256:** `{result.sha256}`",
        f"- **Integridade:** {'VERIFICADA' if result.integrity_ok else 'COMPROMETIDA'}",
        f"- **Nível de risco:** {a.risk_level}",
        f"- **Examinador:** {result.custody.examiner}",
        "",
        "## Cabeçalhos",
        "",
        "| Campo | Valor |",
        "|---|---|",
    ]
    out += [f"| {k} | {_md_escape(v)} |" for k, v in a.headers.items()]
    out += ["", "## Autenticação", ""]
    out += [f"- **{k.upper()}:** {v}" for k, v in a.authentication.items()] or ["- (sem Authentication-Results)"]
    out += ["", "## Rota de entrega (Received)", "", "| # | De | IP | Por | Protocolo | Horário |", "|---|---|---|---|---|---|"]
    out += [
        f"| {h.index} | {_md_escape(h.from_host)} | {h.ip} | {h.by_host} | {h.protocol} | {_fmt(h.timestamp)} |"
        for h in a.hops
    ]
    out += ["", "## Links", ""]
    out += [
        f"- `{_md_escape(link.url)}`" + (f" — texto exibido: “{_md_escape(link.text)}”" if link.text else "")
        for link in a.links
    ] or ["- (nenhum)"]
    out += ["", "## Anexos", ""]
    out += [
        f"- **{_md_escape(att.filename)}** ({att.content_type}, {att.size} bytes) — SHA-256 `{att.sha256}`"
        for att in a.attachments
    ] or ["- (nenhum)"]
    out += ["", "## Indicadores de comprometimento", ""]
    out += [f"- **[{i.severity}]** {_md_escape(i.description)}" for i in a.indicators] or ["- (nenhum)"]
    out += ["", "## Timeline", "", "| Horário | Fonte | Evento |", "|---|---|---|"]
    out += [f"| {_fmt(t.timestamp)} | {t.source} | {_md_escape(t.description)} |" for t in result.timeline]
    out += ["", "## Cadeia de custódia", "", "| Horário | Ação | Examinador | Detalhes | SHA-256 |", "|---|---|---|---|---|"]
    out += [
        f"| {e.timestamp} | {e.action} | {e.examiner} | {_md_escape(e.details)} | {e.sha256 or '-'} |"
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
