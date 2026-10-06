"""Fluxo do caso: aquisição → hash → metadados → integridade → timeline → relatório."""

import os
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path

from evidencelab.custody import ChainOfCustody
from evidencelab.email_analysis import EmailAnalysis, analyze_email
from evidencelab.hashing import sha256_file
from evidencelab.timeline import TimelineEntry, build_timeline

CUSTODY_FILE = "cadeia_custodia.json"


class IntegrityError(Exception):
    pass


@dataclass
class CaseResult:
    evidence_path: Path
    case_dir: Path
    sha256: str
    analysis: EmailAnalysis
    custody: ChainOfCustody
    timeline: list[TimelineEntry]
    steps: list[str] = field(default_factory=list)
    integrity_ok: bool = False


def acquire(source: Path, case_dir: Path, custody: ChainOfCustody) -> tuple[Path, str]:
    """Copia a evidência para o diretório do caso (somente leitura) e registra o hash."""
    evidence_dir = case_dir / "evidencia"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    target = evidence_dir / source.name
    if target.exists():
        raise FileExistsError(f"Evidência já adquirida neste caso: {target}")

    source_hash = sha256_file(source)
    shutil.copy2(source, target)
    os.chmod(target, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    custody.record("Coleta", f"Origem: {source.resolve()} → {target}")

    copy_hash = sha256_file(target)
    if copy_hash != source_hash:
        raise IntegrityError("Hash da cópia difere do original durante a aquisição")
    custody.record("Hash inicial", "SHA-256 calculado na cópia de trabalho", copy_hash)
    return target, copy_hash


def verify(evidence: Path, expected: str) -> bool:
    return sha256_file(evidence) == expected


def run_case(source: Path, case_dir: Path, examiner: str | None = None) -> CaseResult:
    case_dir.mkdir(parents=True, exist_ok=True)
    custody = ChainOfCustody(evidence=source.name)
    if examiner:
        custody.examiner = examiner

    evidence, digest = acquire(source, case_dir, custody)
    steps = ["Arquivo adquirido", "SHA-256 calculado"]

    analysis = analyze_email(evidence)
    custody.record(
        "Análise",
        f"{len(analysis.hops)} saltos, {len(analysis.links)} links, "
        f"{len(analysis.attachments)} anexos, {len(analysis.indicators)} indicadores",
    )
    steps.append("Metadados extraídos")

    integrity_ok = verify(evidence, digest)
    if not integrity_ok:
        custody.record("Verificação de integridade", "FALHA: hash divergente", sha256_file(evidence))
        custody.save(case_dir / CUSTODY_FILE)
        raise IntegrityError("A evidência foi alterada após a aquisição")
    custody.record("Verificação de integridade", "Hash confere com o valor inicial", digest)
    steps.append("Integridade verificada")

    timeline = build_timeline(analysis, custody)
    steps.append("Timeline construída")

    result = CaseResult(
        evidence_path=evidence,
        case_dir=case_dir,
        sha256=digest,
        analysis=analysis,
        custody=custody,
        timeline=timeline,
        steps=steps,
        integrity_ok=integrity_ok,
    )
    return result
