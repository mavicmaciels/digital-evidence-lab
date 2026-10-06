"""Fluxo do caso: aquisição → hash → metadados → integridade → timeline → relatório."""

import os
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path

from evidencelab.custody import ChainOfCustody
from evidencelab.email_analysis import MAX_EML_BYTES, EmailAnalysis, EmailTooLargeError, analyze_email
from evidencelab.hashing import sha256_file
from evidencelab.timeline import TimelineEntry, build_timeline

CUSTODY_FILE = "cadeia_custodia.json"
EVIDENCE_DIR = "evidencia"
READ_ONLY = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH


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
    """Copia a evidência para o caso, marca a cópia como somente leitura e confere hashes.

    O original é apenas lido. Seu SHA-256 é calculado antes e depois da cópia para
    detectar alteração durante a aquisição; a cópia deve ter o mesmo hash.
    """
    evidence_dir = case_dir / EVIDENCE_DIR
    evidence_dir.mkdir(parents=True, exist_ok=True)
    target = evidence_dir / source.name

    info = source.stat()
    source_hash = sha256_file(source)
    with open(source, "rb") as src, open(target, "xb") as dst:  # "x": nunca sobrescreve
        shutil.copyfileobj(src, dst)
    shutil.copystat(source, target)
    os.chmod(target, READ_ONLY)
    custody.record(
        "Coleta",
        f"Origem: {source.resolve()} ({info.st_size} bytes) → cópia de trabalho: {target}",
    )

    copy_hash = sha256_file(target)
    source_after = sha256_file(source)
    if not (source_hash == copy_hash == source_after):
        custody.record("Hash inicial", "FALHA: hashes do original e da cópia divergem", copy_hash)
        raise IntegrityError("Hash da cópia ou do original mudou durante a aquisição")
    custody.record("Hash inicial", "SHA-256 do original e da cópia de trabalho coincidem", copy_hash)
    return target, copy_hash


def verify(evidence: Path, expected: str) -> bool:
    return evidence.is_file() and sha256_file(evidence) == expected


def run_case(
    source: Path,
    case_dir: Path,
    examiner: str | None = None,
    trusted_authserv_id: str | None = None,
) -> CaseResult:
    if source.stat().st_size > MAX_EML_BYTES:
        raise EmailTooLargeError(f"Arquivo excede o limite de {MAX_EML_BYTES} bytes")
    # Um caso = uma evidência: nunca sobrescrever cópia ou registro de custódia existentes.
    for existing in (case_dir / EVIDENCE_DIR / source.name, case_dir / CUSTODY_FILE):
        if existing.exists():
            raise FileExistsError(f"Caso já iniciado ({existing}); use outro --case-dir")

    case_dir.mkdir(parents=True, exist_ok=True)
    custody = ChainOfCustody(evidence=source.name, path=case_dir / CUSTODY_FILE)
    if examiner:
        custody.examiner = examiner

    evidence, digest = acquire(source, case_dir, custody)
    steps = ["Arquivo adquirido (cópia somente leitura)", "SHA-256 calculado"]

    try:
        analysis = analyze_email(evidence, trusted_authserv_id)
    except Exception as exc:
        custody.record("Análise", f"FALHA: {type(exc).__name__}: {exc}")
        raise
    custody.record(
        "Análise",
        f"{len(analysis.hops)} saltos, {len(analysis.links)} links, "
        f"{len(analysis.attachments)} anexos, {len(analysis.indicators)} indicadores",
    )
    steps.append("Metadados extraídos")

    integrity_ok = verify(evidence, digest)
    if not integrity_ok:
        custody.record("Verificação de integridade", "FALHA: hash divergente do inicial")
        raise IntegrityError("A cópia de trabalho foi alterada após a aquisição")
    custody.record("Verificação de integridade", "Hash após a análise igual ao inicial", digest)
    steps.append("Integridade verificada (hash inalterado)")

    timeline = build_timeline(analysis, custody)
    steps.append("Timeline construída (UTC)")

    return CaseResult(
        evidence_path=evidence,
        case_dir=case_dir,
        sha256=digest,
        analysis=analysis,
        custody=custody,
        timeline=timeline,
        steps=steps,
        integrity_ok=integrity_ok,
    )
