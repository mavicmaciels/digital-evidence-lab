"""Interface de linha de comando do Digital Evidence Lab."""

import argparse
import sys
from pathlib import Path

from evidencelab.case import CUSTODY_FILE, IntegrityError, run_case, verify
from evidencelab.custody import ChainOfCustody
from evidencelab.report import render_panel, write_reports


def cmd_analyze(args: argparse.Namespace) -> int:
    source = Path(args.evidence)
    if not source.is_file():
        print(f"Arquivo não encontrado: {source}", file=sys.stderr)
        return 2
    case_dir = Path(args.case_dir) if args.case_dir else Path("casos") / source.stem
    try:
        result = run_case(source, case_dir, examiner=args.examiner)
    except (IntegrityError, FileExistsError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 1
    paths = write_reports(result)
    print(render_panel(result))
    print("\nArquivos gerados:")
    for path in paths:
        print(f"  {path}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    case_dir = Path(args.case_dir)
    custody_path = case_dir / CUSTODY_FILE
    if not custody_path.is_file():
        print(f"Cadeia de custódia não encontrada: {custody_path}", file=sys.stderr)
        return 2
    custody = ChainOfCustody.load(custody_path)
    if args.examiner:
        custody.examiner = args.examiner
    initial = next(e.sha256 for e in custody.events if e.action == "Hash inicial")
    evidence = case_dir / "evidencia" / custody.evidence
    ok = evidence.is_file() and verify(evidence, initial)
    custody.record(
        "Reverificação de integridade",
        "Hash confere" if ok else "FALHA: hash divergente ou arquivo ausente",
        initial,
    )
    custody.save(custody_path)
    print(f"Evidência: {custody.evidence}")
    print(f"SHA-256 esperado: {initial}")
    print("INTEGRIDADE\n● VERIFICADA" if ok else "INTEGRIDADE\n● COMPROMETIDA")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evidencelab", description="Análise forense de e-mails suspeitos (.eml)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Adquire e analisa uma evidência .eml")
    analyze.add_argument("evidence", help="Caminho do arquivo .eml")
    analyze.add_argument("--case-dir", help="Diretório do caso (padrão: casos/<nome>)")
    analyze.add_argument("--examiner", help="Nome do examinador (padrão: usuário do sistema)")
    analyze.set_defaults(func=cmd_analyze)

    check = sub.add_parser("verify", help="Reverifica a integridade de um caso existente")
    check.add_argument("case_dir", help="Diretório do caso")
    check.add_argument("--examiner", help="Nome do examinador")
    check.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
