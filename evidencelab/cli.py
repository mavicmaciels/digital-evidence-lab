"""Interface de linha de comando do Digital Evidence Lab."""

import argparse
import sys
from pathlib import Path

from evidencelab.case import CUSTODY_FILE, EVIDENCE_DIR, IntegrityError, run_case, verify
from evidencelab.custody import ChainOfCustody
from evidencelab.report import INTEGRITY_FAIL, INTEGRITY_OK, SCOPE_NOTE, render_panel, write_reports
from evidencelab.sanitize import safe


def cmd_analyze(args: argparse.Namespace) -> int:
    source = Path(args.evidence)
    if not source.is_file():
        print(f"Arquivo não encontrado: {safe(source)}", file=sys.stderr)
        return 2
    case_dir = Path(args.case_dir) if args.case_dir else Path("casos") / source.stem
    try:
        result = run_case(source, case_dir, examiner=args.examiner, trusted_authserv_id=args.authserv_id)
    except (IntegrityError, OSError, ValueError) as exc:
        print(f"ERRO: {safe(exc)}", file=sys.stderr)
        return 1
    paths = write_reports(result)
    print(render_panel(result))
    print("\nArquivos gerados:")
    for path in paths:
        print(f"  {safe(path)}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    case_dir = Path(args.case_dir)
    custody_path = case_dir / CUSTODY_FILE
    try:
        custody = ChainOfCustody.load(custody_path)
    except FileNotFoundError:
        print(f"Cadeia de custódia não encontrada: {safe(custody_path)}", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Cadeia de custódia ilegível: {safe(exc)}", file=sys.stderr)
        return 1

    chain_ok = custody.verify_chain()
    initial = custody.initial_hash()
    # O nome vem do JSON: só o componente final é usado, evitando caminhos fora do caso.
    name = Path(custody.evidence).name
    evidence = case_dir / EVIDENCE_DIR / name
    hash_ok = name not in {"", ".", ".."} and bool(initial) and verify(evidence, initial)

    if args.examiner:
        custody.examiner = args.examiner
    if chain_ok:  # não se acrescenta evento a um registro já inconsistente
        custody.record(
            "Reverificação de integridade",
            "Hash igual ao inicial" if hash_ok else "FALHA: hash divergente, ausente ou arquivo não encontrado",
            initial or "",
        )

    print(f"Evidência: {safe(evidence.name)}")
    print(f"SHA-256 inicial: {safe(initial or '(não registrado)')}")
    print(f"Registro de custódia (encadeamento): {'ÍNTEGRO' if chain_ok else 'INCONSISTENTE'}")
    print("INTEGRIDADE DA CÓPIA DE TRABALHO")
    print(INTEGRITY_OK if hash_ok else INTEGRITY_FAIL)
    print(f"\nNota: {SCOPE_NOTE}")
    return 0 if (hash_ok and chain_ok) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evidencelab", description="Triagem forense de e-mails suspeitos (.eml)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Adquire e analisa uma evidência .eml")
    analyze.add_argument("evidence", help="Caminho do arquivo .eml")
    analyze.add_argument("--case-dir", help="Diretório do caso (padrão: casos/<nome>)")
    analyze.add_argument("--examiner", help="Nome do examinador (padrão: usuário do sistema)")
    analyze.add_argument(
        "--authserv-id",
        help="authserv-id de um serviço de autenticação que você tem fundamento externo para "
        "considerar confiável (ex.: o servidor de borda da sua organização). Só o "
        "Authentication-Results mais alto com esse authserv-id é usado e pontuado. Sem esta "
        "opção, os cabeçalhos são apenas listados como declarados e não pontuam.",
    )
    analyze.set_defaults(func=cmd_analyze)

    check = sub.add_parser("verify", help="Reverifica a integridade de um caso existente")
    check.add_argument("case_dir", help="Diretório do caso")
    check.add_argument("--examiner", help="Nome do examinador")
    check.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
