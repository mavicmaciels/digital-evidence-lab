"""python -m evidencelab.gui — inicia a interface local e abre o navegador."""

import argparse
import webbrowser
from pathlib import Path

from evidencelab.gui.server import EvidenceLabServer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m evidencelab.gui",
        description="Interface visual local (somente 127.0.0.1) do Digital Evidence Lab",
    )
    parser.add_argument("--port", type=int, default=0, help="porta local (padrão: aleatória)")
    parser.add_argument("--cases-dir", default="casos", help="diretório dos casos (padrão: casos)")
    parser.add_argument("--no-browser", action="store_true", help="não abrir o navegador automaticamente")
    args = parser.parse_args(argv)

    server = EvidenceLabServer(Path(args.cases_dir), port=args.port)
    print("Digital Evidence Lab — interface local")
    print(f"Endereço (contém o token desta sessão; não compartilhe): {server.url}")
    print("Servido apenas em 127.0.0.1. Ctrl+C para encerrar.")
    if not args.no_browser:
        webbrowser.open(server.url)  # abre apenas o endereço local da própria interface
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrado.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
