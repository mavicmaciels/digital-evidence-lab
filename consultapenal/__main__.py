"""python -m consultapenal — inicia o painel local e abre o navegador."""

import argparse
import webbrowser

from consultapenal.server import ConsultaPenalServer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m consultapenal",
                                     description="Painel local do Consulta Penal (somente 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="porta local (padrão: 8765)")
    parser.add_argument("--no-browser", action="store_true", help="não abrir o navegador automaticamente")
    args = parser.parse_args(argv)

    server = ConsultaPenalServer(port=args.port)
    print("Consulta Penal — painel local")
    print(f"Endereço: {server.url}")
    print("Servido apenas em 127.0.0.1. Ctrl+C para encerrar.")
    if not args.no_browser:
        webbrowser.open(server.url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrado.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
