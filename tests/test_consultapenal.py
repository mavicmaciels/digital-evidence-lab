import http.client
import json
import shutil
import tempfile
import threading
import unittest
from pathlib import Path

from consultapenal.conteudo import DADOS_DIR, ConteudoInvalido, buscar, carregar_acervo, normalizar
from consultapenal.server import ConsultaPenalServer


class ConteudoTest(unittest.TestCase):
    def setUp(self):
        self.acervo = carregar_acervo()

    def test_dados_validos_e_links_rapidos_obrigatorios(self):
        nomes = {lei["nome"] for lei in self.acervo["leis"]}
        for esperado in ("Código Penal", "Código de Processo Penal", "Código Civil",
                         "Código de Processo Civil", "Lei Maria da Penha",
                         "Estatuto da Criança e do Adolescente"):
            self.assertIn(esperado, nomes)
        self.assertTrue({"penal", "civel"} <= {area["id"] for area in self.acervo["areas"]})

    def test_conteudo_marcado_como_demonstrativo(self):
        for chave in ("leis", "erros", "ebooks"):
            for item in self.acervo[chave]:
                self.assertEqual(item.get("status"), "demonstrativo", f"{chave}: {item['id']}")

    def test_normalizar_ignora_acento_e_caixa(self):
        self.assertEqual(normalizar("Tráfico  PRIVILEGIADO"), "trafico privilegiado")

    def test_busca_encontra_por_palavras_sem_acento(self):
        titulos = [r["titulo"] for r in buscar(self.acervo, "trafico privilegiado")]
        self.assertEqual(titulos[0], "Tráfico privilegiado")
        self.assertIn("Guarda compartilhada", [r["titulo"] for r in buscar(self.acervo, "GUARDA")])
        self.assertIn("Código Civil", [r["titulo"] for r in buscar(self.acervo, "10.406")])

    def test_busca_vazia_ou_sem_resultado(self):
        self.assertEqual(buscar(self.acervo, "   "), [])
        self.assertEqual(buscar(self.acervo, "termo inexistente xyz"), [])

    def test_validacao_aponta_arquivo_e_problema(self):
        with tempfile.TemporaryDirectory() as tmp:
            destino = Path(tmp) / "dados"
            shutil.copytree(DADOS_DIR, destino)
            (destino / "ebooks.json").write_text('{"ebooks": [{"id": "x", "titulo": "X", "area": "tributario"}]}', encoding="utf-8")
            with self.assertRaisesRegex(ConteudoInvalido, "ebooks.json.*área desconhecida"):
                carregar_acervo(destino)
            (destino / "erros.json").write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(ConteudoInvalido, "erros.json: JSON inválido"):
                carregar_acervo(destino)


class ServidorTest(unittest.TestCase):
    def setUp(self):
        self.server = ConsultaPenalServer(port=0)
        self.server.quiet = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def get(self, path, host=None, method="GET"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, headers={"Host": host or f"127.0.0.1:{self.port}"})
        resp = conn.getresponse()
        corpo = resp.read()
        conn.close()
        return resp, corpo

    def test_pagina_e_estaticos_com_csp(self):
        for caminho in ("/", "/static/app.css", "/static/app.js"):
            resp, _ = self.get(caminho)
            self.assertEqual(resp.status, 200, caminho)
            self.assertIn("default-src 'none'", resp.getheader("Content-Security-Policy"))

    def test_api_painel_e_busca(self):
        resp, corpo = self.get("/api/painel")
        self.assertEqual(resp.status, 200)
        self.assertEqual(len(json.loads(corpo)["leis"]), 6)
        resp, corpo = self.get("/api/busca?q=alimentos")
        self.assertIn("Alimentos", [r["titulo"] for r in json.loads(corpo)["resultados"]])

    def test_host_estranho_metodo_e_caminho_bloqueados(self):
        self.assertEqual(self.get("/", host="evil.example")[0].status, 403)
        self.assertEqual(self.get("/../server.py")[0].status, 404)
        self.assertEqual(self.get("/", method="POST")[0].status, 405)


if __name__ == "__main__":
    unittest.main()
