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
        for chave in ("leis", "erros", "ebooks", "temas", "jurisprudencia"):
            for item in self.acervo[chave]:
                self.assertEqual(item.get("status"), "demonstrativo", f"{chave}: {item['id']}")

    def test_fichas_por_area_e_ordenadas(self):
        temas = self.acervo["temas"]
        for area in ("penal", "civel", "familia"):
            self.assertTrue([f for f in temas if f["area"] == area], area)
        penal = [f["id"] for f in temas if f["area"] == "penal"]
        self.assertEqual(penal[0], "trafico-privilegiado")

    def test_ficha_completa_resolve_todas_as_relacoes(self):
        ficha = next(f for f in self.acervo["temas"] if f["id"] == "guarda-compartilhada")
        for campo in ("base_legal", "jurisprudencia", "checklist", "erros", "ebooks", "relacionados"):
            self.assertTrue(ficha[campo], campo)

    def test_ficha_parcial_recebe_listas_vazias(self):
        ficha = next(f for f in self.acervo["temas"] if f["id"] == "alimentos")
        self.assertEqual(ficha["jurisprudencia"], [])
        self.assertEqual(ficha["checklist"], [])

    def test_jurisprudencia_demonstrativa_sem_trechos(self):
        for julgado in self.acervo["jurisprudencia"]:
            for campo in ("ementa", "tese", "trecho"):
                self.assertNotIn(campo, julgado)

    def test_modelo_de_ficha_nao_e_carregado(self):
        self.assertTrue((DADOS_DIR / "temas" / "_modelo.json").exists())
        self.assertNotIn("nome-do-arquivo-sem-extensao", {f["id"] for f in self.acervo["temas"]})

    def test_normalizar_ignora_acento_e_caixa(self):
        self.assertEqual(normalizar("Tráfico  PRIVILEGIADO"), "trafico privilegiado")

    def test_busca_encontra_por_palavras_sem_acento(self):
        titulos = [r["titulo"] for r in buscar(self.acervo, "trafico privilegiado")]
        self.assertEqual(titulos[0], "Tráfico privilegiado")
        self.assertIn("Guarda compartilhada", [r["titulo"] for r in buscar(self.acervo, "GUARDA")])
        self.assertIn("Código Civil", [r["titulo"] for r in buscar(self.acervo, "10.406")])
        # palavra-chave cadastrada na ficha
        self.assertEqual(buscar(self.acervo, "pensao")[0]["id"], "alimentos")

    def test_busca_vazia_ou_sem_resultado(self):
        self.assertEqual(buscar(self.acervo, "   "), [])
        self.assertEqual(buscar(self.acervo, "termo inexistente xyz"), [])

    def _copia(self, tmp):
        destino = Path(tmp) / "dados"
        shutil.copytree(DADOS_DIR, destino)
        return destino

    def _editar_ficha(self, destino, id_, **mudancas):
        caminho = destino / "temas" / f"{id_}.json"
        ficha = json.loads(caminho.read_text(encoding="utf-8"))
        ficha.update(mudancas)
        caminho.write_text(json.dumps(ficha, ensure_ascii=False), encoding="utf-8")

    def test_referencia_inexistente_na_ficha(self):
        casos = [
            ({"base_legal": [{"lei": "lei-inexistente"}]}, "referência a leis inexistente"),
            ({"jurisprudencia": ["nao-existe"]}, "referência a jurisprudencia inexistente"),
            ({"erros": ["nao-existe"]}, "referência a erros inexistente"),
            ({"ebooks": ["nao-existe"]}, "referência a ebooks inexistente"),
            ({"relacionados": ["nao-existe"]}, "referência a temas inexistente"),
            ({"relacionados": ["alimentos"]}, "relacionada a si mesma"),
        ]
        for mudanca, mensagem in casos:
            with self.subTest(mensagem=mensagem), tempfile.TemporaryDirectory() as tmp:
                destino = self._copia(tmp)
                self._editar_ficha(destino, "alimentos", **mudanca)
                with self.assertRaisesRegex(ConteudoInvalido, "temas/alimentos.json.*" + mensagem):
                    carregar_acervo(destino)

    def test_ficha_com_formato_invalido(self):
        casos = [
            ({"id": "outro-id"}, "deve ser igual ao nome do arquivo"),
            ({"resumo": ""}, "sem resumo"),
            ({"area": "tributario"}, "área desconhecida"),
            ({"revisado_em": "08/10/2026"}, "AAAA-MM-DD"),
            ({"checklist": "texto solto"}, "deve ser uma lista"),
        ]
        for mudanca, mensagem in casos:
            with self.subTest(mensagem=mensagem), tempfile.TemporaryDirectory() as tmp:
                destino = self._copia(tmp)
                self._editar_ficha(destino, "alimentos", **mudanca)
                with self.assertRaisesRegex(ConteudoInvalido, mensagem):
                    carregar_acervo(destino)

    def test_links_rapidos_e_consulta_recente_conferidos(self):
        with tempfile.TemporaryDirectory() as tmp:
            destino = self._copia(tmp)
            painel = json.loads((destino / "painel.json").read_text(encoding="utf-8"))
            painel["links_rapidos"].append("nao-existe")
            (destino / "painel.json").write_text(json.dumps(painel), encoding="utf-8")
            with self.assertRaisesRegex(ConteudoInvalido, "links_rapidos"):
                carregar_acervo(destino)

    def test_validacao_aponta_arquivo_e_problema(self):
        with tempfile.TemporaryDirectory() as tmp:
            destino = self._copia(tmp)
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
        for caminho in ("/", "/static/app.css", "/static/js/app.js", "/static/js/ui.js",
                        "/static/js/painel.js", "/static/js/temas.js"):
            resp, _ = self.get(caminho)
            self.assertEqual(resp.status, 200, caminho)
            self.assertIn("default-src 'none'", resp.getheader("Content-Security-Policy"))

    def test_api_painel_e_busca(self):
        resp, corpo = self.get("/api/painel")
        self.assertEqual(resp.status, 200)
        acervo = json.loads(corpo)
        self.assertEqual(len(acervo["painel"]["links_rapidos"]), 6)
        self.assertEqual(len(acervo["temas"]), 12)
        resp, corpo = self.get("/api/busca?q=alimentos")
        self.assertIn("Alimentos", [r["titulo"] for r in json.loads(corpo)["resultados"]])

    def test_host_estranho_metodo_e_caminho_bloqueados(self):
        self.assertEqual(self.get("/", host="evil.example")[0].status, 403)
        self.assertEqual(self.get("/../server.py")[0].status, 404)
        self.assertEqual(self.get("/static/js/../../server.py")[0].status, 404)
        self.assertEqual(self.get("/dados/painel.json")[0].status, 404)
        self.assertEqual(self.get("/", method="POST")[0].status, 405)


if __name__ == "__main__":
    unittest.main()
