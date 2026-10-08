"""Acervo da plataforma: leitura e validação dos arquivos de dados e busca local.

Todo o conteúdo exibido no painel vem dos arquivos JSON em `dados/`. Para cadastrar ou
atualizar leis, temas, erros recorrentes, ebooks ou consultas recentes, edite o arquivo
correspondente; a interface não contém textos jurídicos fixos.

A busca é determinística: compara palavras normalizadas (sem acento, sem caixa) com o
conteúdo cadastrado. Nenhuma resposta é gerada ou inferida.
"""

import json
import re
import unicodedata
from pathlib import Path

DADOS_DIR = Path(__file__).resolve().parent / "dados"
AREAS_VALIDAS = {"penal", "civel", "familia"}
MAX_CONSULTA = 120
MAX_RESULTADOS = 20

# arquivo -> (chave da lista, campos obrigatórios de cada item)
ESQUEMA = {
    "leis.json": ("leis", ("id", "sigla", "nome", "norma", "area")),
    "areas.json": ("areas", ("id", "nome", "descricao", "temas")),
    "erros.json": ("erros", ("id", "titulo", "incorreto", "correto")),
    "ebooks.json": ("ebooks", ("id", "titulo", "area")),
    "consultas_recentes.json": ("consultas", ("id", "titulo", "area", "etapas")),
}


class ConteudoInvalido(Exception):
    """Arquivo de dados ausente ou fora do formato esperado."""


def _ler(dados_dir: Path, nome: str):
    caminho = dados_dir / nome
    try:
        with caminho.open(encoding="utf-8") as arquivo:
            return json.load(arquivo)
    except FileNotFoundError as exc:
        raise ConteudoInvalido(f"{nome}: arquivo não encontrado") from exc
    except json.JSONDecodeError as exc:
        raise ConteudoInvalido(f"{nome}: JSON inválido (linha {exc.lineno}, coluna {exc.colno})") from exc


def _validar_lista(nome: str, documento, chave: str, campos: tuple) -> list:
    itens = documento.get(chave) if isinstance(documento, dict) else None
    if not isinstance(itens, list):
        raise ConteudoInvalido(f"{nome}: esperada a lista \"{chave}\"")
    vistos = set()
    for posicao, item in enumerate(itens, start=1):
        if not isinstance(item, dict):
            raise ConteudoInvalido(f"{nome}: item {posicao} não é um objeto")
        faltando = [campo for campo in campos if item.get(campo) in (None, "")]
        if faltando:
            raise ConteudoInvalido(f"{nome}: item {posicao} sem {', '.join(faltando)}")
        if item["id"] in vistos:
            raise ConteudoInvalido(f"{nome}: id repetido \"{item['id']}\"")
        vistos.add(item["id"])
        area = item.get("area", item["id"] if chave == "areas" else None)
        if area is not None and area not in AREAS_VALIDAS:
            raise ConteudoInvalido(f"{nome}: item \"{item['id']}\" com área desconhecida \"{area}\"")
    return itens


def carregar_acervo(dados_dir: Path = DADOS_DIR) -> dict:
    """Lê e valida todos os arquivos de dados. Lido a cada requisição: editar o JSON
    e recarregar a página basta para ver a alteração."""
    painel = _ler(dados_dir, "painel.json")
    if not isinstance(painel, dict) or not painel.get("nome"):
        raise ConteudoInvalido("painel.json: campo \"nome\" obrigatório")
    acervo = {"painel": painel}
    for nome, (chave, campos) in ESQUEMA.items():
        acervo[chave] = _validar_lista(nome, _ler(dados_dir, nome), chave, campos)
    return acervo


def normalizar(texto: str) -> str:
    decomposto = unicodedata.normalize("NFKD", texto.casefold())
    sem_acento = "".join(ch for ch in decomposto if not unicodedata.combining(ch))
    return re.sub(r"[^0-9a-z§]+", " ", sem_acento).strip()


def _indice(acervo: dict) -> list[dict]:
    """Lista plana de itens pesquisáveis: título, descrição e texto completo."""
    itens = []
    for lei in acervo["leis"]:
        itens.append({
            "tipo": "Lei", "id": lei["id"], "area": lei["area"],
            "titulo": lei["nome"], "descricao": lei["norma"],
            "texto": " ".join([lei["sigla"], lei["nome"], lei["norma"], *lei.get("palavras_chave", [])]),
        })
    for area in acervo["areas"]:
        for tema in area["temas"]:
            itens.append({
                "tipo": "Tema", "id": tema["id"], "area": area["id"],
                "titulo": tema["titulo"], "descricao": tema.get("resumo", ""),
                "texto": " ".join([tema["titulo"], tema.get("resumo", ""), area["nome"]]),
            })
    for erro in acervo["erros"]:
        itens.append({
            "tipo": "Erro recorrente", "id": erro["id"], "area": None,
            "titulo": erro["titulo"], "descricao": erro["correto"],
            "texto": " ".join([erro["titulo"], erro.get("categoria", ""), erro["incorreto"],
                               erro["correto"], erro.get("explicacao", "")]),
        })
    for ebook in acervo["ebooks"]:
        itens.append({
            "tipo": "Ebook", "id": ebook["id"], "area": ebook["area"],
            "titulo": ebook["titulo"], "descricao": ebook.get("descricao", ""),
            "texto": " ".join([ebook["titulo"], ebook.get("subtitulo", ""), ebook.get("descricao", "")]),
        })
    return itens


def buscar(acervo: dict, consulta: str, limite: int = MAX_RESULTADOS) -> list[dict]:
    """Retorna os itens que contêm todas as palavras da consulta, títulos primeiro."""
    termos = normalizar(consulta[:MAX_CONSULTA]).split()
    if not termos:
        return []
    resultados = []
    for item in _indice(acervo):
        titulo = normalizar(item["titulo"])
        texto = normalizar(item["texto"])
        if all(termo in texto for termo in termos):
            pontos = sum(2 for termo in termos if termo in titulo) + (3 if titulo.startswith(termos[0]) else 0)
            resultados.append((pontos, item))
    resultados.sort(key=lambda par: (-par[0], normalizar(par[1]["titulo"])))
    return [{k: v for k, v in item.items() if k != "texto"} for _, item in resultados[:limite]]
