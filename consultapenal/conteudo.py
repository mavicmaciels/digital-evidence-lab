"""Acervo da plataforma: leitura e validação dos arquivos de dados e busca local.

Todo o conteúdo exibido vem dos arquivos JSON em `dados/`. Para cadastrar ou atualizar
leis, fichas temáticas, jurisprudência, erros recorrentes, ebooks ou consultas recentes,
edite o arquivo correspondente; a interface não contém textos jurídicos fixos.

Fichas temáticas ficam em `dados/temas/<id>.json` (uma por arquivo; arquivos iniciados
por "_" são modelos e não são carregados). As referências de cada ficha a leis,
jurisprudência, erros, ebooks e temas relacionados são conferidas na leitura: um id
inexistente gera erro com o nome do arquivo, em vez de um link quebrado na tela.

A busca é determinística: compara palavras normalizadas (sem acento, sem caixa) com o
conteúdo cadastrado. Nenhuma resposta é gerada ou inferida.
"""

import json
import re
import unicodedata
from pathlib import Path

DADOS_DIR = Path(__file__).resolve().parent / "dados"
AREAS_VALIDAS = {"penal", "civel", "familia"}
ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
DATA_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MAX_CONSULTA = 120
MAX_RESULTADOS = 20

# arquivo -> (chave da lista, campos obrigatórios de cada item)
ESQUEMA = {
    "leis.json": ("leis", ("id", "sigla", "nome", "norma", "area")),
    "areas.json": ("areas", ("id", "nome", "descricao")),
    "jurisprudencia.json": ("jurisprudencia", ("id", "area", "tribunal", "assunto")),
    "erros.json": ("erros", ("id", "titulo", "incorreto", "correto")),
    "ebooks.json": ("ebooks", ("id", "titulo", "area")),
    "consultas_recentes.json": ("consultas", ("id", "titulo", "area", "etapas")),
}

CAMPOS_FICHA = ("id", "titulo", "area", "resumo", "status")
# campo da ficha -> coleção cujos ids ele referencia
LISTAS_FICHA = {
    "jurisprudencia": "jurisprudencia",
    "erros": "erros",
    "ebooks": "ebooks",
    "relacionados": "temas",
}


class ConteudoInvalido(Exception):
    """Arquivo de dados ausente ou fora do formato esperado."""


def _ler(caminho: Path, nome: str):
    try:
        with caminho.open(encoding="utf-8") as arquivo:
            return json.load(arquivo)
    except FileNotFoundError as exc:
        raise ConteudoInvalido(f"{nome}: arquivo não encontrado") from exc
    except json.JSONDecodeError as exc:
        raise ConteudoInvalido(f"{nome}: JSON inválido (linha {exc.lineno}, coluna {exc.colno})") from exc


def _validar_item(nome: str, item, rotulo: str, campos: tuple) -> None:
    if not isinstance(item, dict):
        raise ConteudoInvalido(f"{nome}: {rotulo} não é um objeto")
    faltando = [campo for campo in campos if item.get(campo) in (None, "")]
    if faltando:
        raise ConteudoInvalido(f"{nome}: {rotulo} sem {', '.join(faltando)}")
    if not isinstance(item["id"], str) or not ID_RE.match(item["id"]):
        raise ConteudoInvalido(f"{nome}: id \"{item['id']}\" inválido (use letras minúsculas, números e hífens)")


def _validar_lista(nome: str, documento, chave: str, campos: tuple) -> list:
    itens = documento.get(chave) if isinstance(documento, dict) else None
    if not isinstance(itens, list):
        raise ConteudoInvalido(f"{nome}: esperada a lista \"{chave}\"")
    vistos = set()
    for posicao, item in enumerate(itens, start=1):
        _validar_item(nome, item, f"item {posicao}", campos)
        if item["id"] in vistos:
            raise ConteudoInvalido(f"{nome}: id repetido \"{item['id']}\"")
        vistos.add(item["id"])
        area = item.get("area", item["id"] if chave == "areas" else None)
        if area is not None and area not in AREAS_VALIDAS:
            raise ConteudoInvalido(f"{nome}: item \"{item['id']}\" com área desconhecida \"{area}\"")
    return itens


def _carregar_fichas(dados_dir: Path) -> list[dict]:
    pasta = dados_dir / "temas"
    if not pasta.is_dir():
        raise ConteudoInvalido("temas/: pasta não encontrada")
    fichas = []
    for caminho in sorted(pasta.glob("*.json")):
        if caminho.name.startswith("_"):
            continue
        nome = f"temas/{caminho.name}"
        ficha = _ler(caminho, nome)
        _validar_item(nome, ficha, "ficha", CAMPOS_FICHA)
        if ficha["id"] != caminho.stem:
            raise ConteudoInvalido(f"{nome}: o id \"{ficha['id']}\" deve ser igual ao nome do arquivo")
        if ficha["area"] not in AREAS_VALIDAS:
            raise ConteudoInvalido(f"{nome}: área desconhecida \"{ficha['area']}\"")
        revisado = ficha.get("revisado_em")
        if revisado is not None and not (isinstance(revisado, str) and DATA_RE.match(revisado)):
            raise ConteudoInvalido(f"{nome}: \"revisado_em\" deve ser null ou AAAA-MM-DD")
        for campo in ("palavras_chave", "base_legal", "checklist", *LISTAS_FICHA):
            valor = ficha.setdefault(campo, [])
            if not isinstance(valor, list):
                raise ConteudoInvalido(f"{nome}: \"{campo}\" deve ser uma lista")
        for posicao, base in enumerate(ficha["base_legal"], start=1):
            if not isinstance(base, dict) or not base.get("lei"):
                raise ConteudoInvalido(f"{nome}: base_legal {posicao} sem \"lei\"")
        if not all(isinstance(item, str) and item.strip() for item in ficha["checklist"]):
            raise ConteudoInvalido(f"{nome}: itens do checklist devem ser textos")
        fichas.append(ficha)
    fichas.sort(key=lambda f: (f.get("ordem", 999), normalizar(f["titulo"])))
    return fichas


def _conferir_referencias(acervo: dict) -> None:
    ids = {chave: {item["id"] for item in acervo[chave]}
           for chave in ("leis", "jurisprudencia", "erros", "ebooks", "temas")}

    def exigir(origem: str, colecao: str, ref) -> None:
        if ref not in ids[colecao]:
            raise ConteudoInvalido(f"{origem}: referência a {colecao} inexistente \"{ref}\"")

    for ficha in acervo["temas"]:
        origem = f"temas/{ficha['id']}.json"
        for base in ficha["base_legal"]:
            exigir(origem, "leis", base["lei"])
        for campo, colecao in LISTAS_FICHA.items():
            for ref in ficha[campo]:
                exigir(origem, colecao, ref)
        if ficha["id"] in ficha["relacionados"]:
            raise ConteudoInvalido(f"{origem}: a ficha não pode ser relacionada a si mesma")
    for ref in acervo["painel"].get("links_rapidos", []):
        exigir("painel.json (links_rapidos)", "leis", ref)
    for consulta in acervo["consultas"]:
        if consulta.get("tema"):
            exigir("consultas_recentes.json", "temas", consulta["tema"])


def carregar_acervo(dados_dir: Path = DADOS_DIR) -> dict:
    """Lê e valida todos os arquivos de dados. Lido a cada requisição: editar o JSON
    e recarregar a página basta para ver a alteração."""
    dados_dir = Path(dados_dir)
    painel = _ler(dados_dir / "painel.json", "painel.json")
    if not isinstance(painel, dict) or not painel.get("nome"):
        raise ConteudoInvalido("painel.json: campo \"nome\" obrigatório")
    acervo = {"painel": painel}
    for nome, (chave, campos) in ESQUEMA.items():
        acervo[chave] = _validar_lista(nome, _ler(dados_dir / nome, nome), chave, campos)
    acervo["temas"] = _carregar_fichas(dados_dir)
    _conferir_referencias(acervo)
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
    for ficha in acervo["temas"]:
        itens.append({
            "tipo": "Tema", "id": ficha["id"], "area": ficha["area"],
            "titulo": ficha["titulo"], "descricao": ficha["resumo"],
            "texto": " ".join([ficha["titulo"], ficha["resumo"], *ficha["palavras_chave"]]),
        })
    for julgado in acervo["jurisprudencia"]:
        itens.append({
            "tipo": "Jurisprudência", "id": julgado["id"], "area": julgado["area"],
            "titulo": julgado["assunto"], "descricao": julgado["tribunal"],
            "texto": " ".join(str(julgado.get(c, "")) for c in ("assunto", "tribunal", "classe", "numero")),
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
