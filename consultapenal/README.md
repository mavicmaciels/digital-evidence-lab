# Consulta Penal (v0.2)

Plataforma local de consulta jurídica prática (Penal, Cível e Família). O conteúdo é
cadastrado manualmente em arquivos JSON e conferido pela autora. A busca localiza apenas
o que está cadastrado; **nenhum conteúdo é gerado por inteligência artificial**.

> **Conteúdo atual é demonstrativo e fictício**, usado só para visualizar o layout.
> Não constitui orientação jurídica validada.

## Como iniciar

```bash
python3 -m consultapenal            # abre http://127.0.0.1:8765/ no navegador
python3 -m consultapenal --port 9000 --no-browser
```

Requer Python 3.10+ e nenhuma dependência externa. O servidor escuta apenas em 127.0.0.1.

## Onde cadastrar o conteúdo

Todo o conteúdo do painel vem de `consultapenal/dados/`. Edite o arquivo e recarregue a
página — não é preciso reiniciar o servidor.

| Arquivo | O que contém | Campos obrigatórios |
|---|---|---|
| `painel.json` | Nome, títulos, aviso, sugestões de busca e `links_rapidos` (ids de leis) | `nome` |
| `leis.json` | Diplomas legais (com `fonte_oficial`) | `id`, `sigla`, `nome`, `norma`, `area` |
| `areas.json` | Áreas (Penal, Cível, Família) | `id`, `nome`, `descricao` |
| `temas/<id>.json` | **Fichas temáticas**, uma por arquivo | `id`, `titulo`, `area`, `resumo`, `status` |
| `jurisprudencia.json` | Julgados selecionados (só referência, sem trechos) | `id`, `area`, `tribunal`, `assunto` |
| `erros.json` | Erros recorrentes de escrita (incorreto → correto) | `id`, `titulo`, `incorreto`, `correto` |
| `ebooks.json` | Vitrine de ebooks (`capa`: `bordo`, `grafite` ou `areia`) | `id`, `titulo`, `area` |
| `consultas_recentes.json` | Consulta a retomar (`tema` aponta para uma ficha) | `id`, `titulo`, `area`, `etapas` |

Áreas válidas: `penal`, `civel`, `familia`. Ids usam letras minúsculas, números e hífens e
devem ser únicos. Se um arquivo estiver inválido, o painel exibe o arquivo e o problema.

### Ficha temática

Copie `dados/temas/_modelo.json` para `dados/temas/<id>.json` (o nome do arquivo deve
ser igual ao `id`; arquivos iniciados por `_` não são carregados).

| Campo | Conteúdo |
|---|---|
| `status` | `rascunho`, `demonstrativo` ou `conferido` |
| `revisado_em` | `null` ou data `AAAA-MM-DD` da última conferência |
| `ordem` | posição dentro da área (opcional) |
| `palavras_chave` | termos extras para a busca e o filtro |
| `resumo` | síntese do tema |
| `base_legal` | `[{"lei": "<id em leis.json>", "dispositivos": "…", "observacao": "…"}]` |
| `jurisprudencia` | ids de `jurisprudencia.json` |
| `checklist` | lista de textos (as marcações ficam só no navegador) |
| `erros` | ids de `erros.json` |
| `ebooks` | ids de `ebooks.json` |
| `relacionados` | ids de outras fichas |
| `observacoes` | texto livre |

Todas as referências são conferidas ao carregar: um id inexistente gera erro indicando
a ficha e o campo.

## Páginas

| Endereço | Página |
|---|---|
| `#/` | Visão geral |
| `#/leis-e-temas` e `#/leis-e-temas/<area>` | Fichas e legislação por área, com filtro |
| `#/temas/<id>` | Ficha temática |
| `#/leis/<id>` | Lei, com link para a fonte oficial e fichas que a citam |

## Estrutura

```
consultapenal/
├── __main__.py     # python -m consultapenal
├── server.py       # servidor local somente leitura (GET), CSP restritiva
├── conteudo.py     # leitura/validação dos JSON, referências cruzadas e busca
├── dados/          # conteúdo cadastrável (temas/ = fichas)
└── static/         # index.html, app.css e js/ (app, ui, painel, temas)
```

Testes: `python3 -m unittest tests.test_consultapenal`.

## Documentação

O caderno do projeto (ebook em PDF, com o estado atual, modelo de dados e capturas de tela)
está em `docs/consultapenal/ebook/consulta-penal-caderno-do-projeto.pdf`; a fonte é
`docs/consultapenal/ebook/ebook.html`.
