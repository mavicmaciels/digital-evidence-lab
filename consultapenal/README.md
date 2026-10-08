# Consulta Penal — painel inicial (v0.1)

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
| `painel.json` | Nome, títulos, aviso e sugestões de busca | `nome` |
| `leis.json` | Links rápidos para diplomas legais | `id`, `sigla`, `nome`, `norma`, `area` |
| `areas.json` | Cartões por área e seus temas | `id`, `nome`, `descricao`, `temas` |
| `erros.json` | Erros recorrentes de escrita (incorreto → correto) | `id`, `titulo`, `incorreto`, `correto` |
| `ebooks.json` | Vitrine de ebooks (`capa`: `bordo`, `grafite` ou `areia`) | `id`, `titulo`, `area` |
| `consultas_recentes.json` | Consulta a retomar, com etapas | `id`, `titulo`, `area`, `etapas` |

Áreas válidas: `penal`, `civel`, `familia`. Ids devem ser únicos em cada arquivo. Se um
arquivo estiver inválido, o painel exibe uma mensagem indicando o arquivo e o problema.

## Estrutura

```
consultapenal/
├── __main__.py     # python -m consultapenal
├── server.py       # servidor local somente leitura (GET), CSP restritiva
├── conteudo.py     # leitura/validação dos JSON e busca sem acento/caixa
├── dados/          # conteúdo cadastrável
└── static/         # index.html, app.css, app.js (sem dependências externas)
```

Testes: `python3 -m unittest tests.test_consultapenal`.
