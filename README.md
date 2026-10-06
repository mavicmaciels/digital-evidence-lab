# Digital Evidence Lab

[![Tests](https://github.com/mavicmaciels/digital-evidence-lab/actions/workflows/tests.yml/badge.svg)](https://github.com/mavicmaciels/digital-evidence-lab/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Triagem forense de e-mails suspeitos (`.eml`) com preservação de evidência e cadeia de custódia.**

Ferramenta de linha de comando em Python (somente biblioteca padrão) que reproduz, em
escala de laboratório, o fluxo de trabalho de um analista de DFIR diante de um possível
phishing: adquirir a evidência sem alterá-la, registrar hashes, extrair metadados,
avaliar indicadores de suspeita e documentar cada etapa em uma cadeia de custódia
verificável.

> [!IMPORTANT]
> **Aviso:** projeto com finalidade **educacional e de portfólio**. Não substitui
> perícia forense oficial, laudo pericial nem procedimentos institucionais de
> preservação de evidências (por exemplo, os previstos nos arts. 158-A a 158-F do
> Código de Processo Penal ou na ABNT NBR ISO/IEC 27037). Os resultados são apoio à
> triagem e não constituem prova de fraude, de autenticidade ou de autoria.

---

## Objetivo

Demonstrar, de forma prática e testada, competências de:

- **Resposta a incidentes / DFIR:** aquisição, hashing, verificação de integridade,
  linha do tempo e documentação.
- **Análise de phishing:** leitura de cabeçalhos, rota `Received`, resultados de
  SPF/DKIM/DMARC, links e anexos.
- **Desenvolvimento seguro:** tratar o e-mail como entrada hostil e não executar,
  não acessar nem exibir sem neutralizar nada que venha dele.
- **Rigor terminológico:** separar o que a ferramenta *verifica* (integridade da cópia)
  do que ela *não pode afirmar* (autenticidade do conteúdo, autoria).

## Funcionalidades

| Etapa | O que faz |
|---|---|
| **Aquisição** | Copia o `.eml` para `casos/<nome>/evidencia/` com criação exclusiva (nunca sobrescreve), preserva os timestamps do arquivo e marca a cópia como somente leitura. O original é apenas lido. |
| **SHA-256** | Calcula o hash do original **antes e depois** da cópia e o da cópia de trabalho. Os três têm de coincidir. |
| **Metadados** | Cabeçalhos principais (com decodificação RFC 2047), saltos `Received` em ordem cronológica (IP, hosts, protocolo, data original e em UTC), `Authentication-Results`, links (texto e HTML) e anexos, inclusive dentro de mensagens encaminhadas, com SHA-256 de cada um. |
| **Autenticação** | Classifica SPF, DKIM e DMARC em **aprovado / falha / falha fraca / inconclusivo / ausente**. Ausência e inconclusivo são apenas informativos e não pontuam. |
| **Indicadores** | Heurísticas com severidade (alta/média/baixa/info), como DMARC `fail`, links para IP, texto do link que mostra um domínio e leva a outro, domínio do remetente usado como subdomínio de outro domínio, punycode, esquemas `javascript:`/`data:`, anexos executáveis, imagens de disco, Office com macros, extensão dupla, caracteres bidirecionais em nomes de arquivo e linguagem de urgência. |
| **Integridade** | Recalcula o hash após a análise. O comando `verify` repete a verificação depois e registra o resultado. |
| **Timeline** | Une eventos do e-mail e da custódia em uma linha do tempo única, em UTC. |
| **Cadeia de custódia** | Registro append-only em JSON, persistido a cada evento, com **encadeamento de hashes** (`prev_hash` → `event_hash`) que revela edições posteriores. |
| **Relatórios** | Painel no terminal, `relatorio_<nome>.json` (para ferramentas) e `relatorio_<nome>.md` (para pessoas, com URLs desarmadas). |

## Exemplo de uso

Requer **Python 3.10+**, sem dependências externas.

```bash
# Adquirir e analisar (cria casos/email_suspeito/)
python3 -m evidencelab analyze samples/email_suspeito.eml --examiner "Nome do analista"

# Opcional: considerar apenas os Authentication-Results emitidos pelo seu servidor
python3 -m evidencelab analyze mensagem.eml --authserv-id mx.suaempresa.com.br

# Reverificar depois a integridade da cópia e do registro de custódia
python3 -m evidencelab verify casos/email_suspeito
```

Saída (resumida) para o exemplo fictício incluído:

```
[✓] Arquivo adquirido (cópia somente leitura)
[✓] SHA-256 calculado
[✓] Metadados extraídos
[✓] Integridade verificada (hash inalterado)
[✓] Timeline construída (UTC)

SHA-256
723de153...6d31

CADEIA DE CUSTÓDIA (UTC)
14:07  Coleta
14:07  Hash inicial
14:07  Análise
14:07  Verificação de integridade
14:07  Relatório

INTEGRIDADE DA CÓPIA DE TRABALHO
● VERIFICADA (hash inalterado)

AUTENTICAÇÃO (declarada por mx.vitima.example)
  SPF   falha (fail)
  DKIM  ausente (none)
  DMARC falha (fail)

NÍVEL DE SUSPEITA (heurístico): ALTO  [pontuação 20]
  [alta ] DMARC = fail (declarado por mx.vitima.example); indício, não prova: ...
  [alta ] Link aponta para endereço IP: hxxp://203[.]0[.]113[.]45/banco/login.php?id=8812
  [alta ] Anexo executável com extensão dupla: Comprovante_Bloqueio.pdf.exe
  ...

Notas:
- O hash atesta apenas que a cópia de trabalho não foi alterada desde a aquisição.
  Não comprova a autenticidade do conteúdo nem a autoria da mensagem.
- O nível de suspeita é heurístico: indica prioridade de análise, não prova fraude nem legitimidade.
```

Códigos de saída: `0` sucesso; `1` falha de integridade, de encadeamento da custódia ou
erro de análise; `2` arquivo ou caso não encontrado.

## Arquitetura

```
           ┌──────────┐   ┌──────────┐   ┌────────────────┐   ┌────────────┐   ┌──────────┐
 .eml ───▶ │ aquisição│──▶│ SHA-256  │──▶│ email_analysis │──▶│ integridade│──▶│ timeline │──▶ relatórios
           └────┬─────┘   └────┬─────┘   └───────┬────────┘   └─────┬──────┘   └──────────┘
                │              │                 │                  │
                └──────────────┴────── custody (registro encadeado, salvo a cada evento) ──────┘
```

- **`case.py`** orquestra o fluxo e é o único módulo que escreve no diretório do caso.
- **`email_analysis.py`** é puro: recebe um caminho e devolve estruturas de dados, sem
  efeitos colaterais.
- **`sanitize.py`** concentra a neutralização de conteúdo hostil (controle/ANSI/bidi,
  Markdown, defang de URLs). Toda saída para humanos passa por ele.
- **`custody.py`** implementa o registro com encadeamento de hashes e gravação atômica.

## Estrutura de diretórios

```
digital-evidence-lab/
├── evidencelab/
│   ├── __main__.py        # python -m evidencelab
│   ├── cli.py             # subcomandos analyze / verify
│   ├── case.py            # aquisição, verificação e orquestração do caso
│   ├── custody.py         # cadeia de custódia com encadeamento de hashes
│   ├── email_analysis.py  # parsing do .eml, SPF/DKIM/DMARC, links, anexos, indicadores
│   ├── hashing.py         # SHA-256 em blocos
│   ├── report.py          # painel, JSON e Markdown
│   ├── sanitize.py        # escape de controle/bidi, Markdown seguro, defang
│   └── timeline.py        # linha do tempo unificada em UTC
├── samples/
│   └── email_suspeito.eml # phishing fictício (domínios .example, IPs RFC 5737)
├── tests/
│   └── test_evidencelab.py
├── .github/workflows/
│   └── tests.yml          # CI: unittest em Python 3.10–3.13
├── LICENSE                # MIT
└── README.md

casos/<nome>/              # gerado em tempo de execução (ignorado pelo git)
├── evidencia/<arquivo>.eml   # cópia de trabalho, somente leitura
├── cadeia_custodia.json
├── relatorio_<nome>.json
└── relatorio_<nome>.md
```

## Testes

```bash
python3 -m unittest -v
```

São 37 testes, organizados em grupos:

- **Hash:** valor conhecido do SHA-256 (vetor `abc`) e abreviação.
- **Preservação:** o original mantém hash, `mtime` e permissões após o fluxo completo; a
  cópia fica sem permissão de escrita e com o mesmo `mtime`; aquisição repetida e uma
  segunda evidência no mesmo caso são recusadas.
- **Custódia:** ordem dos eventos, timestamps em UTC, adulteração da evidência e
  adulteração do JSON de custódia detectadas pelo `verify`.
- **SPF/DKIM/DMARC:** ausência, `none`, inconclusivo (`temperror`, `neutral`,
  `permerror`), falhas, comentários e chaves parecidas (`x-dkim=`) ignorados,
  cabeçalho forjado mais abaixo desconsiderado, `--authserv-id` e várias assinaturas DKIM.
- **Falsos positivos:** e-mail corporativo legítimo (com "senha" e Reply-To de helpdesk)
  classificado como BAIXO; subdomínios da mesma organização; sufixos como `.com.br`.
- **Robustez:** datas sem fuso, URL malformada, IPv6 em `Received`, anexo dentro de
  `message/rfc822`, nome de arquivo com caractere bidirecional, link `javascript:`.
- **Segurança:** nenhuma conexão de rede nem criação de processo durante o fluxo
  (`socket`, `subprocess`, `os.system` bloqueados no teste); nenhum anexo gravado no
  disco; sequências ANSI e HTML neutralizados no terminal e no Markdown.

## Aspectos de segurança

- **Nada é executado nem acessado.** Anexos são decodificados apenas em memória para
  o cálculo do hash e nunca são gravados nem abertos. URLs são tratadas como texto e
  nenhuma requisição de rede é feita. O pacote não importa `socket`, `subprocess`,
  `urllib.request` ou equivalentes, e há teste automatizado para isso.
- **Entrada hostil.** Limite de tamanho (50 MiB), parsing com `email.policy.default`,
  tolerância a cabeçalhos e MIME malformados (os defeitos são registrados no
  relatório), extração de links com `html.parser` sem renderizar HTML.
- **Saída neutralizada.** Caracteres de controle, sequências ANSI e controles
  bidirecionais (ex.: U+202E) são escapados. No Markdown, HTML e sintaxe de
  link/tabela são escapados e as URLs aparecem desarmadas (`hxxp://dominio[.]com`).
- **Não sobrescrita.** A cópia é criada em modo exclusivo, e um caso já iniciado nunca
  tem cópia ou registro de custódia sobrescritos. O nome lido do JSON de custódia é
  reduzido ao componente final para impedir acesso a caminhos fora do caso.
- **Authentication-Results forjáveis.** Esse cabeçalho pode ser inserido pelo
  remetente. Por padrão vale apenas o mais recente (topo); com `--authserv-id`,
  apenas o do servidor indicado.

## Terminologia: o que a ferramenta afirma e o que não afirma

| Conceito | Neste projeto |
|---|---|
| **Integridade** | Verificada para a **cópia de trabalho**: o SHA-256 não mudou desde a aquisição. É a única propriedade que o hash comprova. |
| **Autenticidade** | **Não comprovada.** Hash igual não demonstra que o conteúdo é genuíno, só que não mudou após a coleta. SPF/DKIM/DMARC são os resultados *declarados* pelo servidor receptor, não revalidados aqui (DKIM pode ser revalidado com a chave pública do domínio, fora do escopo). |
| **Autoria** | **Não atribuída.** Cabeçalhos como `From`, `Date` e os `Received` mais antigos são definidos ou forjáveis pelo remetente. Atribuir autoria exige outras fontes, como logs do provedor, dados cadastrais e ordem judicial. |
| **Cadeia de custódia** | Registro documental das ações sobre a evidência (quem, quando, o quê, com qual hash). O encadeamento de hashes evidencia edições no registro, mas **não é assinatura digital nem carimbo de tempo**: quem controla o arquivo pode recalcular a cadeia. |
| **Nível de suspeita** | Priorização heurística para triagem. Não é laudo nem conclusão. |

## Relação entre DFIR, análise de phishing e prova digital

O phishing é um dos principais vetores iniciais de incidentes. Em **DFIR**, o e-mail
suspeito costuma ser o primeiro artefato: dele saem indicadores (IPs, domínios, hashes
de anexos) para bloquear, procurar em outras caixas e correlacionar com logs de proxy,
EDR e autenticação. A **análise de phishing** responde se a mensagem é maliciosa, o que
ela tenta fazer e quem mais a recebeu.

Quando o incidente pode virar processo administrativo, trabalhista ou judicial, o mesmo
arquivo vira **prova digital**, e aí a forma como foi tratado importa tanto quanto o
que se concluiu: aquisição sem alteração, hash registrado na coleta, cópia de trabalho
separada do original, documentação de cada manuseio e conclusões limitadas ao que os
dados sustentam. Este projeto modela esse cuidado de ponta a ponta. Ele trabalha sobre
uma cópia, registra cada ação, separa fatos verificáveis de heurísticas e declara
explicitamente os limites de cada conclusão.

## Limitações

- O `.eml` analisado é o que foi entregue à ferramenta. Ela não verifica como foi
  exportado do cliente ou servidor de e-mail, etapa que é crítica em uma coleta real.
- SPF/DKIM/DMARC **não são revalidados** (não há consultas DNS nem verificação de
  assinatura DKIM). Só o resultado declarado no `Authentication-Results` é usado.
- O domínio registrável é aproximado com uma lista reduzida de sufixos de dois níveis,
  não com a Public Suffix List completa.
- Os `Received` são interpretados por expressão regular. Formatos incomuns podem gerar
  campos vazios, e os saltos anteriores à infraestrutura do destinatário podem ser forjados.
- As heurísticas e os pesos de severidade são deliberadamente simples e geram falsos
  positivos e negativos. Não há análise de reputação, sandbox nem verificação de anexos
  por antivírus.
- O encadeamento da custódia não substitui assinatura digital, carimbo de tempo
  (RFC 3161) ou armazenamento WORM.
- A permissão somente leitura na cópia é uma proteção contra acidentes, não contra um
  usuário com privilégios.

## Licença e dados

Código distribuído sob a **licença MIT**. Veja o arquivo [`LICENSE`](LICENSE).

O arquivo `samples/email_suspeito.eml` é **inteiramente fictício**. Usa domínios
reservados `.example`, IPs de documentação (RFC 5737) e um "executável" de poucos bytes
sem código funcional. Não contém dados pessoais nem marcas reais.
