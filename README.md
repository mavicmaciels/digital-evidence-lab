# Digital Evidence Lab

Ferramenta forense em Python (somente biblioteca padrão) para análise de e-mails
suspeitos (`.eml`), com cadeia de custódia e verificação de integridade.

```
DIGITAL EVIDENCE LAB

Evidência: email_suspeito.eml

[✓] Arquivo adquirido
[✓] SHA-256 calculado
[✓] Metadados extraídos
[✓] Integridade verificada
[✓] Timeline construída

SHA-256
723de153...6d31

CADEIA DE CUSTÓDIA
10:32  Coleta
10:33  Hash inicial
10:41  Análise
10:41  Verificação de integridade
10:52  Relatório

INTEGRIDADE
● VERIFICADA
```

## Fluxo

1. **Aquisição** – a evidência é copiada para `<caso>/evidencia/` e marcada como somente leitura.
2. **SHA-256** – o hash do original e da cópia é calculado e comparado.
3. **Metadados** – cabeçalhos, rota `Received`, SPF/DKIM/DMARC, links e anexos (com hash).
4. **Integridade** – o hash é recalculado após a análise e comparado com o inicial.
5. **Timeline** – eventos do e-mail e da custódia em uma linha do tempo única (UTC).
6. **Relatório** – painel no terminal + `relatorio_<nome>.json`, `relatorio_<nome>.md` e `cadeia_custodia.json`.

Indicadores detectados: falhas de SPF/DKIM/DMARC, `Reply-To`/`Return-Path` divergentes,
links para IP, texto do link diferente do destino, domínio do remetente usado como
subdomínio enganoso, anexos executáveis e com extensão dupla, linguagem de urgência e
divergência entre `Date` e o primeiro salto. O nível de risco (BAIXO/MÉDIO/ALTO) é
derivado desses indicadores.

## Uso

Requer Python 3.10+.

```bash
# Adquirir e analisar (cria casos/email_suspeito/)
python3 -m evidencelab analyze samples/email_suspeito.eml --examiner "Nome do perito"

# Reverificar a integridade de um caso existente (registra o evento na custódia)
python3 -m evidencelab verify casos/email_suspeito
```

`verify` retorna código de saída `1` se a evidência foi alterada ou removida.

## Testes

```bash
python3 -m unittest -v
```

O arquivo `samples/email_suspeito.eml` é um exemplo fictício: domínios `.example`,
IPs de documentação (RFC 5737) e um anexo inofensivo.
