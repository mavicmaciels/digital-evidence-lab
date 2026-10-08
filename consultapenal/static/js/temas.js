// "Leis e temas": navegação por área, ficha temática e página de lei.
import {
  el, icone, seloArea, seloStatus, formatarData, normalizar, vazio, linkExterno, porId,
  armazenamento, NOMES_AREA, ORDEM_AREAS,
} from "./ui.js";
import { capa, cartaoLei, comparacao } from "./painel.js";

function trilha(...itens) {
  return el("nav", { class: "trilha-pagina", "aria-label": "Você está em" },
    el("ol", {}, itens.map(([texto, href], i) => el("li", {},
      href ? el("a", { href, text: texto }) : el("span", { "aria-current": "page", text: texto }),
      i < itens.length - 1 ? icone("i-chevron") : null))));
}

function avisoDemonstrativo(item, texto) {
  return item.status === "demonstrativo"
    ? el("p", { class: "aviso", role: "note" }, icone("i-info"), el("span", { text: texto }))
    : null;
}

function contador(iconeId, n, singular, plural) {
  return el("span", { class: "contador" }, icone(iconeId), `${n} ${n === 1 ? singular : plural}`);
}

// ----- lista: Leis e temas -------------------------------------------------------------
function cartaoFicha(ficha) {
  return el("a", { class: "ficha-cartao", href: `#/temas/${ficha.id}` },
    el("span", { class: "ficha-cartao-tags" }, seloArea(ficha.area), seloStatus(ficha.status)),
    el("h3", { text: ficha.titulo }),
    el("p", { class: "ficha-cartao-resumo", text: ficha.resumo }),
    el("span", { class: "ficha-cartao-rodape" },
      contador("i-livro", ficha.base_legal.length, "lei", "leis"),
      contador("i-balanca", ficha.jurisprudencia.length, "julgado", "julgados"),
      contador("i-check", ficha.checklist.length, "item", "itens")));
}

export function renderLista(acervo, area) {
  const areaValida = ORDEM_AREAS.includes(area) ? area : null;
  const fichasDaArea = acervo.temas.filter((f) => !areaValida || f.area === areaValida);
  const leisDaArea = acervo.leis.filter((l) => !areaValida || l.area === areaValida);
  const contagem = (id) => acervo.temas.filter((f) => !id || f.area === id).length;

  const abas = el("nav", { class: "abas", "aria-label": "Filtrar por área" },
    [[null, "Todas"], ...ORDEM_AREAS.map((id) => [id, NOMES_AREA[id]])].map(([id, nome]) =>
      el("a", { href: id ? `#/leis-e-temas/${id}` : "#/leis-e-temas", class: "aba",
                "aria-current": (id === areaValida) ? "page" : null },
        nome, el("span", { class: "aba-contagem", text: String(contagem(id)) }))));

  const filtro = el("input", { type: "search", id: "filtro-fichas", class: "filtro", placeholder: "Filtrar por título ou palavra-chave…",
                               "aria-label": "Filtrar fichas", autocomplete: "off", maxlength: "80" });
  const grupos = el("div", { class: "grupos-fichas" });
  const semResultado = vazio("Nenhuma ficha corresponde ao filtro.");

  const desenhar = () => {
    const termo = normalizar(filtro.value.trim());
    const visiveis = fichasDaArea.filter((f) => !termo ||
      normalizar([f.titulo, ...f.palavras_chave].join(" ")).includes(termo));
    const areas = areaValida ? [areaValida] : ORDEM_AREAS;
    const blocos = areas.map((id) => {
      const itens = visiveis.filter((f) => f.area === id);
      if (!itens.length) return null;
      return el("section", { class: "grupo-fichas", "aria-label": NOMES_AREA[id] },
        areaValida ? null : el("h3", { class: "grupo-titulo" }, seloArea(id), `${itens.length} ficha${itens.length === 1 ? "" : "s"}`),
        el("div", { class: "fichas" }, itens.map(cartaoFicha)));
    }).filter(Boolean);
    grupos.replaceChildren(...(blocos.length ? blocos : [semResultado]));
  };
  filtro.addEventListener("input", desenhar);
  desenhar();

  return {
    titulo: "Leis e temas",
    trilha: areaValida ? ["Leis e temas", NOMES_AREA[areaValida]] : ["Leis e temas"],
    conteudo: [
      el("header", { class: "pagina-cabeca" },
        el("h1", { tabindex: "-1", text: areaValida ? `Leis e temas · ${NOMES_AREA[areaValida]}` : "Leis e temas" }),
        el("p", { class: "subtitulo", text: "Fichas temáticas e legislação organizadas por área. Abra uma ficha para ver base legal, jurisprudência selecionada, checklist, erros recorrentes e ebooks relacionados." })),
      abas,
      el("section", { class: "bloco", "aria-labelledby": "titulo-fichas" },
        el("div", { class: "bloco-cabecalho bloco-cabecalho-filtro" },
          el("h2", { id: "titulo-fichas", text: "Fichas temáticas" }),
          el("label", { class: "filtro-rotulo" }, icone("i-busca"), filtro)),
        grupos),
      el("section", { class: "bloco", "aria-labelledby": "titulo-legislacao" },
        el("div", { class: "bloco-cabecalho" },
          el("h2", { id: "titulo-legislacao", text: "Legislação" }),
          el("p", { text: "Diplomas cadastrados. O texto legal não é reproduzido: consulte sempre a fonte oficial." })),
        leisDaArea.length ? el("div", { class: "leis leis-grade" }, leisDaArea.map(cartaoLei)) : vazio("Nenhuma lei cadastrada nesta área.")),
    ],
  };
}

// ----- ficha temática ------------------------------------------------------------------
const SECOES = [
  ["base-legal", "Base legal", "i-livro"],
  ["jurisprudencia", "Jurisprudência selecionada", "i-balanca"],
  ["checklist", "Checklist", "i-check"],
  ["erros", "Erros recorrentes", "i-pena"],
];

function secao(id, titulo, iconeId, quantidade, ...corpo) {
  return el("section", { class: "cartao ficha-secao", id: `secao-${id}`, "aria-labelledby": `titulo-${id}` },
    el("div", { class: "cartao-cabecalho" },
      el("span", { class: "cartao-icone" }, icone(iconeId)),
      el("h2", { id: `titulo-${id}`, text: titulo }),
      quantidade != null ? el("span", { class: "secao-contagem", text: String(quantidade) }) : null),
    ...corpo);
}

function blocoBaseLegal(ficha, leis) {
  if (!ficha.base_legal.length) return vazio();
  return el("ul", { class: "lista-base" }, ficha.base_legal.map((base) => {
    const lei = leis.get(base.lei);
    return el("li", {},
      el("div", { class: "base-topo" },
        el("a", { href: `#/leis/${lei.id}`, class: "base-lei" }, el("strong", { text: lei.nome }), el("span", { text: lei.norma })),
        lei.fonte_oficial ? linkExterno(lei.fonte_oficial, "Fonte oficial") : null),
      base.dispositivos
        ? el("p", { class: "base-dispositivos" }, el("span", { class: "rotulo", text: "Dispositivos" }), base.dispositivos)
        : el("p", { class: "pendente", text: "Dispositivos a cadastrar." }),
      base.observacao ? el("p", { class: "base-obs", text: base.observacao }) : null);
  }));
}

function blocoJurisprudencia(ficha, julgados) {
  if (!ficha.jurisprudencia.length) return vazio();
  return el("ul", { class: "lista-juris" }, ficha.jurisprudencia.map((id) => {
    const j = julgados.get(id);
    const referencia = [j.classe, j.numero].filter(Boolean).join(" n. ");
    return el("li", {},
      el("div", { class: "juris-topo" },
        el("span", { class: "rotulo", text: [j.tribunal, j.orgao_julgador].filter(Boolean).join(" · ") }),
        seloStatus(j.status)),
      el("p", { class: "juris-assunto", text: j.assunto }),
      el("p", { class: "juris-ref", text: [referencia, j.data_julgamento ? `julgado em ${formatarData(j.data_julgamento)}` : ""].filter(Boolean).join(" · ") }),
      j.fonte_oficial ? linkExterno(j.fonte_oficial, "Inteiro teor na fonte oficial")
                      : el("p", { class: "pendente", text: "Sem trecho cadastrado. Link para o inteiro teor a cadastrar." }));
  }));
}

function blocoChecklist(ficha) {
  if (!ficha.checklist.length) return vazio();
  const chave = `consultapenal:checklist:${ficha.id}`;
  const marcados = new Set(armazenamento.ler(chave, []));
  const progresso = el("span", { class: "checklist-progresso" });
  const atualizar = () => { progresso.textContent = `${marcados.size} de ${ficha.checklist.length} conferidos`; };
  const itens = ficha.checklist.map((texto, i) => {
    const caixa = el("input", { type: "checkbox", id: `chk-${i}`, checked: marcados.has(i) });
    caixa.addEventListener("change", () => {
      if (caixa.checked) marcados.add(i); else marcados.delete(i);
      armazenamento.gravar(chave, [...marcados]);
      atualizar();
    });
    return el("li", {}, caixa, el("label", { for: `chk-${i}`, text: texto }));
  });
  const limpar = el("button", { type: "button", class: "botao-texto", text: "Desmarcar todos" });
  limpar.addEventListener("click", () => {
    marcados.clear();
    armazenamento.remover(chave);
    for (const caixa of itens.map((li) => li.firstChild)) caixa.checked = false;
    atualizar();
  });
  atualizar();
  return [el("ul", { class: "checklist" }, itens),
    el("div", { class: "checklist-rodape" }, progresso, limpar),
    el("p", { class: "nota", text: "As marcações ficam salvas apenas neste navegador." })];
}

function blocoErros(ficha, erros) {
  if (!ficha.erros.length) return vazio();
  return el("ul", { class: "lista-erros" }, ficha.erros.map((id) => {
    const erro = erros.get(id);
    return el("li", {}, el("h3", { text: erro.titulo }), comparacao(erro),
      erro.explicacao ? el("p", { class: "explicacao", text: erro.explicacao }) : null);
  }));
}

function lateralFicha(ficha, ebooks, temas) {
  const sumario = el("nav", { class: "cartao sumario", "aria-label": "Nesta ficha" },
    el("h2", { text: "Nesta ficha" }),
    el("ul", {}, SECOES.map(([id, titulo, iconeId]) => el("li", {},
      el("button", { type: "button", "data-rolar": `secao-${id}` }, icone(iconeId), titulo)))));
  const relacionados = ficha.relacionados.map((id) => temas.get(id));
  return el("aside", { class: "ficha-lateral" },
    sumario,
    el("section", { class: "cartao", "aria-labelledby": "titulo-ebooks-ficha" },
      el("h2", { id: "titulo-ebooks-ficha", text: "Ebooks" }),
      ficha.ebooks.length ? el("ul", { class: "mini-ebooks" }, ficha.ebooks.map((id) => {
        const ebook = ebooks.get(id);
        return el("li", {}, capa(ebook), el("div", {}, el("strong", { text: ebook.titulo }), seloArea(ebook.area)));
      })) : vazio()),
    el("section", { class: "cartao", "aria-labelledby": "titulo-relacionados" },
      el("h2", { id: "titulo-relacionados", text: "Temas relacionados" }),
      relacionados.length ? el("ul", { class: "relacionados" }, relacionados.map((tema) => el("li", {},
        el("a", { href: `#/temas/${tema.id}` }, el("span", { text: tema.titulo }), seloArea(tema.area))))) : vazio()),
    el("section", { class: "cartao", "aria-labelledby": "titulo-observacoes" },
      el("h2", { id: "titulo-observacoes", text: "Observações" }),
      ficha.observacoes ? el("p", { class: "observacoes", text: ficha.observacoes }) : vazio()));
}

export function renderFicha(acervo, id) {
  const ficha = acervo.temas.find((f) => f.id === id);
  if (!ficha) return null;
  const leis = porId(acervo.leis);
  const julgados = porId(acervo.jurisprudencia);
  const erros = porId(acervo.erros);
  const ebooks = porId(acervo.ebooks);
  const temas = porId(acervo.temas);
  const area = NOMES_AREA[ficha.area];

  return {
    titulo: ficha.titulo,
    trilha: ["Leis e temas", area, ficha.titulo],
    conteudo: [
      trilha(["Leis e temas", "#/leis-e-temas"], [area, `#/leis-e-temas/${ficha.area}`], [ficha.titulo]),
      el("header", { class: "pagina-cabeca ficha-cabeca" },
        el("div", { class: "ficha-tags" }, el("span", { class: "rotulo", text: "Ficha temática" }), seloArea(ficha.area), seloStatus(ficha.status)),
        el("h1", { tabindex: "-1", text: ficha.titulo }),
        el("p", { class: "subtitulo", text: ficha.resumo }),
        el("div", { class: "ficha-meta" },
          el("span", {}, icone("i-relogio"), ficha.revisado_em ? `Revisada em ${formatarData(ficha.revisado_em)}` : "Ainda não revisada"),
          ficha.palavras_chave.length ? el("span", { class: "palavras" },
            ficha.palavras_chave.map((p) => el("button", { type: "button", class: "chip chip-p", "data-busca": p, text: p }))) : null)),
      avisoDemonstrativo(ficha, "Ficha demonstrativa: estrutura preenchida com conteúdo fictício para visualizar o layout. Não constitui orientação jurídica validada."),
      el("div", { class: "ficha-corpo" },
        el("div", { class: "ficha-principal" },
          secao("base-legal", "Base legal", "i-livro", ficha.base_legal.length, blocoBaseLegal(ficha, leis)),
          secao("jurisprudencia", "Jurisprudência selecionada", "i-balanca", ficha.jurisprudencia.length, blocoJurisprudencia(ficha, julgados)),
          secao("checklist", "Checklist", "i-check", ficha.checklist.length, blocoChecklist(ficha)),
          secao("erros", "Erros recorrentes", "i-pena", ficha.erros.length, blocoErros(ficha, erros))),
        lateralFicha(ficha, ebooks, temas)),
    ],
  };
}

// ----- página de lei -------------------------------------------------------------------
export function renderLei(acervo, id) {
  const lei = acervo.leis.find((l) => l.id === id);
  if (!lei) return null;
  const citacoes = acervo.temas.flatMap((ficha) =>
    ficha.base_legal.filter((b) => b.lei === lei.id).map((b) => ({ ficha, base: b })));
  const area = NOMES_AREA[lei.area];

  return {
    titulo: lei.nome,
    trilha: ["Leis e temas", area, lei.sigla],
    conteudo: [
      trilha(["Leis e temas", "#/leis-e-temas"], [area, `#/leis-e-temas/${lei.area}`], [lei.nome]),
      el("header", { class: "pagina-cabeca ficha-cabeca" },
        el("div", { class: "ficha-tags" }, el("span", { class: "rotulo", text: lei.sigla }), seloArea(lei.area), seloStatus(lei.status)),
        el("h1", { tabindex: "-1", text: lei.nome }),
        el("p", { class: "subtitulo", text: lei.norma }),
        el("div", { class: "ficha-meta" },
          lei.fonte_oficial ? linkExterno(lei.fonte_oficial, "Abrir texto na fonte oficial") : el("span", { class: "pendente", text: "Fonte oficial a cadastrar." }))),
      el("p", { class: "aviso", role: "note" }, icone("i-info"),
        el("span", { text: "O texto da lei não é reproduzido na plataforma. Confira sempre a redação vigente na fonte oficial." })),
      el("section", { class: "cartao ficha-secao", "aria-labelledby": "titulo-citacoes" },
        el("div", { class: "cartao-cabecalho" },
          el("span", { class: "cartao-icone" }, icone("i-documento")),
          el("h2", { id: "titulo-citacoes", text: "Fichas que usam esta lei" }),
          el("span", { class: "secao-contagem", text: String(citacoes.length) })),
        citacoes.length ? el("ul", { class: "relacionados relacionados-largos" }, citacoes.map(({ ficha, base }) => el("li", {},
          el("a", { href: `#/temas/${ficha.id}` },
            el("span", {}, el("strong", { text: ficha.titulo }),
              el("small", { text: base.dispositivos || "Dispositivos a cadastrar" })),
            seloArea(ficha.area))))) : vazio("Nenhuma ficha cita esta lei ainda.")),
    ],
  };
}
