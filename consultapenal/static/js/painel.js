// Visão geral: painel inicial e busca no acervo.
import { el, icone, seloArea, formatarData, porId, ORDEM_AREAS } from "./ui.js";

const ICONES_LEI = { livro: "i-livro", documento: "i-documento", escudo: "i-escudo", pessoas: "i-pessoas" };
const ICONES_AREA = { balanca: "i-balanca", pena: "i-pena", casa: "i-casa" };

function preencherCampos(painel) {
  for (const node of document.querySelectorAll("[data-campo]")) {
    const valor = node.dataset.campo.split(".").reduce((obj, k) => (obj == null ? obj : obj[k]), painel);
    if (typeof valor === "string") node.textContent = valor;
  }
  document.getElementById("sugestoes").replaceChildren(...(painel.buscas_sugeridas || []).map((termo) =>
    el("button", { type: "button", class: "chip", "data-busca": termo, text: termo })));
}

function renderAreas(areas, temas) {
  document.getElementById("areas").replaceChildren(...areas.map((area) => {
    const doTema = temas.filter((t) => t.area === area.id);
    return el("article", { class: "area area-" + area.id },
      el("div", { class: "area-topo" },
        el("span", { class: "area-icone" }, icone(ICONES_AREA[area.icone] || "i-livro")),
        el("div", {}, el("h3", { text: area.nome }), el("p", { text: area.descricao }))),
      el("ul", { class: "area-temas" }, doTema.slice(0, 4).map((tema) => el("li", {},
        el("a", { href: `#/temas/${tema.id}` }, el("span", { text: tema.titulo }), icone("i-chevron"))))),
      el("a", { class: "area-todos", href: `#/leis-e-temas/${area.id}` },
        `Ver ${doTema.length} ficha${doTema.length === 1 ? "" : "s"} de ${area.nome}`, icone("i-seta")));
  }));
}

function renderErros(erros) {
  const alvo = document.getElementById("erros");
  if (!erros.length) { alvo.replaceChildren(el("p", { class: "vazio", text: "Nenhum erro cadastrado." })); return; }
  let atual = 0;
  const desenhar = () => {
    const erro = erros[atual];
    const navegacao = erros.length > 1 ? el("div", { class: "paginacao" },
      el("button", { type: "button", class: "botao-icone", "aria-label": "Erro anterior", "data-dir": "-1" }, icone("i-chevron", "invertido")),
      el("span", { text: `${atual + 1} de ${erros.length}` }),
      el("button", { type: "button", class: "botao-icone", "aria-label": "Próximo erro", "data-dir": "1" }, icone("i-chevron"))) : null;
    alvo.replaceChildren(
      el("div", { class: "erro-titulo" }, el("span", { class: "rotulo", text: erro.categoria || "Escrita" }), el("h3", { text: erro.titulo })),
      comparacao(erro),
      erro.explicacao ? el("p", { class: "explicacao", text: erro.explicacao }) : null,
      navegacao);
    for (const botao of alvo.querySelectorAll("[data-dir]")) {
      botao.addEventListener("click", () => {
        atual = (atual + Number(botao.dataset.dir) + erros.length) % erros.length;
        desenhar();
      });
    }
  };
  desenhar();
}

// Par "incorreto → correto", usado também na ficha temática.
export function comparacao(erro) {
  return el("div", { class: "comparacoes" },
    el("div", { class: "comparacao incorreto" }, el("span", { class: "marcador" }, icone("i-x")),
      el("div", {}, el("span", { class: "rotulo", text: "Incorreto" }), el("s", { text: erro.incorreto }))),
    el("div", { class: "comparacao correto" }, el("span", { class: "marcador" }, icone("i-check")),
      el("div", {}, el("span", { class: "rotulo", text: "Correto" }), el("p", { text: erro.correto }))));
}

function renderRetomar(consultas) {
  const alvo = document.getElementById("retomar");
  const consulta = consultas[0];
  if (!consulta) { alvo.replaceChildren(el("p", { class: "vazio", text: "Nenhuma consulta recente." })); return; }
  const feitas = consulta.etapas.filter((e) => e.concluida).length;
  const total = consulta.etapas.length;
  const barra = el("div", { class: "progresso", role: "progressbar", "aria-valuemin": "0",
    "aria-valuemax": String(total), "aria-valuenow": String(feitas), "aria-label": "Etapas concluídas" }, el("span"));
  barra.firstChild.style.width = total ? `${(feitas / total) * 100}%` : "0";
  alvo.replaceChildren(
    el("div", { class: "retomar-topo" },
      el("span", { class: "retomar-icone" }, icone("i-documento")),
      el("div", {},
        el("h3", { text: consulta.titulo }),
        el("p", { class: "meta" }, seloArea(consulta.area),
          el("span", { text: [consulta.tipo, consulta.referencia, formatarData(consulta.atualizado_em)].filter(Boolean).join(" · ") })))),
    el("div", { class: "progresso-linha" }, barra, el("span", { text: `${feitas} de ${total} etapas` })),
    el("ul", { class: "etapas" }, consulta.etapas.map((etapa) => el("li", { class: etapa.concluida ? "feita" : "" },
      el("span", { class: "caixa" }, etapa.concluida ? icone("i-check") : null),
      el("span", { text: etapa.titulo }),
      el("span", { class: "sr", text: etapa.concluida ? "(concluída)" : "(pendente)" })))),
    consulta.tema
      ? el("a", { class: "botao-contorno", href: `#/temas/${consulta.tema}` }, "Retomar consulta", icone("i-seta"))
      : el("button", { type: "button", class: "botao-contorno", "data-busca": consulta.titulo }, "Retomar consulta", icone("i-seta")));
}

function renderEbooks(ebooks) {
  document.getElementById("ebooks").replaceChildren(...ebooks.map((ebook) =>
    el("button", { type: "button", class: "ebook", "data-busca": ebook.titulo },
      capa(ebook),
      el("span", { class: "ebook-info" },
        el("strong", { text: ebook.titulo }),
        seloArea(ebook.area),
        ebook.descricao ? el("small", { text: ebook.descricao }) : null))));
}

export function capa(ebook) {
  return el("span", { class: "capa capa-" + (ebook.capa || "bordo") },
    el("span", { class: "capa-titulo", text: ebook.titulo }),
    el("span", { class: "capa-filete" }),
    el("span", { class: "capa-sub", text: ebook.subtitulo || "" }));
}

export function cartaoLei(lei) {
  return el("a", { class: "lei", href: `#/leis/${lei.id}` },
    el("span", { class: "lei-icone" }, icone(ICONES_LEI[lei.icone] || "i-livro")),
    el("span", { class: "lei-texto" }, el("strong", { text: lei.nome }), el("span", { text: lei.norma })),
    icone("i-chevron", "lei-seta"));
}

function renderLinksRapidos(painel, leis) {
  const indice = porId(leis);
  const ids = painel.links_rapidos || leis.map((l) => l.id);
  document.getElementById("leis").replaceChildren(...ids.map((id) => indice.get(id)).filter(Boolean).map(cartaoLei));
}

export function renderPainel(acervo) {
  preencherCampos(acervo.painel);
  const areas = [...acervo.areas].sort((a, b) => ORDEM_AREAS.indexOf(a.id) - ORDEM_AREAS.indexOf(b.id));
  renderAreas(areas, acervo.temas);
  renderErros(acervo.erros);
  renderRetomar(acervo.consultas);
  renderEbooks(acervo.ebooks);
  renderLinksRapidos(acervo.painel, acervo.leis);
}

// ----- busca ---------------------------------------------------------------------------
const DESTINOS = { Tema: "temas", Lei: "leis" };

export async function executarBusca(consulta) {
  const painel = document.getElementById("resultados");
  const termo = consulta.trim();
  if (!termo) { painel.hidden = true; return; }
  painel.hidden = false;
  painel.replaceChildren(el("p", { class: "vazio", text: "Buscando…" }));
  try {
    const resposta = await fetch("/api/busca?q=" + encodeURIComponent(termo));
    const dados = await resposta.json();
    if (!resposta.ok) throw new Error(dados.erro || "Falha na busca.");
    const cabecalho = el("div", { class: "resultados-cabecalho" },
      el("p", {}, el("strong", { text: String(dados.resultados.length) }),
        ` resultado${dados.resultados.length === 1 ? "" : "s"} para “`, el("span", { text: termo }), "” no acervo cadastrado"),
      el("button", { type: "button", class: "botao-texto", id: "limpar-busca", text: "Limpar" }));
    const lista = dados.resultados.length
      ? el("ul", {}, dados.resultados.map((item) => {
          const conteudo = [
            el("span", { class: "rotulo", text: item.tipo }),
            el("div", {}, el("strong", { text: item.titulo }), item.descricao ? el("p", { text: item.descricao }) : null),
            seloArea(item.area)];
          const destino = DESTINOS[item.tipo];
          return el("li", {}, destino ? el("a", { class: "resultado", href: `#/${destino}/${item.id}` }, conteudo)
                                      : el("div", { class: "resultado" }, conteudo));
        }))
      : el("p", { class: "vazio", text: "Nada encontrado. A busca considera apenas o conteúdo cadastrado na plataforma." });
    painel.replaceChildren(cabecalho, lista);
    document.getElementById("limpar-busca").addEventListener("click", () => {
      document.getElementById("campo-busca").value = "";
      painel.hidden = true;
    });
  } catch (erro) {
    painel.replaceChildren(el("p", { class: "vazio", text: erro.message }));
  }
}
