"use strict";

// Painel inicial. Todo o conteúdo vem de /api/painel (arquivos em consultapenal/dados/).
// Textos dos dados são inseridos sempre com textContent, nunca como HTML.

const NOMES_AREA = { penal: "Penal", civel: "Cível", familia: "Família" };
const ICONES_LEI = { livro: "i-livro", documento: "i-documento", escudo: "i-escudo", pessoas: "i-pessoas" };
const ICONES_AREA = { balanca: "i-balanca", pena: "i-pena", casa: "i-casa" };
const SVG_NS = "http://www.w3.org/2000/svg";

function el(tag, attrs = {}, ...filhos) {
  const node = document.createElement(tag);
  for (const [chave, valor] of Object.entries(attrs)) {
    if (chave === "class") node.className = valor;
    else if (chave === "text") node.textContent = valor;
    else node.setAttribute(chave, valor);
  }
  for (const filho of filhos) if (filho != null) node.append(filho);
  return node;
}

function icone(id, classe) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("aria-hidden", "true");
  if (classe) svg.setAttribute("class", classe);
  const use = document.createElementNS(SVG_NS, "use");
  use.setAttribute("href", "#" + id);
  svg.append(use);
  return svg;
}

function seloArea(area) {
  return area ? el("span", { class: "tag tag-" + area, text: NOMES_AREA[area] || area }) : null;
}

function formatarData(iso) {
  const [ano, mes, dia] = String(iso).split("-").map(Number);
  if (!ano || !mes || !dia) return "";
  return new Date(ano, mes - 1, dia).toLocaleDateString("pt-BR", { day: "2-digit", month: "short", year: "numeric" });
}

// ----- aviso flutuante --------------------------------------------------------------
let temporizador;
function avisar(texto) {
  const toast = document.getElementById("aviso-flutuante");
  toast.textContent = texto;
  toast.hidden = false;
  clearTimeout(temporizador);
  temporizador = setTimeout(() => { toast.hidden = true; }, 3200);
}

// ----- campos simples do painel.json ------------------------------------------------
function preencherCampos(painel) {
  for (const node of document.querySelectorAll("[data-campo]")) {
    const valor = node.dataset.campo.split(".").reduce((obj, k) => (obj == null ? obj : obj[k]), painel);
    if (typeof valor === "string") node.textContent = valor;
  }
  if (painel.nome) document.title = painel.nome;
  const chips = document.getElementById("sugestoes");
  chips.replaceChildren(...(painel.buscas_sugeridas || []).map((termo) =>
    el("button", { type: "button", class: "chip", "data-busca": termo, text: termo })));
}

// ----- seções -------------------------------------------------------------------------
function renderAreas(areas) {
  document.getElementById("areas").replaceChildren(...areas.map((area) => el("article", { class: "area area-" + area.id },
    el("div", { class: "area-topo" },
      el("span", { class: "area-icone" }, icone(ICONES_AREA[area.icone] || "i-livro")),
      el("div", {}, el("h3", { text: area.nome }), el("p", { text: area.descricao }))),
    el("ul", { class: "area-temas" }, ...area.temas.map((tema) => el("li", {},
      el("button", { type: "button", "data-busca": tema.titulo },
        el("span", { text: tema.titulo }), icone("i-chevron"))))))));
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
      el("div", { class: "comparacao incorreto" }, el("span", { class: "marcador" }, icone("i-x")),
        el("div", {}, el("span", { class: "rotulo", text: "Incorreto" }), el("s", { text: erro.incorreto }))),
      el("div", { class: "comparacao correto" }, el("span", { class: "marcador" }, icone("i-check")),
        el("div", {}, el("span", { class: "rotulo", text: "Correto" }), el("p", { text: erro.correto }))),
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
    el("ul", { class: "etapas" }, ...consulta.etapas.map((etapa) => el("li", { class: etapa.concluida ? "feita" : "" },
      el("span", { class: "caixa" }, etapa.concluida ? icone("i-check") : null),
      el("span", { text: etapa.titulo }),
      el("span", { class: "sr", text: etapa.concluida ? "(concluída)" : "(pendente)" })))),
    el("button", { type: "button", class: "botao-contorno", "data-busca": consulta.titulo },
      "Retomar consulta", icone("i-seta")));
}

function renderEbooks(ebooks) {
  document.getElementById("ebooks").replaceChildren(...ebooks.map((ebook) =>
    el("button", { type: "button", class: "ebook", "data-busca": ebook.titulo },
      el("span", { class: "capa capa-" + (ebook.capa || "bordo") },
        el("span", { class: "capa-titulo", text: ebook.titulo }),
        el("span", { class: "capa-filete" }),
        el("span", { class: "capa-sub", text: ebook.subtitulo || "" })),
      el("span", { class: "ebook-info" },
        el("strong", { text: ebook.titulo }),
        seloArea(ebook.area),
        ebook.descricao ? el("small", { text: ebook.descricao }) : null))));
}

function renderLeis(leis) {
  document.getElementById("leis").replaceChildren(...leis.map((lei) =>
    el("button", { type: "button", class: "lei", "data-busca": lei.nome },
      el("span", { class: "lei-icone" }, icone(ICONES_LEI[lei.icone] || "i-livro")),
      el("span", { class: "lei-texto" }, el("strong", { text: lei.nome }), el("span", { text: lei.norma })),
      icone("i-chevron", "lei-seta"))));
}

// ----- busca ---------------------------------------------------------------------------
async function executarBusca(consulta) {
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
      ? el("ul", {}, ...dados.resultados.map((item) => el("li", {},
          el("span", { class: "rotulo", text: item.tipo }),
          el("div", {}, el("strong", { text: item.titulo }), item.descricao ? el("p", { text: item.descricao }) : null),
          seloArea(item.area))))
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

function buscarPor(termo) {
  const campo = document.getElementById("campo-busca");
  campo.value = termo;
  executarBusca(termo);
  document.querySelector(".busca").scrollIntoView({ behavior: "smooth", block: "start" });
}

// ----- menu ----------------------------------------------------------------------------
function configurarMenu() {
  const lateral = document.getElementById("lateral");
  const veu = document.getElementById("veu");
  const botao = document.getElementById("abrir-menu");
  const alternar = (aberto) => {
    lateral.classList.toggle("aberta", aberto);
    veu.hidden = !aberto;
    botao.setAttribute("aria-expanded", String(aberto));
  };
  botao.addEventListener("click", () => alternar(!lateral.classList.contains("aberta")));
  veu.addEventListener("click", () => alternar(false));
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") alternar(false); });
  for (const link of lateral.querySelectorAll("a")) {
    link.addEventListener("click", (ev) => {
      ev.preventDefault();
      alternar(false);
      if (link.hasAttribute("data-em-breve")) avisar(`“${link.firstChild.nextSibling.textContent.trim()}” será implementado nas próximas etapas.`);
    });
  }
}

// ----- início --------------------------------------------------------------------------
async function iniciar() {
  configurarMenu();
  document.getElementById("form-busca").addEventListener("submit", (ev) => {
    ev.preventDefault();
    executarBusca(document.getElementById("campo-busca").value);
  });
  document.addEventListener("click", (ev) => {
    const alvo = ev.target.closest("[data-busca]");
    if (alvo) buscarPor(alvo.dataset.busca);
  });
  document.addEventListener("keydown", (ev) => {
    const digitando = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
    if (ev.key === "/" && !digitando) { ev.preventDefault(); document.getElementById("campo-busca").focus(); }
  });

  try {
    const resposta = await fetch("/api/painel");
    const acervo = await resposta.json();
    if (!resposta.ok) throw new Error(acervo.erro || "Não foi possível carregar o painel.");
    preencherCampos(acervo.painel);
    renderAreas(acervo.areas);
    renderErros(acervo.erros);
    renderRetomar(acervo.consultas);
    renderEbooks(acervo.ebooks);
    renderLeis(acervo.leis);
  } catch (erro) {
    document.getElementById("conteudo").prepend(el("p", { class: "aviso aviso-erro", role: "alert", text: erro.message }));
  }
}

document.addEventListener("DOMContentLoaded", iniciar);
