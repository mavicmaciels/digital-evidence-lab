// Inicialização e navegação. O acervo (consultapenal/dados/) é carregado uma vez;
// para ver edições nos arquivos de dados, recarregue a página.
import { el, avisar } from "./ui.js";
import { renderPainel, executarBusca } from "./painel.js";
import { renderLista, renderFicha, renderLei } from "./temas.js";

let acervo = null;
let nomeApp = "Consulta Penal";

const vistaPainel = () => document.getElementById("vista-painel");
const vistaPagina = () => document.getElementById("vista-pagina");

// ----- rotas -------------------------------------------------------------------------
// #/                       visão geral
// #/leis-e-temas[/area]    lista por área
// #/temas/<id>             ficha temática
// #/leis/<id>              página de lei
function resolver(partes) {
  const [secao, id] = partes;
  if (!secao) return { menu: "visao-geral", painel: true, trilha: ["Visão geral"], titulo: null };
  if (secao === "leis-e-temas") return { menu: "leis-e-temas", ...renderLista(acervo, id) };
  if (secao === "temas" && id) { const v = renderFicha(acervo, id); if (v) return { menu: "leis-e-temas", ...v }; }
  if (secao === "leis" && id) { const v = renderLei(acervo, id); if (v) return { menu: "leis-e-temas", ...v }; }
  return {
    menu: null, titulo: "Página não encontrada", trilha: ["Página não encontrada"],
    conteudo: [el("header", { class: "pagina-cabeca" },
      el("h1", { tabindex: "-1", text: "Página não encontrada" }),
      el("p", { class: "subtitulo", text: "O endereço não corresponde a nenhum conteúdo cadastrado." }),
      el("a", { class: "botao-contorno botao-curto", href: "#/", text: "Voltar à visão geral" }))],
  };
}

function navegar() {
  const hash = location.hash;
  if (hash && !hash.startsWith("#/")) return; // âncoras internas (ex.: pular para o conteúdo)
  const partes = hash.slice(2).split("/").filter(Boolean).map(decodeURIComponent);
  const vista = resolver(partes);

  vistaPainel().hidden = !vista.painel;
  vistaPagina().hidden = !!vista.painel;
  if (!vista.painel) vistaPagina().replaceChildren(...vista.conteudo.filter(Boolean));

  document.title = vista.titulo ? `${vista.titulo} · ${nomeApp}` : nomeApp;
  document.getElementById("trilha-atual").textContent = vista.trilha.join(" / ");
  for (const link of document.querySelectorAll(".menu a")) {
    const ativo = link.dataset.menu === vista.menu;
    link.classList.toggle("ativo", ativo);
    if (ativo) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
  }
  window.scrollTo(0, 0);
  if (!vista.painel) vistaPagina().querySelector("h1")?.focus({ preventScroll: true });
}

function buscarPor(termo) {
  if (location.hash && location.hash !== "#/") {
    location.hash = "#/";
  }
  document.getElementById("campo-busca").value = termo;
  executarBusca(termo);
  requestAnimationFrame(() => document.querySelector(".busca").scrollIntoView({ behavior: "smooth", block: "start" }));
}

// ----- menu --------------------------------------------------------------------------
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
      alternar(false);
      if (link.hasAttribute("data-em-breve")) {
        ev.preventDefault();
        avisar(`“${link.dataset.nome}” será implementado nas próximas etapas.`);
      }
    });
  }
}

// ----- início ------------------------------------------------------------------------
async function iniciar() {
  configurarMenu();
  document.getElementById("form-busca").addEventListener("submit", (ev) => {
    ev.preventDefault();
    executarBusca(document.getElementById("campo-busca").value);
  });
  document.addEventListener("click", (ev) => {
    const busca = ev.target.closest("[data-busca]");
    if (busca) { buscarPor(busca.dataset.busca); return; }
    const rolar = ev.target.closest("[data-rolar]");
    if (rolar) document.getElementById(rolar.dataset.rolar)?.scrollIntoView({ behavior: "smooth", block: "start" });
  });
  document.addEventListener("keydown", (ev) => {
    const digitando = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
    if (ev.key === "/" && !digitando) {
      ev.preventDefault();
      if (location.hash && location.hash !== "#/") location.hash = "#/";
      document.getElementById("campo-busca").focus();
    }
  });

  try {
    const resposta = await fetch("/api/painel");
    const dados = await resposta.json();
    if (!resposta.ok) throw new Error(dados.erro || "Não foi possível carregar o acervo.");
    acervo = dados;
    nomeApp = acervo.painel.nome || nomeApp;
    renderPainel(acervo);
  } catch (erro) {
    document.getElementById("conteudo").prepend(el("p", { class: "aviso aviso-erro", role: "alert", text: erro.message }));
    return;
  }
  window.addEventListener("hashchange", navegar);
  navegar();
}

document.addEventListener("DOMContentLoaded", iniciar);
