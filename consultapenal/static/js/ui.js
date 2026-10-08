// Utilitários de interface compartilhados pelas páginas.
// Textos dos dados são inseridos sempre com textContent, nunca como HTML.

export const NOMES_AREA = { penal: "Penal", civel: "Cível", familia: "Família" };
export const ORDEM_AREAS = ["penal", "civel", "familia"];
const NOMES_STATUS = { demonstrativo: "Demonstrativo", rascunho: "Rascunho", conferido: "Conferido" };
const SVG_NS = "http://www.w3.org/2000/svg";

export function el(tag, attrs = {}, ...filhos) {
  const node = document.createElement(tag);
  for (const [chave, valor] of Object.entries(attrs)) {
    if (valor == null || valor === false) continue;
    if (chave === "class") node.className = valor;
    else if (chave === "text") node.textContent = valor;
    else node.setAttribute(chave, valor === true ? "" : valor);
  }
  for (const filho of filhos.flat()) if (filho != null && filho !== false) node.append(filho);
  return node;
}

export function icone(id, classe) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("aria-hidden", "true");
  if (classe) svg.setAttribute("class", classe);
  const use = document.createElementNS(SVG_NS, "use");
  use.setAttribute("href", "#" + id);
  svg.append(use);
  return svg;
}

export function seloArea(area) {
  return area ? el("span", { class: "tag tag-" + area, text: NOMES_AREA[area] || area }) : null;
}

export function seloStatus(status) {
  if (!status) return null;
  return el("span", { class: "tag tag-status tag-" + status, text: NOMES_STATUS[status] || status });
}

export function formatarData(iso) {
  const [ano, mes, dia] = String(iso || "").split("-").map(Number);
  if (!ano || !mes || !dia) return "";
  return new Date(ano, mes - 1, dia).toLocaleDateString("pt-BR", { day: "2-digit", month: "short", year: "numeric" });
}

export function normalizar(texto) {
  return String(texto).normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
}

export function vazio(texto = "Nenhum item cadastrado nesta seção.") {
  return el("p", { class: "vazio", text: texto });
}

export function linkExterno(href, texto) {
  return el("a", { class: "link-externo", href, target: "_blank", rel: "noopener noreferrer" },
    texto, icone("i-externo"));
}

// Indexa uma coleção por id para resolver as referências das fichas.
export function porId(lista) {
  return new Map(lista.map((item) => [item.id, item]));
}

let temporizador;
export function avisar(texto) {
  const toast = document.getElementById("aviso-flutuante");
  toast.textContent = texto;
  toast.hidden = false;
  clearTimeout(temporizador);
  temporizador = setTimeout(() => { toast.hidden = true; }, 3200);
}

// Armazenamento local opcional (pode estar indisponível em janelas privativas).
export const armazenamento = {
  ler(chave, padrao) {
    try { const valor = localStorage.getItem(chave); return valor ? JSON.parse(valor) : padrao; } catch { return padrao; }
  },
  gravar(chave, valor) {
    try { localStorage.setItem(chave, JSON.stringify(valor)); } catch { /* sem persistência */ }
  },
  remover(chave) {
    try { localStorage.removeItem(chave); } catch { /* sem persistência */ }
  },
};
