// Digital Evidence Lab — interface local.
// Regra de segurança: todo conteúdo vindo do .eml é inserido apenas como texto
// (textContent / nós de texto). Nenhuma URL do e-mail vira link; anexos não têm download.
"use strict";

(function () {
  const token = document.querySelector('meta[name="del-token"]').getAttribute("content");
  const $ = (id) => document.getElementById(id);
  const form = $("intake-form");
  const fileInput = $("eml");
  const button = $("analyze");
  const statusBox = $("status");
  let clientHash = null;
  let currentSha = "";

  // ----- utilitários de DOM (somente texto) -------------------------------------
  function el(tag, className, ...children) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    for (const child of children) {
      if (child === null || child === undefined) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function setText(id, value) {
    $(id).textContent = value === null || value === undefined || value === "" ? "—" : String(value);
  }

  function fillTable(tableId, rows, emptyText, columns) {
    const body = $(tableId).querySelector("tbody");
    clear(body);
    if (!rows.length) {
      const td = el("td", "empty-row", emptyText);
      td.colSpan = columns;
      body.append(el("tr", null, td));
      return;
    }
    // Rótulos das colunas para o layout empilhado em telas estreitas (atributo de texto).
    const labels = [...$(tableId).querySelectorAll("thead th")].map((th) => th.textContent);
    for (const cells of rows) {
      const tr = el("tr");
      cells.forEach((cell, i) => {
        const cellNode = cell instanceof Node && cell.tagName === "TD" ? cell : el("td", null, cell);
        cellNode.setAttribute("data-label", labels[i] || "");
        tr.append(cellNode);
      });
      body.append(tr);
    }
  }

  function td(text, className) {
    return el("td", className, text === "" || text === null || text === undefined ? "—" : text);
  }

  function formatBytes(n) {
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / (1024 * 1024)).toFixed(1) + " MB";
  }

  function utc(iso) {
    // "2026-10-05T13:13:57Z" ou "...+00:00" -> "2026-10-05 13:13:57"
    if (!iso || iso === "-") return "—";
    return String(iso).replace("T", " ").replace(/(Z|\+00:00)$/, "");
  }

  const SEVERITY_LABEL = { alta: "ALTA", "média": "MÉDIA", baixa: "BAIXA", info: "INFO" };
  const SEVERITY_CLASS = { alta: "sev-high", "média": "sev-med", baixa: "sev-low", info: "sev-info" };
  const LEVEL_CLASS = { ALTO: "lvl-high", "MÉDIO": "lvl-med", BAIXO: "lvl-low" };

  function sevBadge(sev) {
    return el("span", "sev " + (SEVERITY_CLASS[sev] || "sev-info"), SEVERITY_LABEL[sev] || sev);
  }

  // ----- estado -------------------------------------------------------------------
  function showStatus(kind, message) {
    statusBox.hidden = false;
    statusBox.className = "status status-" + kind;
    statusBox.setAttribute("role", kind === "error" ? "alert" : "status");
    statusBox.textContent = message;
  }

  function updateButton() {
    button.disabled = !(clientHash && $("examiner").value.trim());
  }

  async function sha256Hex(buffer) {
    const digest = await crypto.subtle.digest("SHA-256", buffer);
    return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
  }

  fileInput.addEventListener("change", async () => {
    clientHash = null;
    updateButton();
    const file = fileInput.files[0];
    $("eml-name").textContent = file ? file.name : "nenhum arquivo selecionado";
    if (!file) {
      $("eml-info").textContent = "";
      return;
    }
    if (!/\.eml$/i.test(file.name)) {
      setText("eml-info", "Selecione um arquivo .eml");
      showStatus("error", "O arquivo selecionado não tem extensão .eml.");
      return;
    }
    setText("eml-info", "Calculando SHA-256 no navegador…");
    try {
      clientHash = await sha256Hex(await file.arrayBuffer());
      setText("eml-info", formatBytes(file.size) + " · SHA-256 (navegador) " + clientHash);
      statusBox.hidden = true;
    } catch (err) {
      setText("eml-info", "Não foi possível ler o arquivo");
      showStatus("error", "Falha ao ler o arquivo no navegador.");
    }
    updateButton();
  });

  $("examiner").addEventListener("input", updateButton);

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const file = fileInput.files[0];
    if (!file || !clientHash) return;
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    button.textContent = "Analisando…";
    document.body.classList.add("is-busy");
    showStatus("loading", "Enviando ao servidor local e analisando a evidência…");
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/octet-stream",
          "X-DEL-Token": token,
          "X-DEL-Filename": encodeURIComponent(file.name),
          "X-DEL-Examiner": encodeURIComponent($("examiner").value.trim()),
          "X-DEL-Authserv-Id": encodeURIComponent($("authserv").value.trim()),
          "X-DEL-Client-SHA256": clientHash,
        },
        body: file,
        credentials: "omit",
        cache: "no-store",
      });
      let data = null;
      try {
        data = await response.json();
      } catch (_) {
        data = null;
      }
      if (!response.ok || !data || data.erro) {
        throw new Error((data && data.erro) || "Falha na análise (HTTP " + response.status + ").");
      }
      render(data);
      showStatus("success", "Análise concluída. Relatórios e cadeia de custódia gravados no caso " + data.caso + ".");
      $("results").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
      showStatus("error", err.message || "Falha na análise.");
    } finally {
      button.removeAttribute("aria-busy");
      button.textContent = "Analisar evidência";
      document.body.classList.remove("is-busy");
      updateButton();
    }
  });

  $("copy-sha").addEventListener("click", async () => {
    const feedback = $("copy-feedback");
    try {
      await navigator.clipboard.writeText(currentSha);
      feedback.textContent = "Copiado";
    } catch (_) {
      const range = document.createRange();
      range.selectNodeContents($("sha-value"));
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      feedback.textContent = "Selecionado — use Ctrl+C";
    }
    setTimeout(() => { feedback.textContent = ""; }, 2500);
  });

  // ----- renderização ---------------------------------------------------------------
  function render(d) {
    $("empty").hidden = true;
    $("results").hidden = false;

    setText("case-id", d.caso);
    setText("case-file", d.evidencia);
    const firstEvent = (d.cadeia_custodia.eventos || [])[0];
    setText("case-examiner", firstEvent ? firstEvent.examiner : "");
    const base = "/api/report/" + encodeURIComponent(d.caso) + "/";
    $("dl-json").href = base + "json?t=" + encodeURIComponent(token);
    $("dl-md").href = base + "md?t=" + encodeURIComponent(token);

    // Cards
    const intValue = $("integrity-value");
    intValue.className = "card-value " + (d.integridade_ok ? "ok" : "bad");
    intValue.textContent = d.integridade_ok ? "VERIFICADA" : "FALHA";
    setText("integrity-detail", d.integridade_ok
      ? "SHA-256 após a análise igual ao valor registrado na aquisição."
      : "SHA-256 diverge do valor registrado na aquisição.");
    setText("caveat-hash", "Hash não prova autoria nem autenticidade: auxilia a verificação de integridade e depende do valor de referência e do procedimento de aquisição.");
    $("caveat-hash").title = d.avisos.hash;

    const level = $("level-value");
    level.className = "level " + (LEVEL_CLASS[d.nivel_suspeita] || "");
    level.textContent = d.nivel_suspeita;
    setText("level-score", "pontuação " + d.pontuacao);
    const counts = $("level-counts");
    clear(counts);
    for (const sev of ["alta", "média", "baixa", "info"]) {
      counts.append(el("li", null, sevBadge(sev), el("span", "mono", String(d.contagem_severidade[sev] || 0))));
    }
    setText("caveat-heuristic", d.avisos.heuristico);

    currentSha = d.sha256;
    setText("sha-value", d.sha256);

    // Contadores da navegação
    setText("n-ind", d.indicadores.length);
    setText("n-links", d.links.length);
    setText("n-att", d.anexos.length);
    setText("n-rcv", d.saltos_received.length);

    // Autenticação
    const auth = d.autenticacao;
    setText("caveat-auth", d.avisos.autenticacao);
    setText("auth-situation", d.autenticacao_situacao);
    const mechs = $("auth-mechs");
    clear(mechs);
    if (d.autenticacao_selecionado) {
      for (const key of ["spf", "dkim", "dmarc"]) {
        const r = auth.resultados_cabecalho_selecionado[key];
        mechs.append(el("div", "mech mech-" + r.status.replace(/\s+/g, "-"),
          el("span", "mech-name", key.toUpperCase()),
          el("span", "mech-status", r.status),
          el("span", "mech-raw mono", r.result ? "declarado: " + r.result : "sem resultado declarado")));
      }
    }
    fillTable("auth-table", auth.cabecalhos_declarados.map((h) => [
      td(String(h.position), "mono"),
      td(h.authserv_id || "(vazio)", "mono"),
      td(Object.entries(h.declared).map(([m, v]) => m + "=" + v.join("/")).join("  ") || "(sem spf/dkim/dmarc)", "mono"),
      td(h.selected ? "sim" : "não"),
    ]), "Nenhum cabeçalho Authentication-Results na mensagem.", 4);

    // Indicadores
    const list = $("indicators");
    clear(list);
    if (!d.indicadores.length) list.append(el("li", "empty-row", "Nenhum indicador."));
    const order = { alta: 0, "média": 1, baixa: 2, info: 3 };
    [...d.indicadores].sort((a, b) => order[a.severity] - order[b.severity]).forEach((i) => {
      list.append(el("li", "indicator", sevBadge(i.severity), el("span", "indicator-text", i.description)));
    });

    // Links (somente versão desarmada; nunca <a>)
    fillTable("links-table", d.links.map((l) => [
      td(l.source, "mono nowrap"),
      td(l.url_defanged, "mono break"),
      td(l.text, "break"),
    ]), "Nenhum link encontrado.", 3);

    // Anexos (apenas metadados)
    fillTable("att-table", d.anexos.map((a) => [
      td(a.filename, "mono break"),
      td(a.content_type, "mono"),
      td(formatBytes(a.size), "num mono nowrap"),
      td(a.sha256, "mono hash-cell"),
    ]), "Nenhum anexo.", 4);

    // Received
    fillTable("rcv-table", d.saltos_received.map((h) => [
      td(String(h.index), "mono"),
      td(h.from_host, "mono break"),
      td(h.ip, "mono nowrap"),
      td(h.by_host, "mono break"),
      td(h.protocol, "mono"),
      td(utc(h.timestamp), "mono nowrap"),
    ]), "Nenhum cabeçalho Received.", 6);

    // Timeline
    const tl = $("timeline");
    clear(tl);
    for (const t of d.timeline_utc) {
      tl.append(el("li", "tl-item tl-" + (t.fonte === "custódia" ? "custody" : "email"),
        el("span", "tl-time mono", utc(t.timestamp)),
        el("span", "tl-source", t.fonte),
        el("span", "tl-desc", t.descricao)));
    }

    // Custódia
    const chainOk = d.cadeia_custodia.encadeamento_integro;
    const chain = $("chain-state");
    chain.className = "tag " + (chainOk ? "tag-ok" : "tag-bad");
    chain.textContent = chainOk ? "encadeamento íntegro" : "encadeamento INCONSISTENTE";
    setText("caveat-custody", d.avisos.custodia);
    fillTable("cus-table", d.cadeia_custodia.eventos.map((e) => [
      td(utc(e.timestamp), "mono nowrap"),
      td(e.action, "nowrap"),
      td(e.examiner, "examiner"),
      td(e.details, "break small"),
      td(e.sha256 || "—", "mono hash-cell"),
      td(e.event_hash, "mono hash-cell"),
    ]), "Sem eventos.", 6);

    setText("note-heuristic", d.avisos.heuristico);
    setText("note-hash", d.avisos.hash);
    setText("note-auth", d.avisos.autenticacao);
    setText("note-custody", d.avisos.custodia);
  }
})();
