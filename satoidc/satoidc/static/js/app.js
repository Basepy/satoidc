/* SatOIDC — interações mínimas das telas (sem framework). */

/* Mostrar senha */
document.querySelectorAll("[data-toggle-password]").forEach((toggle) => {
  const input = document.querySelector(toggle.dataset.togglePassword);
  toggle.addEventListener("change", () => {
    if (input) input.type = toggle.checked ? "text" : "password";
  });
});

/* Copiar para a área de transferência: <button data-copy="texto"> */
document.addEventListener("click", (event) => {
  const btn = event.target.closest("[data-copy]");
  if (!btn) return;
  const original = btn.innerHTML;
  navigator.clipboard
    .writeText(btn.dataset.copy)
    .then(() => {
      btn.setAttribute("data-copied", "true");
      window.setTimeout(() => btn.removeAttribute("data-copied"), 1500);
    })
    .catch(() => {
      btn.innerHTML = original;
    });
});

/* Diálogos: Esc fecha (segue o link "Cancelar" do diálogo) e foca o primeiro campo */
const dialog = document.querySelector("[role='dialog']");
if (dialog) {
  const first = dialog.querySelector("input:not([type=hidden]):not([type=checkbox]), textarea");
  if (first) first.focus();
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    const cancel = dialog.querySelector("[data-cancel]");
    if (cancel) window.location.assign(cancel.getAttribute("href"));
  });
}

/* Confirmação por digitação (excluir cliente): só habilita o botão quando bater */
document.querySelectorAll("[data-confirm-input]").forEach((input) => {
  const btn = document.querySelector(input.dataset.confirmInput);
  const check = () => {
    const ok = input.value.trim() === input.dataset.confirmValue;
    btn.disabled = !ok;
    btn.style.opacity = ok ? "1" : "0.5";
  };
  input.addEventListener("input", check);
  check();
});

/* Tela "Entrar com Lightning" (LNURL-auth) */
function initLightningPage(root) {
  const qrBox = root.querySelector("[data-qr]");
  const statusEl = root.querySelector("[data-status]");
  const spinner = root.querySelector("[data-spinner]");
  const statusText = root.querySelector("[data-status-text]");
  const expiryEl = root.querySelector("[data-expiry]");
  const timerEl = root.querySelector("[data-timer]");
  const codeEl = root.querySelector("[data-code]");
  const copyBtn = root.querySelector("[data-copy-lnurl]");
  const openLink = root.querySelector("[data-open]");
  const retryBtn = root.querySelector("[data-retry]");
  const iconCopy = copyBtn ? copyBtn.innerHTML : "";
  const iconDone =
    '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 12 5 5 9-10"></path></svg>';
  let pollTimer = null;
  let clockTimer = null;
  let current = null;
  let deadline = 0;

  function setStatus(text, kind) {
    statusText.textContent = text;
    statusEl.style.color = kind === "error" ? "var(--c-b3261e)" : kind === "success" ? "var(--c-17603a)" : "";
    spinner.style.display = kind ? "none" : "";
  }

  function stopTimers() {
    window.clearInterval(pollTimer);
    window.clearInterval(clockTimer);
    pollTimer = clockTimer = null;
  }

  function renderQr(text) {
    const qr = qrcode(0, "M");
    qr.addData(text);
    qr.make();
    const n = qr.getModuleCount();
    let path = "";
    for (let r = 0; r < n; r += 1) {
      for (let c = 0; c < n; c += 1) {
        if (qr.isDark(r, c)) path += `M${c} ${r}h1v1h-1z`;
      }
    }
    const size = Number(qrBox.dataset.qrSize) || 200;
    const old = qrBox.querySelector("svg");
    if (old) old.remove();
    qrBox.insertAdjacentHTML(
      "afterbegin",
      `<svg width="${size}" height="${size}" viewBox="0 0 ${n} ${n}" shape-rendering="crispEdges" role="img" aria-label="Código QR LNURL-auth" style="display: block"><path d="${path}" fill="#1B1C23"></path></svg>`
    );
  }

  function formatClock(seconds) {
    return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
  }

  function fail(text) {
    stopTimers();
    const svg = qrBox.querySelector("svg");
    if (svg) svg.style.opacity = "0.15";
    if (openLink) {
      openLink.setAttribute("aria-disabled", "true");
      openLink.style.opacity = "0.5";
      openLink.style.pointerEvents = "none";
    }
    if (expiryEl) expiryEl.hidden = true;
    setStatus(text, "error");
    if (retryBtn) retryBtn.hidden = false;
  }

  function tickClock() {
    const left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
    if (timerEl) timerEl.textContent = formatClock(left);
    if (left === 0) fail("O código expirou.");
  }

  async function poll() {
    if (!current) return;
    try {
      const res = await fetch(`/auth/lnurl/status/${current.k1}`, { credentials: "same-origin" });
      const data = await res.json();
      if (data.status === "OK") {
        stopTimers();
        setStatus("Carteira confirmada. Entrando…", "success");
        window.location.assign(data.redirect || "/");
      } else if (data.status === "EXPIRED") {
        fail("O código expirou.");
      } else if (data.status === "ERROR") {
        fail("Não foi possível concluir. Gere um novo código.");
      }
    } catch (error) {
      setStatus("Sem conexão. Tentando novamente…");
    }
  }

  async function begin() {
    stopTimers();
    if (retryBtn) retryBtn.hidden = true;
    if (expiryEl) expiryEl.hidden = false;
    if (openLink) {
      openLink.style.opacity = "";
      openLink.style.pointerEvents = "";
    }
    setStatus("Gerando código…");
    try {
      const res = await fetch("/auth/lnurl", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: root.dataset.action, redirect_to: root.dataset.redirect || "/" }),
      });
      if (!res.ok) throw new Error("challenge");
      current = await res.json();
      renderQr(current.lnurl);
      if (codeEl) codeEl.textContent = `${current.lnurl.slice(0, 22).toLowerCase()}…${current.lnurl.slice(-5).toLowerCase()}`;
      if (openLink) {
        openLink.href = current.uri;
        openLink.removeAttribute("aria-disabled");
      }
      deadline = Date.now() + current.expires_in * 1000;
      tickClock();
      setStatus("Aguardando sua carteira…");
      pollTimer = window.setInterval(poll, 2000);
      clockTimer = window.setInterval(tickClock, 1000);
    } catch (error) {
      fail("Não foi possível gerar o código.");
    }
  }

  if (copyBtn) copyBtn.addEventListener("click", () => {
    if (!current) return;
    navigator.clipboard
      .writeText(current.lnurl)
      .then(() => {
        copyBtn.innerHTML = iconDone;
        window.setTimeout(() => (copyBtn.innerHTML = iconCopy), 1500);
      })
      .catch(() => setStatus("Não foi possível copiar automaticamente.", "error"));
  });
  if (retryBtn) retryBtn.addEventListener("click", begin);
  begin();
}

document.querySelectorAll("[data-lightning]").forEach(initLightningPage);

/* Menu lateral (telas logadas no celular) */
document.querySelectorAll("[data-toggle-nav]").forEach((btn) => {
  btn.addEventListener("click", () => document.body.classList.toggle("nav-open"));
});
document.addEventListener("click", (event) => {
  if (!document.body.classList.contains("nav-open")) return;
  if (event.target.closest(".dc-nav, [data-toggle-nav]")) return;
  document.body.classList.remove("nav-open");
});

/* Filtro de tabela: <input data-filter="#tabela"> esconde as linhas [data-row] sem o texto */
document.querySelectorAll("[data-filter]").forEach((input) => {
  const table = document.querySelector(input.dataset.filter);
  if (!table) return;
  const rows = [...table.querySelectorAll("tr[data-row]")];
  const counter = input.closest("section")?.querySelector("[data-count]");
  input.addEventListener("input", () => {
    const term = input.value.trim().toLowerCase();
    let shown = 0;
    rows.forEach((row) => {
      const match = !term || row.textContent.toLowerCase().includes(term) || (row.dataset.search || "").toLowerCase().includes(term);
      row.hidden = !match;
      if (match) shown += 1;
    });
    if (counter) counter.textContent = `${shown} ${shown === 1 ? counter.dataset.one : counter.dataset.many}`;
  });
});

/* Menu de ações da linha (kebab) */
document.addEventListener("click", (event) => {
  const trigger = event.target.closest("[data-menu]");
  document.querySelectorAll("[data-menu-panel]").forEach((panel) => {
    const owner = panel.previousElementSibling;
    const open = trigger === owner && panel.hidden;
    panel.hidden = !open;
    if (owner) owner.setAttribute("aria-expanded", String(open));
  });
});
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  document.querySelectorAll("[data-menu-panel]").forEach((panel) => (panel.hidden = true));
});

/* Client secret: "Concluir" só libera depois de marcar que guardou o secret */
document.querySelectorAll("[data-ack-target]").forEach((done) => {
  const box = done.closest("form")?.querySelector("input[name=ack]");
  if (!box) return;
  const sync = () => done.setAttribute("aria-disabled", String(!box.checked));
  box.addEventListener("change", sync);
  sync();
});
