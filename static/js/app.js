(() => {
  // —— Tema dark / light (4.1) ——
  const themeBtn = document.getElementById("theme-toggle");
  if (themeBtn) {
    const syncLabel = () => {
      const t = document.documentElement.getAttribute("data-theme") || "dark";
      themeBtn.textContent = t === "dark" ? "Claro" : "Oscuro";
    };
    syncLabel();
    themeBtn.addEventListener("click", () => {
      const cur = document.documentElement.getAttribute("data-theme") || "dark";
      const next = cur === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try {
        localStorage.setItem("brepay-theme", next);
      } catch (_) {}
      syncLabel();
    });
  }

  // —— Anclas Ver (avisos) ——
  function focusHashTarget() {
    const raw = window.location.hash.slice(1);
    if (!raw) return;
    const el = document.getElementById(raw);
    if (!el) return;
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    el.classList.add("is-highlight");
    window.setTimeout(() => el.classList.remove("is-highlight"), 2200);
  }
  focusHashTarget();
  window.addEventListener("hashchange", focusHashTarget);
  document.querySelectorAll(".notif-jump").forEach((link) => {
    link.addEventListener("click", (e) => {
      const url = new URL(link.href, window.location.origin);
      if (url.pathname !== window.location.pathname || !url.hash) return;
      e.preventDefault();
      if (window.location.hash === url.hash) focusHashTarget();
      else window.location.hash = url.hash;
    });
  });

  // —— Lookup Bre-B ——
  const input = document.getElementById("receiver_breb");
  const hint = document.getElementById("breb-hint");
  if (input && hint) {
    let timer = null;
    input.addEventListener("input", () => {
      clearTimeout(timer);
      const q = input.value.trim();
      if (q.length < 3) {
        hint.hidden = true;
        hint.dataset.found = "";
        hint.dataset.name = "";
        return;
      }
      timer = setTimeout(async () => {
        try {
          const res = await fetch(`/api/lookup-breb?q=${encodeURIComponent(q)}`);
          const data = await res.json();
          hint.hidden = false;
          if (data.found) {
            hint.className = "breb-hint found";
            hint.dataset.found = "1";
            hint.dataset.name = `${data.key.full_name} (@${data.key.username})`;
            hint.textContent = `Destino: ${data.key.full_name} (@${data.key.username}) · ${data.key.key_type}`;
          } else {
            hint.className = "breb-hint missing";
            hint.dataset.found = "0";
            hint.dataset.name = "";
            hint.textContent = "Llave Bre-B no registrada";
          }
        } catch {
          hint.hidden = true;
        }
      }, 280);
    });
  }

  // —— Wizard de transferencia (4.3) ——
  const form = document.getElementById("transfer-form");
  if (!form) return;

  const panes = [...form.querySelectorAll(".wizard-pane")];
  const stepli = [...document.querySelectorAll("#wizard-steps li")];
  const passwordInput = document.getElementById("confirm-password-input");
  const confirmError = document.getElementById("confirm-error");
  const balanceEl = document.getElementById("user-balance");
  let step = 1;

  const money = (n) =>
    n.toLocaleString("es-CO", { style: "currency", currency: "COP", minimumFractionDigits: 2 });

  function showStep(n) {
    step = n;
    panes.forEach((p) => {
      p.hidden = Number(p.dataset.pane) !== n;
    });
    stepli.forEach((li, idx) => {
      const s = idx + 1;
      li.classList.toggle("is-active", s === n);
      li.classList.toggle("is-done", s < n);
    });
  }

  function fillSummary() {
    const breb = (document.getElementById("receiver_breb")?.value || "").trim();
    const amount = Number(document.getElementById("transfer-amount")?.value || "");
    const note = (document.getElementById("transfer-note")?.value || "").trim() || "—";
    const balance = Number(balanceEl?.dataset.balance || "0");
    document.getElementById("sum-breb").textContent = breb;
    document.getElementById("sum-dest").textContent =
      hint?.dataset.found === "1" ? hint.dataset.name : "Se resolverá al enviar";
    document.getElementById("sum-amount").textContent = money(amount);
    document.getElementById("sum-note").textContent = note;
    document.getElementById("sum-remaining").textContent =
      balance >= amount ? money(balance - amount) : "Saldo insuficiente";
  }

  form.querySelectorAll("[data-wizard-next]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (step === 1) {
        const breb = (document.getElementById("receiver_breb")?.value || "").trim();
        if (breb.length < 3) {
          document.getElementById("receiver_breb")?.reportValidity();
          return;
        }
        showStep(2);
        return;
      }
      if (step === 2) {
        const amountEl = document.getElementById("transfer-amount");
        if (!amountEl?.checkValidity()) {
          amountEl?.reportValidity();
          return;
        }
        fillSummary();
        showStep(3);
        passwordInput?.focus();
      }
    });
  });

  form.querySelectorAll("[data-wizard-back]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (step > 1) showStep(step - 1);
    });
  });

  form.addEventListener("submit", (e) => {
    if (step !== 3) {
      e.preventDefault();
      return;
    }
    const pwd = (passwordInput?.value || "").trim();
    if (pwd.length < 6) {
      e.preventDefault();
      if (confirmError) {
        confirmError.hidden = false;
        confirmError.textContent = "Ingresa tu contraseña (mín. 6 caracteres) para autorizar la firma.";
      }
      passwordInput?.focus();
    }
  });

  showStep(1);
})();
