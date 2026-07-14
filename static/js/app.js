(() => {
  // —— Anclas Ver (avisos → solicitud / sección) ——
  function focusHashTarget() {
    const raw = window.location.hash.slice(1);
    if (!raw) return;
    const el = document.getElementById(raw);
    if (!el) return;
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    el.classList.add("is-highlight");
    window.setTimeout(() => el.classList.remove("is-highlight"), 2200);
  }

  window.focusHashTarget();
  window.addEventListener("hashchange", focusHashTarget);

  document.querySelectorAll(".notif-jump").forEach((link) => {
    link.addEventListener("click", (e) => {
      const url = new URL(link.href, window.location.origin);
      if (url.pathname !== window.location.pathname) return;
      if (!url.hash) return;
      // Misma página: forzar foco aunque el hash no cambie
      e.preventDefault();
      if (window.location.hash === url.hash) {
        focusHashTarget();
      } else {
        window.location.hash = url.hash;
      }
    });
  });

  // —— Lookup Bre-B en vivo ——
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

  // —— Confirmación en dos pasos (1.3) ——
  const form = document.getElementById("transfer-form");
  const dialog = document.getElementById("transfer-confirm");
  if (!form || !dialog || typeof dialog.showModal !== "function") return;

  const confirmField = document.getElementById("confirm-password-field");
  const passwordInput = document.getElementById("confirm-password-input");
  const confirmSign = document.getElementById("confirm-sign");
  const confirmError = document.getElementById("confirm-error");
  const balanceEl = document.getElementById("user-balance");
  let allowSubmit = false;

  const money = (n) =>
    n.toLocaleString("es-CO", { style: "currency", currency: "COP", minimumFractionDigits: 2 });

  form.addEventListener("submit", (e) => {
    if (allowSubmit) {
      allowSubmit = false;
      return;
    }
    e.preventDefault();

    const breb = (document.getElementById("receiver_breb")?.value || "").trim();
    const amountRaw = document.getElementById("transfer-amount")?.value || "";
    const note = (document.getElementById("transfer-note")?.value || "").trim() || "—";
    const amount = Number(amountRaw);
    const balance = Number(balanceEl?.dataset.balance || "0");

    if (!breb || !Number.isFinite(amount) || amount <= 0) {
      form.reportValidity();
      return;
    }

    document.getElementById("sum-breb").textContent = breb;
    document.getElementById("sum-dest").textContent =
      hint?.dataset.found === "1" ? hint.dataset.name : "Se resolverá al enviar";
    document.getElementById("sum-amount").textContent = money(amount);
    document.getElementById("sum-note").textContent = note;
    document.getElementById("sum-remaining").textContent =
      balance >= amount ? money(balance - amount) : "Saldo insuficiente";

    if (confirmField) confirmField.value = "";
    if (passwordInput) passwordInput.value = "";
    if (confirmError) {
      confirmError.hidden = true;
      confirmError.textContent = "";
    }

    dialog.showModal();
    passwordInput?.focus();
  });

  confirmSign?.addEventListener("click", () => {
    const pwd = (passwordInput?.value || "").trim();
    if (pwd.length < 6) {
      if (confirmError) {
        confirmError.hidden = false;
        confirmError.textContent = "Ingresa tu contraseña (mín. 6 caracteres) para autorizar la firma.";
      }
      passwordInput?.focus();
      return;
    }
    if (confirmField) confirmField.value = pwd;
    allowSubmit = true;
    dialog.close();
    form.requestSubmit();
  });

  dialog.addEventListener("close", () => {
    if (passwordInput) passwordInput.value = "";
  });

  passwordInput?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      confirmSign?.click();
    }
  });
})();
