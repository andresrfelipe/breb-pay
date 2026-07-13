(() => {
  const input = document.getElementById("receiver_breb");
  const hint = document.getElementById("breb-hint");
  if (!input || !hint) return;

  let timer = null;
  input.addEventListener("input", () => {
    clearTimeout(timer);
    const q = input.value.trim();
    if (q.length < 3) {
      hint.hidden = true;
      return;
    }
    timer = setTimeout(async () => {
      try {
        const res = await fetch(`/api/lookup-breb?q=${encodeURIComponent(q)}`);
        const data = await res.json();
        hint.hidden = false;
        if (data.found) {
          hint.className = "breb-hint found";
          hint.textContent = `Destino: ${data.key.full_name} (@${data.key.username}) · ${data.key.key_type}`;
        } else {
          hint.className = "breb-hint missing";
          hint.textContent = "Llave Bre-B no registrada";
        }
      } catch {
        hint.hidden = true;
      }
    }, 280);
  });
})();
