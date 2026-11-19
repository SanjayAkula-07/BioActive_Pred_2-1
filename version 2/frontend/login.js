(() => {
  const $ = (id) => document.getElementById(id);
  const params = new URLSearchParams(location.search);
  const next = params.get("next") || "/app/";
  let signup = params.get("mode") === "signup";

  const form = $("authForm"), err = $("error"), btn = $("submitBtn");

  function render() {
    $("formTitle").textContent = signup ? "Create account" : "Log In";
    btn.textContent = signup ? "Sign Up" : "Log In";
    $("modeToggle").textContent = signup ? "Log In" : "Sign Up";
    $("confirmWrap").hidden = !signup;
    $("password").autocomplete = signup ? "new-password" : "current-password";
    err.hidden = true;
  }
  function showError(msg) { err.textContent = msg; err.hidden = false; err.style.cssText = ""; }

  $("modeToggle").addEventListener("click", () => { signup = !signup; render(); });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const email = $("email").value.trim(), password = $("password").value;
    if (!email || !password) return showError("Enter your email and password.");
    if (signup) {
      if (password.length < 8) return showError("Password must be at least 8 characters.");
      if (password !== $("confirm").value) return showError("Passwords do not match.");
    }
    btn.disabled = true; err.hidden = true;
    try {
      const res = await fetch(signup ? "/auth/signup" : "/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ email, password, next }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || "Something went wrong. Please try again.");
      if (data.confirm) {            // Supabase email confirmation is enabled
        signup = false; render();
        err.textContent = data.detail; err.hidden = false; err.style.cssText = "background:#eff6ff;color:#1d4ed8";
        btn.disabled = false; return;
      }
      location.replace(data.next || "/app/");
    } catch (ex) {
      showError(ex.message);
      btn.disabled = false;
    }
  });

  // Live model status badge (/health is public)
  fetch("/health").then((r) => {
    const ok = r.ok;
    $("modelPillText").textContent = ok ? "Bioactive Model Online" : "Model Offline";
    $("modelPill").classList.toggle("offline", !ok);
  }).catch(() => {
    $("modelPillText").textContent = "Model Offline";
    $("modelPill").classList.add("offline");
  });

  render();
})();
