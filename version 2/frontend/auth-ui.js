/* Shared by every protected page: user chip + logout, and bounce to login on 401. */
(() => {
  const loginUrl = () => "/app/login?next=" + encodeURIComponent(location.pathname + location.search);

  // Any API call that comes back 401 (expired session) sends the user to sign in again.
  const _fetch = window.fetch.bind(window);
  window.fetch = async (...args) => {
    const res = await _fetch(...args);
    const url = String(args[0] && args[0].url || args[0]);
    if (res.status === 401 && !url.includes("/auth/")) location.href = loginUrl();
    return res;
  };

  document.addEventListener("DOMContentLoaded", async () => {
    const host = document.querySelector(".nav-right");
    if (!host) return;
    try {
      const res = await _fetch("/auth/me", { credentials: "same-origin" });
      if (!res.ok) return (location.href = loginUrl());
      const { email } = await res.json();
      const menu = document.createElement("div");
      menu.className = "user-menu";
      menu.innerHTML = '<span class="user-email"></span><button type="button" class="logout-btn">Log out</button>';
      menu.querySelector(".user-email").textContent = email;
      menu.querySelector(".logout-btn").addEventListener("click", async () => {
        await _fetch("/auth/logout", { method: "POST", credentials: "same-origin" });
        location.href = "/app/login";
      });
      host.insertBefore(menu, host.firstChild);
    } catch (_) { /* offline: leave nav untouched */ }
  });
})();
