"use strict";

(() => {
  const key = "scalar.theme";
  const system = window.matchMedia("(prefers-color-scheme: dark)");
  const valid = (value) => value === "dark" || value === "light" ? value : null;
  let preference = null;
  try { preference = valid(localStorage.getItem(key)); } catch { preference = null; }

  function apply() {
    const theme = preference || (system.matches ? "dark" : "light");
    document.documentElement.dataset.theme = theme;
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
      const label = theme === "dark" ? "Switch to light mode" : "Switch to dark mode";
      button.title = label;
      button.setAttribute("aria-label", label);
      button.setAttribute("aria-pressed", String(theme === "dark"));
      const glyph = document.createElement("i");
      glyph.setAttribute("data-lucide", theme === "dark" ? "sun" : "moon");
      glyph.setAttribute("aria-hidden", "true");
      button.replaceChildren(glyph);
    });
    globalThis.lucide?.createIcons({ attrs: { "stroke-width": 1.7 } });
  }

  apply();
  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
      button.addEventListener("click", () => {
        preference = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
        try { localStorage.setItem(key, preference); } catch {}
        apply();
      });
    });
    apply();
  });
  system.addEventListener("change", () => { if (preference === null) apply(); });
  window.addEventListener("storage", (event) => {
    if (event.key === key || event.key === null) { preference = valid(event.newValue); apply(); }
  });
})();
