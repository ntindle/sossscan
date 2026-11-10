// The theme on the text pages (lib/pages.ts), which don't run the pipeline map's script. Loaded as a plain script in
// <head>, it applies the saved choice before the page paints, as index.html's inline script does. Then it shows the
// header's Theme button, which cycles system, light and dark like the home page's (setupTheme in pipeline.js).
(() => {
  const root = document.documentElement;
  let cur = 'system';
  try {
    const saved = localStorage.getItem('pl:theme');
    if (saved === 'light' || saved === 'dark') { cur = saved; root.setAttribute('data-theme', saved); }
  } catch { /* storage blocked */ }

  document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('theme');
    if (!btn) return;
    const paint = () => { btn.textContent = `Theme: ${cur}`; };
    btn.addEventListener('click', () => {
      cur = { system: 'light', light: 'dark', dark: 'system' }[cur];
      if (cur === 'system') root.removeAttribute('data-theme'); else root.setAttribute('data-theme', cur);
      try { if (cur === 'system') localStorage.removeItem('pl:theme'); else localStorage.setItem('pl:theme', cur); } catch { /* storage blocked */ }
      paint();
    });
    paint();
    btn.hidden = false;
  });
})();
