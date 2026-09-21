(function () {
  const STORAGE_KEY = 'wtl.ui.preferences.v1';
  const root = document.documentElement;

  function validTheme(value) {
    return value === 'system' || value === 'light' || value === 'dark';
  }

  function validDensity(value) {
    return value === 'standard' || value === 'compact';
  }

  let stored = {};
  try {
    stored = JSON.parse(sessionStorage.getItem(STORAGE_KEY) || '{}') || {};
  } catch (_) {
    stored = {};
  }

  const themePreference = validTheme(stored.theme) ? stored.theme : 'system';
  const density = validDensity(stored.density) ? stored.density : 'standard';
  let systemDark = false;
  try {
    systemDark = !!window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  } catch (_) {
    systemDark = false;
  }

  const actualTheme = themePreference === 'system'
    ? (systemDark ? 'dark' : 'light')
    : themePreference;

  root.dataset.theme = actualTheme;
  root.dataset.themePreference = themePreference;
  root.dataset.density = density;
  const nativeShell = window.__WTL_NATIVE_SHELL;
  if (nativeShell && nativeShell.trusted) {
    root.dataset.wtlHost = nativeShell.customFrame ? 'native' : 'system-frame';
    if (nativeShell.token && typeof window.wtlWindowAction === 'function') {
      Promise.resolve(window.wtlWindowAction(nativeShell.token, `theme:${actualTheme}`)).catch(() => {});
    }
  }
  window.__WTL_UI_PREFERENCES = { theme: themePreference, density: density };
})();
