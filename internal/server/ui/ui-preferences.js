(function () {
  const STORAGE_KEY = 'wtl.ui.preferences.v1';
  const root = document.documentElement;
  const validThemes = new Set(['system', 'light', 'dark']);
  const validDensities = new Set(['standard', 'compact']);
  const systemTheme = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
  const initial = window.__WTL_UI_PREFERENCES || {};
  const state = {
    theme: validThemes.has(initial.theme) ? initial.theme : 'system',
    density: validDensities.has(initial.density) ? initial.density : 'standard'
  };

  function actualTheme() {
    if (state.theme !== 'system') return state.theme;
    return systemTheme && systemTheme.matches ? 'dark' : 'light';
  }

  function persist() {
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify({
        theme: state.theme,
        density: state.density
      }));
    } catch (_) {
      // Storage can be disabled. The current page still keeps the selected appearance.
    }
  }

  function applyPreferences(save) {
    root.dataset.theme = actualTheme();
    root.dataset.themePreference = state.theme;
    root.dataset.density = state.density;
    window.__WTL_UI_PREFERENCES = { theme: state.theme, density: state.density };
    if (save) persist();
    updatePreferenceControls();
    syncHostTheme();
  }

  function syncHostTheme() {
    const host = window.__WTL_NATIVE_SHELL;
    if (!host || !host.token || typeof window.wtlWindowAction !== 'function') return;
    Promise.resolve(window.wtlWindowAction(host.token, `theme:${actualTheme()}`)).catch(() => {});
  }

  function updatePreferenceControls() {
    document.querySelectorAll('[data-wtl-theme-value]').forEach(button => {
      const selected = button.dataset.wtlThemeValue === state.theme;
      button.setAttribute('aria-checked', String(selected));
      button.tabIndex = selected ? 0 : -1;
      button.classList.toggle('active', selected);
    });
    document.querySelectorAll('[data-wtl-density-value]').forEach(button => {
      const selected = button.dataset.wtlDensityValue === state.density;
      button.setAttribute('aria-checked', String(selected));
      button.tabIndex = selected ? 0 : -1;
      button.classList.toggle('active', selected);
    });
    document.querySelectorAll('.wtl-preferences-trigger').forEach(button => {
      const themeNames = { system: '跟随系统', light: '浅色', dark: '深色' };
      const densityName = state.density === 'compact' ? '紧凑' : '标准';
      button.title = `外观：${themeNames[state.theme]}；列表：${densityName}`;
    });
  }

  function moveWithinGroup(event, selector) {
    if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(event.key)) return;
    const buttons = Array.from(event.currentTarget.parentElement.querySelectorAll(selector));
    const index = buttons.indexOf(event.currentTarget);
    if (index < 0) return;
    event.preventDefault();
    const delta = event.key === 'ArrowLeft' || event.key === 'ArrowUp' ? -1 : 1;
    const next = buttons[(index + delta + buttons.length) % buttons.length];
    next.focus();
    next.click();
  }

  function createOption(value, label, dataName, onSelect) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'wtl-preference-option';
    button.setAttribute('role', 'radio');
    button.dataset[dataName] = value;
    button.textContent = label;
    button.addEventListener('click', () => onSelect(value));
    button.addEventListener('keydown', event => {
      const selector = dataName === 'wtlThemeValue'
        ? '[data-wtl-theme-value]'
        : '[data-wtl-density-value]';
      moveWithinGroup(event, selector);
    });
    return button;
  }

  function createPreferencesControl() {
    const meta = document.querySelector('header .app-meta');
    if (!meta || meta.querySelector('.wtl-preferences')) return;

    const container = document.createElement('div');
    container.className = 'wtl-preferences';

    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'wtl-preferences-trigger';
    trigger.setAttribute('aria-haspopup', 'dialog');
    trigger.setAttribute('aria-expanded', 'false');
    trigger.innerHTML = '<span class="wtl-theme-swatch" aria-hidden="true"></span><span>外观</span>';

    const menu = document.createElement('div');
    menu.className = 'wtl-preferences-menu';
    menu.hidden = true;
    menu.setAttribute('role', 'dialog');
    menu.setAttribute('aria-label', '外观和列表密度');

    const themeLabel = document.createElement('div');
    themeLabel.className = 'wtl-preference-label';
    themeLabel.textContent = '外观';
    const themeGroup = document.createElement('div');
    themeGroup.className = 'wtl-preference-group';
    themeGroup.setAttribute('role', 'radiogroup');
    themeGroup.setAttribute('aria-label', '外观');
    themeGroup.append(
      createOption('system', '跟随系统', 'wtlThemeValue', value => { state.theme = value; applyPreferences(true); }),
      createOption('light', '浅色', 'wtlThemeValue', value => { state.theme = value; applyPreferences(true); }),
      createOption('dark', '深色', 'wtlThemeValue', value => { state.theme = value; applyPreferences(true); })
    );

    const densityLabel = document.createElement('div');
    densityLabel.className = 'wtl-preference-label';
    densityLabel.textContent = '列表密度';
    const densityGroup = document.createElement('div');
    densityGroup.className = 'wtl-preference-group';
    densityGroup.setAttribute('role', 'radiogroup');
    densityGroup.setAttribute('aria-label', '列表密度');
    densityGroup.append(
      createOption('standard', '标准', 'wtlDensityValue', value => { state.density = value; applyPreferences(true); }),
      createOption('compact', '紧凑', 'wtlDensityValue', value => { state.density = value; applyPreferences(true); })
    );

    menu.append(themeLabel, themeGroup, densityLabel, densityGroup);
    container.append(trigger, menu);
    meta.append(container);

    function closeMenu(returnFocus) {
      if (menu.hidden) return;
      menu.hidden = true;
      trigger.setAttribute('aria-expanded', 'false');
      if (returnFocus) trigger.focus();
    }

    function openMenu() {
      menu.hidden = false;
      trigger.setAttribute('aria-expanded', 'true');
      updatePreferenceControls();
      const selected = menu.querySelector('[aria-checked="true"]');
      if (selected) selected.focus();
    }

    trigger.addEventListener('click', () => menu.hidden ? openMenu() : closeMenu(false));
    trigger.addEventListener('keydown', event => {
      if (event.key === 'ArrowDown') {
        event.preventDefault();
        openMenu();
      }
    });
    menu.addEventListener('keydown', event => {
      if (event.key === 'Escape') {
        event.preventDefault();
        closeMenu(true);
      }
    });
    document.addEventListener('pointerdown', event => {
      if (!container.contains(event.target)) closeMenu(false);
    });
  }

  function createAboutButton() {
    const meta = document.querySelector('header .app-meta');
    if (!meta || meta.querySelector('.wtl-about-trigger')) return;

    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'wtl-about-trigger';
    trigger.textContent = '关于';
    trigger.setAttribute('aria-haspopup', 'dialog');
    meta.append(trigger);

    const dialog = document.createElement('dialog');
    dialog.className = 'wtl-about-dialog';
    dialog.innerHTML = '<div class="dialog-head"><h2>关于 WinTraceLens</h2><button type="button" class="secondary" data-about-close>关闭</button></div><dl class="dialog-body"><dt>版本</dt><dd data-about-version>-</dd></dl>';
    document.body.appendChild(dialog);

    function openAbout() {
      const version = document.querySelector('[data-app-version]');
      dialog.querySelector('[data-about-version]').textContent = version ? version.textContent.trim() : '-';
      dialog.showModal();
    }

    trigger.addEventListener('click', openAbout);
    dialog.querySelector('[data-about-close]').addEventListener('click', () => dialog.close());
    dialog.addEventListener('click', event => {
      if (event.target === dialog) dialog.close();
    });
  }

  function prepareWindowShell() {
    const host = window.__WTL_NATIVE_SHELL;
    if (!host || !host.trusted) return;
    root.dataset.wtlHost = host.customFrame ? 'native' : 'system-frame';
    if (!host.customFrame || typeof window.wtlWindowAction !== 'function') return;

    const header = document.querySelector('body > header');
    const meta = header && header.querySelector('.app-meta');
    if (!header || !meta || meta.querySelector('.wtl-window-controls')) return;

    const controls = document.createElement('div');
    controls.className = 'wtl-window-controls';
    controls.setAttribute('aria-label', '窗口操作');
    controls.innerHTML = '<button type="button" class="wtl-window-button minimize" title="最小化" aria-label="最小化">&#x2212;</button><button type="button" class="wtl-window-button maximize" title="最大化" aria-label="最大化">&#x25A1;</button><button type="button" class="wtl-window-button close" title="关闭" aria-label="关闭">&#x00D7;</button>';
    meta.appendChild(controls);

    const maximize = controls.querySelector('.maximize');
    function invoke(action) {
      return Promise.resolve(window.wtlWindowAction(host.token, action));
    }
    function updateWindowState() {
      invoke('state').then(state => {
        const maximized = state === 'maximized';
        maximize.innerHTML = maximized ? '&#x2750;' : '&#x25A1;';
        maximize.title = maximized ? '还原' : '最大化';
        maximize.setAttribute('aria-label', maximize.title);
      }).catch(() => {});
    }

    controls.querySelector('.minimize').addEventListener('click', () => invoke('minimize').catch(() => {}));
    maximize.addEventListener('click', () => invoke('toggle-maximize').then(updateWindowState).catch(() => {}));
    controls.querySelector('.close').addEventListener('click', () => invoke('close').catch(() => {}));
    let pendingDrag = null;
    header.addEventListener('pointerdown', event => {
      if (event.button !== 0 || event.target.closest('button, a, input, select, textarea, .app-meta')) return;
      pendingDrag = { id: event.pointerId, x: event.clientX, y: event.clientY };
      header.setPointerCapture(event.pointerId);
    });
    header.addEventListener('pointermove', event => {
      if (!pendingDrag || event.pointerId !== pendingDrag.id) return;
      if (Math.hypot(event.clientX - pendingDrag.x, event.clientY - pendingDrag.y) < 4) return;
      pendingDrag = null;
      if (header.hasPointerCapture(event.pointerId)) header.releasePointerCapture(event.pointerId);
      invoke('drag').catch(() => {});
    });
    header.addEventListener('pointerup', event => {
      if (pendingDrag && event.pointerId === pendingDrag.id) pendingDrag = null;
    });
    header.addEventListener('pointercancel', () => { pendingDrag = null; });
    header.addEventListener('dblclick', event => {
      if (event.target.closest('button, a, input, select, textarea, .app-meta')) return;
      invoke('toggle-maximize').then(updateWindowState).catch(() => {});
    });
    header.addEventListener('contextmenu', event => {
      if (event.target.closest('button, a, input, select, textarea, .app-meta')) return;
      event.preventDefault();
      invoke('system-menu').then(updateWindowState).catch(() => {});
    });
    window.addEventListener('resize', updateWindowState);
    updateWindowState();
  }

  function markTable(table) {
    if (!(table instanceof HTMLTableElement)) return;
    table.classList.add('wtl-table');
    table.querySelectorAll('tbody tr').forEach(row => {
      const isDataRow = row.cells.length > 1 && !row.querySelector('.empty');
      row.classList.toggle('wtl-data-row', isDataRow);
    });
  }

  function enhanceTables(scope) {
    const selector = '.table-wrap table, table.process-table, table.detail-table, table.source-table, table.summary-table, table.wmi-table';
    if (scope instanceof HTMLTableElement && scope.matches(selector)) markTable(scope);
    if (scope.querySelectorAll) scope.querySelectorAll(selector).forEach(markTable);
  }

  function observeTables() {
    enhanceTables(document);
    const observer = new MutationObserver(records => {
      for (const record of records) {
        record.addedNodes.forEach(node => {
          if (node.nodeType !== Node.ELEMENT_NODE) return;
          if (node instanceof HTMLTableRowElement) {
            const table = node.closest('table');
            if (table) markTable(table);
            return;
          }
          enhanceTables(node);
        });
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  function prepareNavigation() {
    document.querySelectorAll('.top-nav').forEach(nav => {
      const active = nav.querySelector('[aria-current="page"]');
      if (active) {
        const reveal = () => {
          const target = active.offsetLeft - Math.max(0, (nav.clientWidth - active.offsetWidth) / 2);
          nav.scrollLeft = Math.max(0, target);
        };
        reveal();
        active.addEventListener('focus', reveal);
      }
      nav.querySelectorAll('a').forEach(link => {
        link.addEventListener('focus', () => link.scrollIntoView({ block: 'nearest', inline: 'nearest' }));
      });
    });
  }

  function prepareProcessDetails() {
    if (location.pathname !== '/' && location.pathname !== '/index.html') return;
    const detail = document.querySelector('section.detail');
    const head = detail && detail.querySelector('.detail-head');
    if (!detail || !head || head.querySelector('.wtl-detail-toggle')) return;

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'secondary mini wtl-detail-toggle';
    button.textContent = '收起详情';
    button.setAttribute('aria-expanded', 'true');
    button.addEventListener('click', () => {
      const collapsed = detail.classList.toggle('wtl-detail-collapsed');
      document.body.classList.toggle('wtl-detail-collapsed', collapsed);
      button.textContent = collapsed ? '展开详情' : '收起详情';
      button.setAttribute('aria-expanded', String(!collapsed));
    });
    head.append(button);

    const resizer = document.createElement('div');
    resizer.className = 'wtl-detail-resizer';
    resizer.setAttribute('role', 'separator');
    resizer.setAttribute('aria-orientation', 'horizontal');
    resizer.title = '拖动调整详情高度；双击恢复默认高度';
    detail.prepend(resizer);
    const main = detail.closest('main');
    let startY = 0;
    let startHeight = 0;
    resizer.addEventListener('pointerdown', event => {
      if (event.button !== 0) return;
      startY = event.clientY;
      startHeight = detail.getBoundingClientRect().height;
      resizer.setPointerCapture(event.pointerId);
      event.preventDefault();
    });
    resizer.addEventListener('pointermove', event => {
      if (!resizer.hasPointerCapture(event.pointerId)) return;
      const height = Math.max(150, Math.min(window.innerHeight * 0.5, startHeight + startY - event.clientY));
      main.style.setProperty('--wtl-process-detail-height', `${Math.round(height)}px`);
    });
    resizer.addEventListener('dblclick', () => {
      main.style.removeProperty('--wtl-process-detail-height');
    });
  }

  function pageClass() {
    const page = (location.pathname.split('/').pop() || 'index.html').replace(/\.html$/i, '') || 'index';
    document.body.classList.add(`wtl-page-${page}`);
  }

  function init() {
    pageClass();
    prepareWindowShell();
    createPreferencesControl();
    createAboutButton();
    prepareNavigation();
    prepareProcessDetails();
    observeTables();
    applyPreferences(false);
  }

  if (systemTheme) {
    const onSystemTheme = () => {
      if (state.theme === 'system') applyPreferences(false);
    };
    if (systemTheme.addEventListener) systemTheme.addEventListener('change', onSystemTheme);
    else if (systemTheme.addListener) systemTheme.addListener(onSystemTheme);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
