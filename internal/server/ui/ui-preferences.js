(function () {
  const STORAGE_KEY = 'wtl.ui.preferences.v1';
  const root = document.documentElement;
  const validThemes = new Set(['system', 'light', 'dark']);
  const validDensities = new Set(['standard', 'compact']);
  const validFrames = new Set(['integrated', 'system']);
  const systemTheme = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
  const initial = window.__WTL_UI_PREFERENCES || {};
  const nativeHost = window.__WTL_NATIVE_SHELL || {};
  const state = {
    theme: validThemes.has(initial.theme) ? initial.theme : 'system',
    density: validDensities.has(initial.density) ? initial.density : 'standard',
    framePreference: validFrames.has(nativeHost.framePreference) ? nativeHost.framePreference : 'integrated'
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
    window.__WTL_UI_PREFERENCES = { theme: state.theme, density: state.density, framePreference: state.framePreference };
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
    document.querySelectorAll('[data-wtl-frame-value]').forEach(button => {
      const selected = button.dataset.wtlFrameValue === state.framePreference;
      button.setAttribute('aria-checked', String(selected));
      button.tabIndex = selected ? 0 : -1;
      button.classList.toggle('active', selected);
    });
    document.querySelectorAll('[data-wtl-frame-status]').forEach(element => {
      const current = nativeHost.currentFrame === 'system' ? '系统标题栏' : '融合标题栏';
      const next = state.framePreference === 'system' ? '系统标题栏' : '融合标题栏';
      const override = nativeHost.frameOverride ? '（本次由命令行强制）' : '';
      const pending = nativeHost.currentFrame === state.framePreference ? '' : `；下次启动：${next}`;
      const reason = nativeHost.frameReason ? `；${nativeHost.frameReason}` : '';
      element.textContent = `当前：${current}${override}${pending}${reason}`;
    });
    document.querySelectorAll('.wtl-preferences-trigger').forEach(button => {
      const themeNames = { system: '跟随系统', light: '浅色', dark: '深色' };
      const densityName = state.density === 'compact' ? '紧凑' : '标准';
      const frameName = state.framePreference === 'system' ? '系统标题栏' : '融合标题栏';
      button.title = `外观：${themeNames[state.theme]}；列表：${densityName}；窗口：${frameName}`;
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
        : dataName === 'wtlDensityValue'
          ? '[data-wtl-density-value]'
          : '[data-wtl-frame-value]';
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
    if (nativeHost.trusted && nativeHost.token && typeof window.wtlWindowAction === 'function') {
      const frameLabel = document.createElement('div');
      frameLabel.className = 'wtl-preference-label';
      frameLabel.textContent = '窗口样式';
      const frameGroup = document.createElement('div');
      frameGroup.className = 'wtl-preference-group';
      frameGroup.setAttribute('role', 'radiogroup');
      frameGroup.setAttribute('aria-label', '窗口样式');
      const selectFrame = value => {
        Promise.resolve(window.wtlWindowAction(nativeHost.token, `frame-preference:${value}`)).then(() => {
          state.framePreference = value;
          updatePreferenceControls();
        }).catch(error => {
          const status = menu.querySelector('[data-wtl-frame-status]');
          if (status) status.textContent = `保存窗口样式失败：${error && error.message ? error.message : error}`;
        });
      };
      frameGroup.append(
        createOption('integrated', '融合标题栏', 'wtlFrameValue', selectFrame),
        createOption('system', '系统标题栏', 'wtlFrameValue', selectFrame)
      );
      const frameStatus = document.createElement('div');
      frameStatus.className = 'wtl-frame-status';
      frameStatus.dataset.wtlFrameStatus = '';
      menu.append(frameLabel, frameGroup, frameStatus);
      Promise.resolve(window.wtlWindowAction(nativeHost.token, 'frame-preference-get')).then(value => {
        if (validFrames.has(value)) {
          state.framePreference = value;
          updatePreferenceControls();
        }
      }).catch(() => {});
    }
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
    dialog.setAttribute('aria-labelledby', 'wtl-about-title');
    dialog.innerHTML = `
      <div class="wtl-about-shell">
        <div class="wtl-about-head">
          <div class="wtl-about-identity">
            <span class="wtl-about-mark" aria-hidden="true"></span>
            <div>
              <h2 id="wtl-about-title">WinTraceLens</h2>
              <p>Windows 应急响应与现场取证</p>
            </div>
          </div>
          <button type="button" class="wtl-about-close" data-about-close title="关闭" aria-label="关闭">&#x00D7;</button>
        </div>
        <div class="wtl-about-content">
          <div class="wtl-about-release">
            <span class="wtl-about-version" data-about-version>-</span>
            <span class="wtl-about-local">本机运行</span>
          </div>
          <p class="wtl-about-summary">面向受攻击 Windows 主机的快速现场排查与证据收集工具，集中查看进程、持久化、事件日志、通信与文件痕迹。</p>
          <div class="wtl-about-capabilities" aria-label="主要能力">
            <span>进程与内存</span>
            <span>持久化与日志</span>
            <span>通信与文件痕迹</span>
          </div>
          <dl class="wtl-about-facts">
            <div><dt>运行环境</dt><dd data-about-platform>检测中</dd></div>
            <div><dt>当前权限</dt><dd data-about-permission>检测中</dd></div>
            <div class="wide"><dt>兼容性</dt><dd data-about-compatibility>检测中</dd></div>
          </dl>
          <p class="wtl-about-boundary"><strong>使用边界</strong><span>以只读采集和辅助分析为主，不执行样本，不自动上传证据，不代替完整内存取证或专业 EDR。</span></p>
        </div>
        <div class="wtl-about-footer">
          <span>界面资源随程序提供，可在离线环境中使用。</span>
          <button type="button" data-about-close>完成</button>
        </div>
      </div>`;
    document.body.appendChild(dialog);

    function platformLabel(info) {
      const arch = { amd64: 'x64', '386': 'x86', arm64: 'ARM64' }[info.goarch] || info.goarch || '-';
      const os = info.goos === 'windows' ? 'Windows' : (info.goos || '未知系统');
      return `${os} / ${arch}`;
    }

    function updateAboutInfo(info) {
      const version = document.querySelector('[data-app-version]');
      const versionText = info && info.version ? info.version : (version ? version.textContent.trim() : '-');
      const permissionText = info && info.adminKnown
        ? (info.isAdmin ? '管理员权限' : '标准用户权限')
        : '权限状态未知';
      const compatibilityText = info && info.compatibility ? info.compatibility : '未获取兼容性信息';
      const platformText = info ? platformLabel(info) : 'Windows';

      dialog.querySelector('[data-about-version]').textContent = versionText || '-';
      dialog.querySelector('[data-about-platform]').textContent = platformText;
      dialog.querySelector('[data-about-permission]').textContent = permissionText;
      const compatibility = dialog.querySelector('[data-about-compatibility]');
      compatibility.textContent = compatibilityText;
      compatibility.title = compatibilityText;
    }

    async function refreshAboutInfo() {
      try {
        const response = await fetch('/api/about', { cache: 'no-store' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        updateAboutInfo(await response.json());
      } catch (_) {
        updateAboutInfo(null);
      }
    }

    function openAbout() {
      updateAboutInfo(null);
      dialog.showModal();
      refreshAboutInfo();
    }

    trigger.addEventListener('click', openAbout);
    dialog.querySelectorAll('[data-about-close]').forEach(button => {
      button.addEventListener('click', () => dialog.close());
    });
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
    let rectUpdateFrame = 0;
    function updateMaximizeHitRegion() {
      if (rectUpdateFrame) cancelAnimationFrame(rectUpdateFrame);
      rectUpdateFrame = requestAnimationFrame(() => {
        rectUpdateFrame = 0;
        const rect = maximize.getBoundingClientRect();
        const scale = window.devicePixelRatio || 1;
        invoke(`max-button-rect:${rect.left},${rect.top},${rect.width},${rect.height},${scale}`).catch(() => {});
      });
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
    window.addEventListener('resize', () => {
      updateWindowState();
      updateMaximizeHitRegion();
    });
    if (window.visualViewport) window.visualViewport.addEventListener('resize', updateMaximizeHitRegion);
    updateWindowState();
    updateMaximizeHitRegion();
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
    if (!detail || !head) return;

    const button = head.querySelector('.wtl-detail-toggle');
    if (button && !button.dataset.wtlBound) {
      button.dataset.wtlBound = 'true';
      button.addEventListener('click', () => {
        const collapsed = detail.classList.toggle('wtl-detail-collapsed');
        document.body.classList.toggle('wtl-detail-collapsed', collapsed);
        button.textContent = collapsed ? '展开详情' : '收起详情';
        button.setAttribute('aria-expanded', String(!collapsed));
      });
    }

    const menuTrigger = head.querySelector('#detail-more-trigger');
    const menu = document.querySelector('#detail-more-menu');
    if (menuTrigger && menu && !menuTrigger.dataset.wtlBound) {
      menuTrigger.dataset.wtlBound = 'true';
      const enabledItems = () => Array.from(menu.querySelectorAll('[role="menuitem"]:not(:disabled)'));
      const positionMenu = () => {
        const triggerRect = menuTrigger.getBoundingClientRect();
        const menuRect = menu.getBoundingClientRect();
        const margin = 8;
        const left = Math.max(margin, Math.min(triggerRect.right - menuRect.width, innerWidth - menuRect.width - margin));
        let top = triggerRect.bottom + 4;
        if (top + menuRect.height > innerHeight - margin) top = Math.max(margin, triggerRect.top - menuRect.height - 4);
        menu.style.left = `${Math.round(left)}px`;
        menu.style.top = `${Math.round(top)}px`;
      };
      const closeMenu = returnFocus => {
        if (menu.hidden) return;
        menu.hidden = true;
        menuTrigger.setAttribute('aria-expanded', 'false');
        if (returnFocus) menuTrigger.focus();
      };
      const openMenu = () => {
        if (menuTrigger.disabled) return;
        menu.hidden = false;
        menuTrigger.setAttribute('aria-expanded', 'true');
        positionMenu();
        const items = enabledItems();
        if (items.length) items[0].focus();
      };
      menuTrigger.addEventListener('click', () => menu.hidden ? openMenu() : closeMenu(false));
      menuTrigger.addEventListener('keydown', event => {
        if (event.key === 'ArrowDown') {
          event.preventDefault();
          openMenu();
        }
      });
      menu.addEventListener('keydown', event => {
        const items = enabledItems();
        const index = items.indexOf(document.activeElement);
        if (event.key === 'Escape') {
          event.preventDefault();
          closeMenu(true);
        } else if (items.length && ['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
          event.preventDefault();
          let next = index;
          if (event.key === 'Home') next = 0;
          else if (event.key === 'End') next = items.length - 1;
          else next = (index + (event.key === 'ArrowUp' ? -1 : 1) + items.length) % items.length;
          items[next].focus();
        }
      });
      menu.addEventListener('click', event => {
        if (event.target.closest('[role="menuitem"]')) closeMenu(true);
      });
      document.addEventListener('pointerdown', event => {
        if (!menu.hidden && !menu.contains(event.target) && !menuTrigger.contains(event.target)) closeMenu(false);
      });
      window.addEventListener('resize', () => closeMenu(false));
      window.addEventListener('scroll', () => closeMenu(false), true);
    }

    let resizer = detail.querySelector('.wtl-detail-resizer');
    if (resizer) return;
    resizer = document.createElement('div');
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
