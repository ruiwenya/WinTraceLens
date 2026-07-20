(function () {
  const nativeFetch = window.fetch.bind(window);
  const progressState = {
    active: 0,
    value: 0,
    timer: null,
    hideTimer: null
  };

  function progressLabel(pathname) {
    const labels = [
      ['/api/process', '正在采集进程信息'],
      ['/api/connections', '正在采集网络连接'],
      ['/api/host', '正在采集主机信息'],
      ['/api/findings', '正在分析风险线索'],
      ['/api/threat', '正在加载威胁分析'],
      ['/api/security', '正在读取事件日志'],
      ['/api/history', '正在采集历史通信'],
      ['/api/filetrace', '正在扫描文件痕迹'],
      ['/api/investigation', '正在整理案件证据'],
      ['/api/ai', '正在进行 AI 分析'],
      ['/api/yara', '正在执行 YARA 扫描'],
      ['/api/export', '正在生成取证导出']
    ];
    const match = labels.find(item => pathname.startsWith(item[0]));
    return match ? match[1] : '正在采集数据';
  }

  function ensureProgress() {
    let root = document.getElementById('wtl-global-progress');
    if (root) return root;

    root = document.createElement('div');
    root.id = 'wtl-global-progress';
    root.hidden = true;
    root.setAttribute('role', 'progressbar');
    root.setAttribute('aria-valuemin', '0');
    root.setAttribute('aria-valuemax', '100');
    root.innerHTML = '<span class="wtl-progress-label">正在采集数据</span><span class="wtl-progress-track"><span class="wtl-progress-bar"></span></span>';
    (document.body || document.documentElement).appendChild(root);
    return root;
  }

  function renderProgress(label) {
    const root = ensureProgress();
    root.hidden = false;
    root.setAttribute('aria-valuenow', String(Math.round(progressState.value)));
    root.querySelector('.wtl-progress-label').textContent = label;
    root.querySelector('.wtl-progress-bar').style.width = `${progressState.value}%`;
  }

  function startProgress(pathname) {
    progressState.active += 1;
    if (progressState.hideTimer) {
      clearTimeout(progressState.hideTimer);
      progressState.hideTimer = null;
    }
    if (progressState.active === 1) progressState.value = 8;
    renderProgress(progressLabel(pathname));
    if (!progressState.timer) {
      progressState.timer = setInterval(() => {
        progressState.value = Math.min(92, progressState.value + Math.max(0.7, (92 - progressState.value) * 0.08));
        renderProgress(progressLabel(pathname));
      }, 320);
    }
  }

  function finishProgress() {
    progressState.active = Math.max(0, progressState.active - 1);
    if (progressState.active !== 0) return;
    if (progressState.timer) {
      clearInterval(progressState.timer);
      progressState.timer = null;
    }
    progressState.value = 100;
    renderProgress('采集完成');
    progressState.hideTimer = setTimeout(() => {
      const root = document.getElementById('wtl-global-progress');
      if (root && progressState.active === 0) root.hidden = true;
    }, 450);
  }

  window.fetch = function (input, init) {
    const requestURL = typeof input === 'string' ? input : input.url;
    const resolved = new URL(requestURL, window.location.href);
    if (resolved.origin === window.location.origin && resolved.pathname.startsWith('/api/')) {
      const next = { ...(init || {}) };
      next.headers = new Headers(next.headers || (typeof input !== 'string' ? input.headers : undefined));
      next.headers.set('X-WTL-Token', window.__WTL_API_TOKEN || '');
      const tracked = resolved.pathname !== '/api/about';
      if (tracked) startProgress(resolved.pathname);
      try {
        const request = nativeFetch(input, next);
        return tracked ? Promise.resolve(request).finally(finishProgress) : request;
      } catch (err) {
        if (tracked) finishProgress();
        throw err;
      }
    }
    return nativeFetch(input, init);
  };

  const searchCache = new Map();
  window.wtlLooksLikeRegex = function (query) {
    const raw = String(query || '').trim();
    return raw.startsWith('re:') ||
      (raw.startsWith('/') && raw.lastIndexOf('/') > 0) ||
      raw.includes('.*') ||
      raw.includes('.+') ||
      raw.includes('.?') ||
      /\\[dDsSwWbB]/.test(raw) ||
      /\[[^\]]+\]/.test(raw) ||
      raw.startsWith('^') ||
      raw.endsWith('$');
  };

  window.wtlCompileQuery = function (query) {
    const raw = String(query || '').trim();
    if (!raw) return { type: 'empty' };
    if (searchCache.has(raw)) return searchCache.get(raw);

    let matcher;
    try {
      if (raw.startsWith('re:')) {
        matcher = { type: 'regex', value: new RegExp(raw.slice(3), 'i') };
      } else if (raw.startsWith('/') && raw.lastIndexOf('/') > 0) {
        const end = raw.lastIndexOf('/');
        const flags = raw.slice(end + 1);
        if (!/^[dgimsuvy]*$/.test(flags)) throw new Error('不支持的正则标志');
        matcher = { type: 'regex', value: new RegExp(raw.slice(1, end), flags.replace(/[gy]/g, '')) };
      } else if (window.wtlLooksLikeRegex(raw)) {
        matcher = { type: 'regex', value: new RegExp(raw, 'i') };
      } else {
        matcher = { type: 'text', value: raw.toLowerCase() };
      }
    } catch (err) {
      throw new Error(`正则表达式无效：${err.message || err}`);
    }
    if (searchCache.size >= 32) searchCache.delete(searchCache.keys().next().value);
    searchCache.set(raw, matcher);
    return matcher;
  };

  window.wtlMatchesQuery = function (query, values) {
    const matcher = window.wtlCompileQuery(query);
    if (matcher.type === 'empty') return true;
    const content = (Array.isArray(values) ? values : [values])
      .map(value => value == null ? '' : String(value))
      .join(' ');
    if (matcher.type === 'regex') return matcher.value.test(content);
    return content.toLowerCase().includes(matcher.value);
  };

  window.wtlDownload = async function (url) {
    const response = await window.fetch(url, { cache: 'no-store' });
    if (!response.ok) {
      throw new Error((await response.text()) || `HTTP ${response.status}`);
    }
    const blob = await response.blob();
    const disposition = response.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename="?([^";]+)"?/i);
    const anchor = document.createElement('a');
    anchor.href = URL.createObjectURL(blob);
    anchor.download = match ? match[1] : 'WinTraceLens-export.csv';
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(anchor.href), 1000);
  };

  function setText(selector, value) {
    document.querySelectorAll(selector).forEach(node => {
      node.textContent = value;
    });
  }

  function setPermission(info) {
    document.querySelectorAll('[data-admin-status]').forEach(node => {
      node.classList.remove('admin', 'limited', 'unknown');
      if (!info || !info.adminKnown) {
        node.textContent = '权限未知';
        node.classList.add('unknown');
        return;
      }
      if (info.isAdmin) {
        node.textContent = '管理员权限';
        node.classList.add('admin');
        return;
      }
      node.textContent = '普通权限';
      node.classList.add('limited');
    });
  }

  async function loadAbout() {
    try {
      const res = await fetch('/api/about', { cache: 'no-store' });
      if (!res.ok) throw new Error('about api failed');
      const info = await res.json();
      if (info.version) setText('[data-app-version]', info.version);
      setPermission(info);
    } catch {
      setPermission(null);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', loadAbout);
  } else {
    loadAbout();
  }
})();
