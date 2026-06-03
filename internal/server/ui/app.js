(function () {
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
