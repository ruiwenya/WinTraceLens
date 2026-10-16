(() => {
  'use strict';

  let dialog;
  let title;
  let body;
  let status;
  let copy;
  let copyValue = '';

  function element(tag, className, value) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value != null) node.textContent = String(value);
    return node;
  }

  function prepare() {
    if (dialog) return;
    dialog = element('dialog', 'evidence-detail');
    dialog.id = 'evidence-detail-dialog';
    dialog.setAttribute('aria-labelledby', 'evidence-detail-title');
    const head = element('div', 'dialog-head');
    title = element('h2');
    title.id = 'evidence-detail-title';
    head.append(title);
    body = element('div', 'evidence-detail-body');
    const footer = element('div', 'evidence-detail-footer');
    status = element('span', 'status');
    status.setAttribute('role', 'status');
    copy = element('button', 'secondary', '复制全部');
    copy.type = 'button';
    copy.dataset.detailCopy = '';
    copy.addEventListener('click', async () => {
      copy.disabled = true;
      const value = copyValue;
      try {
        await navigator.clipboard.writeText(value);
        if (copyValue === value) status.textContent = '已复制完整详情';
      } catch {
        if (copyValue === value) status.textContent = '复制失败，可选中文本复制';
      } finally {
        copy.disabled = false;
      }
    });
    const close = element('button', 'secondary', '关闭');
    close.type = 'button';
    close.dataset.detailClose = '';
    close.autofocus = true;
    close.addEventListener('click', () => dialog.close());
    footer.append(status, copy, close);
    dialog.append(head, body, footer);
    document.body.append(dialog);
  }

  window.wtlShowEvidenceDetail = (heading, sections) => {
    prepare();
    title.textContent = heading;
    title.title = heading;
    body.replaceChildren();
    status.textContent = '';
    const lines = [heading];
    for (const section of sections) {
      const block = element('section', 'dialog-section');
      block.append(element('h3', '', section.title));
      const grid = element('dl', 'dialog-grid');
      lines.push('', section.title);
      for (const [label, value] of section.fields) {
        const displayed = value == null || value === '' ? '-' : String(value);
        grid.append(element('dt', '', label), element('dd', '', displayed));
        lines.push(`${label}: ${displayed}`);
      }
      block.append(grid);
      body.append(block);
    }
    copyValue = lines.join('\n');
    if (!dialog.open) dialog.showModal();
    body.scrollTop = 0;
  };
})();
