(function () {
  const meta = document.querySelector('header .app-meta');
  if (!meta || document.getElementById('wtl-export-evidence')) return;
  const trigger = document.createElement('button');
  trigger.id = 'wtl-export-evidence';
  trigger.type = 'button';
  trigger.textContent = '导出取证包';
  trigger.title = '采集或导出勾选来源的证据';
  meta.appendChild(trigger);
  const modal = document.createElement('dialog');
  modal.id = 'wtl-evidence-dialog';
  modal.setAttribute('aria-labelledby', 'wtl-evidence-title');
  modal.innerHTML = `
    <div class="wtl-evidence-heading"><h2 id="wtl-evidence-title">导出取证包</h2><button type="button" data-close>关闭</button></div>
    <p class="wtl-evidence-scope">CSV + JSON + TXT + SHA-256 清单 <span data-selected></span></p>
    <div class="wtl-evidence-list"><table><thead><tr><th><input type="checkbox" data-all aria-label="全选证据来源"></th><th>证据来源</th><th>采集状态</th><th>数据组 / 条数</th><th>最近采集</th></tr></thead><tbody></tbody></table></div>
    <div class="wtl-evidence-options">
      <label>日志开始 <input type="date" data-start></label><label>日志结束 <input type="date" data-end></label>
      <label title="用于日志、文件痕迹和分析结果；进程、主机基础清单保留完整数据">结果条数 <select data-limit><option>500</option><option>1000</option><option>3000</option></select></label>
      <label>进程上限 <select data-process-limit><option>100</option><option selected>300</option><option>800</option></select></label>
    </div>
    <p class="wtl-evidence-note">一键采集勾选来源及必要关联数据；ZIP 仅包含勾选来源。文件痕迹含 Go 原生落地点，默认最近 7 天，可能使用临时 VSS 并在读取后清理。模块与内存按进程上限采集。</p>
    <p class="wtl-evidence-note">YARA 只导出已有结果，不自动运行。取证包不含本工具保存的 API Key、AI 对话和原始样本；主机数据请按敏感证据保管。</p>
    <div class="wtl-evidence-feedback" role="status" aria-live="polite"></div>
    <div class="wtl-evidence-progress" hidden><progress max="100" value="0" aria-label="采集阶段进度"></progress><small data-percent></small></div>
    <details class="wtl-evidence-warnings" hidden><summary>采集提示</summary><ul></ul></details>
    <div class="wtl-evidence-actions"><button type="button" data-refresh>更新范围</button><button type="button" data-collect disabled>一键获取证据</button><button type="button" data-stop hidden title="保留已完成数据，等待当前系统查询收尾，不再启动下一阶段">停止后续采集</button><button type="button" data-export disabled>生成并下载 ZIP</button></div>`;
  document.body.appendChild(modal);
  const el = selector => modal.querySelector(selector);
  const feedback = el('.wtl-evidence-feedback');
  const progressRoot = el('.wtl-evidence-progress');
  let selection = null;
  try {
    const stored = JSON.parse(sessionStorage.getItem('wtl-evidence-sources'));
    if (Array.isArray(stored)) selection = new Set(stored);
  } catch {}
  let coverage = null, busy = '', controller = null, generation = 0, estimateTimer = null, pollTimer = null;
  const day = date => date.getFullYear() + '-' + String(date.getMonth() + 1).padStart(2, '0') + '-' + String(date.getDate()).padStart(2, '0');
  const start = new Date(); start.setDate(start.getDate() - 6);
  el('[data-start]').value = day(start);
  el('[data-end]').value = day(new Date());

  function selectedIDs() { return (coverage?.sources || []).filter(source => selection?.has(source.id)).map(source => source.id); }
  function saveSelection() { try { sessionStorage.setItem('wtl-evidence-sources', JSON.stringify([...selection])); } catch {} }
  function controls() {
    const chosen = (coverage?.sources || []).filter(source => selection?.has(source.id));
    el('[data-export]').disabled = !!busy || !chosen.some(source => source.datasets);
    el('[data-collect]').disabled = !!busy || !!coverage?.collecting || !chosen.some(source => source.collectable);
    el('[data-refresh]').disabled = !!busy;
    el('[data-stop]').hidden = busy !== 'collect';
    el('[data-collect]').hidden = busy === 'collect';
    el('[data-close]').textContent = busy === 'export' ? '取消' : '关闭';
    el('[data-selected]').textContent = '已勾选 ' + chosen.length + ' 项';
    const all = el('[data-all]');
    all.checked = !!coverage && chosen.length === coverage.sources.length;
    all.indeterminate = chosen.length > 0 && !all.checked;
    modal.querySelectorAll('input, select').forEach(input => { input.disabled = !!busy; });
    if (busy) modal.setAttribute('aria-busy', 'true'); else modal.removeAttribute('aria-busy');
  }
  function setPercent(value, estimated) {
    value = Math.min(100, Math.max(0, Math.round(value)));
    progressRoot.hidden = false;
    el('progress').value = value;
    el('[data-percent]').textContent = (estimated ? '估算 ' : '') + value + '%';
    el('progress').setAttribute('aria-valuetext', el('[data-percent]').textContent);
    el('[data-percent]').title = estimated ? '等待估算，不代表真实剩余时间' : '已处理阶段比例，不代表成功率或剩余时间';
  }
  function estimate() {
    let value = 3; setPercent(value, true);
    estimateTimer = setInterval(() => { value = Math.min(90, value + Math.max(.5, (90 - value) * .04)); setPercent(value, true); }, 450);
  }
  function clearEstimate() { if (estimateTimer) clearInterval(estimateTimer); estimateTimer = null; }
  function idle() { clearEstimate(); busy = ''; controller = null; controls(); }
  function begin(kind) {
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = null; clearEstimate();
    controller = new AbortController(); busy = kind; feedback.classList.remove('error'); controls();
    return ++generation;
  }
  function renderCoverage(status) {
    coverage = status;
    if (selection === null) selection = new Set(status.sources.map(source => source.id));
    const valid = new Set(status.sources.map(source => source.id));
    selection = new Set([...selection].filter(id => valid.has(id)));
    saveSelection();
    const fragment = document.createDocumentFragment();
    for (const source of status.sources) {
      const row = document.createElement('tr'); row.dataset.source = source.id;
      const checkCell = document.createElement('td');
      const checkbox = document.createElement('input'); checkbox.type = 'checkbox'; checkbox.checked = selection.has(source.id);
      checkbox.dataset.sourceChoice = source.id; checkbox.setAttribute('aria-label', '选择' + source.label);
      checkbox.addEventListener('change', () => { if (checkbox.checked) selection.add(source.id); else selection.delete(source.id); saveSelection(); controls(); });
      checkCell.appendChild(checkbox); row.appendChild(checkCell);
      const statusText = source.failures ? '含 ' + source.failures + ' 组失败记录' : source.datasets ? (source.warnings ? '含 ' + source.warnings + ' 条提示' : '已采集') : '未采集';
      const values = [source.label, statusText + (!source.collectable ? '（需指定规则）' : ''), source.datasets ? source.datasets + ' 组 / ' + source.rows + ' 条' : '-', source.datasets ? new Date(source.collectedAt).toLocaleString('zh-CN', { hour12: false }) : '-'];
      values.forEach((value, index) => { const cell = document.createElement('td'); cell.textContent = value;
        if (index === 1) { cell.dataset.sourceStatus = source.id; cell.className = source.datasets ? (source.warnings ? 'warning' : 'available') : 'unavailable'; }
        row.appendChild(cell);
      });
      fragment.appendChild(row);
    }
    el('tbody').replaceChildren(fragment);
  }
  async function loadCoverage(message = '', quiet = false) {
    const current = begin('status');
    if (!quiet) { feedback.textContent = '正在整理证据范围…'; estimate(); }
    try {
      const response = await fetch('/api/export/evidence/status', { cache: 'no-store', signal: controller.signal });
      if (!response.ok) throw new Error(await response.text());
      const status = await response.json();
      if (current !== generation) return;
      renderCoverage(status);
      feedback.textContent = status.collecting ? '采集任务正在执行或收尾；已完成的数据仍可导出。' : message || ('共 ' + status.datasetCount + ' 组快照。可直接导出，也可一键获取勾选来源。');
      if (status.collecting && modal.open) pollTimer = setTimeout(() => loadCoverage(message, true), 3000);
    } catch (err) {
      if (current !== generation || err.name === 'AbortError') return;
      feedback.classList.add('error'); feedback.textContent = '读取范围失败：' + (err.message || err);
    } finally { if (current === generation) { idle(); progressRoot.hidden = true; } }
  }
  function stop(close) {
    generation++; if (controller) controller.abort();
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = null; idle();
    if (close) { modal.close(); progressRoot.hidden = true; }
    else loadCoverage('已停止后续采集，完成的数据已保留。');
  }
  trigger.addEventListener('click', () => { modal.showModal(); loadCoverage(); });
  el('[data-close]').addEventListener('click', () => stop(true));
  modal.addEventListener('cancel', event => { event.preventDefault(); stop(true); });
  el('[data-stop]').addEventListener('click', () => stop(false));
  el('[data-refresh]').addEventListener('click', () => loadCoverage());
  el('[data-all]').addEventListener('change', event => { selection = new Set(event.target.checked ? coverage.sources.map(source => source.id) : []); saveSelection(); renderCoverage(coverage); controls(); });

  el('[data-export]').addEventListener('click', async () => {
    const sources = selectedIDs();
    if (!sources.length) return;
    const current = begin('export'); estimate(); feedback.textContent = '正在打包勾选来源并计算校验值…';
    try {
      await window.wtlDownload('/api/export/evidence', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sources }), signal: controller.signal });
      if (current !== generation) return;
      clearEstimate(); setPercent(100, false); feedback.textContent = '取证包已生成，已交给下载管理器。请确认保存位置。';
    } catch (err) {
      if (current !== generation || err.name === 'AbortError') return;
      feedback.classList.add('error'); feedback.textContent = '导出失败：' + (err.message || err); progressRoot.hidden = true;
    } finally { if (current === generation) idle(); }
  });

  el('[data-collect]').addEventListener('click', async () => {
    const sources = selectedIDs();
    if (!sources.length) return;
    const request = { sources, start: el('[data-start]').value, end: el('[data-end]').value, maxRecords: Number(el('[data-limit]').value), maxProcesses: Number(el('[data-process-limit]').value) };
    const current = begin('collect'); setPercent(0, false);
    feedback.textContent = '正在准备一键采集…';
    const warnings = el('.wtl-evidence-warnings'); warnings.hidden = true; el('.wtl-evidence-warnings ul').replaceChildren();
    let done = false, finalMessage = '';
    function consume(line) {
      if (!line.trim()) return;
      const event = JSON.parse(line);
      setPercent(event.percent, false);
      if (event.type === 'done') { done = true; finalMessage = event.detail; return; }
      feedback.textContent = '阶段 ' + event.completed + ' / ' + event.total + '：' + event.label + (event.detail ? ' · ' + event.detail : '');
      const cell = modal.querySelector('[data-source-status="' + event.source + '"]');
      if (cell) { cell.textContent = ({ running: '正在采集', complete: '已完成', partial: '部分完成 / 有提示', failed: '采集失败' })[event.status] || event.status; cell.className = event.status === 'complete' ? 'available' : 'warning'; }
      for (const warning of event.warnings || []) { const item = document.createElement('li'); item.textContent = event.label + '：' + warning; el('.wtl-evidence-warnings ul').appendChild(item); warnings.hidden = false; }
    }
    try {
      const response = await fetch('/api/export/evidence/collect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request), signal: controller.signal });
      if (!response.ok) throw new Error(await response.text());
      if (!response.body) throw new Error('当前环境不支持采集进度流');
      const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', { fatal: true });
      let pending = '';
      while (true) {
        const result = await reader.read();
        if (current !== generation) { await reader.cancel(); return; }
        pending += decoder.decode(result.value || new Uint8Array(), { stream: !result.done });
        if (pending.length > 4 * 1024 * 1024) throw new Error('采集进度响应过大');
        let newline;
        while ((newline = pending.indexOf('\n')) >= 0) { consume(pending.slice(0, newline)); pending = pending.slice(newline + 1); }
        if (result.done) break;
      }
      if (pending.trim()) consume(pending);
      if (!done) throw new Error('采集连接已中断，已完成的数据仍保留');
    } catch (err) {
      if (current !== generation || err.name === 'AbortError') return;
      controller.abort(); finalMessage = '采集未全部完成：' + (err.message || err); feedback.classList.add('error');
    } finally {
      if (current === generation) { idle(); await loadCoverage(finalMessage); }
    }
  });
})();
