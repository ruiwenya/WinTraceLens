// Usage: node scripts/test-webview-theme-ui.cjs [absolute-path-to-playwright]
// Set WTL_CLI to validate a candidate CLI without replacing release artifacts.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { chromium } = require(process.argv[2] || 'playwright');

const root = path.resolve(__dirname, '..');
const cliPath = process.env.WTL_CLI || path.join(root, 'dist', 'WinTraceLens-cli.exe');
const output = process.env.WTL_UI_OUTPUT || path.join(root, 'dist', 'webview-ui-preview');
const pages = [
  '/',
  '/host.html',
  '/findings.html',
  '/threat.html',
  '/investigation.html',
  '/registry.html',
  '/filetrace.html',
  '/history.html',
  '/security.html',
  '/yara.html',
  '/ai.html'
];

function assertOfflineAssets() {
  const uiDir = path.join(root, 'internal', 'server', 'ui');
  const candidates = fs.readdirSync(uiDir)
    .filter(name => /\.(?:html|css|js)$/i.test(name))
    .map(name => path.join(uiDir, name));
  const remoteResource = /<(?:script|link|img|source|video|audio)\b[^>]*(?:src|href)\s*=\s*["']https?:\/\//i;
  const remoteCSS = /(?:@import\s+(?:url\()?\s*["']?https?:\/\/|url\(\s*["']?https?:\/\/)/i;
  for (const file of candidates) {
    const source = fs.readFileSync(file, 'utf8');
    assert(!remoteResource.test(source), `${path.basename(file)} loads a remote page asset`);
    assert(!remoteCSS.test(source), `${path.basename(file)} loads a remote CSS asset`);
  }
}

fs.mkdirSync(output, { recursive: true });
assertOfflineAssets();
const child = spawn(cliPath, ['-no-browser', '-hash-limit-mb', '16'], {
  cwd: root,
  windowsHide: true,
  stdio: ['ignore', 'pipe', 'pipe']
});
let browser;

function waitForURL() {
  return new Promise((resolve, reject) => {
    let text = '';
    const timer = setTimeout(() => reject(new Error('CLI startup timed out')), 30000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { clearTimeout(timer); reject(new Error(`CLI exited: ${code}`)); });
    child.stdout.on('data', data => {
      text += data.toString();
      const match = text.match(/http:\/\/127\.0\.0\.1:\d+\S*/);
      if (match) {
        clearTimeout(timer);
        resolve(match[0]);
      }
    });
  });
}

async function main() {
  const bootstrapURL = await waitForURL();
  const origin = new URL(bootstrapURL).origin;
  browser = await chromium.launch({
    channel: 'msedge',
    headless: true,
    args: ['--disable-gpu', '--disable-extensions', '--disable-background-networking']
  });
  const page = await browser.newPage({ viewport: { width: 1280, height: 820 } });
  const apiRequests = [];
  const remoteAssetRequests = [];
  page.on('request', request => {
    const requestURL = new URL(request.url());
    if (requestURL.pathname.startsWith('/api/')) apiRequests.push(request.url());
    if (requestURL.protocol !== 'data:' && requestURL.origin !== origin) remoteAssetRequests.push(request.url());
  });

  const processes = page.waitForResponse(response => new URL(response.url()).pathname === '/api/processes', { timeout: 180000 });
  await page.goto(bootstrapURL, { waitUntil: 'domcontentloaded' });
  assert.equal((await processes).status(), 200, 'process collection failed');
  await page.locator('#rows tr').first().waitFor({ state: 'attached', timeout: 30000 });
  const monitorStatus = await page.evaluate(async () => {
    const response = await fetch('/api/network/monitor?watch=1');
    return { status: response.status, body: await response.json() };
  });
  assert.equal(monitorStatus.status, 200, 'short-connection monitor endpoint failed');
  assert.equal(monitorStatus.body.intervalSeconds, 1, 'short-connection monitor interval changed unexpectedly');
  assert.equal(monitorStatus.body.capacity, 5000, 'short-connection monitor capacity changed unexpectedly');
  assert(monitorStatus.body.startedAt, 'short-connection monitor was not started by the CLI');
  const standardLayout = await page.evaluate(() => {
    const header = document.querySelector('body > header').getBoundingClientRect();
    const detail = document.querySelector('section.detail').getBoundingClientRect();
    const toolbar = document.querySelector('.toolbar');
    const visibleRows = [...document.querySelectorAll('#rows tr')].filter(row => {
      const rect = row.getBoundingClientRect();
      return rect.height > 0 && rect.top >= 0 && rect.bottom <= innerHeight;
    });
    return {
      headerHeight: header.height,
      detailHeight: detail.height,
      dataRows: document.querySelectorAll('#rows tr').length,
      visibleRows: visibleRows.length,
      currentModuleDisplay: getComputedStyle(document.querySelector('.current-module')).display,
      toolbarLeftBorder: getComputedStyle(toolbar).borderLeftWidth,
      bodyOverflow: getComputedStyle(document.body).overflow
    };
  });
  assert(standardLayout.headerHeight <= 44, `web header is still taller than the second-round target: ${standardLayout.headerHeight}px`);
  assert(standardLayout.detailHeight >= 180 && standardLayout.detailHeight <= 210, 'default process detail height is outside the target range');
  assert(standardLayout.dataRows > 0, 'process data rows were not rendered');
  assert(standardLayout.visibleRows >= 12, `only ${standardLayout.visibleRows} complete process rows are visible`);
  assert.equal(standardLayout.currentModuleDisplay, 'none', 'duplicate current-module heading remains visible');
  assert.equal(standardLayout.toolbarLeftBorder, '0px', 'toolbar still renders as a framed card');
  assert.equal(standardLayout.bodyOverflow, 'hidden', 'the whole page still owns vertical scrolling');
  await page.screenshot({ path: path.join(output, 'process-light-standard.png') });

  const filter = page.locator('#filter');
  await filter.fill('svchost');
  const firstVisible = page.locator('#rows tr').first();
  await firstVisible.click();
  const selectedPID = await firstVisible.getAttribute('data-pid');
  const requestCount = apiRequests.length;

  await page.locator('.wtl-preferences-trigger').click();
  await page.locator('[data-wtl-theme-value="dark"]').click();
  await page.locator('[data-wtl-density-value="compact"]').click();
  assert.equal(await filter.inputValue(), 'svchost', 'theme change cleared the process filter');
  assert.equal(await page.locator(`#rows tr[data-pid="${selectedPID}"]`).count(), 1, 'theme change cleared selection');
  assert.equal(apiRequests.length, requestCount, 'appearance change triggered an API request');
  assert.deepEqual(await page.evaluate(() => ({
    theme: document.documentElement.dataset.theme,
    density: document.documentElement.dataset.density
  })), { theme: 'dark', density: 'compact' });
  const compactRowHeight = await page.locator('#rows tr').first().evaluate(row => row.getBoundingClientRect().height);
  assert(compactRowHeight <= 30, `compact process row is too tall: ${compactRowHeight}px`);
  await page.screenshot({ path: path.join(output, 'process-dark-compact.png') });

  await page.locator('.wtl-preferences-trigger').click();
  const toggle = page.locator('.wtl-detail-toggle');
  if (await toggle.count()) {
    await toggle.click();
    assert.equal(await toggle.getAttribute('aria-expanded'), 'false');
    await toggle.click();
    assert.equal(await toggle.getAttribute('aria-expanded'), 'true');
  }

  const resizer = page.locator('.wtl-detail-resizer');
  if (await resizer.count()) {
    const before = await page.locator('section.detail').evaluate(node => node.getBoundingClientRect().height);
    const box = await resizer.boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down();
    await page.mouse.move(box.x + box.width / 2, box.y - 30, { steps: 3 });
    await page.mouse.up();
    const after = await page.locator('section.detail').evaluate(node => node.getBoundingClientRect().height);
    assert(after >= before + 20, 'process detail resizer did not change the detail height');
    assert.equal(await filter.inputValue(), 'svchost', 'detail resize cleared the process filter');
    assert.equal(await page.locator(`#rows tr[data-pid="${selectedPID}"]`).count(), 1, 'detail resize cleared selection');
    await resizer.dblclick();
  }

  await page.locator('.wtl-about-trigger').click();
  await page.locator('.wtl-about-dialog').waitFor({ state: 'visible' });
  assert.notEqual(await page.locator('[data-about-version]').textContent(), '', 'About dialog has no version information');
  assert.match(await page.locator('[data-about-platform]').textContent(), /Windows/i, 'About dialog has no runtime platform');
  assert.notEqual(await page.locator('[data-about-permission]').textContent(), '检测中', 'About dialog did not resolve the privilege state');
  assert.notEqual(await page.locator('[data-about-compatibility]').textContent(), '检测中', 'About dialog did not resolve compatibility information');
  assert.equal(await page.locator('.wtl-about-facts dt').count(), 3, 'About dialog fact layout is incomplete');
  assert.equal(await page.locator('.wtl-about-dialog img').count(), 0, 'About dialog unexpectedly depends on an image asset');
  await page.screenshot({ path: path.join(output, 'about-dialog-dark.png') });
  await page.locator('.wtl-about-footer [data-about-close]').click();

  await page.locator('#wtl-export-evidence').click();
  await page.locator('#wtl-evidence-dialog').waitFor({ state: 'visible' });
  await page.screenshot({ path: path.join(output, 'evidence-dialog-dark.png') });
  await page.keyboard.press('Escape');

  const findingsFixture = {
    generatedAt: '2026-09-11 10:00:00',
    sourceSummary: '深色风险色回归样例',
    collectionErrors: [],
    items: [
      { level: '高', source: '进程', name: 'high-risk.sample', reason: '高风险样例', signature: '签名异常', path: 'C:\\Temp\\high-risk.sample' },
      { level: '中', source: '服务', name: 'medium-risk.sample', reason: '中风险样例', signature: '无签名请注意!!!', path: 'C:\\ProgramData\\medium-risk.sample' },
      { level: '低', source: '任务', name: 'low-risk.sample', reason: '低风险样例', signature: '已签名', path: 'C:\\Windows\\low-risk.sample' }
    ]
  };
  const findingsRoute = url => new URL(url).pathname === '/api/findings';
  await page.route(findingsRoute, route => route.fulfill({
    status: 200,
    contentType: 'application/json; charset=utf-8',
    body: JSON.stringify(findingsFixture)
  }));
  await page.goto(origin + '/findings.html', { waitUntil: 'domcontentloaded' });
  await page.locator('.pill.high').waitFor();
  const riskStyles = await page.locator('.pill.high, .pill.medium, .pill.low').evaluateAll(elements => elements.map(element => ({
    background: getComputedStyle(element).backgroundColor,
    color: getComputedStyle(element).color
  })));
  assert(riskStyles.every(style => !style.background.includes('255, 240') && !style.background.includes('255, 247') && !style.background.includes('238, 245')), 'dark risk pills use light-theme backgrounds');
  await page.locator('#filter').focus();
  const focusStyle = await page.locator('#filter').evaluate(element => ({
    outline: getComputedStyle(element).outlineStyle,
    shadow: getComputedStyle(element).boxShadow
  }));
  assert.equal(focusStyle.outline, 'none', 'search focus still uses an outer outline');
  assert(!focusStyle.shadow.includes('3px'), 'search focus still uses the old blue glow');
  await page.screenshot({ path: path.join(output, 'findings-dark-muted.png') });
  await page.unroute(findingsRoute);

  const historyFixture = {
    generatedAt: '2026-09-15 17:00:00',
    collectionErrors: [],
    records: [
      { time: '2026-09-15 16:58:00', source: 'Sysmon', eventId: '3', process: 'scanner.exe', pid: '1200', proto: 'TCP', local: '10.0.0.8:50000', remote: '10.0.0.10:445', action: '允许', user: 'LAB\\analyst', details: '连接证据' },
      { time: '2026-09-15 16:59:00', source: 'Sysmon DNS', eventId: '22', process: 'scanner.exe', pid: '1200', query: 'example.test', details: 'DNS 查询证据' }
    ]
  };
  const liveFixture = {
    generatedAt: '2026-09-15 17:00:00',
    count: 1,
    items: [{ observedAt: '2026-09-15 17:00:00', pid: 1200, process: 'scanner.exe', protocol: 'TCP', local: '10.0.0.8:50001', remote: '203.0.113.20:443', remoteKind: '公网/外部', state: 'ESTABLISHED', path: 'C:\\Tools\\scanner.exe' }]
  };
  const monitorFixture = {
    startedAt: '2026-09-15 16:55:00',
    generatedAt: '2026-09-15 17:00:02',
    intervalSeconds: 1,
    capacity: 5000,
    count: 1,
    items: [{ firstSeen: '2026-09-15 16:56:01', lastSeen: '2026-09-15 16:59:59', occurrences: 2, samples: 4, currentlyActive: false, pid: 2200, process: 'beacon.exe', protocol: 'TCPv4', local: '10.0.0.8:50100', remote: '198.51.100.77:445', remoteIp: '198.51.100.77', remotePort: 445, remoteKind: '公网/外部', state: 'SYN-SENT', path: 'C:\\ProgramData\\beacon.exe' }]
  };
  const historyRoute = url => new URL(url).pathname === '/api/network/history';
  const liveRoute = url => new URL(url).pathname === '/api/network/live';
  const monitorRoute = url => new URL(url).pathname === '/api/network/monitor';
  await page.route(historyRoute, route => route.fulfill({ status: 200, contentType: 'application/json; charset=utf-8', body: JSON.stringify(historyFixture) }));
  await page.route(liveRoute, route => route.fulfill({ status: 200, contentType: 'application/json; charset=utf-8', body: JSON.stringify(liveFixture) }));
  await page.route(monitorRoute, route => route.fulfill({ status: 200, contentType: 'application/json; charset=utf-8', body: JSON.stringify(monitorFixture) }));
  await page.goto(origin + '/history.html', { waitUntil: 'domcontentloaded' });
  await page.locator('button[data-tab="dns"]').click();
  await page.locator('#table tbody tr').waitFor();
  assert.equal(await page.locator('#table thead th').count(), 3, 'DNS records still expose unavailable cache metadata');
  assert.equal(await page.locator('#table thead').getByText('时间', { exact: true }).count(), 0, 'DNS records still expose a misleading time column');
  assert.equal(await page.locator('#table thead').getByText('进程', { exact: true }).count(), 0, 'DNS records still expose a misleading process column');
  assert.equal(await page.locator('#table thead').getByText('PID', { exact: true }).count(), 0, 'DNS records still expose a misleading PID column');
  assert.equal(await page.locator('#table thead').getByText('本地地址').count(), 0, 'DNS records still expose connection-only columns');
  await page.screenshot({ path: path.join(output, 'history-dns-three-columns-dark.png') });
  await page.locator('button[data-tab="live"]').click();
  assert.equal(await page.locator('#table tbody tr td').nth(0).textContent(), '2026-09-15 17:00:00', 'Current connection does not show its snapshot time');
  assert.equal(await page.locator('#table tbody tr td').nth(1).textContent(), '当前快照', 'Current connection still claims to be a continuous live record');
  await page.screenshot({ path: path.join(output, 'history-current-snapshot-dark.png') });
  await page.locator('button[data-tab="monitor"]').click();
  assert.equal(await page.locator('#table tbody tr').count(), 1, 'Short-connection monitor records are missing');
  const monitorText = await page.locator('#table').innerText();
  assert(monitorText.includes('SYN-SENT') && monitorText.includes('198.51.100.77:445'), 'Short-connection monitor omits SYN evidence');
  assert.equal(await page.locator('#table tbody tr td').nth(7).textContent(), '2 / 4', 'Short-connection appearance and sample counts are incorrect');
  await page.screenshot({ path: path.join(output, 'history-short-connection-monitor-dark.png') });
  await page.locator('button[data-tab="all"]').click();
  assert.equal(await page.locator('#table tbody tr').count(), 3, 'All evidence does not merge connection history, DNS, and short-connection observations');
  assert.equal(await page.locator('#table thead th').count(), 7, 'All evidence still uses the oversized source-specific table');
  const allEvidenceText = await page.locator('#table').innerText();
  assert(allEvidenceText.includes('短连接监测') && allEvidenceText.includes('example.test') && allEvidenceText.includes('10.0.0.10:445'), 'All evidence omits one or more historical evidence sources');
  const allCSVDownload = page.waitForEvent('download');
  await page.locator('#export-csv').click();
  assert.match((await allCSVDownload).suggestedFilename(), /^network-all-\d{4}-\d{2}-\d{2}\.csv$/, 'All evidence CSV did not use the merged client-side export');
  await page.screenshot({ path: path.join(output, 'history-all-evidence-dark.png') });
  await page.unroute(historyRoute);
  await page.unroute(liveRoute);
  await page.unroute(monitorRoute);

  await page.route('**/api/**', route => route.fulfill({
    status: 503,
    contentType: 'application/json; charset=utf-8',
    body: JSON.stringify({ error: 'UI smoke-test fixture' })
  }));

  for (const pathname of pages.slice(1)) {
    await page.goto(origin + pathname, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(150);
    const state = await page.evaluate(() => ({
      theme: document.documentElement.dataset.theme,
      density: document.documentElement.dataset.density,
      navCount: document.querySelectorAll('.top-nav a').length,
      currentCount: document.querySelectorAll('.top-nav [aria-current="page"]').length,
      horizontalOverflow: document.documentElement.scrollWidth - innerWidth
    }));
    assert.equal(state.theme, 'dark', `${pathname}: theme preference was lost`);
    assert.equal(state.density, 'compact', `${pathname}: density preference was lost`);
    assert.equal(state.navCount, 11, `${pathname}: incomplete navigation`);
    assert.equal(state.currentCount, 1, `${pathname}: current navigation item is ambiguous`);
    assert(state.horizontalOverflow <= 1, `${pathname}: page has horizontal overflow`);
    if (pathname === '/yara.html') {
      await page.locator('.wtl-preferences-trigger').click();
      await page.locator('[data-wtl-density-value="standard"]').click();
      if (await page.locator('.wtl-preferences-menu').isVisible()) await page.locator('.wtl-preferences-trigger').click();
      const verifyYaraLayout = async label => {
        const layout = await page.evaluate(() => {
          const workspace = document.querySelector('.yara-workspace').getBoundingClientRect();
          const panels = [...document.querySelectorAll('.yara-workspace .panel')].map(panel => panel.getBoundingClientRect());
          const results = document.querySelector('.yara-workspace .results').getBoundingClientRect();
          const memoryCheckbox = document.querySelector('#include-process-memory');
          const checkboxRect = memoryCheckbox.getBoundingClientRect();
          const optionStyle = getComputedStyle(memoryCheckbox.closest('label'));
          return {
            pageOverflowY: document.documentElement.scrollHeight - innerHeight,
            workspaceBottom: workspace.bottom,
            panelCount: panels.length,
            panelsContained: panels.every(rect => rect.top >= workspace.top - 1 && rect.bottom <= workspace.bottom + 1 && rect.width > 250),
            resultsHeight: results.height,
            checkboxWidth: checkboxRect.width,
            checkboxHeight: checkboxRect.height,
            checkboxLabelBackground: optionStyle.backgroundColor
          };
        });
        assert(layout.pageOverflowY <= 1, `${label}: YARA page owns an unwanted document scrollbar`);
        assert(layout.workspaceBottom <= await page.evaluate(() => innerHeight + 1), `${label}: YARA workspace is clipped below the viewport`);
        assert.equal(layout.panelCount, 4, `${label}: YARA workspace panels are incomplete`);
        assert(layout.panelsContained, `${label}: one or more YARA panels overflow the workspace`);
        assert(layout.resultsHeight >= 180, `${label}: YARA result area is too short`);
        assert.equal(layout.checkboxWidth, 15, `${label}: YARA checkbox width inherited a text-input size`);
        assert.equal(layout.checkboxHeight, 15, `${label}: YARA checkbox height inherited a text-input size`);
        assert.notEqual(layout.checkboxLabelBackground, 'rgb(255, 255, 255)', `${label}: YARA checkbox option uses a hard-coded white background`);
      };
      await verifyYaraLayout('1280x820');
      await page.screenshot({ path: path.join(output, 'yara-standard-1280x820.png') });
      await page.setViewportSize({ width: 1920, height: 1080 });
      await verifyYaraLayout('1920x1080');
      await page.screenshot({ path: path.join(output, 'yara-standard-1920x1080.png') });
      await page.setViewportSize({ width: 1280, height: 820 });
      const compactOption = page.locator('[data-wtl-density-value="compact"]');
      if (!await compactOption.isVisible()) await page.locator('.wtl-preferences-trigger').click();
      await compactOption.click();
    }
  }

  await page.goto(origin + '/ai.html', { waitUntil: 'domcontentloaded' });
  await page.setViewportSize({ width: 960, height: 650 });
  const narrowState = await page.evaluate(() => ({
    pageOverflow: document.documentElement.scrollWidth - innerWidth,
    navScrollable: document.querySelector('.top-nav').scrollWidth >= document.querySelector('.top-nav').clientWidth
  }));
  assert(narrowState.pageOverflow <= 1, 'AI page overflows at the supported narrow width');
  assert(narrowState.navScrollable, 'navigation does not remain horizontally available');
  await page.screenshot({ path: path.join(output, 'ai-dark-compact-960x650.png') });

  const shellActions = [];
  const shellContext = await browser.newContext({ viewport: { width: 1280, height: 820 } });
  await shellContext.addInitScript(() => {
    window.__WTL_SHELL_ACTIONS = [];
    window.__WTL_NATIVE_SHELL = {
      trusted: true,
      customFrame: true,
      currentFrame: 'integrated',
      framePreference: 'integrated',
      frameOverride: false,
      frameReason: '',
      token: 'ui-fixture'
    };
    window.wtlWindowAction = async (_token, action) => {
      window.__WTL_SHELL_ACTIONS.push(action);
      if (action === 'state') return 'normal';
      if (action === 'frame-preference-get') return 'integrated';
      if (action.startsWith('frame-preference:')) return action.split(':')[1];
      return 'normal';
    };
  });
  const shellPage = await shellContext.newPage();
  const longPath = `C:\\ProgramData\\应急响应\\${'超长无空格路径片段'.repeat(24)}\\scanner-host.exe`;
  const processItems = Array.from({ length: 36 }, (_, index) => ({
    pid: 4242 + index,
    name: index === 0 ? 'scanner-host.exe' : `fixture-${String(index).padStart(2, '0')}.exe`,
    md5: index === 0 ? '0123456789abcdef0123456789abcdef' : '',
    signature: index === 0 ? '无签名请注意!!!' : '已签名',
    signatureMsg: index === 0 ? '测试用长路径进程' : '测试签名',
    connectionCount: index % 4,
    userName: 'LAB\\analyst',
    userSid: 'S-1-5-21-1000',
    integrityLevel: 'High',
    architecture: 'x64',
    protection: '未保护',
    sessionId: 1,
    parentPid: 100,
    parentName: 'parent.exe',
    parentCreatedAt: '2026-09-22 08:58:00',
    createdAt: '2026-09-22 09:00:00',
    path: index === 0 ? longPath : `C:\\Tools\\fixture-${index}.exe`,
    commandLine: index === 0 ? `"${longPath}" --mode=collect --case=${'A'.repeat(120)}` : `fixture-${index}.exe`,
    fileCreated: '2026-09-20 12:00:00',
    fileModified: '2026-09-21 12:00:00',
    threadCount: 12 + index,
    handleCount: 80 + index,
    privateMemoryBytes: 64 * 1024 * 1024,
    workingSetBytes: 96 * 1024 * 1024,
    enumerationSources: 'Toolhelp / NtQuery',
    enumerationWarning: ''
  }));
  await shellPage.route('**/api/**', route => {
    const requestURL = new URL(route.request().url());
    if (requestURL.pathname === '/api/processes') {
      return route.fulfill({ status: 200, contentType: 'application/json; charset=utf-8', body: JSON.stringify({ items: processItems }) });
    }
    if (/^\/api\/process\/4242\/modules$/.test(requestURL.pathname)) {
      return route.fulfill({ status: 200, contentType: 'application/json; charset=utf-8', body: JSON.stringify({ items: [] }) });
    }
    if (/^\/api\/process\/4242\/connections$/.test(requestURL.pathname)) {
      return route.fulfill({ status: 200, contentType: 'application/json; charset=utf-8', body: JSON.stringify({ items: [] }) });
    }
    return route.fulfill({ status: 503, contentType: 'application/json; charset=utf-8', body: JSON.stringify({ error: 'native shell UI fixture' }) });
  });
  await shellPage.goto(bootstrapURL, { waitUntil: 'domcontentloaded' });
  await shellPage.locator('#rows tr[data-pid="4242"]').waitFor();
  await shellPage.locator('#detail-title').waitFor();
  assert.equal(await shellPage.locator('.wtl-window-button').count(), 3, 'integrated frame controls are incomplete');
  assert.equal(await shellPage.evaluate(() => document.documentElement.dataset.wtlHost), 'native');
  assert.equal(await shellPage.locator('header .release-badge').evaluate(node => getComputedStyle(node).display), 'none');
  assert((await shellPage.locator('#detail-title').getAttribute('title')).length > 200, 'long process summary fixture was not rendered');

  const geometryScenarios = [
    { width: 800, height: 650, theme: 'light', density: 'standard', name: '800x650-light-standard' },
    { width: 960, height: 820, theme: 'dark', density: 'compact', name: '960x820-dark-compact' },
    { width: 1280, height: 820, theme: 'dark', density: 'standard', name: '1280x820-dark-standard' }
  ];
  const geometryResults = [];
  for (const scenario of geometryScenarios) {
    await shellPage.setViewportSize({ width: scenario.width, height: scenario.height });
    await shellPage.locator('.wtl-preferences-trigger').click();
    await shellPage.locator(`[data-wtl-theme-value="${scenario.theme}"]`).click();
    await shellPage.locator(`[data-wtl-density-value="${scenario.density}"]`).click();
    if (await shellPage.locator('.wtl-preferences-menu').isVisible()) await shellPage.locator('.wtl-preferences-trigger').click();
    await shellPage.waitForTimeout(50);
    const geometry = await shellPage.evaluate(() => {
      const viewport = { left: 0, top: 0, right: innerWidth, bottom: innerHeight };
      const buttons = ['detail-copy-md5', 'detail-more-trigger', 'detail-toggle'].map(id => document.getElementById(id));
      const clippedByAncestors = element => {
        const rect = element.getBoundingClientRect();
        let node = element.parentElement;
        while (node && node !== document.body) {
          const style = getComputedStyle(node);
          if (/(hidden|clip|auto|scroll)/.test(`${style.overflow} ${style.overflowX} ${style.overflowY}`)) {
            const ancestor = node.getBoundingClientRect();
            if (rect.left < ancestor.left - 1 || rect.right > ancestor.right + 1 || rect.top < ancestor.top - 1 || rect.bottom > ancestor.bottom + 1) return true;
          }
          node = node.parentElement;
        }
        return false;
      };
      const buttonGeometry = buttons.map(button => {
        const rect = button.getBoundingClientRect();
        const center = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
        return {
          id: button.id,
          rect: { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom, width: rect.width, height: rect.height },
          insideViewport: rect.left >= viewport.left && rect.top >= viewport.top && rect.right <= viewport.right && rect.bottom <= viewport.bottom,
          clipped: clippedByAncestors(button),
          centerHit: center === button || button.contains(center)
        };
      });
      const list = document.querySelector('.panel:not(.detail) .table-wrap').getBoundingClientRect();
      const visibleRows = [...document.querySelectorAll('#rows tr[data-pid]')].filter(row => {
        const rect = row.getBoundingClientRect();
        return rect.height > 0 && rect.top >= list.top - 1 && rect.bottom <= list.bottom + 1;
      }).length;
      const detailBody = document.querySelector('#detail-body').getBoundingClientRect();
      const visibleFields = [...document.querySelectorAll('#detail-body .detail-field')].filter(field => {
        const rect = field.getBoundingClientRect();
        return rect.height > 0 && rect.top >= detailBody.top - 1 && rect.bottom <= detailBody.bottom + 1;
      }).length;
      return {
        buttonGeometry,
        horizontalOverflow: document.documentElement.scrollWidth - innerWidth,
        visibleRows,
        visibleFields,
        detailHeight: document.querySelector('section.detail').getBoundingClientRect().height,
        detailScrollOwners: [...document.querySelectorAll('section.detail, #detail-body, .detail-overview-basic')].filter(node => {
          const style = getComputedStyle(node);
          return /(auto|scroll)/.test(style.overflowY) && node.scrollHeight > node.clientHeight + 1;
        }).map(node => node.id || node.className)
      };
    });
    assert(geometry.horizontalOverflow <= 1, `${scenario.name}: root page has horizontal overflow`);
    for (const button of geometry.buttonGeometry) {
      assert(button.insideViewport, `${scenario.name}: ${button.id} is outside the viewport: ${JSON.stringify(button.rect)}`);
      assert(!button.clipped, `${scenario.name}: ${button.id} is clipped by an ancestor`);
      assert(button.centerHit, `${scenario.name}: ${button.id} center is not clickable`);
    }
    assert(geometry.visibleFields >= 3, `${scenario.name}: fewer than three complete detail fields are visible`);
    assert.deepEqual(geometry.detailScrollOwners, ['detail-body'], `${scenario.name}: detail uses nested vertical scrolling`);
    if (scenario.width === 1280 && scenario.height === 820 && scenario.density === 'standard') {
      assert(geometry.visibleRows >= 12, `${scenario.name}: only ${geometry.visibleRows} complete process rows are visible`);
      assert(geometry.detailHeight >= 180 && geometry.detailHeight <= 210, `${scenario.name}: detail height is outside 180-210px`);
    }
    geometryResults.push({ ...scenario, ...geometry });
    await shellPage.screenshot({ path: path.join(output, `process-long-path-${scenario.name}-before-menu.png`) });
    await shellPage.locator('#detail-more-trigger').click();
    const menuState = await shellPage.evaluate(() => {
      const menu = document.querySelector('#detail-more-menu');
      const rect = menu.getBoundingClientRect();
      return {
        labels: [...menu.querySelectorAll('[role="menuitem"]')].map(item => item.textContent.trim()),
        insideViewport: rect.left >= 0 && rect.top >= 0 && rect.right <= innerWidth && rect.bottom <= innerHeight,
        centerTarget: (() => {
          const target = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
          return target && menu.contains(target);
        })()
      };
    });
    assert.deepEqual(menuState.labels, ['导出模块', '导出连接', '查历史通信', '刷新连接', '打开位置'], `${scenario.name}: detail menu actions changed`);
    assert(menuState.insideViewport, `${scenario.name}: detail menu is outside the viewport`);
    assert(menuState.centerTarget, `${scenario.name}: detail menu is covered by another layer`);
    await shellPage.screenshot({ path: path.join(output, `process-long-path-${scenario.name}-menu.png`) });
    await shellPage.keyboard.press('Escape');
    assert.equal(await shellPage.locator('#detail-more-menu').isHidden(), true, `${scenario.name}: Escape did not close detail menu`);
    assert.equal(await shellPage.evaluate(() => document.activeElement && document.activeElement.id), 'detail-more-trigger', `${scenario.name}: focus did not return to More button`);
  }

  await shellPage.locator('.wtl-preferences-trigger').click();
  assert.equal(await shellPage.locator('[data-wtl-frame-value]').count(), 2, 'window frame preference is not exposed');
  assert((await shellPage.locator('[data-wtl-frame-status]').textContent()).includes('当前：融合标题栏'), 'current window frame is not reported');
  await shellPage.locator('[data-wtl-frame-value="system"]').click();
  assert((await shellPage.locator('[data-wtl-frame-status]').textContent()).includes('下次启动：系统标题栏'), 'pending system-frame preference is not reported');
  shellActions.push(...await shellPage.evaluate(() => window.__WTL_SHELL_ACTIONS));
  assert(shellActions.some(action => action.startsWith('max-button-rect:')), 'maximize hit-test rectangle was not sent to the native host');
  assert(shellActions.includes('frame-preference:system'), 'system-frame preference was not sent to the native host');
  await shellPage.screenshot({ path: path.join(output, 'integrated-frame-window-preference.png') });
  await shellContext.close();

  const systemFrameContext = await browser.newContext({ viewport: { width: 960, height: 650 } });
  await systemFrameContext.addInitScript(() => {
    window.__WTL_NATIVE_SHELL = {
      trusted: true,
      customFrame: false,
      currentFrame: 'system',
      framePreference: 'system',
      frameOverride: true,
      frameReason: '命令行参数 -system-frame 已强制使用系统标题栏',
      token: 'system-frame-fixture'
    };
    window.wtlWindowAction = async (_token, action) => action === 'frame-preference-get' ? 'system' : 'normal';
  });
  const systemFramePage = await systemFrameContext.newPage();
  await systemFramePage.route('**/api/**', route => route.fulfill({ status: 503, contentType: 'application/json; charset=utf-8', body: JSON.stringify({ error: 'system frame fixture' }) }));
  await systemFramePage.goto(bootstrapURL, { waitUntil: 'domcontentloaded' });
  assert.equal(await systemFramePage.locator('.wtl-window-button').count(), 0, 'system frame still renders duplicate HTML window controls');
  assert.equal(await systemFramePage.evaluate(() => document.documentElement.dataset.wtlHost), 'system-frame');
  await systemFramePage.locator('.wtl-preferences-trigger').click();
  assert((await systemFramePage.locator('[data-wtl-frame-status]').textContent()).includes('命令行强制'), 'system-frame override reason is not visible');
  await systemFramePage.screenshot({ path: path.join(output, 'system-frame-fallback.png') });
  await systemFrameContext.close();
  fs.writeFileSync(path.join(output, 'layout-metrics.json'), JSON.stringify({
    generatedAt: new Date().toISOString(),
    geometry: geometryResults,
    shellActions
  }, null, 2), 'utf8');
  assert.deepEqual(remoteAssetRequests, [], `page requested remote assets: ${remoteAssetRequests.join(', ')}`);
}

main().then(() => {
  process.stdout.write(`WebView UI theme test passed. Screenshots: ${output}\n`);
}).catch(error => {
  console.error(error);
  process.exitCode = 1;
}).finally(async () => {
  if (browser) await browser.close().catch(() => {});
  child.kill();
  child.stdout.destroy();
  child.stderr.destroy();
  child.unref();
});
