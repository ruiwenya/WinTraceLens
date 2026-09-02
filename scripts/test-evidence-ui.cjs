// Usage: node scripts/test-evidence-ui.cjs [absolute-path-to-playwright]
// Runs the local CLI server, checks collection/export selection, and saves a
// test evidence ZIP and screenshots under dist/evidence-ui-test (not published).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { chromium } = require(process.argv[2] || 'playwright');

const root = path.resolve(__dirname, '..');
const output = path.join(root, 'dist', 'evidence-ui-test');
fs.mkdirSync(output, { recursive: true });
const child = spawn(path.join(root, 'dist', 'WinTraceLens-cli.exe'), ['-no-browser', '-hash-limit-mb', '16'], {
  cwd: root, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']
});
let browser;

async function main() {
  const url = await new Promise((resolve, reject) => {
    let text = '';
    const timer = setTimeout(() => reject(new Error('CLI startup timed out')), 30000);
    child.once('error', err => { clearTimeout(timer); reject(err); });
    child.once('exit', code => { clearTimeout(timer); reject(new Error(`CLI exited: ${code}`)); });
    child.stdout.on('data', data => {
      text += data.toString();
      const match = text.match(/http:\/\/127\.0\.0\.1:\d+\S*/);
      if (match) { clearTimeout(timer); resolve(match[0]); }
    });
  });
  browser = await chromium.launch({ channel: 'msedge', headless: true });
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, acceptDownloads: true });
  const completed = page.waitForResponse(response => new URL(response.url()).pathname === '/api/processes', { timeout: 180000 });
  await page.goto(url);
  const response = await completed;
  assert.equal(response.status(), 200, 'process collection failed');
  const modules = await page.evaluate(async pid => {
    const result = await fetch(`/api/process/${pid}/modules`);
    return result.status;
  }, child.pid);
  assert.equal(modules, 200, 'own-process module collection failed');
  const status = await page.evaluate(async () => (await fetch('/api/export/evidence/status')).json());
  assert(status.sources.find(source => source.id === 'processes').datasets > 0);
  assert(status.sources.find(source => source.id === 'process-modules').datasets > 0);
  assert.equal(status.sources.find(source => source.id === 'memory').datasets, 0, 'export initiated a scan');
  await page.locator('#wtl-export-evidence').click();
  await page.locator('#wtl-evidence-dialog [data-export]').waitFor();
  await page.waitForFunction(() => !document.querySelector('#wtl-evidence-dialog [data-export]').disabled);
  assert.equal(await page.locator('[data-source-choice="native-files"]').count(), 0, 'native files must be grouped under file traces');
  await page.locator('[data-all]').uncheck();
  assert(await page.locator('[data-export]').isDisabled(), 'empty selection can export');
  assert(await page.locator('[data-collect]').isDisabled(), 'empty selection can collect');
  await page.locator('[data-source-choice="connections"]').check();
  const collecting = page.waitForResponse(response => new URL(response.url()).pathname === '/api/export/evidence/collect');
  await page.locator('[data-collect]').click();
  const collected = await collecting;
  assert.equal(collected.status(), 200, 'one-click network collection failed');
  assert.deepEqual(collected.request().postDataJSON().sources, ['connections']);
  const progress = (await collected.text()).trim().split('\n').map(line => JSON.parse(line));
  assert.equal(progress[0].percent, 0);
  assert.equal(progress.at(-1).type, 'done');
  assert.equal(progress.at(-1).percent, 100);
  assert.deepEqual([...new Set(progress.filter(event => event.source).map(event => event.source))], ['connections']);
  await page.waitForFunction(() => document.querySelector('.wtl-evidence-feedback').textContent.includes('采集结束'));
  await page.waitForFunction(() => !document.querySelector('[data-export]').disabled);
  await page.screenshot({ path: path.join(output, 'desktop.png') });
  const downloading = page.waitForEvent('download');
  const exporting = page.waitForRequest(request => new URL(request.url()).pathname === '/api/export/evidence');
  await page.locator('#wtl-evidence-dialog [data-export]').click();
  assert.deepEqual((await exporting).postDataJSON().sources, ['connections']);
  const download = await downloading;
  assert.match(download.suggestedFilename(), /^WinTraceLens-evidence-.*\.zip$/);
  await download.saveAs(path.join(output, 'evidence.zip'));
  assert.equal(await download.failure(), null);
  await page.waitForFunction(() => document.querySelector('.wtl-evidence-feedback').textContent.includes('取证包已生成'));
  await page.locator('#wtl-evidence-dialog [data-close]').click();

  await page.setViewportSize({ width: 390, height: 844 });
  await page.locator('#wtl-export-evidence').click();
  await page.waitForFunction(() => !document.querySelector('#wtl-evidence-dialog [data-export]').disabled);
  assert(await page.locator('[data-source-choice="connections"]').isChecked(), 'selection lost after reopening');
  assert.equal(await page.locator('[data-source-choice="processes"]').isChecked(), false);
  const fits = await page.locator('#wtl-evidence-dialog').evaluate(element => {
    const rect = element.getBoundingClientRect();
    return rect.left >= 0 && rect.right <= innerWidth && rect.top >= 0 && rect.bottom <= innerHeight;
  });
  assert(fits, 'export dialog overflows narrow viewport');
  await page.screenshot({ path: path.join(output, 'narrow.png') });
  await page.keyboard.press('Escape');

  await page.route('**/api/export/evidence/status', route => route.fulfill({ status: 503, body: 'fixture unavailable' }), { times: 1 });
  await page.locator('#wtl-export-evidence').click();
  await page.waitForFunction(() => document.querySelector('.wtl-evidence-feedback').textContent.includes('读取范围失败'));
  await page.locator('#wtl-evidence-dialog [data-refresh]').click();
  await page.waitForFunction(() => !document.querySelector('#wtl-evidence-dialog [data-export]').disabled);
  await page.route('**/api/export/evidence/collect', route => route.fulfill({
    contentType: 'application/x-ndjson', body: [
      { type: 'progress', source: 'connections', label: '实时网络连接', status: 'running', completed: 0, total: 1, percent: 0 },
      { type: 'result', source: 'connections', label: '实时网络连接', status: 'partial', completed: 1, total: 1, percent: 100, warnings: ['fixture partial data'] },
      { type: 'done', status: 'partial', completed: 1, total: 1, percent: 100, detail: '采集结束：有提示。' }
    ].map(event => JSON.stringify(event)).join('\n') + '\n'
  }), { times: 1 });
  await page.locator('[data-collect]').click();
  await page.waitForFunction(() => document.querySelector('.wtl-evidence-feedback').textContent.includes('采集结束：有提示'));
  assert.match(await page.locator('.wtl-evidence-warnings').textContent(), /fixture partial data/);
  await page.waitForFunction(() => !document.querySelector('[data-collect]').disabled);
  await page.route('**/api/export/evidence/collect', async route => {
    await new Promise(resolve => setTimeout(resolve, 1000));
    await route.fulfill({ status: 500, body: 'fixture cancelled' }).catch(() => {});
  }, { times: 1 });
  await page.locator('[data-collect]').click();
  assert.match(await page.locator('[data-percent]').textContent(), /0%/);
  await page.locator('[data-stop]').click();
  await page.waitForFunction(() => document.querySelector('.wtl-evidence-feedback').textContent.includes('已停止后续采集'));
  await page.waitForFunction(() => !document.querySelector('[data-export]').disabled);
  await page.route('**/api/export/evidence', async route => {
    await new Promise(resolve => setTimeout(resolve, 1000));
    await route.fulfill({ status: 500, body: 'fixture cancelled' }).catch(() => {});
  }, { times: 1 });
  await page.locator('#wtl-evidence-dialog [data-export]').click();
  await page.locator('#wtl-evidence-dialog [data-close]').click();
  assert.equal(await page.locator('#wtl-evidence-dialog').isVisible(), false);
  await page.setViewportSize({ width: 1280, height: 900 });

  // Atomic API progress is explicitly an estimate, with no false success on errors.
  let releaseProgress, finishProgressRoute;
  const progressGate = new Promise(resolve => { releaseProgress = resolve; });
  const progressRouteFinished = new Promise(resolve => { finishProgressRoute = resolve; });
  await page.route('**/api/network/history?progress-fixture=1', async route => {
    await progressGate;
    try { await route.fulfill({ status: 503, body: 'fixture failure' }); }
    finally { finishProgressRoute(); }
  }, { times: 1 });
  await page.evaluate(() => { window.progressFixture = fetch('/api/network/history?progress-fixture=1').then(response => response.status); });
  await page.waitForFunction(() => document.querySelector('.wtl-progress-percent').textContent.includes('估算'));
  releaseProgress();
  assert.equal(await page.evaluate(() => window.progressFixture), 503);
  await progressRouteFinished;
  assert.equal(await page.locator('.wtl-progress-percent').textContent(), '未完成');

  // Header coverage without triggering unrelated scans (including VSS/AI/YARA).
  await page.route('**/api/**', route => {
    const pathname = new URL(route.request().url()).pathname;
    if (pathname === '/api/about' || pathname.startsWith('/api/export/')) return route.continue();
    return route.fulfill({ status: 503, body: 'UI coverage only: collection skipped' });
  });
  for (const name of ['host', 'findings', 'threat', 'registry', 'filetrace', 'security', 'history', 'investigation', 'yara', 'ai']) {
    await page.goto(new URL(`/${name}.html`, url).href);
    const button = page.locator('#wtl-export-evidence');
    await button.waitFor();
    assert.equal(await button.count(), 1, `missing/duplicate export button on ${name}`);
    const box = await button.boundingBox();
    assert(box && box.x >= 0 && box.x + box.width <= 1280, `header overflow on ${name}`);
    if (name === 'threat') {
      assert(!await page.locator('.module-title').textContent().then(text => text.includes('V2')), 'old threat heading still visible');
    }
  }
  console.log(JSON.stringify({ result: 'passed', datasetCount: status.datasetCount, zip: path.join(output, 'evidence.zip'), headerPages: 11, narrowViewport: '390x844', selectedSources: ['connections'], oneClickCollection: true, failureRecovery: true, cancellation: true, percentageLabels: true }));
}

main().catch(err => { console.error(err); process.exitCode = 1; }).finally(async () => {
  if (browser) await browser.close();
  child.kill();
});
