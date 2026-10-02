const { test, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;

const CONSOLE = "http://127.0.0.1:8900/";
const VIEWS = ["overview", "edges", "certificates", "vpn", "backups", "readiness", "wolfpack"];

async function signIn(page) {
  await page.goto(CONSOLE);
  await page.fill("#tok", "browser-test");
  await page.click("form.login button");
  await expect(page.locator(".tile").first()).toBeVisible();
}

test("a wrong token is refused", async ({ page }) => {
  await page.goto(CONSOLE);
  await page.fill("#tok", "wrong");
  await page.click("form.login button");
  await expect(page.locator(".login .bad")).toContainText("not accepted");
});

for (const scheme of ["light", "dark"]) {
  for (const width of [1280, 390]) {
    test(`every page opens, ${scheme} at ${width}px`, async ({ browser }) => {
      const page = await (await browser.newContext({ colorScheme: scheme, viewport: { width, height: 850 } })).newPage();
      const errors = [];
      page.on("pageerror", e => errors.push(e.message));
      await signIn(page);
      for (const view of VIEWS) {
        await page.evaluate(v => (location.hash = v), view);
        await expect(page.locator(`nav a[data-view="${view}"]`)).toHaveAttribute("aria-current", "page");
        await expect(page.locator("#view h1")).toBeVisible();
        await expect(page.locator(".notice.bad")).toHaveCount(0);
        expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(0);
      }
      expect(errors).toEqual([]);
    });
  }
}

test("overview tiles open their pages; certificates are listed; Wolf Pack sits outside Products", async ({ page }) => {
  await signIn(page);
  await page.click('a.tile[href="#certificates"]');
  await expect(page).toHaveURL(/#certificates$/);
  await expect(page.locator("tbody tr")).toHaveCount(3);
  await expect(page.locator("tbody")).toContainText("old.example.test");
  const groups = await page.$$eval("nav .group", g => g.map(x => [x.textContent, x.nextElementSibling.dataset.view]));
  expect(groups).toEqual([["Products", "edges"], ["Also from Acxelin", "wolfpack"]]);
  await page.evaluate(() => (location.hash = "overview"));
  await page.click("a.also");
  await expect(page).toHaveURL(/#wolfpack$/);
  await expect(page.locator("#view h1")).toHaveText("Wolf Pack CBOM");
});

test("an address naming a built-in property opens the overview, not an error", async ({ page }) => {
  const errors = [];
  page.on("pageerror", e => errors.push(e.message));
  await signIn(page);
  for (const name of ["constructor", "toString", "__proto__"]) {
    await page.evaluate(n => (location.hash = n), name);
    await expect(page.locator("nav a[aria-current]")).toHaveAttribute("data-view", "overview");
  }
  expect(errors).toEqual([]);
});

test("no serious accessibility problems on the console pages", async ({ page }) => {
  await signIn(page);
  for (const view of ["overview", "certificates", "wolfpack"]) {
    await page.evaluate(v => (location.hash = v), view);
    await expect(page.locator("#view h1")).toBeVisible();
    const found = (await new AxeBuilder({ page }).analyze()).violations.filter(v => ["serious", "critical"].includes(v.impact));
    expect(found.map(v => `${view} ${v.id}: ${v.nodes.map(n => n.target).join(", ")}`)).toEqual([]);
  }
});

test("a slow response cannot replace the page selected later", async ({ page }) => {
  await signIn(page);
  let release, started;
  const pending = new Promise(resolve => (release = resolve));
  const requested = new Promise(resolve => (started = resolve));
  await page.route("**/api/edges", async route => {
    started();
    await pending;
    await route.fulfill({ json: [] });
  });
  await page.evaluate(() => (location.hash = "edges"));
  await requested;
  await page.evaluate(() => (location.hash = "certificates"));
  await expect(page.locator("#view h1")).toHaveText("Certificates");
  const response = page.waitForResponse("**/api/edges");
  release();
  await response;
  await page.waitForTimeout(100);
  await expect(page.locator("#view h1")).toHaveText("Certificates");
});

test("certificate actions report errors and stay usable", async ({ page }) => {
  const errors = [];
  page.on("pageerror", e => errors.push(e.message));
  await signIn(page);
  await page.evaluate(() => (location.hash = "certificates"));
  await expect(page.locator("#view h1")).toHaveText("Certificates");
  await page.route("**/api/certificates/*", route => route.fulfill({ status: 400, json: { error: "Cannot open CA key; check its passphrase." } }));
  await page.click("#maintain");
  await expect(page.locator("#issued")).toContainText("check its passphrase");
  await expect(page.locator("#maintain")).toBeEnabled();
  await page.locator("[data-revoke]").first().click();
  await page.click('[data-confirm="yes"]');
  await expect(page.locator("#issued")).toContainText("check its passphrase");
  await expect(page.locator("[data-revoke]").first()).toBeEnabled();
  expect(errors).toEqual([]);
});

test("issuance shows progress, prevents duplicate submits, and confirms the result", async ({ page }) => {
  await signIn(page);
  await page.evaluate(() => (location.hash = "certificates"));
  await page.fill('[name="common_name"]', "new.example.test");
  let release, started, requests = 0;
  const pending = new Promise(resolve => (release = resolve));
  const requested = new Promise(resolve => (started = resolve));
  await page.route("**/api/certificates/issue", async route => {
    requests++;
    started();
    await pending;
    await route.fulfill({ json: { serial: "1234567890abcdef", folder: "/pki/issued/new" } });
  });
  await page.click("#issue button");
  await requested;
  await expect(page.locator("#issue button")).toBeDisabled();
  await expect(page.locator("#issued")).toContainText("Issuing");
  release();
  await expect(page.locator("#issued")).toContainText("Issued 1234567890abcdef");
  await expect(page.locator("#issued")).toContainText("/pki/issued/new");
  expect(requests).toBe(1);
});

test("an already running scan resumes polling when its page opens", async ({ page }) => {
  await signIn(page);
  let reads = 0;
  await page.route("**/api/scan", route => route.fulfill({ json: { running: ++reads === 1, last: null, error: null, targets: [], every_hours: 0 } }));
  await page.evaluate(() => (location.hash = "readiness"));
  await expect(page.locator("#scan button")).toHaveText("Scanning…");
  await expect(page.locator("#scan button")).toHaveText("Scan", { timeout: 5000 });
  await expect(page.locator("#scan button")).toBeEnabled();
});

test("a customer can issue and revoke a real certificate", async ({ page }) => {
  await signIn(page);
  await page.evaluate(() => (location.hash = "certificates"));
  await page.fill('[name="common_name"]', "browser-new.example.test");
  await page.click("#issue button");
  await expect(page.locator("#issued")).toContainText("Issued");
  const row = page.locator("tbody tr").filter({ hasText: "browser-new.example.test" });
  await expect(row).toContainText("valid");
  await row.getByRole("button", { name: "Revoke", exact: true }).click();
  await row.getByRole("button", { name: "Confirm: revoke browser-new.example.test", exact: true }).click();
  await expect(row).toContainText("revoked");
  await expect(page.locator("#issued")).toContainText("CRL has been refreshed");
});

const assessment = { running: false, targets: [], every_hours: 0, error: null,
  last: { finished: 1000000000, changes: [], summary: { endpoints: 4, pq_key_exchange: 2, pq_certificates: 1, expiring_30d: 1, grades: { A: 1, B: 1, C: 1, F: 1 } }, endpoints: [
    { target: 'legacy.test:443', protocol: 'tls', grade: 'C', negotiated: 'X25519', accepts: ['X25519'], trusted: false, legacy: ['TLSv1.0'], certificate: { key: 'RSA-2048', quantum_safe: false, days_left: 12 } },
    { target: 'hybrid.test:443', protocol: 'tls', grade: 'B', negotiated: 'X25519MLKEM768', accepts: ['X25519MLKEM768', 'X25519'], certificate: { key: 'ECDSA', quantum_safe: false } },
    { target: 'strict.test:443', protocol: 'tls', grade: 'A', negotiated: 'MLKEM768', accepts: ['MLKEM768'], certificate: { key: 'ML-DSA-65', quantum_safe: true } },
    { target: '=offline.test:443', protocol: 'tls', grade: 'F', error: 'connection refused', negotiated: null, accepts: [], certificate: null },
  ] },
};
test('readiness filters real observations, explains evidence and exports safe CSV and complete JSON', async ({ page }) => {
  await page.route('**/api/scan', r => r.fulfill({ json: assessment })); await signIn(page);
  await page.evaluate(() => (location.hash = 'readiness'));
  await expect(page.locator('#endpoint-count')).toHaveText('4 of 4 endpoints');
  await expect(page.locator('#endpoint-results tbody tr').first()).toContainText('legacy.test');
  await page.selectOption('#endpoint-grade', 'C'); await page.click('#endpoint-results summary');
  for (const message of ['Upgrade TLS','Certificate trust failed','Disable legacy protocols','Renew and verify']) await expect(page.locator('#endpoint-results')).toContainText(message);
  await page.fill('#endpoint-search', 'missing'); await expect(page.locator('#endpoint-results')).toContainText('No endpoints match');
  await page.fill('#endpoint-search', ''); await page.selectOption('#endpoint-grade', 'F');
  const csvDownload = page.waitForEvent('download'); await page.click('#scan-csv'); const c = await csvDownload;
  const contents = require('fs').readFileSync(await c.path(), 'utf8');
  expect(contents).toContain("'=offline.test:443"); expect(contents).not.toContain('legacy.test');
  const jsonDownload = page.waitForEvent('download'); await page.click('#scan-json'); const j = await jsonDownload;
  expect(JSON.parse(require('fs').readFileSync(await j.path(), 'utf8'))).toEqual(assessment.last);
  expect((await new AxeBuilder({ page }).analyze()).violations.filter(v => ['serious', 'critical'].includes(v.impact))).toEqual([]);
});
test('CBOM import stays local, escapes content, preserves prior data on invalid input and clears on logout', async ({page}) => {
  let mutations=0;page.on('request',r=>{if(r.method()==='POST')mutations++;});await signIn(page);
  await page.evaluate(()=>(location.hash='readiness'));
  const bom={bomFormat:'CycloneDX',components:[{type:'cryptographic-asset',name:'<img src=x onerror=alert(1)>',properties:[{name:'wolfpack:tier',value:'high'},{name:'wolfpack:recommendation',value:'Upgrade RSA usage'}],evidence:{occurrences:[{location:'src/login.py'}]}}]};
  await page.getByText('Advanced: review a CBOM from another scanner', {exact:true}).click();
  await page.setInputFiles('#inventory-file',{name:'cbom.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(bom))});
  await expect(page.locator('#inventory-message')).toContainText('1 cryptographic assets loaded locally');
  await expect(page.locator('#inventory-results')).toContainText('<img src=x');await expect(page.locator('#inventory-results img')).toHaveCount(0);expect(mutations).toBe(0);
  await page.fill('#inventory-search','missing');await expect(page.locator('#inventory-results')).toContainText('No assets match');await page.fill('#inventory-search','');
  await page.setInputFiles('#inventory-file',{name:'invalid.json',mimeType:'application/json',buffer:Buffer.from('{}')});
  await expect(page.locator('#inventory-message')).toContainText('Expected a CycloneDX');await expect(page.locator('#inventory-results')).toContainText('Upgrade RSA usage');
  await page.click('#logout');await page.fill('#tok','browser-test');await page.click('form.login button');await expect(page.locator('#inventory-results')).toContainText('Load cbom.json');
});
test('VPN distinguishes missing telemetry and incomplete PQ protection', async ({page}) => {
  await page.route('**/api/tunnels',r=>r.fulfill({json:[{source:'unix:///charon',error:'gateway unavailable'}]}));await signIn(page);await page.evaluate(()=>(location.hash='vpn'));
  await expect(page.locator('.metrics')).toContainText('Unknown');await expect(page.locator('#view')).toContainText('does not connect this browser');
  await page.unroute('**/api/tunnels');await page.route('**/api/tunnels',r=>r.fulfill({json:[{peer:'branch',state:'ESTABLISHED',key_exchange:'X25519',ppk:false,established_s:60,children:[]}]}));
  await page.evaluate(()=>(location.hash='readiness'));await expect(page.locator('#view h1')).toHaveText('Readiness');await page.evaluate(()=>(location.hash='vpn'));
  await expect(page.locator('.metrics')).toContainText('Review required');await expect(page.locator('.metrics')).toContainText('0/1');
});

test('an actual local assessment retains its targets for the next scan', async ({page}) => {
  await signIn(page);
  await page.evaluate(() => (location.hash = 'readiness'));
  await page.fill('textarea[name=targets]', '127.0.0.1:1');
  await page.click('#scan button');
  await expect(page.locator('#endpoint-count')).toHaveText('1 of 1 endpoints');
  await expect(page.locator('textarea[name=targets]')).toHaveValue('127.0.0.1:1');
  await expect(page.locator('#endpoint-results')).toContainText('Unreachable');
});


test('one registered project scan shows real crypto callers and exports private relationship evidence', async ({page}) => {
  await signIn(page); await page.evaluate(() => (location.hash='readiness'));
  await page.click('#project-scan button');
  await expect(page.locator('#project-count')).toContainText('assets');
  await expect(page.locator('#project-message')).toHaveText('Complete');
  const row=page.locator('#project-results tbody tr').filter({hasText:'RSA'}).first();
  await row.getByText('Inspect affected code', {exact:true}).click();
  await expect(row).toContainText('keys.py#make');
  await expect(row).toContainText('service.py#checkout');
  await page.locator('#project-advanced summary').click();
  const pending=page.waitForEvent('download'); await page.click('#project-graph');
  const download=await pending; expect(download.suggestedFilename()).toBe('pqcsuite-code-relationships.json');
  const data=JSON.parse(require('fs').readFileSync(await download.path(),'utf8'));
  expect(data.calls.some(c=>c.target==='keys.py#make')).toBe(true);
  expect(JSON.stringify(data)).not.toContain('65537');
});


test('add an approved repository and scan TypeScript without manually importing a CBOM', async ({page}) => {
  await signIn(page); await page.evaluate(() => (location.hash='readiness'));
  await page.selectOption('#project-add select','web-api'); await page.click('#project-add button');
  await expect(page.locator('#project-scan select')).toContainText('web-api');
  await page.locator('#project-scan select').selectOption({label:'web-api (#2)'});
  await page.click('#project-scan button'); await expect(page.locator('#project-message')).toHaveText('Complete');
  await expect(page.locator('#project-results')).toContainText('SHA-256');
  const row=page.locator('#project-results tbody tr').filter({hasText:'SHA-256'}).first(); await row.getByText('Inspect affected code', {exact:true}).click();
  await expect(row).toContainText('api.ts#checkout');
  await page.locator('#project-advanced summary').click(); await expect(page.locator('#project-advanced')).toContainText('TypeScript');
  await expect(page.getByText('Previous local scans',{exact:true})).toBeVisible();
});


test('an approved parent with no registered projects starts with Add repository', async ({page}) => {
  await page.route('**/api/projects', r=>r.fulfill({json:{running:false,stage:'',error:null,last:null,projects:[],available:['local-api'],history:[]}}));
  await signIn(page); await page.evaluate(()=>(location.hash='readiness'));
  await expect(page.locator('#view h2').first()).toHaveText('Repository readiness');
  await expect(page.locator('#project-add')).toBeVisible();
  await expect(page.locator('#view')).toContainText('Choose an available repository above');
});


test('remediation owner, deadlines and exceptions survive navigation and rescanning', async ({page}) => {
  await signIn(page); await page.evaluate(() => (location.hash='readiness'));
  await page.selectOption('#project-scan select', '0');
  await expect(page.locator('#project-scan select')).toHaveValue('0');
  await page.click('#project-scan button'); await expect(page.locator('#project-message')).toHaveText('Complete');
  const row=page.locator('#project-results tbody tr').filter({hasText:'RSA'}).first();
  await row.locator('summary').last().click();
  await row.locator('[name=owner]').fill('Migration team <test>');
  await row.locator('[name=due]').fill('2099-01-01');
  await row.locator('[name=status]').selectOption('exception');
  await row.locator('button').click();
  await expect(row.locator('.tracking-message')).toContainText('rationale');
  await row.locator('[name=reason]').fill('Compatibility review pending');
  await row.locator('[name=until]').fill('2099-01-01');
  await row.locator('button').click();
  await expect(row).toContainText('Migration team <test>');
  await page.reload(); await expect(page.locator('#project-results')).toContainText('Migration team <test>');
  await page.click('#project-scan button'); await expect(page.locator('#project-message')).toHaveText('Complete');
  await expect(page.locator('#view')).toContainText('still observed');
  await expect(page.locator('#project-results')).toContainText('Migration team <test>');
  expect((await new AxeBuilder({page}).analyze()).violations.filter(v=>['serious','critical'].includes(v.impact))).toEqual([]);
});


test('successful PQ negotiation without an encrypted child never claims VPN protection', async ({page}) => {
  const tunnel={peer:'branch',state:'ESTABLISHED',ppk:true,key_exchange:'CURVE_25519 + ML_KEM_768',established_s:60,children:[]};
  await page.route('**/api/tunnels', r=>r.fulfill({json:[tunnel]}));
  await signIn(page); await page.evaluate(()=>(location.hash='vpn'));
  await expect(page.locator('.metrics')).toContainText('Review required');
  await expect(page.locator('#view')).toContainText('IKE only · no encrypted tunnel');
  await expect(page.locator('.metrics')).not.toContainText('PQ observed');
  tunnel.children=[{state:'INSTALLED',bytes_in:128,bytes_out:256}];
  await page.evaluate(()=>(location.hash='readiness')); await expect(page.locator('#view h1')).toHaveText('Readiness');
  await page.evaluate(()=>(location.hash='vpn'));
  await expect(page.locator('.metrics')).toContainText('PQ observed');
});


test('deployment verification preserves a failed observation and explains rescan invalidation', async ({page}) => {
  await signIn(page); await page.evaluate(() => (location.hash='readiness'));
  await page.selectOption('#project-scan select', '0');
  await page.click('#project-scan button'); await expect(page.locator('#project-message')).toHaveText('Complete');
  await page.getByText('Verify a deployed service', {exact:true}).click();
  await page.locator('#project-verify [name=release]').fill('pilot-release <1>');
  await page.locator('#project-verify [name=association]').fill('Deployment manifest links this repository to the service');
  await page.locator('#project-verify [name=expected_sha256]').fill('0'.repeat(64));
  await page.locator('#project-verify button').click();
  await expect(page.locator('#view')).toContainText('Not verified');
  await expect(page.locator('#view')).toContainText('pilot-release <1>');
  await page.click('#project-scan button'); await expect(page.locator('#project-message')).toHaveText('Complete');
  await page.getByText('Verify a deployed service', {exact:true}).click();
  await expect(page.locator('#view')).toContainText('source rescanned; reverify');
  await page.getByText('Analysis coverage and incremental parsing', {exact:true}).click();
  await expect(page.locator('#view')).toContainText('Reused syntax: 2');
  expect((await new AxeBuilder({page}).analyze()).violations.filter(v=>['serious','critical'].includes(v.impact))).toEqual([]);
});
