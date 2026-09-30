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
