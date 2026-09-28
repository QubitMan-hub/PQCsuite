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
