const { test, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;

const SITE = "http://127.0.0.1:8765/";
const PAGES = ["index.html", "wolf-pack.html", "security.html", "console-demo.html", "readiness-sample.html", "404.html", "wolf-pack-sample.html", "wolf-pack-inventory.html", "product-manual.html"];
const WIDTHS = [1280, 900, 390, 360];

const serious = async page =>
  (await new AxeBuilder({ page }).analyze()).violations.filter(v => ["serious", "critical"].includes(v.impact)).map(v => `${v.id}: ${v.nodes.map(n => n.target).join(", ")}`);

for (const name of PAGES) {
  test(`${name}: no script errors, no sideways scroll, no serious accessibility problems`, async ({ page }) => {
    const errors = [];
    page.on("pageerror", e => errors.push(e.message));
    page.on("console", m => m.type() === "error" && errors.push(m.text()));
    for (const width of WIDTHS) {
      await page.setViewportSize({ width, height: 850 });
      await page.goto(SITE + name, { waitUntil: "networkidle" });
      expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth), `${name} at ${width}px`).toBeLessThanOrEqual(0);
    }
    expect(errors).toEqual([]);
    expect(await serious(page)).toEqual([]);
  });
}

test("phone menu opens, closes on a link, and the section marker follows on desktop", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(SITE + "index.html");
  const first = page.locator("#nav a:not(.btn)").first();
  await expect(first).toBeHidden();
  await page.click(".menu");
  await expect(first).toBeVisible();
  await first.click();
  await expect(page.locator(".top")).not.toHaveClass(/open/);
  await page.setViewportSize({ width: 1280, height: 850 });
  await page.goto(SITE + "index.html");
  await page.click('#nav a[href="#app"]');
  await expect(page.locator('#nav a[aria-current]')).toHaveAttribute("href", "#app");
});

test("copy buttons copy the command", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto(SITE + "index.html");
  await page.setViewportSize({ width: 390, height: 900 });
  await page.locator(".copy").first().click();
  // the command wraps on a phone, but what is copied is still one line
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("docker run --rm ghcr.io/qubitman-hub/pqcsuite");
  await page.locator("#tls .copy").click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toMatch(/^pqcsuite tls edge --target \S+ --cert chain\.pem --key key\.pem$/);
});

test("the finder suggests steps and sends own-code questions to Wolf Pack", async ({ page }) => {
  await page.goto(SITE + "index.html");
  const steps = page.locator("#steps li a");
  await expect(steps).toHaveText(["Readiness assessment", "TLS 1.3 + mTLS", "Evidence report"]);
  await page.click("text=Cryptography inside our own software");
  await page.locator("fieldset").nth(1).getByText("Yes").click();
  await page.locator("fieldset").nth(2).getByText("No").click();
  await expect(steps).toHaveText(["Wolf Pack CBOM"]);
  await steps.first().click();
  await expect(page).toHaveURL(/wolf-pack\.html$/);
});

test("the finder stays hidden without JavaScript", async ({ browser }) => {
  const page = await (await browser.newContext({ javaScriptEnabled: false })).newPage();
  await page.goto(SITE + "index.html");
  await expect(page.locator("#start")).toBeHidden();
});

test("Wolf Pack is one click from the home page, links back, and opens its sample report", async ({ page }) => {
  await page.goto(SITE + "index.html");
  await expect(page.locator("#products a[href*='wolf']")).toHaveCount(0);
  await page.click("#nav a.tool");
  await expect(page).toHaveURL(/wolf-pack\.html$/);
  await page.getByRole("link", {name:"Try a sample assessment", exact:true}).click();
  await expect(page).toHaveTitle(/payments-api/);
  await page.goBack();
  await page.click("#nav a.back");
  await expect(page).toHaveURL(/index\.html$/);
});

test("Try it leads engineers to the tour, the install and the documentation, from every page's footer too", async ({ page }) => {
  await page.goto(SITE + "index.html");
  await page.goto(SITE + "index.html#use");
  await expect(page.locator("#use .path > li")).toHaveCount(3);
  await expect(page.locator("#use pre").first()).toHaveText("docker run --rm ghcr.io/qubitman-hub/pqcsuite");
  // a backup that one key opens is refused by the product, so the site must never show one
  await expect(page.locator("#vault pre")).toContainText("-r ops.pub -r recovery.pub");
  for (const name of ["index.html", "wolf-pack.html", "security.html", "404.html"]) {
    await page.goto(SITE + name);
    const docs = page.locator("body > footer nav div", { hasText: "Documentation" }).locator("a");
    await expect(docs).toHaveCount(6);
    for (const href of await docs.evaluateAll(as => as.map(a => a.href))) expect(href).toMatch(/^https:\/\/github\.com\/QubitMan-hub\/PQCsuite/);
  }
});

test("the Also from Acxelin band opens Wolf Pack", async ({ page }) => {
  await page.goto(SITE + "index.html");
  await page.click("#also >> text=Explore Wolf Pack CBOM");
  await expect(page).toHaveURL(/wolf-pack\.html$/);
});

test("fonts come from the site", async ({ page }) => {
  const hosts = new Set();
  page.on("request", r => hosts.add(new URL(r.url()).host));
  await page.goto(SITE + "index.html", { waitUntil: "networkidle" });
  expect([...hosts]).toEqual(["127.0.0.1:8765"]);
  expect(await page.evaluate(async () => (await document.fonts.ready, [...document.fonts].filter(f => f.status === "loaded").map(f => f.family)))).toContain("Host Grotesk");
});

test("the console demo shows example data, stays in the browser and refuses changes", async ({ page }) => {
  const hosts = new Set();
  page.on("request", r => hosts.add(new URL(r.url()).host));
  await page.goto(SITE + "console-demo.html#certificates");
  await expect(page.locator(".demo-bar")).toContainText("invented example data");
  await expect(page.getByText("CN=Example Bank Root")).toBeVisible();
  await page.locator("button:has-text('Revoke')").first().click();
  await page.locator("button:has-text('Confirm')").click();
  await expect(page.getByText("changes are switched off")).toBeVisible();
  await page.click('nav a[href="#readiness"]');
  await expect(page.getByText(/payments-api · Last completed/)).toBeVisible();
  expect([...hosts]).toEqual(["127.0.0.1:8765"]);
});
