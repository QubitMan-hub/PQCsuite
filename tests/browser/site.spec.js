const { test, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;

const SITE = "http://127.0.0.1:8765/";
const PAGES = ["index.html", "wolf-pack.html", "404.html", "wolf-pack-sample.html", "wolf-pack-inventory.html"];
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
  await page.click('#nav a[href="#plan"]');
  await expect(page.locator('#nav a[aria-current]')).toHaveAttribute("href", "#plan");
});

test("copy buttons copy the command", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto(SITE + "index.html");
  await page.locator(".copy").first().click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toMatch(/^pqcsuite tls edge/);
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
  await page.click("text=Open a sample report");
  await expect(page).toHaveTitle(/payments-api/);
  await page.goBack();
  await page.click("#nav a.back");
  await expect(page).toHaveURL(/index\.html$/);
});

test("fonts come from the site", async ({ page }) => {
  const hosts = new Set();
  page.on("request", r => hosts.add(new URL(r.url()).host));
  await page.goto(SITE + "index.html", { waitUntil: "networkidle" });
  expect([...hosts]).toEqual(["127.0.0.1:8765"]);
  expect(await page.evaluate(async () => (await document.fonts.ready, [...document.fonts].filter(f => f.status === "loaded").map(f => f.family)))).toContain("Host Grotesk");
});
