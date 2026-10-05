const { test, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;

const SITE = "http://127.0.0.1:8765/index.html";
const CONSOLE = "http://127.0.0.1:8900/";
const WINDOW = "http://127.0.0.1:8901/";
const card = (page) => page.locator(".tour-card");
const asNewcomer = (page) => page.addInitScript(() => Object.defineProperty(navigator, "webdriver", { get: () => false }));

async function walk(page, steps) {
  await expect(card(page)).toContainText(`Step 1 of ${steps}`);
  expect((await new AxeBuilder({ page }).include(".tour-card").analyze()).violations).toEqual([]);
  await page.click(".tour-card .go");
  await expect(card(page)).toContainText(`Step 2 of ${steps}`);
  await page.click(".tour-card button:has-text('Back')");
  await expect(card(page)).toContainText(`Step 1 of ${steps}`);
  for (let i = 1; i < steps; i++) {
    await page.keyboard.press("ArrowRight");
    await expect(card(page)).toContainText(`Step ${i + 1} of ${steps}`);
  }
  await expect(page.locator(".tour-card .go")).toHaveText("Finish");
  await page.click(".tour-card .go");
  await expect(card(page)).toHaveCount(0);
}

test("the website greets a newcomer with a tour once, and replays it from its button", async ({ page }) => {
  await asNewcomer(page);
  await page.goto(SITE);
  await walk(page, 10);
  await page.reload();
  await expect(page.locator("#why")).toBeVisible();
  await expect(card(page)).toHaveCount(0);
  await page.click("#tour");
  await expect(card(page)).toContainText("Step 1 of 10");
  await page.keyboard.press("Escape");
  await expect(card(page)).toHaveCount(0);
  await expect(page.locator("#tour")).toBeFocused();
});

test("the website tour fits a phone", async ({ browser }) => {
  const page = await (await browser.newContext({ viewport: { width: 390, height: 800 } })).newPage();
  await page.goto(SITE);
  await page.click("#tour");
  for (let i = 1; i < 10; i++) { await page.click(".tour-card .go"); await expect(card(page)).toContainText(`Step ${i + 1} of 10`); }
  const box = await card(page).boundingBox();
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width).toBeLessThanOrEqual(390);
  expect(box.y + box.height).toBeLessThanOrEqual(800);
});

test("the console tour opens each page in turn", async ({ page }) => {
  await asNewcomer(page);
  await page.goto(CONSOLE);
  await page.fill("#tok", "browser-test");
  await page.click("form.login button");
  await expect(card(page)).toContainText("Step 1 of 10");
  const pages = ["overview", "edges", "certificates", "vpn", "backups", "readiness", "wolfpack"];
  await page.click(".tour-card .go");
  for (const [k, view] of pages.entries()) {
    await expect(card(page)).toContainText(`Step ${k + 2} of 10`);
    await page.click(".tour-card .go");
    await expect(page).toHaveURL(new RegExp("#" + view + "$"));
    await expect(page.locator(`nav a[data-view="${view}"]`)).toHaveAttribute("aria-current", "page");
  }
  await page.keyboard.press("Escape");
  await page.click("#tour");
  await walk(page, 10);
});

test("the VPN window tour", async ({ page, request }) => {
  await asNewcomer(page);
  const r = await request.post(WINDOW + "api/ticket", { headers: { Authorization: "Bearer browser-test" }, data: {} });
  await page.goto(WINDOW + "#" + (await r.json()).ticket);
  await walk(page, 6);
  await page.click("#tour");
  await expect(card(page)).toContainText("Step 1 of 6");
});

test("a visitor who leaves mid-tour is not shown it again", async ({ page }) => {
  await asNewcomer(page);
  await page.goto(SITE);
  await expect(card(page)).toContainText("Step 1 of 10");
  await page.reload();
  await expect(page.locator("#why")).toBeVisible();
  await expect(card(page)).toHaveCount(0);
});

test("the tour scrolls to each part and settles the card beside it", async ({ page }) => {
  await page.goto(SITE);
  await page.click("#tour");
  for (let i = 1; i < 6; i++) await page.click(".tour-card .go");
  await expect(card(page)).toContainText("Step 6 of 10");
  await expect(card(page)).not.toHaveClass(/away/);
  const [spot, target] = await Promise.all([page.locator(".tour-spot").boundingBox(), page.locator("#products h2").boundingBox()]);
  expect(Math.abs(spot.y + 6 - target.y)).toBeLessThan(2);
  expect(target.y).toBeGreaterThan(0);
  expect(target.y + target.height).toBeLessThan(page.viewportSize().height);
});

test("the console demo has its own tour, worded for the demo", async ({ page }) => {
  await asNewcomer(page);
  await page.goto(SITE.replace("index.html", "console-demo.html"));
  await expect(card(page)).toContainText("invented example data");
  for (let i = 1; i < 10; i++) { await page.click(".tour-card .go"); await expect(card(page)).toContainText(`Step ${i + 1} of 10`); }
  await expect(card(page)).toContainText("switched off in the demo");
  await page.click(".tour-card .go");
  await expect(card(page)).toHaveCount(0);
});

test("the tour is always one click away, from every page", async ({ page }) => {
  await page.goto(SITE);
  await page.click("#nav a.help");
  await expect(card(page)).toContainText("Step 1 of 10");
  await page.keyboard.press("Escape");
  await page.goto(SITE.replace("index.html", "security.html"));
  await page.click("#nav a.help");
  await expect(page).toHaveURL(/index\.html$/);
  await expect(card(page)).toContainText("Step 1 of 10");
  await page.keyboard.press("Escape");
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(SITE.replace("index.html", "wolf-pack.html"));
  await page.click(".menu");
  await page.getByRole("link", { name: "Take the tour" }).click();
  await expect(card(page)).toContainText("Step 1 of 10");
});
