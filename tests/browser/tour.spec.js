const { test, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;

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

test("the console tour opens each page in turn", async ({ page }) => {
  await asNewcomer(page);
  await page.goto(CONSOLE);
  await page.fill("#tok", "browser-test");
  await page.click("form.login button");
  await expect(card(page)).toContainText("Step 1 of 9");
  const pages = ["overview", "edges", "certificates", "vpn", "backups", "readiness"];
  await page.click(".tour-card .go");
  for (const [k, view] of pages.entries()) {
    await expect(card(page)).toContainText(`Step ${k + 2} of 9`);
    await page.click(".tour-card .go");
    await expect(page).toHaveURL(new RegExp("#" + view + "$"));
    await expect(page.locator(`nav a[data-view="${view}"]`)).toHaveAttribute("aria-current", "page");
  }
  await page.keyboard.press("Escape");
  await page.click("#tour");
  await walk(page, 9);
});

test("the VPN window tour", async ({ page, request }) => {
  await asNewcomer(page);
  const r = await request.post(WINDOW + "api/ticket", { headers: { Authorization: "Bearer browser-test" }, data: {} });
  await page.goto(WINDOW + "#" + (await r.json()).ticket);
  await walk(page, 6);
  await page.click("#tour");
  await expect(card(page)).toContainText("Step 1 of 6");
});
