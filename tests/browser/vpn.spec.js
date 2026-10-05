const fs = require("fs");
const path = require("path");
const { test, expect } = require("@playwright/test");
const AxeBuilder = require("@axe-core/playwright").default;

const WINDOW = "http://127.0.0.1:8901/";
const INVITATION = path.join(__dirname, ".fixtures", "laptop.pqcinvite");

test("without the key from the address the window shows no state", async ({ page }) => {
  await page.goto(WINDOW);
  await expect(page.locator("#error")).toContainText("Open the address printed by");
  await page.goto("about:blank");
  await page.goto(WINDOW + "#wrong");
  await expect(page.locator("#error")).toContainText("open the address printed by");
  await page.goto("about:blank");
  await page.goto(WINDOW + "#browser-test");
  await expect(page.locator("#word")).toHaveText("Not set up");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("open an invitation, enroll, connect, disconnect", async ({ browser }) => {
  test.skip(!fs.existsSync(INVITATION), "the gateway behind the window needs OpenSSL 3.5 (see vpn_server.py output)");
  for (const [scheme, width] of [["light", 1280], ["dark", 390]]) {
    const page = await (await browser.newContext({ colorScheme: scheme, viewport: { width, height: 850 } })).newPage();
    const errors = [];
    page.on("pageerror", e => errors.push(e.message));
    await page.goto(WINDOW + "#browser-test");
    await expect(page).toHaveURL(WINDOW);
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(0);
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
    if (scheme === "light") {
      await expect(page.locator("#word")).toHaveText("Not set up");
      await page.setInputFiles("#invite", INVITATION);
      await expect(page.locator("#inv-name")).toHaveText("laptop.pqcinvite");
      await page.fill("#pass", "device pass");
      await page.fill("#repeat", "something else");
      await page.click("#connect");
      await expect(page.locator("#error")).toContainText("different");
      await page.click("#again .show");
      await expect(page.locator("#repeat")).toHaveAttribute("type", "text");
      await page.fill("#pass", "device pass");
      await page.fill("#repeat", "device pass");
      await page.click("#connect");
    } else {
      await expect(page.locator("#again")).toBeHidden();
      await page.fill("#pass", "wrong");
      await page.click("#connect");
      await expect(page.locator("#error")).toContainText("does not unlock");
      await page.fill("#pass", "device pass");
      await page.click("#connect");
    }
    await expect(page.locator("#word")).toHaveText("Keys agreed, not protected", { timeout: 30000 });
    await expect(page).toHaveTitle(/Keys agreed, not protected/);
    await page.reload();
    await expect(page.locator("#word")).toHaveText("Keys agreed, not protected");
    await expect(page.locator("#facts")).toContainText("10.99.0.");
    await page.click("#more summary");
    await expect(page.locator("#details")).toContainText("Post-quantum");
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
    await page.click("#disconnect");
    await expect(page.locator("#word")).toHaveText("Disconnected");
    await expect(page.locator("#pass")).toHaveValue("");
    expect(errors).toEqual([]);
  }
});
