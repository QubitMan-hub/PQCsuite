const {test,expect}=require('@playwright/test');
const AxeBuilder=require('@axe-core/playwright').default;
test('Wolf report filters, sorts, opens evidence and exports actions',async({page})=>{
 await page.goto('http://127.0.0.1:8765/wolf-pack-sample.html');await expect(page.locator('#queue-tools')).toBeVisible();
 const count=await page.locator('#migration-rows tr[data-asset]').count();expect(count).toBeGreaterThan(0);
 await page.selectOption('#finding-sort','asset');const names=await page.locator('#migration-rows tr[data-asset] td:nth-child(2)').allTextContents();expect(names).toEqual(names.slice().sort((a,b)=>a.localeCompare(b)));
 await page.fill('#finding-search','no-such-algorithm');await expect(page.locator('#finding-empty')).toBeVisible();await page.click('#finding-reset');await expect(page.locator('#finding-count')).toHaveText(`${count} of ${count} assets`);
 await page.locator('#migration-rows a').first().click();const id=await page.locator('#migration-rows a').first().getAttribute('href');await expect(page.locator(id)).toHaveAttribute('open','');
 await page.fill('#finding-search','RSA');const visible=await page.locator('#migration-rows tr[data-asset]:visible').count();expect(visible).toBeLessThan(count);expect(visible).toBeGreaterThan(0);
 const pending=page.waitForEvent('download');await page.click('#finding-export');const d=await pending;const contents=require('fs').readFileSync(await d.path(),'utf8');expect(contents).toContain('RSA');expect(contents).toContain('Next action');
 const found=(await new AxeBuilder({page}).analyze()).violations.filter(v=>['serious','critical'].includes(v.impact));expect(found.map(v=>v.id)).toEqual([]);
 await page.setViewportSize({width:390,height:850});expect(await page.evaluate(()=>document.documentElement.scrollWidth-innerWidth)).toBe(0);
});
test('Wolf report remains readable without JavaScript',async({browser})=>{
 const context=await browser.newContext({javaScriptEnabled:false});const page=await context.newPage();await page.goto('http://127.0.0.1:8765/wolf-pack-sample.html');await expect(page.locator('#queue-tools')).toBeHidden();await expect(page.locator('#migration-rows tr').first()).toBeVisible();await expect(page.locator('details').first()).toBeVisible();await context.close();
});
