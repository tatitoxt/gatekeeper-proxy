import http from 'node:http';
import { expect, test } from '@playwright/test';
import { ADMIN_TOKEN, startStack, Stack } from './support';

// Drives the admin dashboard in a real browser against the real gateway process.
test.describe('admin dashboard', () => {
  let stack: Stack;

  test.beforeAll(async () => {
    stack = await startStack();
  });
  test.afterAll(async () => {
    await stack?.stop();
  });

  test('requires the token, shows live security events and blocks an IP', async ({ page }) => {
    await page.goto(`${stack.adminUrl}/_admin`);
    await expect(page.locator('#status-text')).toHaveText(/Unauthorized/);

    await page.locator('#input-token').fill(ADMIN_TOKEN);
    await page.getByRole('button', { name: 'Connect' }).click();
    await expect(page.locator('#status-text')).toHaveText('Connected');
    await expect(page.locator('#routes-list')).toContainText('/api/v1');
    await expect(page.locator('#routes-list')).toContainText('/auth');

    // Attacker-controlled payload must be rendered as inert text, never as markup.
    // Sent verbatim (fetch would percent-encode it) so the stored path contains real markup.
    const payload = '/api/v1/search?q=<img/src=x/onerror=alert(1)>';
    expect(await rawGet(stack.proxyUrl, payload)).toBe(403);
    let dialogs = 0;
    page.on('dialog', (d) => {
      dialogs++;
      void d.dismiss();
    });

    const firstRow = page.locator('#events-table-body tr').first();
    await expect(firstRow).toContainText('WAF: Cross-Site Scripting (XSS) Attack Detected', { timeout: 5_000 });
    await expect(firstRow).toContainText(payload);
    await expect(page.locator('#events-table-body img')).toHaveCount(0);
    await expect(page.locator('#val-waf-blocks')).toHaveText('1');
    expect(dialogs).toBe(0);

    await page.locator('#input-block-ip').fill('203.0.113.7');
    await page.getByRole('button', { name: 'Add to IP Blacklist' }).click();
    await expect(page.locator('#block-notice')).toHaveText('Blocked 203.0.113.7');

    await page.locator('#input-block-ip').fill('not-an-ip');
    await page.getByRole('button', { name: 'Add to IP Blacklist' }).click();
    await expect(page.locator('#block-notice')).toHaveClass(/error/);

    const res = await fetch(`${stack.adminUrl}/api/firewall/blacklist`, {
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` }
    });
    expect((await res.json()).ipBlacklist).toContain('203.0.113.7');
  });
});

function rawGet(baseUrl: string, path: string): Promise<number> {
  const { hostname, port } = new URL(baseUrl);
  return new Promise((resolve, reject) => {
    const req = http.get({ hostname, port, path, agent: false }, (res) => {
      res.resume();
      resolve(res.statusCode ?? 0);
    });
    req.on('error', reject);
  });
}
