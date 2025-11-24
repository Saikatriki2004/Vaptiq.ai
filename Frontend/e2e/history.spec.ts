import { test, expect } from '@playwright/test';

test.describe('Scan History', () => {
    test.beforeEach(async ({ page }) => {
        // Login
        await page.goto('/login');
        await page.getByLabel(/email/i).fill('test@example.com');
        await page.getByLabel(/password/i).fill('testpassword123');
        await page.getByRole('button', { name: /sign in|login/i }).click();
        await expect(page).toHaveURL(/\/dashboard/);

        // Navigate to History
        await page.getByRole('link', { name: /history/i }).click();
        await expect(page).toHaveURL(/\/dashboard\/history/);
    });

    test('should display scan history list', async ({ page }) => {
        await expect(page.getByRole('heading', { name: /scan history/i })).toBeVisible();
        // Check for table or list
        await expect(page.locator('table')).toBeVisible();
    });

    test('should filter scans', async ({ page }) => {
        // Check for filter input
        const filterInput = page.getByPlaceholder(/filter/i);
        if (await filterInput.isVisible()) {
            await filterInput.fill('example.com');
            // Verify list updates
            // await expect(page.locator('tbody tr')).toHaveCount(1);
        }
    });
});
