import { test, expect } from '@playwright/test';

test.describe('Dashboard & Scanning', () => {
    test.beforeEach(async ({ page }) => {
        // Login before each test
        await page.goto('/login');
        await page.getByLabel(/email/i).fill('test@example.com');
        await page.getByLabel(/password/i).fill('testpassword123');
        await page.getByRole('button', { name: /sign in|login/i }).click();
        await expect(page).toHaveURL(/\/dashboard/);
    });

    test('should load dashboard successfully', async ({ page }) => {
        await expect(page.getByRole('heading', { name: /dashboard/i })).toBeVisible();
        await expect(page.getByText(/scan target/i)).toBeVisible();
    });

    test('should start a scan', async ({ page }) => {
        const targetDomain = 'example.com';

        // Enter target domain
        await page.getByPlaceholder(/enter domain/i).fill(targetDomain);

        // Click start scan
        await page.getByRole('button', { name: /start scan/i }).click();

        // Check for status update
        await expect(page.getByText(/scanning/i)).toBeVisible();

        // Check for terminal logs
        await expect(page.locator('.terminal-window')).toBeVisible();
        await expect(page.locator('.terminal-window')).toContainText(`Scanning ${targetDomain}`);
    });

    test('should display vulnerability charts', async ({ page }) => {
        // Check for charts presence
        await expect(page.locator('.recharts-wrapper')).toBeVisible();
    });
});
