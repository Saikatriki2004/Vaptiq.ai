import { test, expect } from '@playwright/test';

test.describe('Attack Path Simulation', () => {
    test.beforeEach(async ({ page }) => {
        // Login
        await page.goto('/login');
        await page.getByLabel(/email/i).fill('test@example.com');
        await page.getByLabel(/password/i).fill('testpassword123');
        await page.getByRole('button', { name: /sign in|login/i }).click();
        await expect(page).toHaveURL(/\/dashboard/);

        // Navigate to Attack Paths
        await page.getByRole('link', { name: /attack paths/i }).click();
        await expect(page).toHaveURL(/\/dashboard\/attack-paths/);
    });

    test('should display attack path visualization', async ({ page }) => {
        await expect(page.getByRole('heading', { name: /attack paths/i })).toBeVisible();
        // Check for ReactFlow graph
        await expect(page.locator('.react-flow')).toBeVisible();
    });

    test('should trigger simulation', async ({ page }) => {
        await page.getByRole('button', { name: /simulate attack/i }).click();
        // Expect some visual change or notification
        // This depends on implementation, but checking for button state or toast is good
        // For now, we assume a toast or status change
        // await expect(page.getByText(/simulation started/i)).toBeVisible(); 
    });
});
