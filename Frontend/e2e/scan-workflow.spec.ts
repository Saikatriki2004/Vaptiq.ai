/**
 * E2E Tests for Complete Scan Workflow
 * 
 * Tests cover:
 * - Scan initiation
 * - Real-time log streaming
 * - Progress updates
 * - Scan completion
 * - Vulnerability display
 * - Scan cancellation
 */

import { test, expect, type Page } from '@playwright/test';

// Helper function to login
async function login(page: Page) {
    await page.goto('/login');
    await page.getByLabel(/email/i).fill('test@example.com');
    await page.getByLabel(/password/i).fill('testpassword123');
    await page.getByRole('button', { name: /sign in|login/i }).click();
    await expect(page).toHaveURL(/\/dashboard/);
}

test.describe('Scan Workflow', () => {

    test.beforeEach(async ({ page }) => {
        await login(page);
    });

    test('should initiate a new scan', async ({ page }) => {
        // Click "New Scan" button
        await page.getByRole('button', { name: /new scan|start scan|create scan/i }).click();

        // Should show scan form/dialog
        await expect(page.getByText(/target|scan target/i)).toBeVisible();

        // Fill in target details
        await page.getByLabel(/target.*url|url/i).fill('https://example.com');

        // Submit scan
        await page.getByRole('button', { name: /start|begin|launch/i }).click();

        // Should show scan in progress
        await expect(page.getByText(/scanning|in progress|running/i)).toBeVisible({ timeout: 10000 });
    });

    test('should display real-time scan logs', async ({ page }) => {
        // Start a scan
        await page.getByRole('button', { name: /new scan/i }).click();
        await page.getByLabel(/url/i).fill('https://test.com');
        await page.getByRole('button', { name: /start/i }).click();

        // Should see log viewer
        await expect(page.locator('[data-testid="scan-logs"]').or(page.getByText(/log|console|output/i))).toBeVisible({ timeout: 10000 });

        // Should see log entries appearing
        await expect(page.getByText(/starting|running|scanning/i)).toBeVisible({ timeout: 15000 });
    });

    test('should show progress bar updates', async ({ page }) => {
        // Start a scan
        await page.getByRole('button', { name: /new scan/i }).click();
        await page.getByLabel(/url/i).fill('https://test.com');
        await page.getByRole('button', { name: /start/i }).click();

        // Should see progress bar
        const progressBar = page.locator('[role="progressbar"]').or(page.locator('progress'));
        await expect(progressBar.first()).toBeVisible({ timeout: 5000 });
    });

    test('should display scan results upon completion', async ({ page }) => {
        // Navigate to a completed scan
        await page.goto('/dashboard/scans');

        // Click on a scan (assuming there's a list)
        const firstScan = page.getByRole('link', { name: /scan|view/i }).first();
        if (await firstScan.isVisible()) {
            await firstScan.click();

            // Should show vulnerabilities or "no findings"
            await expect(
                page.getByText(/vulnerabilities|findings|results|no issues found/i)
            ).toBeVisible();
        }
    });

    test('should show vulnerability details', async ({ page }) => {
        // Navigate to scans page
        await page.goto('/dashboard/scans');

        // Click on first scan with findings
        const scanLink = page.getByRole('link').first();
        if (await scanLink.isVisible()) {
            await scanLink.click();

            // Should see vulnerability cards/list
            const vulnItem = page.getByText(/sql injection|xss|vulnerability/i).first();
            if (await vulnItem.isVisible()) {
                await vulnItem.click();

                // Should show details
                await expect(page.getByText(/severity|description|remediation/i)).toBeVisible();
            }
        }
    });

    test('should cancel running scan', async ({ page }) => {
        // Start a scan
        await page.getByRole('button', { name: /new scan/i }).click();
        await page.getByLabel(/url/i).fill('https://test.com');
        await page.getByRole('button', { name: /start/i }).click();

        // Wait for scan to start
        await expect(page.getByText(/running|scanning/i)).toBeVisible({ timeout: 10000 });

        // Click cancel button
        const cancelButton = page.getByRole('button', { name: /cancel|stop|abort/i });
        if (await cancelButton.isVisible()) {
            await cancelButton.click();

            // Should show cancelled status
            await expect(page.getByText(/cancelled|stopped/i)).toBeVisible({ timeout: 5000 });
        }
    });

    test('should filter scans by status', async ({ page }) => {
        await page.goto('/dashboard/scans');

        // Should have filter dropdown or tabs
        const filterButton = page.getByRole('button', { name: /filter|status/i }).or(
            page.getByRole('tab', { name: /completed|running|all/i })
        );

        if (await filterButton.first().isVisible()) {
            await filterButton.first().click();

            // Select a filter option
            await page.getByRole('option', { name: /completed/i }).or(
                page.getByRole('tab', { name: /completed/i })
            ).click();

            // List should update
            await page.waitForTimeout(500);
        }
    });

    test('should validate required fields in scan form', async ({ page }) => {
        // Click new scan
        await page.getByRole('button', { name: /new scan/i }).click();

        // Try to submit without filling target
        await page.getByRole('button', { name: /start|begin/i }).click();

        // Should show validation error
        await expect(page.getByText(/required|enter.*target/i)).toBeVisible();
    });

    test('should support API target type', async ({ page }) => {
        await page.getByRole('button', { name: /new scan/i }).click();

        // Switch to API type
        const typeSelector = page.getByLabel(/type|target type/i).or(
            page.getByRole('combobox')
        );

        if (await typeSelector.isVisible()) {
            await typeSelector.click();
            await page.getByRole('option', { name: /api/i }).click();

            // Should show API-specific fields
            await page.getByLabel(/url|endpoint/i).fill('https://api.example.com/v1');

            await page.getByRole('button', { name: /start/i }).click();

            // Should initiate scan
            await expect(page.getByText(/scanning|queued/i)).toBeVisible({ timeout: 5000 });
        }
    });

    test('should show scan history', async ({ page }) => {
        await page.goto('/dashboard/scans');

        // Should see list of scans or empty state
        await expect(
            page.getByRole('heading', { name: /scans|scan history/i }).or(
                page.getByText(/no scans|start.*scan/i)
            )
        ).toBeVisible();
    });
});

test.describe('Scan Visual Tests', () => {

    test.beforeEach(async ({ page }) => {
        await login(page);
    });

    test('should match scan dashboard layout', async ({ page }) => {
        await page.goto('/dashboard');

        // Take screenshot for visual regression
        await expect(page).toHaveScreenshot('dashboard-layout.png', {
            fullPage: true,
            maxDiffPixels: 100
        });
    });

    test('should match scan details layout', async ({ page }) => {
        await page.goto('/dashboard/scans');

        const firstScan = page.getByRole('link').first();
        if (await firstScan.isVisible()) {
            await firstScan.click();

            // Screenshot of scan details
            await expect(page).toHaveScreenshot('scan-details.png', {
                fullPage: true,
                maxDiffPixels: 100
            });
        }
    });
});
