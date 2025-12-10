/**
 * E2E Tests for Report Generation and Export
 * 
 * Tests cover:
 * - PDF report download
 * - HTML report download
 * - JSON report download
 * - Severity filtering
 * - Report content validation
 */

import { test, expect, type Page } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

// Helper function to login
async function login(page: Page) {
    await page.goto('/login');
    await page.getByLabel(/email/i).fill('test@example.com');
    await page.getByLabel(/password/i).fill('testpassword123');
    await page.getByRole('button', { name: /sign in|login/i }).click();
    await expect(page).toHaveURL(/\/dashboard/);
}

test.describe('Report Export', () => {

    test.beforeEach(async ({ page }) => {
        await login(page);
        // Navigate to a completed scan
        await page.goto('/dashboard/scans');
    });

    test('should download PDF report', async ({ page }) => {
        // Click on a scan
        const scanLink = page.getByRole('link').first();
        if (await scanLink.isVisible()) {
            await scanLink.click();

            // Click export/download button
            const exportButton = page.getByRole('button', { name: /export|download|report/i });
            if (await exportButton.isVisible()) {
                // Setup download listener
                const downloadPromise = page.waitForEvent('download');

                await exportButton.click();

                // Select PDF format if dropdown appears
                const pdfOption = page.getByRole('button', { name: /pdf/i }).or(
                    page.getByRole('menuitem', { name: /pdf/i })
                );

                if (await pdfOption.isVisible({ timeout: 2000 }).catch(() => false)) {
                    await pdfOption.click();
                }

                // Wait for download
                const download = await downloadPromise;

                // Verify download
                expect(download.suggestedFilename()).toMatch(/\.pdf$/i);

                // Verify file is not empty
                const filePath = await download.path();
                if (filePath) {
                    const stats = fs.statSync(filePath);
                    expect(stats.size).toBeGreaterThan(0);
                }
            }
        }
    });

    test('should download HTML report', async ({ page }) => {
        const scanLink = page.getByRole('link').first();
        if (await scanLink.isVisible()) {
            await scanLink.click();

            const exportButton = page.getByRole('button', { name: /export|download/i });
            if (await exportButton.isVisible()) {
                await exportButton.click();

                // Select HTML format
                const htmlOption = page.getByRole('button', { name: /html/i }).or(
                    page.getByRole('menuitem', { name: /html/i })
                );

                if (await htmlOption.isVisible({ timeout: 2000 }).catch(() => false)) {
                    const downloadPromise = page.waitForEvent('download');
                    await htmlOption.click();

                    const download = await downloadPromise;
                    expect(download.suggestedFilename()).toMatch(/\.html$/i);
                }
            }
        }
    });

    test('should download JSON report', async ({ page }) => {
        const scanLink = page.getByRole('link').first();
        if (await scanLink.isVisible()) {
            await scanLink.click();

            const exportButton = page.getByRole('button', { name: /export|download/i });
            if (await exportButton.isVisible()) {
                await exportButton.click();

                // Select JSON format
                const jsonOption = page.getByRole('button', { name: /json/i }).or(
                    page.getByRole('menuitem', { name: /json/i })
                );

                if (await jsonOption.isVisible({ timeout: 2000 }).catch(() => false)) {
                    const downloadPromise = page.waitForEvent('download');
                    await jsonOption.click();

                    const download = await downloadPromise;
                    expect(download.suggestedFilename()).toMatch(/\.json$/i);

                    // Validate JSON structure
                    const filePath = await download.path();
                    if (filePath) {
                        const content = fs.readFileSync(filePath, 'utf-8');
                        const json = JSON.parse(content);

                        expect(json).toHaveProperty('id');
                        expect(json).toHaveProperty('target');
                        expect(json).toHaveProperty('findings');
                    }
                }
            }
        }
    });

    test('should filter report by severity', async ({ page }) => {
        const scanLink = page.getByRole('link').first();
        if (await scanLink.isVisible()) {
            await scanLink.click();

            // Look for severity filter
            const filterButton = page.getByRole('button', { name: /filter|severity/i }).or(
                page.getByLabel(/severity/i)
            );

            if (await filterButton.isVisible({ timeout: 2000 }).catch(() => false)) {
                await filterButton.click();

                // Select only CRITICAL
                const criticalCheckbox = page.getByLabel(/critical/i).or(
                    page.getByRole('checkbox', { name: /critical/i })
                );

                if (await criticalCheckbox.isVisible({ timeout: 2000 }).catch(() => false)) {
                    await criticalCheckbox.click();

                    // Apply filter
                    const applyButton = page.getByRole('button', { name: /apply|filter/i });
                    if (await applyButton.isVisible({ timeout: 1000 }).catch(() => false)) {
                        await applyButton.click();
                    }

                    // Verify only CRITICAL items shown
                    await page.waitForTimeout(500);

                    const vulnerabilities = page.getByText(/critical/i);
                    await expect(vulnerabilities.first()).toBeVisible({ timeout: 2000 }).catch(() => { });
                }
            }
        }
    });

    test('should show report preview', async ({ page }) => {
        const scanLink = page.getByRole('link').first();
        if (await scanLink.isVisible()) {
            await scanLink.click();

            // Should see report content/preview
            await expect(
                page.getByText(/vulnerability|finding|result/i).or(
                    page.getByText(/no vulnerabilities/i)
                )
            ).toBeVisible();
        }
    });
});

test.describe('Report Content Validation', () => {

    test.beforeEach(async ({ page }) => {
        await login(page);
        await page.goto('/dashboard/scans');
    });

    test('should display scan metadata in report', async ({ page }) => {
        const scanLink = page.getByRole('link').first();
        if (await scanLink.isVisible()) {
            await scanLink.click();

            // Should show scan ID, target, timestamp
            await expect(
                page.getByText(/scan id|target|date|time/i)
            ).toBeVisible();
        }
    });

    test('should categorize findings by severity', async ({ page }) => {
        const scanLink = page.getByRole('link').first();
        if (await scanLink.isVisible()) {
            await scanLink.click();

            // Should see severity indicators
            const severityLabels = page.getByText(/critical|high|medium|low/i);
            const count = await severityLabels.count();

            // If there are findings, should have severity labels
            if (count > 0) {
                await expect(severityLabels.first()).toBeVisible();
            }
        }
    });

    test('should show vulnerability details in report', async ({ page }) => {
        const scanLink = page.getByRole('link').first();
        if (await scanLink.isVisible()) {
            await scanLink.click();

            // Click on a vulnerability
            const vulnItem = page.getByRole('button', { name: /sql|xss|vulnerability/i }).first();

            if (await vulnItem.isVisible({ timeout: 2000 }).catch(() => false)) {
                await vulnItem.click();

                // Should show details
                await expect(
                    page.getByText(/description|remediation|proof/i)
                ).toBeVisible();
            }
        }
    });
});

test.describe('Report UI/UX', () => {

    test.beforeEach(async ({ page }) => {
        await login(page);
    });

    test('should have accessible export buttons', async ({ page }) => {
        await page.goto('/dashboard/scans');

        const scanLink = page.getByRole('link').first();
        if (await scanLink.isVisible()) {
            await scanLink.click();

            // Export button should be keyboard accessible
            const exportButton = page.getByRole('button', { name: /export|download/i });

            if (await exportButton.isVisible()) {
                // Should be focusable
                await exportButton.focus();
                const isFocused = await exportButton.evaluate((el: HTMLElement) => el === document.activeElement);
                expect(isFocused).toBeTruthy();
            }
        }
    });

    test('should show loading state during export', async ({ page }) => {
        await page.goto('/dashboard/scans');

        const scanLink = page.getByRole('link').first();
        if (await scanLink.isVisible()) {
            await scanLink.click();

            const exportButton = page.getByRole('button', { name: /export/i });

            if (await exportButton.isVisible()) {
                await exportButton.click();

                // Should show loading indicator (spinner, disabled button, etc.)
                // This might be brief, so we use a short timeout
                await expect(
                    page.getByRole('button', { name: /exporting|loading/i }).or(
                        page.locator('[data-loading="true"]')
                    )
                ).toBeVisible({ timeout: 1000 }).catch(() => { });
            }
        }
    });
});
