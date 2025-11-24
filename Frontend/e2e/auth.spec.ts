/**
 * E2E Tests for Authentication Flow
 * 
 * Tests cover:
 * - Login functionality
 * - Logout functionality
 * - Protected route redirection
 * - Session persistence
 */

import { test, expect, type Page } from '@playwright/test';

test.describe('Authentication Flow', () => {

    test.beforeEach(async ({ page }) => {
        // Start from the login page
        await page.goto('/login');
    });

    test('should display login page', async ({ page }) => {
        // Check for login form elements
        await expect(page.locator('form')).toBeVisible();
        await expect(page.getByRole('button', { name: /sign in|login/i })).toBeVisible();
    });

    test('should login with valid credentials', async ({ page }) => {
        // Fill in login form
        await page.getByLabel(/email/i).fill('test@example.com');
        await page.getByLabel(/password/i).fill('testpassword123');

        // Submit form
        await page.getByRole('button', { name: /sign in|login/i }).click();

        // Should redirect to dashboard
        await expect(page).toHaveURL(/\/dashboard/);

        // Should see dashboard content
        await expect(page.getByRole('heading', { name: /dashboard/i })).toBeVisible();
    });

    test('should show error with invalid credentials', async ({ page }) => {
        // Fill in with invalid credentials
        await page.getByLabel(/email/i).fill('[email protected]');
        await page.getByLabel(/password/i).fill('wrongpassword');

        // Submit form
        await page.getByRole('button', { name: /sign in|login/i }).click();

        // Should show error message
        await expect(page.getByText(/invalid credentials|authentication failed/i)).toBeVisible();

        // Should stay on login page
        await expect(page).toHaveURL(/\/login/);
    });

    test('should logout successfully', async ({ page }) => {
        // Login first
        await page.goto('/login');
        await page.getByLabel(/email/i).fill('test@example.com');
        await page.getByLabel(/password/i).fill('testpassword123');
        await page.getByRole('button', { name: /sign in|login/i }).click();

        await expect(page).toHaveURL(/\/dashboard/);

        // Click logout button (might be in menu or header)
        const logoutButton = page.getByRole('button', { name: /logout|sign out/i });
        await logoutButton.click();

        // Should redirect to login page
        await expect(page).toHaveURL(/\/login/);
    });

    test('should redirect to login when accessing protected route', async ({ page }) => {
        // Try to access dashboard without authentication
        await page.goto('/dashboard');

        // Should redirect to login
        await expect(page).toHaveURL(/\/login/);
    });

    test('should persist session on page reload', async ({ page }) => {
        // Login
        await page.goto('/login');
        await page.getByLabel(/email/i).fill('test@example.com');
        await page.getByLabel(/password/i).fill('testpassword123');
        await page.getByRole('button', { name: /sign in|login/i }).click();

        await expect(page).toHaveURL(/\/dashboard/);

        // Reload page
        await page.reload();

        // Should still be on dashboard (session persisted)
        await expect(page).toHaveURL(/\/dashboard/);
        await expect(page.getByRole('heading', { name: /dashboard/i })).toBeVisible();
    });

    test('should handle missing email field', async ({ page }) => {
        // Fill only password
        await page.getByLabel(/password/i).fill('testpassword123');

        // Try to submit
        await page.getByRole('button', { name: /sign in|login/i }).click();

        // Should show validation error
        await expect(page.getByText(/email.*required/i)).toBeVisible();
    });

    test('should handle missing password field', async ({ page }) => {
        // Fill only email
        await page.getByLabel(/email/i).fill('test@example.com');

        // Try to submit
        await page.getByRole('button', { name: /sign in|login/i }).click();

        // Should show validation error
        await expect(page.getByText(/password.*required/i)).toBeVisible();
    });

    test('should validate email format', async ({ page }) => {
        // Enter invalid email format
        await page.getByLabel(/email/i).fill('invalid-email');
        await page.getByLabel(/password/i).fill('testpassword123');

        // Try to submit
        await page.getByRole('button', { name: /sign in|login/i }).click();

        // Should show validation error
        await expect(page.getByText(/invalid email|valid email/i)).toBeVisible();
    });
});
