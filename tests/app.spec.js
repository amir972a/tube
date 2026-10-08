const { test, expect } = require('@playwright/test');

test.describe('VideoCMS Foundation Tests', () => {
    test.beforeAll(async () => {
        // We'll clean up the DB to ensure a fresh test run
        // by executing a query before tests
    });

    test('Homepage loads correctly', async ({ page }) => {
        await page.goto('http://localhost:8000');
        await expect(page.locator('h1')).toContainText('به VideoCMS خوش آمدید');
    });

    test('User Registration and Login flow', async ({ page }) => {
        const uniqueSuffix = Date.now().toString();
        const username = `testuser_${uniqueSuffix}`;
        const email = `test_${uniqueSuffix}@example.com`;
        const password = 'Password123!';

        // Register
        await page.goto('http://localhost:8000/register');
        await page.fill('input[name="username"]', username);
        await page.fill('input[name="email"]', email);
        await page.fill('input[name="password"]', password);
        await page.click('button[type="submit"]');

        // Should be logged in and redirected to home
        await expect(page).toHaveURL('http://localhost:8000/');
        await expect(page.locator('a[href="/logout"]')).toBeVisible();

        // Logout
        await page.click('a[href="/logout"]');
        await expect(page).toHaveURL('http://localhost:8000/login');
        await expect(page.locator('a[href="/login"]')).toBeVisible();

        // Login again
        await page.goto('http://localhost:8000/login');
        await page.fill('input[name="email"]', email);
        await page.fill('input[name="password"]', password);
        await page.click('button[type="submit"]');

        await expect(page).toHaveURL('http://localhost:8000/');
        await expect(page.locator('a[href="/logout"]')).toBeVisible();
    });

    test('Admin protection works', async ({ page }) => {
        // Try to access without login
        await page.goto('http://localhost:8000/admin');
        await expect(page).toHaveURL('http://localhost:8000/login');

        // Register a regular user
        const uniqueSuffix = Date.now().toString();
        const username = `reguser_${uniqueSuffix}`;
        const email = `reg_${uniqueSuffix}@example.com`;
        const password = 'Password123!';

        await page.goto('http://localhost:8000/register');
        await page.fill('input[name="username"]', username);
        await page.fill('input[name="email"]', email);
        await page.fill('input[name="password"]', password);
        await page.click('button[type="submit"]');

        // Try to access admin as normal user
        const response = await page.goto('http://localhost:8000/admin');
        expect(response.status()).toBe(403);
    });

    test('CSRF protection works', async ({ request }) => {
        // Send a POST request without CSRF token
        const response = await request.post('http://localhost:8000/login', {
            data: {
                email: 'test@example.com',
                password: 'password'
            }
        });

        expect(response.status()).toBe(403);
    });
});
