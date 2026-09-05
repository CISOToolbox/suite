// @ts-check
const { defineConfig, devices } = require("@playwright/test");

// Unlike the browser-local webapp e2e suites, which serve a static application
// themselves, this one targets the suite stack behind its proxy: a session is
// required, and the certificate is self-signed locally.
module.exports = defineConfig({
    testDir: ".",
    fullyParallel: false,
    workers: 1,
    retries: 0,
    forbidOnly: !!process.env.CI,
    timeout: 60_000,
    expect: { timeout: 8_000 },
    reporter: [["list"], ["html", { outputFolder: "playwright-report", open: "never" }]],
    use: {
        ignoreHTTPSErrors: true,
        headless: true,
        viewport: { width: 1400, height: 950 },
        trace: "on-first-retry",
        screenshot: "only-on-failure",
        actionTimeout: 10_000,
        navigationTimeout: 30_000,
    },
    projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
