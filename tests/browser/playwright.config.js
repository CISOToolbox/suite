// @ts-check
const { defineConfig, devices } = require("@playwright/test");

// Contrairement aux suites webapp/e2e de l'opensource, qui servent elles-mêmes
// une application statique, celle-ci vise la stack suite derrière son proxy :
// il faut une session, et le certificat est auto-signé en local.
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
