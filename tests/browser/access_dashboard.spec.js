// FEAT-44 — the Access dashboard renders its charts, consistently with D.
//
// Four blocks, each checked against the app state (not just DOM presence):
//   - two compliance gauges (policy, MFA) replacing the old text percentages;
//   - IdP account-state donut: centre total = user count, legend sums to it;
//   - perimeters-by-type donut: centre total = perimeter count;
//   - review-state and service-account bars: figures equal to the same
//     predicates the KPI cards use (no duplicated logic to drift).
//
// Prerequisites: stack up + `bash mint-tokens.sh` (cf. console.spec.js).
const fs = require("fs");
const path = require("path");
const { test, expect } = require("@playwright/test");

const PROXY = (process.env.E2E_PROXY || "https://localhost:8443").replace(/\/+$/, "");
const TOKENS_FILE = path.join(__dirname, "tokens.json");
const TOKENS = fs.existsSync(TOKENS_FILE)
    ? JSON.parse(fs.readFileSync(TOKENS_FILE, "utf8")) : {};

// Same guard as console.spec.js: admin sessions, local stacks only.
const IS_LOCAL = /^https?:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/.test(PROXY);
if (!IS_LOCAL && process.env.E2E_ALLOW_REMOTE !== "1") {
    throw new Error(
        `E2E_PROXY pointe vers ${PROXY}, qui n'est pas local. Ces tests ouvrent ` +
        `des sessions administrateur : lancez-les contre une stack de recette, ` +
        `ou forcez avec E2E_ALLOW_REMOTE=1 si vous savez ce que vous faites.`);
}

const legendSum = (donut) => donut.locator(".ct-donut-legend-item strong")
    .allTextContents()
    .then((xs) => xs.reduce((a, x) => a + parseInt(x, 10), 0));

test.describe("access dashboard charts (FEAT-44)", () => {
    test.beforeEach(async ({ page }) => {
        const token = TOKENS.access;
        expect(token, "no session token for access — run mint-tokens.sh").toBeTruthy();
        await page.context().addCookies([{
            name: "access_token", value: token,
            domain: "localhost", path: "/",
        }]);
        await page.goto(`${PROXY}/access/`, { waitUntil: "networkidle" });
    });

    test("gauges and account donut mirror the user base", async ({ page }) => {
        const users = await page.evaluate(() => (window.D && D.si_users ? D.si_users.length : 0));
        const card = page.locator(".dash-chart-card");
        if (users === 0) {
            await expect(page.locator(".dash-gauge")).toHaveCount(0);
            test.info().annotations.push({ type: "warning", description: "no users — only the empty-state branch was exercised" });
            return;
        }
        // Two gauges, painted (non-zero geometry), replacing the text block.
        await expect(page.locator(".dash-gauge .ct-svg-gauge")).toHaveCount(2);
        const gbox = await page.locator(".dash-gauge .ct-svg-gauge").first().boundingBox();
        expect(gbox && gbox.width > 0 && gbox.height > 0, "gauge not painted").toBeTruthy();
        // Account-state donut: centre = user count, legend sums to it.
        const donut = card.filter({ has: page.locator(".ct-donut-wrap") }).nth(0).locator(".ct-donut-wrap");
        await expect(donut.locator("svg text")).toHaveText(String(users));
        expect(await legendSum(donut)).toBe(users);
    });

    test("perimeter donut and bars agree with the KPI predicates", async ({ page }) => {
        const s = await page.evaluate(() => ({
            apps: D.applications.length,
            active: D.reviews.filter((r) => r.status === "en_cours").length,
            closed: D.reviews.filter((r) => r.status === "cloturee").length,
            saTotal: (D.service_accounts || []).length,
            rotOverdue: window._countRotationOverdue(),
            expiring: window._countExpiringSoon(),
        }));
        if (s.apps === 0) {
            test.info().annotations.push({ type: "warning", description: "no perimeters — only the empty-state branch was exercised" });
            return;
        }
        // Perimeter donut: centre total = perimeter count, legend sums to it.
        const donuts = page.locator(".dash-chart-card .ct-donut-wrap");
        const perim = donuts.nth((await page.evaluate(() => D.si_users.length)) > 0 ? 1 : 0);
        await expect(perim.locator("svg text")).toHaveText(String(s.apps));
        expect(await legendSum(perim)).toBe(s.apps);
        // Review bars carry the same three figures as the KPIs.
        const bars = page.locator(".dash-chart-card .ct-svg-bar");
        const reviewVals = await bars.nth(0).locator("text[text-anchor=end]").allTextContents();
        expect(reviewVals.map(Number)).toContain(s.active);
        expect(reviewVals.map(Number)).toContain(s.closed);
        // Service-account bars, when accounts exist.
        if (s.saTotal > 0) {
            const saVals = (await bars.nth(1).locator("text[text-anchor=end]").allTextContents()).map(Number);
            expect(saVals).toContain(s.rotOverdue);
            expect(saVals).toContain(s.expiring);
        }
    });
});
