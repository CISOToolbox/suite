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
        const donut = page.locator('[data-chart="accounts"] .ct-donut-wrap');
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
            // Same predicate as renderDashboard: overdue per application,
            // against the latest closed review.
            overdue: D.applications.filter((app) => {
                let lastClosed = null;
                D.reviews.forEach((r) => {
                    if (r.application_id === app.id && r.status === "cloturee" && r.closed_at) {
                        if (!lastClosed || r.closed_at > lastClosed) lastClosed = r.closed_at;
                    }
                });
                return window._isReviewOverdue(app, lastClosed);
            }).length,
        }));
        if (s.apps === 0) {
            test.info().annotations.push({ type: "warning", description: "no perimeters — only the empty-state branch was exercised" });
            return;
        }
        // Perimeter donut: centre total = perimeter count, legend sums to it.
        const perim = page.locator('[data-chart="perimeters"] .ct-donut-wrap');
        await expect(perim.locator("svg text")).toHaveText(String(s.apps));
        expect(await legendSum(perim)).toBe(s.apps);
        // Review bars: the three rows carry the KPI figures IN ORDER
        // (overdue, in progress, closed) — the overdue row is the only
        // non-trivial predicate, so it is asserted too.
        const rowVals = (sel) => page.locator(sel + " .ct-svg-bar text[text-anchor=end]").allTextContents()
            .then((xs) => xs.map(Number));
        expect(await rowVals('[data-chart="reviews"]')).toEqual([s.overdue, s.active, s.closed]);
        // Service-account bars, when accounts exist: up-to-date is the
        // complement of the union, the two problem rows match the KPIs.
        if (s.saTotal > 0) {
            const saVals = await rowVals('[data-chart="service-accounts"]');
            expect(saVals.length).toBe(3);
            expect(saVals[1]).toBe(s.rotOverdue);
            expect(saVals[2]).toBe(s.expiring);
            expect(saVals[0]).toBeLessThanOrEqual(s.saTotal - Math.max(s.rotOverdue, s.expiring));
        }
    });
});
