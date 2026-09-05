// FEAT-43 — the Asset dashboard renders its charts.
//
// Asserts the two additions of the feature and their CONSISTENCY with the
// data, not just their presence:
//   - the type donut: centre total = number of table rows on the Assets page,
//     and the legend counts sum to that same total (no asset silently dropped
//     by an unknown type value);
//   - the deadlines timeline: rendered only when the deadlines list has
//     entries, with one dot per event (max 8).
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

test.describe("asset dashboard charts (FEAT-43)", () => {
    test.beforeEach(async ({ page }) => {
        const token = TOKENS.asset;
        expect(token, "no session token for asset — run mint-tokens.sh").toBeTruthy();
        await page.context().addCookies([{
            name: "asset_token", value: token,
            domain: "localhost", path: "/",
        }]);
        await page.goto(`${PROXY}/asset/`, { waitUntil: "networkidle" });
    });

    test("type donut totals match the asset count", async ({ page }) => {
        // Asset count read from the app state — the dashboard must agree with it.
        const assetCount = await page.evaluate(() => (window.D && D.assets ? D.assets.length : 0));
        const donut = page.locator(".dash-section .ct-donut-wrap");

        if (assetCount === 0) {
            // Visible in the report, not a silent green: the chart path was
            // NOT exercised on this run (empty dataset).
            await expect(donut).toHaveCount(0);
            test.info().annotations.push({ type: "warning", description: "empty dataset — only the empty-state branch was exercised" });
            return;
        }
        await expect(donut).toHaveCount(1);
        // Centre label = total number of assets.
        await expect(donut.locator("svg text")).toHaveText(String(assetCount));
        // Legend counts sum to the same total: an unknown type value must be
        // charted, not dropped.
        const legendSum = await donut.locator(".ct-donut-legend-item strong")
            .allTextContents()
            .then((xs) => xs.reduce((a, x) => a + parseInt(x, 10), 0));
        expect(legendSum).toBe(assetCount);
        // The color chip must actually be painted: a 0×0 chip means the module
        // lost the donut styles (review finding — they now live in the shared
        // stylesheet, not per module).
        const box = await donut.locator(".ct-donut-dot").first().boundingBox();
        expect(box && box.width > 0 && box.height > 0,
            "legend color chip has no size — donut CSS missing").toBeTruthy();
        // The old hand-rolled bars are gone.
        await expect(page.locator(".type-breakdown, .type-bar-row")).toHaveCount(0);
    });

    test("deadlines timeline mirrors the deadlines list", async ({ page }) => {
        // The list rows are the existing top-6 rendering; the timeline shows
        // the 8 nearest events. Both come from _echeances(), so: list present
        // ⇔ timeline present, and the timeline carries min(8, total) dots.
        const listRows = await page.locator('.dash-section [data-click="openEcheanceAsset"]').count();
        const timeline = page.locator(".dash-section .ct-svg-timeline");
        if (listRows === 0) {
            await expect(timeline).toHaveCount(0);
            test.info().annotations.push({ type: "warning", description: "no deadlines — only the empty-state branch was exercised" });
            return;
        }
        await expect(timeline).toHaveCount(1);
        const total = await page.evaluate(() => (window._echeances ? window._echeances().length : 0));
        await expect(timeline.locator("circle")).toHaveCount(Math.min(8, total));
    });
});
