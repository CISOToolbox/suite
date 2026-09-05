// No console error, anywhere — on load AND while walking the navigation.
//
// This is the only check that looks at what happens between the click and the
// screen. A JS exception that breaks half a panel still leaves the server
// answering 200: neither the unit tests nor the HTTP posture can see it. The
// Risk ER-criteria toggle bug (aria-pressed never updated) lived exactly in
// that blind spot.
//
// Prerequisites: `bash mint-tokens.sh` (one session per module) and the stack
// running. Without tokens.json, the suite fails instead of passing vacuously.
const fs = require("fs");
const path = require("path");
const { test, expect } = require("@playwright/test");

const PROXY = (process.env.E2E_PROXY || "https://localhost:8443").replace(/\/+$/, "");
const MODULES = ["access", "appsec", "asset", "audit", "compliance",
                 "pilot", "risk", "surface", "vendor", "watch"];

const TOKENS_FILE = path.join(__dirname, "tokens.json");
const TOKENS = fs.existsSync(TOKENS_FILE)
    ? JSON.parse(fs.readFileSync(TOKENS_FILE, "utf8")) : {};

// Pilot is served at the proxy root; the others under /<module>/.
const urlOf = (m) => (m === "pilot" ? PROXY + "/" : `${PROXY}/${m}/`);

// Known noise, unrelated to the application code. Every entry added here must
// say WHY: an unjustified exclusion list ends up containing everything, and the
// test no longer looks at anything.
const IGNORED = [
    /favicon\.ico/i,                       // no icon served locally
    /net::ERR_CERT_AUTHORITY_INVALID/i,    // self-signed certificate of the local proxy
];

// These tests mint administrator sessions by borrowing the signing key from
// inside the container. That is harmless locally — whoever can run a
// `docker exec` already controls the process — but there is no reason to point
// an acceptance campaign at an environment holding real data. The refusal is
// explicit rather than left to common sense.
const IS_LOCAL = /^https?:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/.test(PROXY);
if (!IS_LOCAL && process.env.E2E_ALLOW_REMOTE !== "1") {
    throw new Error(
        `E2E_PROXY pointe vers ${PROXY}, qui n'est pas local. Ces tests ouvrent ` +
        `des sessions administrateur : lancez-les contre une stack de recette, ` +
        `ou forcez avec E2E_ALLOW_REMOTE=1 si vous savez ce que vous faites.`);
}

const isNoise = (text) => IGNORED.some((rx) => rx.test(text));

// Retries once by re-resolving the locator: the navigation re-renders on every
// selection, so the element that was found is not always the one that receives
// the click.
async function clickStable(page, selector) {
    for (let attempt = 0; attempt < 2; attempt++) {
        try {
            await page.locator(selector).first().click({ timeout: 5_000 });
            return;
        } catch (err) {
            if (attempt === 1) throw err;
            await page.waitForTimeout(300);
        }
    }
}

test.describe("erreurs console", () => {
    for (const module of MODULES) {
        test(`${module} — chargement et traversée de la navigation`, async ({ page }) => {
            const token = TOKENS[module];
            expect(token, `no session token for ${module} — run mint-tokens.sh`).toBeTruthy();

            await page.context().addCookies([{
                name: `${module}_token`, value: token,
                domain: "localhost", path: "/",
            }]);

            const problems = [];
            const note = (kind, text) => { if (!isNoise(text)) problems.push(`${kind}: ${text}`); };

            page.on("console", (m) => { if (m.type() === "error") note("console", m.text()); });
            page.on("pageerror", (e) => note("exception", e.message));
            page.on("requestfailed", (r) => {
                const f = r.failure();
                note("request", `${r.url()} — ${f ? f.errorText : "failed"}`);
            });
            // An asset answering 404 does not trigger requestfailed: the request
            // did succeed, with a bad status. That is exactly the failure we
            // have just found on ct_schema.js.
            page.on("response", (r) => {
                if (r.status() >= 400) note("http", `${r.status()} ${r.url()}`);
            });

            await page.goto(urlOf(module), { waitUntil: "networkidle" });
            expect(problems, `au chargement de ${module}`).toEqual([]);

            // The navigation is rendered in JS, never present in index.html:
            // we discover it in the DOM rather than hard-coding it.
            const SEL = '[data-click="selectPanel"]';
            // Each entry is identified by its data-args (the panel id), never
            // by its index nor by its text:
            //   - the index breaks because a first click re-renders the
            //     navigation and shortens it (Surface);
            //   - the text breaks because it holds dynamic parts — « ANSSI
            //     Hygiène 38% 16 OK 26 KO » changes between two renders.
            const panels = [...new Set(await page.locator(SEL).evaluateAll((els) =>
                els.map((e) => e.getAttribute("data-args")).filter(Boolean)))];
            expect(panels.length, `${module} n'expose aucune entrée de navigation`).toBeGreaterThan(0);

            const unreachable = [];
            for (const label of panels) {
                const entry = page.locator(`${SEL}[data-args='${label}']`).first();
                if ((await entry.count()) === 0 || !(await entry.isVisible())) {
                    unreachable.push(label);
                    continue;
                }
                // Selecting a panel re-renders the navigation: the node
                // resolved by the locator is detached before the click lands.
                // Without this retry, the test failed one run in three — and a
                // flaky browser suite ends up ignored, which is worse than
                // having no suite at all.
                await clickStable(page, `${SEL}[data-args='${label}']`);
                await page.waitForTimeout(250);   // the render is synchronous, but i18n is lazy
                expect(problems, `${module} — après « ${label} »`).toEqual([]);
            }
            // An entry that has become unreachable is reported, never
            // swallowed: without this, a panel that disappears would lower the
            // coverage without anything saying so.
            expect(unreachable, `${module} — entrées de navigation devenues introuvables`).toEqual([]);
        });
    }
});
