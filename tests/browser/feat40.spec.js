// FEAT-40 — the anti-duplicate guarantees, locked down from the browser.
//
// HERMETIC: a write fence intercepts the WHOLE API — GETs pass through (the
// app loads the real data), writes are absorbed (200 {ok:true}) and the AI
// endpoints are stubbed. Nothing touches the database: the first version of
// this spec wrote into real dev data, that is the lesson. The AI provider is
// never called — what is tested is what the frontend SENDS (the
// include_existing_measures intent) and what it DOES with an enrich response
// (preserve the existing content), not the model.
//
// Three behaviours, each one paid for by a finding of the 2026-09-02 review.
// Prerequisites: stack running + `bash mint-tokens.sh` (cf. console.spec.js).
const fs = require("fs");
const path = require("path");
const { test, expect } = require("@playwright/test");

const PROXY = (process.env.E2E_PROXY || "https://localhost:8443").replace(/\/+$/, "");
const TOKENS_FILE = path.join(__dirname, "tokens.json");
const TOKENS = fs.existsSync(TOKENS_FILE)
    ? JSON.parse(fs.readFileSync(TOKENS_FILE, "utf8")) : {};

const IS_LOCAL = /^https?:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/.test(PROXY);
if (!IS_LOCAL && process.env.E2E_ALLOW_REMOTE !== "1") {
    throw new Error(`E2E_PROXY pointe vers ${PROXY} — voir console.spec.js.`);
}

const ANCIEN_DETAILS = "MFA active sur les portails web.";
const AJOUT = "Étendre la couverture aux comptes de service.";

// Write fence + AI stub. `aiHandler` receives the body of the intercepted AI
// request and returns the JSON to serve.
async function fence(page, aiPattern, aiHandler) {
    await page.route("**/api/**", async (route) => {
        const req = route.request();
        if (aiPattern.test(req.url())) {
            return route.fulfill({ json: aiHandler(req.postDataJSON()) });
        }
        if (req.method() === "GET") return route.continue();
        return route.fulfill({ json: { ok: true } });   // write absorbed
    });
}

function enableAi(page, pfx) {
    // Direct mode (enabled + apikey) as well as managed mode (enabled +
    // can_use admin): the dummy key goes nowhere, everything is intercepted.
    return page.addInitScript(([p]) => {
        localStorage.setItem(p + "_ai_enabled", "true");
        localStorage.setItem(p + "_ai_apikey", "e2e-intercepted");
    }, [pfx]);
}

async function openModule(page, module, pfx) {
    const token = TOKENS[module];
    expect(token, `no session token for ${module} — run mint-tokens.sh`).toBeTruthy();
    await page.context().addCookies([{
        name: `${module}_token`, value: token, domain: "localhost", path: "/",
    }]);
    await enableAi(page, pfx);
    await page.goto(`${PROXY}/${module}/`, { waitUntil: "networkidle" });
}

// Seeds a measure through the app's own seams, in a single evaluate (no stale
// locator: every _updateFieldFromEl re-renders the table). Risk's `let D` is
// not on window; addRow and _updateFieldFromEl are function declarations, so
// they are exposed. Returns the generated id, read from the re-rendered DOM —
// never assumed.
async function seedRiskMeasure(page, details) {
    await page.locator('[data-click="selectPanel"][data-args*="measures"]').first().click();
    await page.waitForTimeout(300);
    const id = await page.evaluate((det) => {
        window.addRow("measures");
        let inputs = document.querySelectorAll('input[data-s="measures"][data-f="mesure"]');
        let el = inputs[inputs.length - 1];
        el.value = "MFA généralisée";
        window._updateFieldFromEl(el);
        const tas = document.querySelectorAll('textarea[data-s="measures"][data-f="details"]');
        const ta = tas[tas.length - 1];
        ta.value = det;
        window._updateFieldFromEl(ta);
        inputs = document.querySelectorAll('input[data-s="measures"][data-f="mesure"]');
        const tr = inputs[inputs.length - 1].closest("tr");
        const m = tr && tr.textContent.match(/(?:MES|M)-\d+/g);
        return m ? m[m.length - 1] : null;
    }, details);
    expect(id, "id de la mesure semée introuvable dans le tableau").toBeTruthy();
    return id;
}

const suggestions = (id) => [
    { action: "enrich", id, mesure: "MFA généralisée", details: AJOUT,
      type: "Prévention" },
    { action: "new", mesure: "Journalisation centralisée",
      details: "Collecter les journaux d'authentification.", type: "Détection" },
];

test.describe("risk — FEAT-40", () => {
    test("la case décochée retire le contexte de la requête, pas seulement de l'écran", async ({ page }) => {
        await openModule(page, "risk", "ebios");
        const bodies = [];
        await fence(page, /\/api\/ai\/risk\/suggest$/, (body) => {
            bodies.push(body);
            return { result: suggestions("M-01") };
        });
        const id = await seedRiskMeasure(page, ANCIEN_DETAILS);
        expect(id).toBeTruthy();

        await page.locator('#toggles-measures [data-click="suggestFor"]').click();
        await expect(page.locator("#ai-include-measures")).toBeChecked();

        // 1st send: box checked (the default) → the intent goes out as true.
        await page.locator('[data-click="_aiRunSuggest"]').first().click();
        await expect.poll(() => bodies.length).toBe(1);
        expect(bodies[0].include_existing_measures).toBe(true);

        // 2nd send: box unchecked — verified on the REQUEST that went out, not
        // on the state of the box (acceptance criterion 8 of the spec).
        await page.evaluate(() => window._aiClosePanel());
        await page.locator('#toggles-measures [data-click="suggestFor"]').click();
        await page.locator("#ai-include-measures").uncheck();
        await page.locator('[data-click="_aiRunSuggest"]').first().click();
        await expect.poll(() => bodies.length).toBe(2);
        expect(bodies[1].include_existing_measures).toBe(false);
    });

    test("accepter un enrich ÉTEND details — l'ancien texte survit", async ({ page }) => {
        await openModule(page, "risk", "ebios");
        let seededId = null;
        await fence(page, /\/api\/ai\/risk\/suggest$/, () =>
            ({ result: suggestions(seededId) }));
        seededId = await seedRiskMeasure(page, ANCIEN_DETAILS);

        await page.locator('#toggles-measures [data-click="suggestFor"]').click();
        await page.locator('[data-click="_aiRunSuggest"]').first().click();

        // The enrich card carries the « mise à jour » badge and the preview.
        const card = page.locator(".ai-card", { hasText: seededId }).first();
        await expect(card).toBeVisible();
        await card.locator(".ai-btn-accept").click();
        await page.waitForTimeout(400);

        // The state is verified in the re-rendered TABLE, not in a variable.
        await page.evaluate(() => window._aiClosePanel());
        await page.locator('[data-click="selectPanel"][data-args*="measures"]').first().click();
        const details = await page.locator('textarea[data-s="measures"][data-f="details"]').last().inputValue();
        expect(details).toContain(ANCIEN_DETAILS);   // the existing text survives
        expect(details).toContain(AJOUT);            // the addition is there
    });
});

test.describe("vendor — FEAT-40", () => {
    test("la case du flux mesures-par-risque est honorée (elle était lue après le vidage du panneau)", async ({ page }) => {
        await openModule(page, "vendor", "tprm");
        const bodies = [];
        await fence(page, /\/api\/ai\/vendor\/suggest-measures$/, (body) => {
            bodies.push(body);
            return { result: [{ action: "new",
                mesure: "Clause de réversibilité MedSecure Cloud",
                details: "Prévoir la sortie.", type: "Contractuelle" }] };
        });

        // Vendor + risk seeded into the state (var D is on window on the
        // Vendor side). The fence absorbs the POSTs: nothing reaches the DB.
        await page.evaluate(() => {
            const v = { id: "PP-901", name: "MedSecure Cloud", status: "active",
                        sector: "Santé", measures: [], certifications: [] };
            window.D.vendors.push(v);
            window._persistCreate("vendor", v);
            const r = { id: "R-901", vendor_id: "PP-901", title: "Défaillance hébergeur",
                        category: "OPS", impact: 4, likelihood: 3, status: "active" };
            window.D.risks.push(r);
            window._persistCreate("risk", r);
        });

        // openAiRiskAssistant renders the box + the « générer des mesures » button.
        // Closing the panel does not destroy the box (only the .open class is
        // removed): _aiShowLoading was the one replacing it — the original bug.
        await page.evaluate(() => {
            const idx = window.D.vendors.findIndex((v) => v.id === "PP-901");
            window.openAiRiskAssistant(idx);
        });
        const box = page.locator("#ai-include-measures").first();
        await expect(box).toBeChecked();
        await box.uncheck();
        await page.locator('[data-click="aiRunMeasureSuggestion"]').first().click();
        await expect.poll(() => bodies.length).toBe(1);
        expect(bodies[0].include_existing_measures).toBe(false);
    });
});
