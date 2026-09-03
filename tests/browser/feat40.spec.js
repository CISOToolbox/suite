// FEAT-40 — les garanties anti-doublon, verrouillées côté navigateur.
//
// HERMÉTIQUE : une barrière d'écriture intercepte TOUTE l'API — les GET
// passent (l'app charge les vraies données), les écritures sont absorbées
// (200 {ok:true}) et les endpoints IA sont simulés. Rien ne touche la base :
// la première version de ce spec a écrit dans les données de dev réelles,
// c'est la leçon. Le fournisseur IA n'est jamais appelé — on teste ce que le
// frontend ENVOIE (l'intention include_existing_measures) et ce qu'il FAIT
// d'une réponse enrich (préserver l'existant), pas le modèle.
//
// Trois comportements, chacun payé par un constat de la revue du 2026-09-02.
// Prérequis : stack en marche + `bash mint-tokens.sh` (cf. console.spec.js).
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

// Barrière d'écriture + simulation IA. `aiHandler` reçoit le corps de la
// requête IA intercepée et rend le JSON à servir.
async function fence(page, aiPattern, aiHandler) {
    await page.route("**/api/**", async (route) => {
        const req = route.request();
        if (aiPattern.test(req.url())) {
            return route.fulfill({ json: aiHandler(req.postDataJSON()) });
        }
        if (req.method() === "GET") return route.continue();
        return route.fulfill({ json: { ok: true } });   // écriture absorbée
    });
}

function enableAi(page, pfx) {
    // Direct (enabled + apikey) comme administré (enabled + can_use admin) :
    // la clé factice ne part nulle part, tout est intercepté.
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

// Sème une mesure par les seams de l'app, en un seul evaluate (pas de
// localisateur périmé : chaque _updateFieldFromEl re-rend le tableau).
// `let D` de Risk n'est pas sur window ; addRow et _updateFieldFromEl sont
// des déclarations de fonction, donc exposées. Rend l'id généré, lu dans le
// DOM re-rendu — jamais supposé.
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

        // 1er envoi : case cochée (défaut) → l'intention part à true.
        await page.locator('[data-click="_aiRunSuggest"]').first().click();
        await expect.poll(() => bodies.length).toBe(1);
        expect(bodies[0].include_existing_measures).toBe(true);

        // 2e envoi : case décochée — vérifié sur la REQUÊTE émise, pas sur
        // l'état de la case (critère d'acceptation 8 de la spec).
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

        // La carte enrich porte le badge « mise à jour » et l'aperçu.
        const card = page.locator(".ai-card", { hasText: seededId }).first();
        await expect(card).toBeVisible();
        await card.locator(".ai-btn-accept").click();
        await page.waitForTimeout(400);

        // L'état vérifié dans le TABLEAU re-rendu, pas dans une variable.
        await page.evaluate(() => window._aiClosePanel());
        await page.locator('[data-click="selectPanel"][data-args*="measures"]').first().click();
        const details = await page.locator('textarea[data-s="measures"][data-f="details"]').last().inputValue();
        expect(details).toContain(ANCIEN_DETAILS);   // l'existant survit
        expect(details).toContain(AJOUT);            // l'ajout est là
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

        // Vendor + risque semés dans l'état (var D est sur window côté
        // Vendor). La barrière absorbe les POST : rien n'atteint la base.
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

        // openAiRiskAssistant rend la case + le bouton « générer des mesures ».
        // Fermer le panneau ne détruit pas la case (classe .open retirée
        // seulement) : c'est _aiShowLoading qui la remplaçait — le bug d'origine.
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
