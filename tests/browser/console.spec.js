// Aucune erreur console, nulle part — au chargement ET pendant la traversée.
//
// C'est le seul contrôle qui regarde ce qui se passe entre le clic et l'écran.
// Une exception JS qui casse la moitié d'un panneau laisse le serveur répondre
// 200 : ni les tests unitaires, ni la posture HTTP ne peuvent la voir. Le bug
// du toggle des critères ER de Risk (aria-pressed jamais mis à jour) vivait
// exactement dans cet angle mort.
//
// Prérequis : `bash mint-tokens.sh` (une session par module) et la stack en
// marche. Sans tokens.json, la suite échoue au lieu de passer à vide.
const fs = require("fs");
const path = require("path");
const { test, expect } = require("@playwright/test");

const PROXY = (process.env.E2E_PROXY || "https://localhost:8443").replace(/\/+$/, "");
const MODULES = ["access", "appsec", "asset", "audit", "compliance",
                 "pilot", "risk", "surface", "vendor", "watch"];

const TOKENS_FILE = path.join(__dirname, "tokens.json");
const TOKENS = fs.existsSync(TOKENS_FILE)
    ? JSON.parse(fs.readFileSync(TOKENS_FILE, "utf8")) : {};

// Pilot est servi à la racine du proxy ; les autres sous /<module>/.
const urlOf = (m) => (m === "pilot" ? PROXY + "/" : `${PROXY}/${m}/`);

// Bruit connu, sans rapport avec le code applicatif. Toute entrée ajoutée ici
// doit dire POURQUOI : une liste d'exclusions non justifiée finit par tout
// contenir, et le test ne regarde plus rien.
const IGNORED = [
    /favicon\.ico/i,                       // pas d'icône servie en local
    /net::ERR_CERT_AUTHORITY_INVALID/i,    // certificat auto-signé du proxy local
];

// Ces tests frappent des sessions administrateur en empruntant la cle de
// signature a l'interieur du conteneur. C'est sans danger en local — qui peut
// faire un `docker exec` controle deja le processus — mais il n'y a aucune
// raison de pointer une campagne de recette vers un environnement portant des
// donnees reelles. Le refus est explicite plutot que laisse au bon sens.
const IS_LOCAL = /^https?:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/.test(PROXY);
if (!IS_LOCAL && process.env.E2E_ALLOW_REMOTE !== "1") {
    throw new Error(
        `E2E_PROXY pointe vers ${PROXY}, qui n'est pas local. Ces tests ouvrent ` +
        `des sessions administrateur : lancez-les contre une stack de recette, ` +
        `ou forcez avec E2E_ALLOW_REMOTE=1 si vous savez ce que vous faites.`);
}

const isNoise = (text) => IGNORED.some((rx) => rx.test(text));

// Reprend une fois en re-resolvant le localisateur : la navigation se re-rend
// a chaque selection, donc l'element trouve n'est pas toujours celui qui recoit
// le clic.
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
            // Un asset qui répond 404 ne déclenche pas requestfailed : la requête
            // a abouti, avec un mauvais statut. C'est exactement la panne qu'on
            // vient de trouver sur ct_schema.js.
            page.on("response", (r) => {
                if (r.status() >= 400) note("http", `${r.status()} ${r.url()}`);
            });

            await page.goto(urlOf(module), { waitUntil: "networkidle" });
            expect(problems, `au chargement de ${module}`).toEqual([]);

            // La navigation est rendue en JS, jamais présente dans index.html :
            // on la découvre dans le DOM plutôt que de la coder en dur.
            const SEL = '[data-click="selectPanel"]';
            // Chaque entrée est identifiée par ses data-args (l'identifiant du
            // panneau), jamais par son index ni par son texte :
            //   - l'index casse parce qu'un premier clic re-rend la navigation
            //     et la raccourcit (Surface) ;
            //   - le texte casse parce qu'il contient du dynamique — « ANSSI
            //     Hygiène 38% 16 OK 26 KO » change entre deux rendus.
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
                // Selectionner un panneau re-rend la navigation : le noeud
                // resolu par le localisateur est detache avant que le clic
                // n'aboutisse. Sans cette reprise, le test echouait une fois
                // sur trois — et une suite navigateur instable finit ignoree,
                // ce qui est pire que pas de suite du tout.
                await clickStable(page, `${SEL}[data-args='${label}']`);
                await page.waitForTimeout(250);   // le rendu est synchrone, mais l'i18n est paresseuse
                expect(problems, `${module} — après « ${label} »`).toEqual([]);
            }
            // Une entrée devenue introuvable est signalée, jamais avalée : sans
            // cela, un panneau qui disparaît ferait baisser la couverture sans
            // que rien ne le dise.
            expect(unreachable, `${module} — entrées de navigation devenues introuvables`).toEqual([]);
        });
    }
});
