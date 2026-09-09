// Shared test base for the browser suite: every spec imports `test` from here,
// never from @playwright/test directly.
//
// Two guards, both paid for by an incident:
//   - LOCAL ONLY: the suite mints admin sessions by borrowing signing keys, so
//     it refuses any proxy whose host is not localhost unless E2E_ALLOW_REMOTE=1.
//   - WRITE FENCE by default: GET/HEAD/OPTIONS reach the stack (the app loads
//     real data), every other request to /api/ issued by the page is absorbed
//     with 200 {ok:true, fenced:true}. The first FEAT-40 spec wrote measures
//     and a vendor into the dev database; nothing a spec does by accident can
//     reach the database any more. The page is sent to about:blank before the
//     fixture is torn down, so an unload-time flush (Risk's keepalive PUT on
//     pagehide) fires while the fence is still alive and is absorbed too.
//
// What the fence does NOT cover: requests outside /api/ (e.g. /auth/logout),
// pages opened with window.open, and page.request/context.request calls —
// none of which the suite uses today. A spec that must really write opts in with
//     test.use({ allowWrites: true });
// and then needs E2E_PROJECT_ID (the dedicated MedSecure test project): only
// requests whose URL path carries that id as a segment, or whose JSON body
// says "project_id": "<id>", go through. Every absorbed write is recorded in
// the `fencedWrites` fixture so an opted-in spec can assert nothing it needed
// was silently swallowed:  expect(fencedWrites).toEqual([]).
const fs = require("fs");
const path = require("path");
const { test: base, expect } = require("@playwright/test");

const PROXY = (process.env.E2E_PROXY || "https://localhost:8443").replace(/\/+$/, "");
let proxyHost = "";
try { proxyHost = new URL(PROXY).hostname; } catch (_) { proxyHost = ""; }
const IS_LOCAL = proxyHost === "localhost" || proxyHost === "127.0.0.1";
if (!IS_LOCAL && process.env.E2E_ALLOW_REMOTE !== "1") {
    throw new Error(`E2E_PROXY points at ${PROXY} — this suite only runs against a local stack (E2E_ALLOW_REMOTE=1 to override).`);
}

const TOKENS_FILE = path.join(__dirname, "tokens.json");
const TOKENS = fs.existsSync(TOKENS_FILE)
    ? JSON.parse(fs.readFileSync(TOKENS_FILE, "utf8")) : {};

// Pilot is served at the proxy root; the others under /<module>/.
const urlOf = (m) => (m === "pilot" ? PROXY + "/" : `${PROXY}/${m}/`);

const READ_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function targetsProject(req, projectId) {
    let segments = [];
    try { segments = new URL(req.url()).pathname.split("/"); } catch (_) { /* absorbed below */ }
    if (segments.includes(projectId)) return true;
    const body = req.postData() || "";
    return new RegExp(`"project_id"\\s*:\\s*"${projectId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`).test(body);
}

const test = base.extend({
    allowWrites: [false, { option: true }],
    fencedWrites: async ({}, use) => { await use([]); },
    page: async ({ page, allowWrites, fencedWrites }, use) => {
        const projectId = process.env.E2E_PROJECT_ID || "";
        if (allowWrites && !projectId) {
            throw new Error("allowWrites needs E2E_PROJECT_ID — the dedicated MedSecure test project, never the dev data.");
        }
        await page.route("**/api/**", (route) => {
            const req = route.request();
            if (READ_METHODS.has(req.method())) return route.continue();
            if (allowWrites && targetsProject(req, projectId)) return route.continue();
            fencedWrites.push(`${req.method()} ${req.url()}`);
            return route.fulfill({ status: 200, json: { ok: true, fenced: true } });
        });
        await use(page);
        // Unload while the route is still installed: pagehide flushes are fenced.
        await page.goto("about:blank").catch(() => {});
    },
});

module.exports = { test, expect, PROXY, TOKENS, urlOf };
