# Browser tests — suite

What these tests look at, and nothing else can see: **what happens between the
click and the screen**. A JavaScript exception that breaks half a panel still
leaves the server answering 200; neither the unit tests nor the HTTP posture
(`tests/run-posture.sh`) can notice it.

Not to be confused with the browser-local web apps' own end-to-end suites,
which serve a static application without a backend. This suite targets the
suite stack behind its proxy, with a session.

## Running

```bash
bash mint-tokens.sh     # one session per module, in tokens.json (gitignored)
npx playwright test     # all 10 modules
npx playwright test --grep "risk —"
npx playwright test --headed        # to watch
```

The stack must be running. `mint-tokens.sh` fails if no token could be minted,
rather than writing an empty file that would let the suite pass vacuously.

## How the session is obtained

Each module signs with its own key, hence one token per module. The account is
**discovered** in Pilot's directory, never hard-coded: a valid JWT is not
enough — `_is_active_upstream` asks Pilot whether the account is active and
refuses any email it does not know. An account present only in one module's
database is therefore unusable.

Pilot has its own `src/auth.py`, whose `create_jwt` also takes the list of
modules; the nine others go through `src/auth_common.py`.

## What the walk does

Opens each module, then **walks every navigation entry**, failing on the first
console error, exception, failed request or response ≥ 400 — on load and after
each click.

Three things learnt while writing it, which explain the code:

- **Entries are identified by their `data-args`**, never by index or text. The
  index breaks because a first click re-renders the navigation and shortens it
  (Surface); the text breaks because it contains dynamic content — "ANSSI
  Hygiène 38% 16 OK 26 KO" changes between two renders.
- **A click is retried once**, re-resolving the locator: selecting a panel
  re-renders the navigation, so the node found is not always the one that
  receives the click. Without this, one run in three failed — and an unstable
  browser suite ends up ignored, which is worse than no suite.
- **A 404 response does not trigger `requestfailed`**: the request completed,
  with a bad status. Hence the separate `response` listener.

## The exclusion list

`IGNORED`, in `console.spec.js`. Every entry must say **why**: an unjustified
list ends up containing everything, and the test no longer looks at anything.

It currently holds two entries, both specific to the local environment: the
missing favicon and the proxy's self-signed certificate.

## Safety of the campaign

These tests open **administrator sessions**. Three properties make them safe,
and must be preserved:

**No credential exists.** `mint-tokens.sh` borrows the signing key from inside
the container (`docker exec`). It creates no account, stores no password, calls
no login route. Whoever can run that `docker exec` already controls the process
and its database: the mechanism gives nothing more and is not exploitable
remotely.

**The account is discovered, never hard-coded** — the first administrator of
Pilot's directory. A dedicated account belongs to a CI stack with its own
directory, never to a production directory.

**The refusal is explicit.** The suite stops if `E2E_PROXY` is not local,
unless `E2E_ALLOW_REMOTE=1`. A misconfigured CI therefore cannot mint
administrator sessions against an environment holding real data.

`tokens.json` is mode `600` and gitignored. It stays valid for
`JWT_EXPIRY_HOURS` (24 h by default): deleting it after the campaign
(`rm tokens.json`) is the right habit.

## The write fence

`fixtures.js` is where every spec imports `test` from, and the only place the
guards each spec used to copy live (proxy, tokens, `urlOf`):

- **local only** — any proxy whose host is not `localhost` is refused
  (`E2E_ALLOW_REMOTE=1` to override, knowingly);
- **write fence by default** — `GET`, `HEAD` and `OPTIONS` reach the stack;
  every other request to `/api/` issued by the page is absorbed
  (`200 {ok:true, fenced:true}`). The page is sent to `about:blank` before the
  test ends, so unload-time flushes (Risk sends a `keepalive` `PUT` on
  `pagehide`) are absorbed too. The first version of one spec wrote measures
  and a vendor into a development database; since then nothing a spec does by
  accident on `/api/` reaches it.

What the fence does not cover: routes outside `/api/` (`/auth/logout`), windows
opened with `window.open`, and `page.request` — no spec uses them. Absorbed
responses carry no `id`: the suite assumes an **already seeded** stack (a
module creating its first project on load fails loudly, by design).

A spec that must really write says so (`test.use({ allowWrites: true })`) and
requires `E2E_PROJECT_ID`, the dedicated test project: only requests whose path
carries that id as a segment, or whose JSON body says `"project_id": "<id>"`,
go through. Absorbed writes are recorded in the `fencedWrites` fixture: an
opted-in spec asserts `expect(fencedWrites).toEqual([])` so it cannot pass by
accident.

## What the first run found

- `cisotoolbox.css` declared seven `@font-face` rules pointing at files that
  existed nowhere. Fixed: the five faces in use are now shipped with the
  design system.
- Pilot loaded the user's avatar from the identity provider in the permissions
  table. The CSP blocked it, so the image never showed; what remained was a
  request to the IdP from the administrator's browser at every render. Fixed —
  only images served by the suite are rendered.
