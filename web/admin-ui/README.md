# OpenBastion Admin UI (ADR-0036)

React and TypeScript, built by Vite, served by the API Gateway under `/ui/` — the same origin
as the public API, so that nothing is opened to another origin. It talks to the public API only
(`docs/api/rest/openapi.yaml`) and asks the services for nothing they do not already
answer.

```sh
(cd ../openbastion-icons && npm ci && npm run build) # local icon package
npm ci                                               # from package-lock.json, exact versions
npm test                                             # Vitest + Testing Library under jsdom
npm run build                                        # type check, then dist/ — what ADMIN_UI_DIR points to
```

Serve it locally: build, then start the Gateway with `ADMIN_UI_DIR=$PWD/web/admin-ui/dist` and
open `http://127.0.0.1:8080/ui/`.

What it does: local and federated login (OIDC return page at `/ui/oidc/callback`); privileged
accounts (list, onboard, rotate, disable); creating a policy; break-glass requests to decide,
a session by id, terminating it; reading back a recording. What it cannot do, because the API
cannot: list policies, list audit events.

Rules it keeps (tested): the token lives in memory only — reloading signs out; the OIDC code and
state are wiped from the address bar before they are sent; everything shown is text, never
markup; nothing is inlined into the page, which runs under `script-src 'self'`.

Dependencies: `react`, `react-dom`, and the local `@openbastion/icons` package at run time;
the icon package must be built before testing or building the UI. `npm audit`: 0 known
vulnerabilities on 30 October 2026.
