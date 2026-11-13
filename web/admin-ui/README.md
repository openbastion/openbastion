# OpenBastion Admin UI (ADR-0036)

React and TypeScript, built by Vite, served by the API Gateway under `/ui/` — the same origin
as the public API, so that nothing is opened to another origin. It talks to the public API only
(`docs/api/rest/openapi.yaml`) and asks the services for nothing they do not already
answer.

```sh
(cd ../packages/icons && npm ci && npm run build) # local icon package
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

The signed-in operator shell (ADR-0073 UX-01) groups only implemented screens in a collapsible
side navigation, adapts it to a keyboard-operable mobile panel, and provides light/dark themes.
The theme is an in-memory display preference; it is not persisted. A skip link, visible focus,
Escape-to-close behavior and focus restoration are part of the shell.

The command palette (ADR-0073 UX-02) opens from the header or with `Ctrl+K` / `Cmd+K`. It filters
implemented navigation destinations locally and can look up one session by its identifier through
`GET /sessions/{sessionId}`. The Gateway remains responsible for authorization and audit; refusals
are shown by the existing notice. The Accounts screen also filters the currently loaded API page
locally and states that scope explicitly. The palette does not search audit history, enumerate all
accounts, query OpenSearch, persist its input, or create a new API. Broader searches and server-side
filters remain unavailable until public API contracts exist. The UI still uses only the public
same-origin Gateway API and does not add runtime dependencies.

Rules it keeps (tested): the token lives in memory only — reloading signs out; the OIDC code and
state are wiped from the address bar before they are sent; everything shown is text, never
markup; nothing is inlined into the page, which runs under `script-src 'self'`.

The interface is multilingual (French and English) with `react-i18next`: every visible string
lives in `src/shared/i18n/locales/` (`fr.ts`, `en.ts`), French is the default and the fallback, and
a test checks that both files carry the same keys. The language selector in the header — and on the
login page, before any session — applies a language at once, without a reload, sets `<html lang>`
and remembers the choice per browser under `openbastion.admin-ui.language.v1` (a presentation
preference only, like the theme; it holds nothing about the account).

Dependencies: `react`, `react-dom`, `i18next`, `react-i18next`, and the local `@openbastion/icons`
package at run time;
the icon package must be built before testing or building the UI. `npm audit`: 0 known
vulnerabilities on 30 October 2026.


The PAM workflow screens (ADR-0073 UX-03) share translated, neutral-by-default session states,
explicit loading and empty states, and a confirmation dialog for secret rotation, account deactivation, approval,
rejection and session termination. The dialog names the affected resource and relevant request
context, explains the Vault reconciliation/verification flow for rotation and proxy revocation for
termination, supports Escape/cancel and focus return, and never sends the mutation before confirmation.
Termination copy explains that the Broker confirms only after proxy revocation; the UI does not
optimistically claim a session has ended. Recording reads show their session, command count, and
empty/loading states; command text remains escaped and paging remains tied to the session whose
recording was opened. Secrets remain write-only: this UX slice does not reveal or cache them.
