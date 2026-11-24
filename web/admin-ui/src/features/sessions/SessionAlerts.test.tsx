import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Api } from "../../shared/api";
import { SignedInContext } from "../../shared/session";
import { fakeApi } from "../../test-helpers";
import { SessionAlerts } from "./SessionAlerts";

const alert = {
  id: "alert_0123456789abcdef0123456789abcdef",
  rule_id: "session.secret_injection_failed",
  rule_version: "1",
  source_event_id: "evt_0123456789abcdef0123456789abcdef",
  session_id: "sess_alert",
  severity: "high",
  status: "unacknowledged",
  summary: "Échec d'injection du secret",
  detected_at: "2026-11-24T10:00:00Z",
  created_at: "2026-11-24T10:00:00Z",
  revision: 7,
};
const page = { alerts: [alert], has_more: false };
const summary = {
  unacknowledged_count: 1,
  by_severity: { info: 0, low: 0, medium: 0, high: 1, critical: 0 },
  as_of: "2026-11-24T10:00:00Z",
  durable: true,
};

function show(api: Api) {
  return render(
    <SignedInContext.Provider value={{ api, who: null, signOut: () => undefined }}>
      <SessionAlerts />
    </SignedInContext.Provider>,
  );
}

describe("SessionAlerts", () => {
  it("filters the public queue and follows the opaque next cursor", async () => {
    const { api, calls } = fakeApi({
      "GET /session-alerts": { body: { ...page, has_more: true, next_cursor: "cursor-next" } },
      "GET /session-alerts/summary": { body: summary },
    });
    show(api);
    expect(await screen.findByText("Échec d'injection du secret")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Sévérité"), { target: { value: "high" } });
    fireEvent.click(screen.getByRole("button", { name: "Filtrer" }));
    await waitFor(() => expect(calls.some((call) => call.path.includes("severity=high"))).toBe(true));
    fireEvent.click(screen.getByRole("button", { name: "Page suivante" }));
    await waitFor(() => expect(calls.some((call) => call.path.includes("cursor=cursor-next"))).toBe(true));
  });

  it("does not send an acknowledgement when the operator cancels confirmation", async () => {
    const { api, calls } = fakeApi({
      "GET /session-alerts": { body: page },
      "GET /session-alerts/summary": { body: summary },
      "POST /session-alerts/alert_0123456789abcdef0123456789abcdef/acknowledge": { body: {} },
    });
    show(api);
    await screen.findByText("Échec d'injection du secret");
    fireEvent.click(screen.getByRole("button", { name: "Acquitter" }));
    expect(screen.getByRole("alertdialog")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Annuler" }));
    expect(calls.some((call) => call.method === "POST")).toBe(false);
  });

  it("acknowledges with the displayed revision and refreshes the queue and summary", async () => {
    const { api, calls } = fakeApi({
      "GET /session-alerts": { body: page },
      "GET /session-alerts/summary": { body: summary },
      "POST /session-alerts/alert_0123456789abcdef0123456789abcdef/acknowledge": { body: { id: alert.id, status: "acknowledged", revision: 8, acknowledged_at: "2026-11-24T10:01:00Z", acknowledged_by: "operator", acknowledgement_event_id: "evt_ack" } },
    });
    show(api);
    await screen.findByText("Échec d'injection du secret");
    fireEvent.click(screen.getByRole("button", { name: "Acquitter" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirmer l'acquittement" }));
    await screen.findByText(/Alerte alert_0123456789abcdef0123456789abcdef acquittée/);
    const request = calls.find((call) => call.method === "POST");
    expect(request?.body).toEqual({ expected_revision: 7 });
    await waitFor(() => expect(calls.filter((call) => call.method === "GET" && call.path.startsWith("/session-alerts?")).length).toBe(2));
    expect(calls.filter((call) => call.method === "GET" && call.path === "/session-alerts/summary")).toHaveLength(2);
  });

  it("keeps the confirmation open and shows the server 403 when acknowledgement is denied", async () => {
    const { api } = fakeApi({
      "GET /session-alerts": { body: page },
      "GET /session-alerts/summary": { body: summary },
      "POST /session-alerts/alert_0123456789abcdef0123456789abcdef/acknowledge": { status: 403, body: "permission denied" },
    });
    show(api);
    await screen.findByText("Échec d'injection du secret");
    fireEvent.click(screen.getByRole("button", { name: "Acquitter" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirmer l'acquittement" }));
    expect((await screen.findByRole("alert")).textContent).toContain("403 — permission denied");
    expect(screen.getByRole("alertdialog")).toBeTruthy();
  });

  it("keeps the alert unacknowledged and reports 503 when the audit dependency is unavailable", async () => {
    const { api, calls } = fakeApi({
      "GET /session-alerts": { body: page },
      "GET /session-alerts/summary": { body: summary },
      "POST /session-alerts/alert_0123456789abcdef0123456789abcdef/acknowledge": { status: 503, body: "audit unavailable" },
    });
    show(api);
    await screen.findByText("Échec d'injection du secret");
    fireEvent.click(screen.getByRole("button", { name: "Acquitter" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirmer l'acquittement" }));
    expect((await screen.findByRole("alert")).textContent).toContain("503 — audit unavailable");
    expect(screen.getByRole("alertdialog")).toBeTruthy();
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(1);
    expect(calls.filter((call) => call.method === "GET" && call.path.startsWith("/session-alerts?")).length).toBe(1);
  });

  it("renders untrusted alert summaries as text rather than HTML", async () => {
    const hostilePage = { alerts: [{ ...alert, summary: '<img src=x onerror="alert(1)">' }], has_more: false };
    const { api } = fakeApi({
      "GET /session-alerts": { body: hostilePage },
      "GET /session-alerts/summary": { body: summary },
    });
    show(api);
    expect(await screen.findByText('<img src=x onerror="alert(1)">')).toBeTruthy();
    expect(document.querySelector("img[src='x']")).toBeNull();
  });

  it("refreshes after a 409 revision conflict without retrying the stale revision", async () => {
    const { api, calls } = fakeApi({
      "GET /session-alerts": { body: page },
      "GET /session-alerts/summary": { body: summary },
      "POST /session-alerts/alert_0123456789abcdef0123456789abcdef/acknowledge": { status: 409, body: "stale revision" },
    });
    show(api);
    await screen.findByText("Échec d'injection du secret");
    fireEvent.click(screen.getByRole("button", { name: "Acquitter" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirmer l'acquittement" }));
    expect((await screen.findByRole("alert")).textContent).toContain("409 — stale revision");
    await waitFor(() => expect(calls.filter((call) => call.method === "GET" && call.path.startsWith("/session-alerts?")).length).toBe(2));
    expect(calls.filter((call) => call.method === "POST")).toHaveLength(1);
  });

  it("surfaces 503 without treating the queue as empty or confirming an acknowledgement", async () => {
    const { api } = fakeApi({
      "GET /session-alerts": { status: 503, body: "audit unavailable" },
      "GET /session-alerts/summary": { status: 503, body: "audit unavailable" },
    });
    show(api);
    expect((await screen.findByRole("alert")).textContent).toContain("503 — audit unavailable");
    expect(screen.queryByText("Aucune alerte ne correspond à ces filtres.")).toBeNull();
  });
});
