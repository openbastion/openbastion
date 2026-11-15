import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { SignedInContext } from "../../shared/session";
import { fakeApi } from "../../test-helpers";
import { SecretInjectionReconciliation } from "./SecretInjectionReconciliation";

const outcome = {
  injection_id: "0123456789abcdef0123456789abcdef",
  session_id: "session-1",
  account_id: "account-prod",
  protocol: "ssh",
  status: "outcome_unknown",
  reason: "missing_terminal_event",
  started_at: "2026-11-15T10:00:00Z",
};
const page = {
  outcomes: [outcome], coverage: "verified_archives_and_retained_chain",
  archived_history_excluded: false, scanned_events: 50, archived_events: 20,
  has_more: false,
};

function mount(routes: Record<string, { status?: number; body?: unknown }>) {
  const { api, calls } = fakeApi(routes);
  render(<SignedInContext.Provider value={{ api, who: null, signOut: () => {} }}><SecretInjectionReconciliation /></SignedInContext.Provider>);
  return calls;
}

describe("secret injection audit reconciliation (ADR-0113)", () => {
  it("shows verified metadata and warns on unknown outcomes without offering reinjection", async () => {
    const calls = mount({ "GET /audit/secret-injections?limit=100": { body: page } });
    fireEvent.click(screen.getByRole("button", { name: "Charger le rapprochement" }));
    expect(await screen.findByText("account-prod")).toBeTruthy();
    expect(screen.getByText("Résultat inconnu")).toBeTruthy();
    expect(screen.getByText(/Vérification manuelle de la cible requise/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /relancer|réinjecter/i })).toBeNull();
    expect(calls[0].path).toBe("/audit/secret-injections?limit=100");
  });

  it("does not render incomplete archive coverage", async () => {
    mount({ "GET /audit/secret-injections?limit=100": { body: { ...page, archived_history_excluded: true } } });
    fireEvent.click(screen.getByRole("button", { name: "Charger le rapprochement" }));
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByText("account-prod")).toBeNull();
  });

  it("paginates only with a canonical cursor returned by the service", async () => {
    const second = { ...page, outcomes: [{ ...outcome, injection_id: "1123456789abcdef0123456789abcdef", status: "completed" }], has_more: false };
    mount({
      "GET /audit/secret-injections?limit=100": { body: { ...page, has_more: true, next_before: outcome.injection_id } },
      [`GET /audit/secret-injections?limit=100&before=${outcome.injection_id}`]: { body: second },
    });
    fireEvent.click(screen.getByRole("button", { name: "Charger le rapprochement" }));
    expect(await screen.findByText("Résultat inconnu")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Charger les injections suivantes" }));
    expect(await screen.findByText("Terminé (audit)")).toBeTruthy();
  });

  it("explains that the cross-session permission is explicit", async () => {
    mount({ "GET /audit/secret-injections?limit=100": { status: 403, body: "forbidden" } });
    fireEvent.click(screen.getByRole("button", { name: "Charger le rapprochement" }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("permission d'audit transverse"));
  });
});
