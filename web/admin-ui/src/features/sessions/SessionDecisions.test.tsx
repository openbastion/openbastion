import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { SignedInContext } from "../../shared/session";
import { Api } from "../../shared/api";
import { fakeApi } from "../../test-helpers";
import { Sessions } from "./Sessions";

// Who may decide a request, as the Session Broker rules it (decide, session_broker_service.go):
// the person who asked never approves their own request; on an approval request they cannot
// reject it either, on a break-glass request they may withdraw it. The page shows the actions
// the caller may take and none other; the Broker stays the only authority.

const request = (over: Record<string, unknown>) => ({
  id: "sess_9", status: "pending_approval", protocol: "ssh", requestedBy: "user_alice", privilegedAccountId: "acc_1",
  justification: "patch", breakGlass: false, approvalRequired: true, expiresAt: "2030-01-01T00:00:00Z", ...over,
});

function as(sub: string, api: Api) {
  const who = { sub, username: sub, roles: ["ops"], exp: 9999999999 };
  render(<SignedInContext.Provider value={{ api, who, signOut: () => {} }}><Sessions /></SignedInContext.Provider>);
}

describe("Sessions — who may decide a request", () => {
  it("shows Approve and Reject to an approver who is not the requester", async () => {
    const { api } = fakeApi({ "GET /sessions": { body: { items: [request({})], page: 1, pageSize: 20, totalItems: 1 } } });
    as("user_bob", api);
    expect(await screen.findByRole("button", { name: "Approuver la session sess_9" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Refuser la session sess_9" })).toBeTruthy();
  });

  it("shows the requester of an approval request no decision, and says why", async () => {
    const { api } = fakeApi({ "GET /sessions": { body: { items: [request({})], page: 1, pageSize: 20, totalItems: 1 } } });
    as("user_alice", api);
    expect(await screen.findByText("Vous avez fait cette demande : une autre personne doit la décider.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Approuver la session sess_9" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Refuser la session sess_9" })).toBeNull();
  });

  it("lets the requester of a break-glass request withdraw it, never approve it", async () => {
    const bg = request({ breakGlass: true, approvalRequired: false });
    const { api, calls } = fakeApi({
      "GET /sessions": { body: { items: [bg], page: 1, pageSize: 20, totalItems: 1 } },
      "POST /sessions/sess_9/reject": { body: { ...bg, status: "denied" } },
    });
    as("user_alice", api);
    const withdraw = await screen.findByRole("button", { name: "Retirer ma demande sess_9" });
    expect(screen.queryByRole("button", { name: "Approuver la session sess_9" })).toBeNull();
    fireEvent.click(withdraw);
    fireEvent.click(screen.getByText("Confirmer le refus"));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/sessions/sess_9/reject")).toBe(true));
  });
});
