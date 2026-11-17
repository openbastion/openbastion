import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ReactNode } from "react";
import { Api } from "../../shared/api";
import { SignedInContext } from "../../shared/session";
import { fakeApi } from "../../test-helpers";
import { Sessions } from "./Sessions";

const signedIn = (api: Api, node: ReactNode) => render(
  <SignedInContext.Provider value={{ api, who: null, signOut: () => undefined }}>{node}</SignedInContext.Provider>,
);

const pending = { items: [], page: 1, pageSize: 50, totalItems: 0 };

describe("Sessions workspace tabs", () => {
  it("loads authorized session history through the bounded public search contract", async () => {
    const session = {
      id: "sess_history", status: "terminated", protocol: "ssh", requestedBy: "alice",
      privilegedAccountId: "acc_prod", targetHost: "db-prod:22", justification: "maintenance window",
      breakGlass: false, expiresAt: "2026-11-17T09:00:00Z", createdAt: "2026-11-17T08:00:00Z",
    };
    const { api, calls } = fakeApi({
      "GET /sessions": { body: pending },
      "GET /sessions/search": { body: { sessions: [session], next: "" } },
    });
    signedIn(api, <Sessions />);
    fireEvent.mouseDown(screen.getByRole("tab", { name: "Historique" }), { button: 0 });
    expect(await screen.findByText("sess_history")).toBeTruthy();
    expect(screen.getByText("db-prod:22")).toBeTruthy();
    const request = calls.find((call) => call.path.startsWith("/sessions/search?"));
    expect(request?.method).toBe("GET");
    expect(request?.path).toContain("from=");
    expect(request?.path).toContain("to=");
    expect(request?.path).not.toContain("q=");
  });

  it("searches recorded command text and opens the selected session in the existing replay screen", async () => {
    const openRecording = (sessionId: string) => { opened.push(sessionId); };
    const opened: string[] = [];
    const { api, calls } = fakeApi({
      "GET /sessions": { body: pending },
      "GET /recordings/search": { body: {
        searchId: "search-1", truncated: false,
        sessions: [{ sessionId: "sess_recorded", hits: [{ timestamp: "2026-11-17T08:00:00Z", command: "systemctl status nginx" }] }],
      } },
    });
    signedIn(api, <Sessions onOpenRecording={openRecording} />);
    fireEvent.mouseDown(screen.getByRole("tab", { name: "Enregistrements" }), { button: 0 });
    fireEvent.change(screen.getByLabelText("Texte à rechercher"), { target: { value: "systemctl" } });
    fireEvent.click(screen.getByRole("button", { name: "Rechercher" }));
    expect(await screen.findByText("systemctl status nginx")).toBeTruthy();
    expect(calls.some((call) => call.path.startsWith("/recordings/search?") && call.path.includes("q=systemctl"))).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Ouvrir la relecture" }));
    expect(opened).toEqual(["sess_recorded"]);
  });

  it("shows the alert API gap and does not invent an unread count or call an unsupported route", async () => {
    const { api, calls } = fakeApi({ "GET /sessions": { body: pending } });
    signedIn(api, <Sessions />);
    const alertTab = screen.getByRole("tab", { name: /Alertes/ });
    expect(alertTab.textContent).toContain("API requise");
    fireEvent.mouseDown(alertTab, { button: 0 });
    expect(await screen.findByText(/La file d'alertes n'est pas encore disponible/)).toBeTruthy();
    expect(screen.getByText(/Aucun compteur ni état de traitement n'est donc simulé/)).toBeTruthy();
    await waitFor(() => expect(calls.every((call) => !call.path.startsWith("/audit/events") && !call.path.startsWith("/sessions/alerts"))).toBe(true));
  });

  it("rejects a history window longer than 31 days before calling the Gateway", async () => {
    const { api, calls } = fakeApi({
      "GET /sessions": { body: pending },
      "GET /sessions/search": { body: { sessions: [], next: "" } },
    });
    signedIn(api, <Sessions />);
    fireEvent.mouseDown(screen.getByRole("tab", { name: "Historique" }), { button: 0 });
    await screen.findByText("Aucune session accessible dans cette période avec ces critères.");
    const before = calls.filter((call) => call.path.startsWith("/sessions/search?")).length;
    fireEvent.change(screen.getByLabelText("Du"), { target: { value: "2026-01-01" } });
    fireEvent.change(screen.getByLabelText("Au"), { target: { value: "2026-02-02" } });
    fireEvent.click(screen.getByRole("button", { name: "Rechercher" }));
    expect((await screen.findByRole("alert")).textContent).toContain("31 jours maximum");
    expect(calls.filter((call) => call.path.startsWith("/sessions/search?")).length).toBe(before);
  });

  it("rejects a recording window longer than 31 days before calling the Gateway", async () => {
    const { api, calls } = fakeApi({ "GET /sessions": { body: pending } });
    signedIn(api, <Sessions />);
    fireEvent.mouseDown(screen.getByRole("tab", { name: "Enregistrements" }), { button: 0 });
    fireEvent.change(screen.getByLabelText("Texte à rechercher"), { target: { value: "systemctl" } });
    fireEvent.change(screen.getByLabelText("Du"), { target: { value: "2026-01-01" } });
    fireEvent.change(screen.getByLabelText("Au"), { target: { value: "2026-02-02" } });
    fireEvent.click(screen.getByRole("button", { name: "Rechercher" }));
    expect((await screen.findByRole("alert")).textContent).toContain("31 jours maximum");
    expect(calls.some((call) => call.path.startsWith("/recordings/search"))).toBe(false);
  });

  it("shows the Gateway refusal when session history cannot be read", async () => {
    const { api } = fakeApi({
      "GET /sessions": { body: pending },
      "GET /sessions/search": { status: 403, body: "forbidden" },
    });
    signedIn(api, <Sessions />);
    fireEvent.mouseDown(screen.getByRole("tab", { name: "Historique" }), { button: 0 });
    expect((await screen.findByRole("alert")).textContent).toContain("403 — forbidden");
  });

  it("shows the Gateway refusal when a recording search is not authorized", async () => {
    const { api } = fakeApi({
      "GET /sessions": { body: pending },
      "GET /recordings/search": { status: 403, body: "forbidden" },
    });
    signedIn(api, <Sessions />);
    fireEvent.mouseDown(screen.getByRole("tab", { name: "Enregistrements" }), { button: 0 });
    fireEvent.change(screen.getByLabelText("Texte à rechercher"), { target: { value: "systemctl" } });
    fireEvent.click(screen.getByRole("button", { name: "Rechercher" }));
    expect((await screen.findByRole("alert")).textContent).toContain("403 — forbidden");
  });

  it("rejects a short recording query without making an API request", async () => {
    const { api, calls } = fakeApi({ "GET /sessions": { body: pending } });
    signedIn(api, <Sessions />);
    fireEvent.mouseDown(screen.getByRole("tab", { name: "Enregistrements" }), { button: 0 });
    fireEvent.change(screen.getByLabelText("Texte à rechercher"), { target: { value: "su" } });
    fireEvent.click(screen.getByRole("button", { name: "Rechercher" }));
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(calls.some((call) => call.path.startsWith("/recordings/search"))).toBe(false);
  });
});
