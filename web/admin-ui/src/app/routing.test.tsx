import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { App } from "./App";
import { fakeApi, fakeToken } from "../test-helpers";
import { destinations, tabFromPath, tabPath } from "./navigation";

// ADR-0137: the destination is the address, with explicit 403/404 and a return to the requested
// address after the sign-in.
async function signIn(entry: string, roles: string[]) {
  const token = fakeToken("alice", roles);
  const { api } = fakeApi({
    "POST /auth/login": { body: { accessToken: token, expiresIn: 3600 } },
  });
  render(<App api={api} initialEntries={[entry]} location={{ pathname: "/ui/", search: "" } as Location} navigate={vi.fn()} />);
  fireEvent.change(await screen.findByLabelText("Utilisateur"), { target: { value: "alice" } });
  fireEvent.change(screen.getByLabelText("Mot de passe"), { target: { value: "pw" } });
  fireEvent.click(screen.getByText("Se connecter"));
}

describe("ADR-0137 — navigation adressable", () => {
  it("derives every path from the single declaration", () => {
    expect(new Set(destinations.map((d) => d.path)).size).toBe(destinations.length);
    for (const d of destinations) expect(tabFromPath(tabPath(d.id))).toBe(d.id);
    expect(tabFromPath("/nope")).toBeUndefined();
  });

  it("returns to the requested address after the sign-in", async () => {
    window.localStorage.clear();
    await signIn("/sessions", ["platform-admin"]);
    await screen.findByRole("button", { name: /alice.*platform-admin/ });
    const navigation = screen.getByRole("navigation", { name: "Sections" });
    expect(within(navigation).getByRole("button", { name: "Sessions" }).getAttribute("aria-current")).toBe("page");
  });

  it("answers an unknown address with an explicit 404 and no current destination", async () => {
    window.localStorage.clear();
    await signIn("/nope", ["platform-admin"]);
    expect(await screen.findByText("Page introuvable")).toBeTruthy();
    await waitFor(() => expect(document.querySelector('[aria-current="page"]')).toBeNull());
  });

  it("redirects a destination with tabs to its first tab and follows a tab address", async () => {
    window.localStorage.clear();
    await signIn("/access", ["platform-admin"]);
    expect(await screen.findByRole("tab", { name: /Ressources/ })).toBeTruthy();
    expect(screen.getByRole("tab", { name: /Ressources/ }).getAttribute("aria-selected")).toBe("true");
    fireEvent.mouseDown(screen.getByRole("tab", { name: /Comptes/ }));
    await waitFor(() => expect(screen.getByRole("tab", { name: /Comptes/ }).getAttribute("aria-selected")).toBe("true"));
  });

  it("opens the tab named by the address, and answers an unknown tab with a 404", async () => {
    window.localStorage.clear();
    await signIn("/audit/evidence", ["platform-admin"]);
    await waitFor(() => expect(screen.getByRole("tab", { name: /Preuves/ }).getAttribute("aria-selected")).toBe("true"));
  });

  it("answers an unknown tab with a 404", async () => {
    window.localStorage.clear();
    await signIn("/sessions/nope", ["platform-admin"]);
    expect(await screen.findByText("Page introuvable")).toBeTruthy();
  });
});
