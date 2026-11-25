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
});
