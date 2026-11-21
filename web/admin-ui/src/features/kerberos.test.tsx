import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { ReactNode } from "react";
import { Api } from "../shared/api";
import { SignedInContext } from "../shared/session";
import { Accounts } from "./accounts/Accounts";
import { kerberosProblem, parseKDCs } from "./accounts/KerberosDialog";
import { fakeApi } from "../test-helpers";

const signedIn = (api: Api, node: ReactNode) => render(<SignedInContext.Provider value={{ api, who: null, signOut: () => {} }}>{node}</SignedInContext.Provider>);
const page = (items: unknown[]) => ({ body: { items, page: 1, pageSize: 20, totalItems: items.length } });

function openAccountsTab() {
  fireEvent.mouseDown(screen.getByRole("tab", { name: /Comptes/ }), { button: 0 });
}

// ADR-0100: the administrator of an RDP account switches it to Kerberos alone, or back to NTLM.
describe("Kerberos on an RDP account", () => {
  const rdp = { id: "acc_r", name: "bureau", username: "ops", targetHost: "desk:3389", targetDomain: "desk.corp.example.com", protocol: "rdp", rotationPolicy: "manual", createdAt: "2026-10-30T10:00:00Z" };
  const ssh = { ...rdp, id: "acc_s", name: "db", targetHost: "db:22", targetDomain: "", protocol: "ssh" };

  it("is offered on an RDP account only, shows the ticket's name, and is saved as the form says", async () => {
    const { api, calls } = fakeApi({ "GET /vault/accounts": page([rdp, ssh]), "PUT /vault/accounts/acc_r/kerberos": { body: { kerberos: { realm: "CORP.EXAMPLE.COM", kdcs: ["dc1.corp.example.com:88"] } } } });
    signedIn(api, <Accounts />);
    openAccountsTab();
    expect(await screen.findAllByRole("button", { name: "Kerberos" })).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Kerberos" }));
    const form = within(await screen.findByRole("dialog"));
    expect(form.getByText(/TERMSRV\/desk\.corp\.example\.com/)).toBeTruthy();
    const save = form.getByRole("button", { name: "Passer en Kerberos" }) as HTMLButtonElement;
    // Nothing to send yet: said, and the button stays off.
    expect(form.getByText("Donnez le royaume.")).toBeTruthy();
    expect(save.disabled).toBe(true);
    fireEvent.change(form.getByLabelText("Royaume"), { target: { value: "corp.example.com" } });
    expect(form.getByText("Donnez au moins un KDC.")).toBeTruthy();
    fireEvent.change(form.getByLabelText("KDC"), { target: { value: "dc1.corp.example.com\n\n  dc2.corp.example.com:8888 " } });
    expect(save.disabled).toBe(false);
    // "Back to NTLM" is there only when Kerberos is set.
    expect(form.queryByRole("button", { name: "Revenir à NTLM" })).toBeNull();
    fireEvent.click(save);
    expect((await screen.findByRole("status")).textContent).toContain("acc_r : Kerberos seul, royaume CORP.EXAMPLE.COM");
    expect(calls.find((c) => c.method === "PUT")).toMatchObject({
      path: "/vault/accounts/acc_r/kerberos",
      body: { kerberos: { realm: "CORP.EXAMPLE.COM", kdcs: ["dc1.corp.example.com", "dc2.corp.example.com:8888"] } },
    });
  });

  it("goes back to NTLM, and a refusal of the Vault is shown in the dialog", async () => {
    const kerberized = { ...rdp, kerberos: { realm: "CORP.EXAMPLE.COM", kdcs: ["dc1.corp.example.com:88"] } };
    const { api, calls } = fakeApi({ "GET /vault/accounts": page([kerberized]), "PUT /vault/accounts/acc_r/kerberos": { status: 409, body: { message: "conflict" } } });
    signedIn(api, <Accounts />);
    openAccountsTab();
    fireEvent.click(await screen.findByRole("button", { name: "Kerberos : CORP.EXAMPLE.COM" }));
    const form = within(await screen.findByRole("dialog"));
    expect((form.getByLabelText("Royaume") as HTMLInputElement).value).toBe("CORP.EXAMPLE.COM");
    expect((form.getByLabelText("KDC") as HTMLTextAreaElement).value).toBe("dc1.corp.example.com:88");
    fireEvent.click(form.getByRole("button", { name: "Revenir à NTLM" }));
    await waitFor(() => expect(form.getByText(/409/)).toBeTruthy());
    expect(screen.getByRole("dialog")).toBeTruthy();
    expect(calls.find((c) => c.method === "PUT")).toMatchObject({ body: { kerberos: null } });
  });

  it("refuses before sending what the Vault would refuse", () => {
    const account = rdp as never;
    const settings = (kdcs: string[], realm = "CORP") => ({ realm, kdcs });
    expect(parseKDCs("a\n b , c\n\n")).toEqual(["a", "b", "c"]);
    expect(kerberosProblem(settings([]), account)).toBe("noKDC");
    expect(kerberosProblem(settings(["a", "b", "c", "d", "e"]), account)).toBe("tooManyKDCs");
    expect(kerberosProblem(settings(["DC1", "dc1:88"]), account)).toBe("duplicateKDC");
    expect(kerberosProblem(settings(["[2001:db8::1]:88", "2001:db8::1"]), account)).toBe("duplicateKDC");
    expect(kerberosProblem(settings(["dc1"]), { ...rdp, targetDomain: "10.0.0.5" } as never)).toBe("ipName");
    expect(kerberosProblem(settings(["dc1"]), { ...rdp, username: "CORP\\ops" } as never)).toBe("domainUser");
    expect(kerberosProblem(settings(["dc1"]), { ...rdp, username: "ops@corp" } as never)).toBe("domainUser");
    expect(kerberosProblem(settings(["dc1", "dc2:8888", "10.0.0.4"]), account)).toBeUndefined();
  });
});
