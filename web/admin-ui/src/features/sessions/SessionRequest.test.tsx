import { describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { Api } from "../../shared/api";
import { SignedInContext } from "../../shared/session";
import { SessionRequest } from "./SessionRequest";

// The session request form (docs/ui/reference-screens/openbastion-sessions-nouvelle-demande-*.svg):
// one request per click, errors where the field is, nothing sent while a field is missing, and the
// fields kept when the server does not confirm.

const created = { id: "sess_1", status: "pending_approval", protocol: "ssh", requestedBy: "alice", privilegedAccountId: "acc_1", justification: "patch", breakGlass: false, expiresAt: "2030-01-01T00:00:00Z" };

// An API whose POST /sessions answers only when the test says so.
function heldApi() {
  const posts: unknown[] = [];
  let answer: (r: Response) => void = () => {};
  const api = new Api(async (_input, init) => {
    posts.push(init?.body ? JSON.parse(String(init.body)) : undefined);
    return new Promise<Response>((resolve) => { answer = resolve; });
  });
  return { api, posts, answer: (r: Response) => answer(r) };
}

function renderForm(api: Api, onDone = vi.fn(), onCancel = vi.fn()) {
  render(
    <SignedInContext.Provider value={{ api, who: null, signOut: () => {} }}>
      <SessionRequest onDone={onDone} onCancel={onCancel} />
    </SignedInContext.Provider>,
  );
  return { onDone, onCancel, form: screen.getByRole("form", { name: "Demander une session" }) };
}

function fill(account: string, justification: string) {
  fireEvent.change(screen.getByLabelText("Compte"), { target: { value: account } });
  fireEvent.change(screen.getByLabelText("Justification"), { target: { value: justification } });
}

describe("SessionRequest", () => {
  it("sends one request however many times it is submitted while the server has not answered", async () => {
    const held = heldApi();
    const { form, onDone } = renderForm(held.api);
    fill("acc_1", "patch");
    fireEvent.submit(form);
    fireEvent.submit(form);
    fireEvent.click(screen.getByRole("button", { name: "Envoi en cours…" }));
    await waitFor(() => expect(held.posts).toHaveLength(1));
    const button = screen.getByRole("button", { name: "Envoi en cours…" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(form.getAttribute("aria-busy")).toBe("true");
    await act(async () => held.answer(new Response(JSON.stringify(created), { status: 201 })));
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(held.posts).toHaveLength(1);
    expect((screen.getByRole("button", { name: "Demander" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("sends nothing while the account or the justification is missing, and says so under each field", async () => {
    const held = heldApi();
    const { form } = renderForm(held.api);
    fill("   ", "  ");
    fireEvent.submit(form);
    expect(await screen.findByText("Renseignez le compte cible.")).toBeTruthy();
    expect(screen.getByText("Une justification explicite est obligatoire.")).toBeTruthy();
    expect(screen.getByText("Corrigez les champs obligatoires avant l'envoi.")).toBeTruthy();
    expect(screen.getByLabelText("Compte").getAttribute("aria-invalid")).toBe("true");
    expect(screen.getByLabelText("Justification").getAttribute("aria-invalid")).toBe("true");
    expect(held.posts).toHaveLength(0);
    // Corrected, the errors go and the request leaves.
    fill("acc_1", "patch");
    fireEvent.submit(form);
    await waitFor(() => expect(held.posts).toHaveLength(1));
    expect(screen.queryByText("Renseignez le compte cible.")).toBeNull();
  });

  it("refuses a duration below one minute without asking the server", async () => {
    const held = heldApi();
    const { form } = renderForm(held.api);
    fill("acc_1", "patch");
    fireEvent.change(screen.getByLabelText("Durée (minutes)"), { target: { value: "0" } });
    fireEvent.submit(form);
    expect(await screen.findByText("Une durée d'au moins une minute est requise.")).toBeTruthy();
    expect(held.posts).toHaveLength(0);
  });

  it("keeps every field when the server does not confirm, and says the request was not created", async () => {
    const held = heldApi();
    const { form, onDone } = renderForm(held.api);
    fill("acc_1", "maintenance window");
    fireEvent.change(screen.getByLabelText("Ticket (si le compte exige une approbation)"), { target: { value: "CHG-1" } });
    fireEvent.submit(form);
    await waitFor(() => expect(held.posts).toHaveLength(1));
    await act(async () => held.answer(new Response(JSON.stringify({ error: "broker unavailable" }), { status: 503 })));
    expect((await screen.findByRole("alert")).textContent).toContain("La création n'est pas confirmée. Vos champs sont conservés.");
    expect((screen.getByLabelText("Compte") as HTMLInputElement).value).toBe("acc_1");
    expect((screen.getByLabelText("Justification") as HTMLTextAreaElement).value).toBe("maintenance window");
    expect((screen.getByLabelText("Ticket (si le compte exige une approbation)") as HTMLInputElement).value).toBe("CHG-1");
    expect(onDone).not.toHaveBeenCalled();
    expect((screen.getByRole("button", { name: "Demander" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("takes the justification in a text area, counts the ticket, and can be cancelled", () => {
    const { onCancel } = renderForm(heldApi().api);
    expect(screen.getByLabelText("Justification").tagName).toBe("TEXTAREA");
    expect(screen.getByText("0/128")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Ticket (si le compte exige une approbation)"), { target: { value: "CHG-2026-0142" } });
    expect(screen.getByText("13/128")).toBeTruthy();
    expect(screen.getByText("La création ne vaut ni approbation ni ouverture de session.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Annuler" }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });
});
