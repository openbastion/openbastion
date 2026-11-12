import { fireEvent, render, screen } from "@testing-library/react";
import type { FormEvent } from "react";
import { describe, expect, it, vi } from "vitest";
import { Form, FormDescription, FormField, Input, InputOTP, RadioGroup, RadioGroupItem, Select, Slider } from "@openbastion/ui";

describe("@openbastion/ui advanced form primitives", () => {
  it("connects labels, descriptions and validation errors to their control", () => {
    render(
      <Form aria-label="Créer un compte">
        <FormField id="account-name" label="Nom du compte" description="Nom visible dans le coffre" error="Ce nom est déjà utilisé" required>
          <Input />
        </FormField>
      </Form>,
    );
    const input = screen.getByRole("textbox", { name: /Nom du compte/ });
    expect(input.getAttribute("id")).toBe("account-name");
    expect(input.getAttribute("aria-invalid")).toBe("true");
    expect(input.getAttribute("aria-describedby")).toBe("account-name-description account-name-error");
    expect(input.hasAttribute("required")).toBe(true);
    expect(screen.getByRole("alert").textContent).toBe("Ce nom est déjà utilisé");
  });

  it("keeps native form submission and description semantics", () => {
    const submit = vi.fn((event: FormEvent<HTMLFormElement>) => event.preventDefault());
    render(<Form aria-label="Recherche" onSubmit={submit}><FormDescription>Filtres facultatifs</FormDescription><button type="submit">Rechercher</button></Form>);
    fireEvent.submit(screen.getByRole("form", { name: "Recherche" }));
    expect(submit).toHaveBeenCalledOnce();
    expect(screen.getByText("Filtres facultatifs").tagName).toBe("P");
  });

  it("supports controlled and uncontrolled native radio groups", () => {
    const change = vi.fn();
    render(<RadioGroup label="Protocole" name="protocol" defaultValue="ssh" onValueChange={change}><RadioGroupItem value="ssh" label="SSH" /><RadioGroupItem value="rdp" label="RDP" /></RadioGroup>);
    expect(screen.getByRole("radio", { name: "SSH" }).hasAttribute("checked")).toBe(true);
    fireEvent.click(screen.getByRole("radio", { name: "RDP" }));
    expect(change).toHaveBeenCalledWith("rdp");
    expect((screen.getByRole("radio", { name: "RDP" }) as HTMLInputElement).checked).toBe(true);
  });

  it("keeps select options and native keyboard interaction available", () => {
    const change = vi.fn();
    render(<><label htmlFor="target">Cible</label><Select id="target" defaultValue="host-a" onChange={change}><option value="host-a">Serveur A</option><option value="host-b">Serveur B</option></Select></>);
    fireEvent.change(screen.getByRole("combobox", { name: "Cible" }), { target: { value: "host-b" } });
    expect(change).toHaveBeenCalledOnce();
    expect((screen.getByRole("combobox") as HTMLSelectElement).value).toBe("host-b");
  });

  it("exposes a native range slider with deterministic bounds", () => {
    render(<><label htmlFor="timeout">Durée</label><Slider id="timeout" min={5} max={60} step={5} defaultValue={30} /></>);
    const slider = screen.getByRole("slider", { name: "Durée" }) as HTMLInputElement;
    expect(slider.min).toBe("5");
    expect(slider.max).toBe("60");
    expect(slider.step).toBe("5");
    expect(slider.value).toBe("30");
  });

  it("uses the browser one-time-code autofill contract and enforces the requested length", () => {
    render(<><label htmlFor="mfa-code">Code MFA</label><InputOTP id="mfa-code" length={8} /></>);
    const input = screen.getByRole("textbox", { name: "Code MFA" }) as HTMLInputElement;
    expect(input.autocomplete).toBe("one-time-code");
    expect(input.inputMode).toBe("numeric");
    expect(input.maxLength).toBe(8);
    fireEvent.change(input, { target: { value: "12345678" } });
    expect(input.value).toBe("12345678");
  });
});
