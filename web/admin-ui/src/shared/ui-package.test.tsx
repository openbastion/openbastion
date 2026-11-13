import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Alert, Badge, Button, Checkbox, Input, Label, Separator, Skeleton, Switch, Textarea } from "@openbastion/ui";

describe("@openbastion/ui foundation components", () => {
  it("preserves native button semantics, ref-compatible props and default non-submit type", () => {
    const onClick = vi.fn();
    render(<Button variant="primary" onClick={onClick}>Continuer</Button>);
    const button = screen.getByRole("button", { name: "Continuer" });
    expect(button.getAttribute("type")).toBe("button");
    expect(button.className).toContain("ob-button--primary");
    fireEvent.click(button);
    expect(onClick).toHaveBeenCalledOnce();
  });

  it("exposes badge tones without replacing caller classes", () => {
    render(<Badge tone="warning" className="custom">À vérifier</Badge>);
    expect(screen.getByText("À vérifier").className).toContain("ob-badge--warning");
    expect(screen.getByText("À vérifier").className).toContain("custom");
  });

  it("announces urgent alerts assertively and routine updates politely", () => {
    const { rerender } = render(<Alert tone="danger">Accès refusé</Alert>);
    expect(screen.getByRole("alert").getAttribute("aria-live")).toBe("assertive");
    rerender(<Alert tone="success">Enregistré</Alert>);
    expect(screen.getByRole("status").getAttribute("aria-live")).toBe("polite");
  });

  it("keeps form controls native and labelable", () => {
    render(<><Label htmlFor="ob-user">Utilisateur</Label><Input id="ob-user" name="username" autoComplete="username" /><Checkbox aria-label="Activer" /><Switch aria-label="Activer MFA" /><Textarea aria-label="Justification" /></>);
    expect(screen.getByLabelText("Utilisateur").getAttribute("name")).toBe("username");
    expect(screen.getByRole("checkbox", { name: "Activer" })).not.toBeNull();
    expect(screen.getByRole("switch", { name: "Activer MFA" })).not.toBeNull();
    expect(screen.getByRole("textbox", { name: "Justification" })).not.toBeNull();
  });

  it("renders decorative separator and announces skeleton loading", () => {
    render(<><Separator /><Skeleton aria-label="Chargement des comptes" /></>);
    expect(screen.getByRole("separator")).not.toBeNull();
    expect(screen.getByRole("status", { name: "Chargement des comptes" })).not.toBeNull();
  });
});
