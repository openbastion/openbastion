import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Badge } from "./Badge";
import { Button } from "./Button";
import { InlineNotice } from "./InlineNotice";
import { StatusBadge } from "./StatusBadge";

describe("shared UI primitives", () => {
  it("renders a semantic button variant and preserves its native action", () => {
    const onClick = vi.fn();
    render(<Button variant="primary" type="submit" onClick={onClick}>Enregistrer</Button>);
    const button = screen.getByRole("button", { name: "Enregistrer" });
    expect(button.className).toContain("ob-button--primary");
    expect(button.getAttribute("type")).toBe("submit");
    fireEvent.click(button);
    expect(onClick).toHaveBeenCalledOnce();
  });

  it("defaults to a non-submitting button and preserves disabled state", () => {
    render(<Button disabled>Annuler</Button>);
    const button = screen.getByRole("button", { name: "Annuler" });
    expect(button.getAttribute("type")).toBe("button");
    expect(button.hasAttribute("disabled")).toBe(true);
  });

  it("renders badges with explicit semantic tones", () => {
    render(<Badge tone="warning">Rotation due</Badge>);
    expect(screen.getByText("Rotation due").className).toContain("ob-badge--warning");
  });

  it("uses alert semantics for danger notices and status semantics for success", () => {
    const { rerender } = render(<InlineNotice tone="danger">Accès refusé</InlineNotice>);
    expect(screen.getByRole("alert").getAttribute("aria-live")).toBe("assertive");
    rerender(<InlineNotice tone="success">Enregistré</InlineNotice>);
    expect(screen.getByRole("status").getAttribute("aria-live")).toBe("polite");
  });

  it("keeps unknown Broker states visible with a neutral badge", () => {
    render(<StatusBadge status="future_state" />);
    expect(screen.getByText("future_state").className).toContain("ob-badge--neutral");
  });
});
