import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { RouteBoundary } from "./RouteStates";

// ADR-0137 §5: one error boundary per route.
let explode = true;
function Screen() {
  if (explode) throw new Error("secret detail that must never be printed");
  return <p>Écran sain</p>;
}

describe("RouteBoundary", () => {
  it("shows a recoverable state without printing the error, then recovers on retry", () => {
    explode = true;
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    render(<RouteBoundary routeKey="/a"><Screen /></RouteBoundary>);
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("Cet écran a rencontré une erreur");
    expect(alert.textContent).not.toContain("secret detail");
    explode = false;
    fireEvent.click(screen.getByRole("button", { name: "Réessayer" }));
    expect(screen.getByText("Écran sain")).toBeTruthy();
    log.mockRestore();
  });

  it("clears itself when the address changes", () => {
    explode = true;
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const { rerender } = render(<RouteBoundary routeKey="/a"><Screen /></RouteBoundary>);
    expect(screen.getByRole("alert")).toBeTruthy();
    explode = false;
    rerender(<RouteBoundary routeKey="/b"><Screen /></RouteBoundary>);
    expect(screen.getByText("Écran sain")).toBeTruthy();
    log.mockRestore();
  });
});
