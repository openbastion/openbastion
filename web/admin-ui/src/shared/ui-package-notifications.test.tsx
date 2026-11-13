import { act, fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Sonner, Toast, ToastProvider, Toaster, useToast } from "@openbastion/ui";

function ToastLauncher() {
  const { toast } = useToast();
  return <button type="button" onClick={() => toast({ title: "Session ouverte", description: "Connexion SSH autorisée", variant: "success" })}>Notifier</button>;
}

describe("@openbastion/ui notification primitives", () => {
  it("shows and manually dismisses a notification", () => {
    render(<ToastProvider><ToastLauncher /><Toaster /></ToastProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Notifier" }));
    expect(screen.getByRole("status").textContent).toContain("Session ouverte");
    expect(screen.getByText("Connexion SSH autorisée")).not.toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Fermer la notification" }));
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("uses an assertive alert role for danger notifications", () => {
    render(<Toast title="Accès refusé" variant="danger" />);
    expect(screen.getByRole("alert").textContent).toContain("Accès refusé");
  });

  it("automatically dismisses notifications after their duration", () => {
    vi.useFakeTimers();
    render(<ToastProvider defaultDuration={1200}><ToastLauncher /><Toaster /></ToastProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Notifier" }));
    expect(screen.getByRole("status")).not.toBeNull();
    act(() => vi.advanceTimersByTime(1200));
    expect(screen.queryByRole("status")).toBeNull();
    vi.useRealTimers();
  });

  it("provides a ready-to-use Sonner composition and caps the visible queue", () => {
    function Burst() {
      const { toast } = useToast();
      return <button type="button" onClick={() => { for (let i = 1; i <= 7; i += 1) toast({ title: `Notification ${i}`, duration: 0 }); }}>Envoyer</button>;
    }
    render(<Sonner position="top-center"><Burst /></Sonner>);
    fireEvent.click(screen.getByRole("button", { name: "Envoyer" }));
    expect(screen.getByLabelText("Notifications").querySelectorAll(".ob-toast")).toHaveLength(5);
    expect(screen.getByText("Notification 7")).not.toBeNull();
    expect(screen.queryByText("Notification 1")).toBeNull();
  });
});
