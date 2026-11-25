import { describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import {
  AppCapabilityButton,
  AppConfirmDialog,
  AppErrorBoundary,
  AppForbiddenPage,
  AppLoadingState,
  AppNotFoundPage,
  AppNotificationProvider,
  useToast,
} from "@openbastion/ui";

function Boom({ explode }: { explode: boolean }) {
  if (explode) throw new Error("secret detail");
  return <p>ok</p>;
}

describe("AppLoadingState", () => {
  it("is one polite busy status with a readable name", () => {
    render(<AppLoadingState label="Chargement des comptes" />);
    const status = screen.getByRole("status");
    expect(status.getAttribute("aria-busy")).toBe("true");
    expect(status.textContent).toBe("Chargement des comptes");
  });
});

describe("AppErrorBoundary", () => {
  it("replaces only its subtree, reports the error, never prints it, and resets on a new key", () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const onError = vi.fn();
    function Host() {
      const [route, setRoute] = useState("/a");
      return (
        <>
          <button onClick={() => setRoute("/b")}>go</button>
          <AppErrorBoundary resetKeys={[route]} onError={onError} fallback={<p role="alert">Écran indisponible</p>}>
            <Boom explode={route === "/a"} />
          </AppErrorBoundary>
          <p>shell intact</p>
        </>
      );
    }
    render(<Host />);
    expect(screen.getByRole("alert").textContent).toBe("Écran indisponible");
    expect(screen.queryByText(/secret detail/)).toBeNull();
    expect(screen.getByText("shell intact")).toBeTruthy();
    expect(onError).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByText("go"));
    expect(screen.getByText("ok")).toBeTruthy();
  });

  it("offers a reset to a function fallback", () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    let explode = true;
    function Flaky() {
      if (explode) throw new Error("x");
      return <p>recovered</p>;
    }
    render(
      <AppErrorBoundary fallback={(_error, reset) => <button onClick={() => { explode = false; reset(); }}>Réessayer</button>}>
        <Flaky />
      </AppErrorBoundary>,
    );
    fireEvent.click(screen.getByText("Réessayer"));
    expect(screen.getByText("recovered")).toBeTruthy();
  });
});

describe("AppConfirmDialog", () => {
  const labels = { confirmLabel: "Supprimer", cancelLabel: "Annuler", workingLabel: "En cours…" };

  it("is an alert dialog, focuses Cancel first, and Escape cancels", async () => {
    const onCancel = vi.fn();
    render(<AppConfirmDialog title="Supprimer ?" description="Irréversible" {...labels} onConfirm={async () => true} onCancel={onCancel} />);
    const dialog = await screen.findByRole("alertdialog", { name: "Supprimer ?" });
    expect(dialog.textContent).toContain("Irréversible");
    await waitFor(() => expect(document.activeElement?.textContent).toBe("Annuler"));
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(onCancel).toHaveBeenCalled();
  });

  it("sends the request once, ignores Escape while it runs, and closes only on success", async () => {
    const onCancel = vi.fn();
    let finish: (ok: boolean) => void = () => undefined;
    const onConfirm = vi.fn(() => new Promise<boolean>((resolve) => { finish = resolve; }));
    render(<AppConfirmDialog title="Supprimer ?" description="d" {...labels} onConfirm={onConfirm} onCancel={onCancel} />);
    const confirm = await screen.findByRole("button", { name: "Supprimer" });
    fireEvent.click(confirm);
    fireEvent.click(screen.getByRole("button", { name: "En cours…" }));
    fireEvent.keyDown(screen.getByRole("alertdialog"), { key: "Escape" });
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onCancel).not.toHaveBeenCalled();
    await act(async () => finish(true));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("stays open and shows the error when the request is refused", async () => {
    const onCancel = vi.fn();
    render(<AppConfirmDialog title="t" description="d" error="Refusé (403)" {...labels} onConfirm={async () => false} onCancel={onCancel} />);
    fireEvent.click(await screen.findByRole("button", { name: "Supprimer" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Supprimer" })).toBeTruthy());
    expect(onCancel).not.toHaveBeenCalled();
    expect(screen.getByText("Refusé (403)")).toBeTruthy();
  });
});

describe("AppCapabilityButton", () => {
  it("is a normal button when allowed", () => {
    const onClick = vi.fn();
    render(<AppCapabilityButton allowed onClick={onClick}>Agir</AppCapabilityButton>);
    fireEvent.click(screen.getByRole("button", { name: "Agir" }));
    expect(onClick).toHaveBeenCalled();
  });

  it("is greyed with the reason in its title and description when not allowed", () => {
    const onClick = vi.fn();
    render(<AppCapabilityButton allowed={false} reason="Droit requis : X" onClick={onClick}>Agir</AppCapabilityButton>);
    const button = screen.getByRole("button", { name: "Agir" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.getAttribute("aria-description")).toBe("Droit requis : X");
    expect(button.parentElement?.getAttribute("title")).toBe("Droit requis : X");
    fireEvent.click(button);
    expect(onClick).not.toHaveBeenCalled();
  });
});

describe("AppNotificationProvider", () => {
  it("shows what useToast produces in one Notifications region", async () => {
    function Producer() {
      const { toast } = useToast();
      return <button onClick={() => toast({ title: "Enregistré" })}>notify</button>;
    }
    render(<AppNotificationProvider><Producer /></AppNotificationProvider>);
    fireEvent.click(screen.getByText("notify"));
    expect(await screen.findByText("Enregistré")).toBeTruthy();
    expect(screen.getAllByRole("region", { name: "Notifications" })).toHaveLength(1);
  });
});

describe("generic refusal pages", () => {
  it("states 403 as an alert and 404 as a status, with the caller's own texts", () => {
    render(<><AppForbiddenPage title="Accès refusé" detail="Droit : a.b" /><AppNotFoundPage title="Introuvable" detail="Adresse inconnue" /></>);
    expect(screen.getByRole("alert").textContent).toContain("Droit : a.b");
    expect(screen.getByText("Introuvable").closest("[data-status]")?.getAttribute("data-status")).toBe("404");
  });
});
