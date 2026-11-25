import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { AppCommandPalette, AppMobileNavigation, AppUserMenu } from "@openbastion/ui";

function Mobile() {
  const [open, setOpen] = useState(false);
  const nav = useRef<HTMLElement>(null);
  const opener = useRef<HTMLButtonElement>(null);
  return (
    <>
      <button ref={opener} onClick={() => setOpen(true)}>Ouvrir</button>
      <AppMobileNavigation open={open} onClose={() => setOpen(false)} containerRef={nav} returnFocusRef={opener} excludeSelector=".skip" />
      <aside ref={nav} aria-label="nav">
        <button className="skip">Réduire</button>
        <a href="#a">Premier</a>
        <button>Dernier</button>
      </aside>
    </>
  );
}

describe("AppMobileNavigation", () => {
  it("moves focus in, cycles Tab, closes on Escape and returns the focus to the opener", () => {
    render(<Mobile />);
    const opener = screen.getByText("Ouvrir");
    opener.focus();
    fireEvent.click(opener);
    expect(document.activeElement).toBe(screen.getByText("Premier"));
    screen.getByText("Dernier").focus();
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(screen.getByText("Premier"));
    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(screen.getByText("Dernier"));
    fireEvent.keyDown(document, { key: "Escape" });
    expect(document.querySelector(".navigation-backdrop")).toBeNull();
    expect(document.activeElement).toBe(opener);
  });

  it("closes from the backdrop and keeps excluded controls out of the focus cycle", () => {
    render(<Mobile />);
    fireEvent.click(screen.getByText("Ouvrir"));
    screen.getByText("Dernier").focus();
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).not.toBe(screen.getByText("Réduire"));
    fireEvent.click(document.querySelector(".navigation-backdrop")!);
    expect(document.querySelector(".navigation-backdrop")).toBeNull();
  });
});

function Menu() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <p>dehors</p>
      <AppUserMenu open={open} onOpenChange={setOpen} trigger="Moi" label="Menu opérateur"><button>Action</button></AppUserMenu>
    </>
  );
}

describe("AppUserMenu", () => {
  it("opens, exposes its state, closes on Escape and on an outside press, and refocuses the trigger", () => {
    render(<Menu />);
    const trigger = screen.getByRole("button", { name: "Moi" });
    fireEvent.click(trigger);
    expect(trigger.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByLabelText("Menu opérateur")).toBeTruthy();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByLabelText("Menu opérateur")).toBeNull();
    expect(document.activeElement).toBe(trigger);
    fireEvent.click(trigger);
    fireEvent.pointerDown(screen.getByText("dehors"));
    expect(screen.queryByLabelText("Menu opérateur")).toBeNull();
  });

  it("stays open on a press inside the panel", () => {
    render(<Menu />);
    fireEvent.click(screen.getByRole("button", { name: "Moi" }));
    fireEvent.pointerDown(screen.getByText("Action"));
    expect(screen.getByLabelText("Menu opérateur")).toBeTruthy();
  });
});

const labels = { title: "Palette", query: "Requête", placeholder: "Chercher", results: "Résultats", empty: "Rien", navigateHint: "↑↓", selectHint: "↵", closeHint: "Échap", closeButton: "Fermer" };

describe("AppCommandPalette", () => {
  it("runs the active command on Enter after arrow navigation, then closes", () => {
    const a = vi.fn();
    const b = vi.fn();
    const onClose = vi.fn();
    render(<AppCommandPalette commands={[{ id: "a", label: "A", detail: "da", run: a }, { id: "b", label: "B", detail: "db", run: b }]} query="" onQueryChange={() => {}} onClose={onClose} labels={labels} />);
    const input = screen.getByRole("combobox");
    expect(document.activeElement).toBe(input);
    fireEvent.keyDown(input, { key: "ArrowDown" });
    expect(input.getAttribute("aria-activedescendant")).toBe("command-b");
    fireEvent.keyDown(input, { key: "Enter" });
    expect(b).toHaveBeenCalledOnce();
    expect(a).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("shows the empty label, reports typing, and closes on Escape", () => {
    const onQuery = vi.fn();
    const onClose = vi.fn();
    render(<AppCommandPalette commands={[]} query="x" onQueryChange={onQuery} onClose={onClose} labels={labels} />);
    expect(screen.getByText("Rien")).toBeTruthy();
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "xy" } });
    expect(onQuery).toHaveBeenCalledWith("xy");
    fireEvent.keyDown(screen.getByRole("combobox"), { key: "Escape" });
    expect(onClose).toHaveBeenCalledOnce();
  });
});
