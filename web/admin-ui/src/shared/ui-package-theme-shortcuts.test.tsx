import { afterEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { AppThemeProvider, useAppShortcuts, useEffectiveTheme } from "@openbastion/ui";

function mockMedia(dark: boolean) {
  let listener: (() => void) | undefined;
  const media = {
    matches: dark,
    addEventListener: (_: string, fn: () => void) => { listener = fn; },
    removeEventListener: () => { listener = undefined; },
  };
  window.matchMedia = vi.fn().mockReturnValue(media) as unknown as typeof window.matchMedia;
  return { flip: () => { media.matches = !media.matches; listener?.(); } };
}

function Probe() {
  return <p>{useEffectiveTheme()}</p>;
}

afterEach(() => { delete (window as { matchMedia?: unknown }).matchMedia; });

describe("AppThemeProvider", () => {
  it("applies an explicit theme and density to the document root and removes them on unmount", () => {
    mockMedia(true);
    const { unmount } = render(<AppThemeProvider theme="light" density="compact"><Probe /></AppThemeProvider>);
    expect(screen.getByText("light")).toBeTruthy();
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(document.documentElement.dataset.density).toBe("compact");
    unmount();
    expect(document.documentElement.dataset.theme).toBeUndefined();
    expect(document.documentElement.dataset.density).toBeUndefined();
  });

  it("follows the system colour scheme, including a later change", () => {
    const media = mockMedia(true);
    render(<AppThemeProvider theme="system" density="comfortable"><Probe /></AppThemeProvider>);
    expect(document.documentElement.dataset.theme).toBe("dark");
    act(() => media.flip());
    expect(document.documentElement.dataset.theme).toBe("light");
  });

  it("refuses useEffectiveTheme outside a provider", () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => render(<Probe />)).toThrow(/AppThemeProvider/);
    error.mockRestore();
  });
});

function Shortcuts({ suspended = false, onPalette, onDestination }: { suspended?: boolean; onPalette: () => void; onDestination: (i: number) => void }) {
  useAppShortcuts({ onCommandPalette: onPalette, onDestination, destinationCount: 6, suspended });
  return <input aria-label="champ" />;
}

describe("useAppShortcuts", () => {
  it("opens the palette with Ctrl+K and Meta+K, even from a text field", () => {
    const onPalette = vi.fn();
    render(<Shortcuts onPalette={onPalette} onDestination={vi.fn()} />);
    fireEvent.keyDown(screen.getByLabelText("champ"), { key: "k", ctrlKey: true });
    fireEvent.keyDown(document.body, { key: "K", metaKey: true });
    expect(onPalette).toHaveBeenCalledTimes(2);
  });

  it("maps Alt+Shift+1…6 to a destination index, but not 7 or a bare digit", () => {
    const onDestination = vi.fn();
    render(<Shortcuts onPalette={vi.fn()} onDestination={onDestination} />);
    fireEvent.keyDown(document.body, { key: "3", altKey: true, shiftKey: true });
    fireEvent.keyDown(document.body, { key: "7", altKey: true, shiftKey: true });
    fireEvent.keyDown(document.body, { key: "2" });
    expect(onDestination).toHaveBeenCalledTimes(1);
    expect(onDestination).toHaveBeenCalledWith(2);
  });

  it("ignores destination shortcuts in a text field or while suspended", () => {
    const onDestination = vi.fn();
    const { rerender } = render(<Shortcuts onPalette={vi.fn()} onDestination={onDestination} />);
    fireEvent.keyDown(screen.getByLabelText("champ"), { key: "1", altKey: true, shiftKey: true });
    rerender(<Shortcuts suspended onPalette={vi.fn()} onDestination={onDestination} />);
    fireEvent.keyDown(document.body, { key: "1", altKey: true, shiftKey: true });
    expect(onDestination).not.toHaveBeenCalled();
  });
});
