import { describe, expect, it, vi } from "vitest";
import { renderHook } from "@testing-library/react";
import { useAppShortcuts } from "@openbastion/ui";

describe("Alt+Shift+digit on a layout where Shift+1 types a symbol", () => {
  it("uses the physical key when event.key is not a digit (US layout: Shift+1 is \"!\")", () => {
    const onDestination = vi.fn();
    renderHook(() => useAppShortcuts({ onDestination, destinationCount: 6 }));
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "!", code: "Digit1", altKey: true, shiftKey: true }));
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "&", code: "Digit7", altKey: true, shiftKey: true }));
    expect(onDestination).toHaveBeenCalledTimes(1);
    expect(onDestination).toHaveBeenCalledWith(0);
  });
});
