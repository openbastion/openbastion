import { describe, expect, it, vi } from "vitest";
import {
  defaultOperatorPreferences,
  operatorPreferencesKey,
  parseOperatorPreferences,
  readOperatorPreferences,
  writeOperatorPreferences,
} from "./operatorPreferences";

describe("operator preferences", () => {
  it("loads only known, versioned presentation preferences", () => {
    expect(parseOperatorPreferences({
      version: 1,
      preferences: {
        theme: "dark",
        density: "compact",
        sidebarCollapsed: true,
        defaultTab: "sessions",
        favorites: ["accounts", "accounts", "unknown", 42],
        token: "must-not-be-kept",
      },
    })).toEqual({
      theme: "dark",
      density: "compact",
      sidebarCollapsed: true,
      defaultTab: "sessions",
      favorites: ["accounts"],
    });
  });

  it("rejects unknown versions and invalid values to safe defaults", () => {
    expect(parseOperatorPreferences({ version: 9, preferences: { theme: "dark" } })).toEqual(defaultOperatorPreferences);
    expect(parseOperatorPreferences({
      version: 1,
      preferences: { theme: "secret", density: "wide", sidebarCollapsed: "yes", defaultTab: "admin", favorites: ["admin"] },
    })).toEqual(defaultOperatorPreferences);
  });

  it("handles malformed storage and unavailable storage without throwing", () => {
    expect(readOperatorPreferences({ getItem: () => "{" })).toEqual(defaultOperatorPreferences);
    expect(readOperatorPreferences({ getItem: () => { throw new Error("blocked"); } })).toEqual(defaultOperatorPreferences);
    expect(writeOperatorPreferences(defaultOperatorPreferences, { setItem: () => { throw new Error("blocked"); } })).toBe(false);
  });

  it("writes a versioned presentation-only document", () => {
    const setItem = vi.fn();
    expect(writeOperatorPreferences({ ...defaultOperatorPreferences, theme: "dark" }, { setItem })).toBe(true);
    expect(setItem).toHaveBeenCalledOnce();
    expect(setItem.mock.calls[0][0]).toBe(operatorPreferencesKey);
    expect(setItem.mock.calls[0][1]).toContain('"theme":"dark"');
    expect(setItem.mock.calls[0][1]).not.toContain("token");
  });
});
