import { describe, expect, it, vi } from "vitest";
import {
  parseSavedAccountViews,
  readSavedAccountViews,
  savedAccountViewsKey,
  writeSavedAccountViews,
} from "./savedAccountViews";

describe("saved account views", () => {
  it("migrates legacy categorical filters and keeps only bounded safe rules", () => {
    expect(parseSavedAccountViews([
      { name: "  SSH à vérifier  ", filters: { protocol: "ssh", approval: "required", identity: "missing", rotation: "due", query: "host-prod" } },
      { name: "ssh à vérifier", filters: { protocol: "all", approval: "all", identity: "all", rotation: "all" } },
      { name: "Invalid", filters: { protocol: "mysql", approval: "all", identity: "all", rotation: "all" } },
      { name: "x", filters: { protocol: "all", approval: "all", identity: "all", rotation: "all" } },
    ])).toEqual([{
      name: "SSH à vérifier",
      rules: [
        { field: "protocol", comparison: "is", value: "ssh", join: "AND" },
        { field: "approval", comparison: "is", value: "required", join: "AND" },
        { field: "identity", comparison: "is", value: "missing", join: "AND" },
        { field: "rotation", comparison: "is", value: "due", join: "AND" },
      ],
    }]);
  });

  it("limits the number of views and rejects invalid storage safely", () => {
    const views = Array.from({ length: 20 }, (_, index) => ({
      name: "Vue " + index,
      rules: [{ field: "protocol", comparison: "is", value: "ssh", join: "AND" }],
    }));
    expect(parseSavedAccountViews(views)).toHaveLength(12);
    expect(readSavedAccountViews({ getItem: () => "not-json" })).toEqual([]);
    expect(readSavedAccountViews({ getItem: () => { throw new Error("blocked"); } })).toEqual([]);
  });

  it("writes version-two rules without search terms or resource data", () => {
    const setItem = vi.fn();
    const view = {
      name: "SSH",
      rules: [{ field: "protocol" as const, comparison: "is" as const, value: "ssh", join: "OR" as const }],
    };
    expect(writeSavedAccountViews([view], { setItem })).toBe(true);
    expect(setItem.mock.calls[0][0]).toBe(savedAccountViewsKey);
    expect(setItem.mock.calls[0][1]).toContain('"version":2');
    expect(setItem.mock.calls[0][1]).toContain('"join":"OR"');
    expect(setItem.mock.calls[0][1]).not.toContain("sessionId");
    expect(writeSavedAccountViews([view], { setItem: () => { throw new Error("blocked"); } })).toBe(false);
  });
});
