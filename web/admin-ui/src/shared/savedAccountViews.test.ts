import { describe, expect, it, vi } from "vitest";
import {
  parseSavedAccountViews,
  readSavedAccountViews,
  savedAccountViewsKey,
  writeSavedAccountViews,
} from "./savedAccountViews";

describe("saved account views", () => {
  it("keeps only bounded names and categorical filter values", () => {
    expect(parseSavedAccountViews([
      { name: "  SSH à vérifier  ", filters: { protocol: "ssh", approval: "required", identity: "missing", rotation: "due", query: "host-prod" } },
      { name: "ssh à vérifier", filters: { protocol: "all", approval: "all", identity: "all", rotation: "all" } },
      { name: "Invalid", filters: { protocol: "mysql", approval: "all", identity: "all", rotation: "all" } },
      { name: "x", filters: { protocol: "all", approval: "all", identity: "all", rotation: "all" } },
    ])).toEqual([
      { name: "SSH à vérifier", filters: { protocol: "ssh", approval: "required", identity: "missing", rotation: "due" } },
    ]);
  });

  it("limits the number of views and rejects invalid storage safely", () => {
    const views = Array.from({ length: 20 }, (_, index) => ({
      name: "Vue " + index,
      filters: { protocol: "all", approval: "all", identity: "all", rotation: "all" },
    }));
    expect(parseSavedAccountViews(views)).toHaveLength(12);
    expect(readSavedAccountViews({ getItem: () => "not-json" })).toEqual([]);
    expect(readSavedAccountViews({ getItem: () => { throw new Error("blocked"); } })).toEqual([]);
  });

  it("writes only the versioned view name and categorical filters", () => {
    const setItem = vi.fn();
    const view = { name: "SSH", filters: { protocol: "ssh" as const, approval: "all" as const, identity: "all" as const, rotation: "all" as const } };
    expect(writeSavedAccountViews([view], { setItem })).toBe(true);
    expect(setItem.mock.calls[0][0]).toBe(savedAccountViewsKey);
    expect(setItem.mock.calls[0][1]).toContain('"protocol":"ssh"');
    expect(setItem.mock.calls[0][1]).not.toContain("sessionId");
    expect(writeSavedAccountViews([view], { setItem: () => { throw new Error("blocked"); } })).toBe(false);
  });
});
