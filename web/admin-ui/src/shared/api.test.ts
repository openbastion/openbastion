import { describe, expect, it, vi } from "vitest";
import { ApiError, claims } from "./api";
import { fakeApi, fakeToken } from "../test-helpers";

describe("Api", () => {
  it("sends the bearer token once given, and none before", async () => {
    const { api, calls } = fakeApi({ "GET /vault/accounts": { body: { items: [] } } });
    await api.request("GET", "/vault/accounts");
    api.setToken("tok-1");
    await api.request("GET", "/vault/accounts");
    expect(calls.map((c) => c.auth)).toEqual([undefined, "Bearer tok-1"]);
  });

  it("keeps the token in memory only: no storage, no cookie", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const { api } = fakeApi({ "GET /x": { body: {} } });
    api.setToken("tok-secret");
    await api.request("GET", "/x");
    expect(setItem).not.toHaveBeenCalled();
    expect(document.cookie).not.toContain("tok-secret");
    setItem.mockRestore();
  });

  it("turns a refusal into an ApiError with the status and a short message", async () => {
    const { api } = fakeApi({ "POST /auth/login": { status: 401, body: "invalid credentials\n" }, "GET /big": { status: 500, body: "x".repeat(5000) } });
    await expect(api.request("POST", "/auth/login", {})).rejects.toEqual(new ApiError(401, "invalid credentials"));
    const err = (await api.request("GET", "/big").catch((e) => e)) as ApiError;
    expect(err.status).toBe(500);
    expect(err.message.length).toBeLessThan(320);
  });

  it("reads the claims of a token for display, and nothing of something else", () => {
    expect(claims(fakeToken("alice", ["dba"]))).toMatchObject({ username: "alice", roles: ["dba"] });
    expect(claims("not-a-token")).toBeNull();
  });
});
