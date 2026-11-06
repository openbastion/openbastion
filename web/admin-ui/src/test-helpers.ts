import { Api } from "./shared/api";

export interface Call {
  method: string;
  path: string;
  body?: unknown;
  auth?: string;
  credentials?: RequestCredentials;
}

// fakeApi answers by "METHOD path" (path without query when no exact match), and records calls.
export function fakeApi(routes: Record<string, { status?: number; body?: unknown }>) {
  const calls: Call[] = [];
  const api = new Api(async (input, init) => {
    const method = init?.method ?? "GET";
    const headers = (init?.headers ?? {}) as Record<string, string>;
    calls.push({ method, path: input, body: init?.body ? JSON.parse(String(init.body)) : undefined, auth: headers["Authorization"], credentials: init?.credentials });
    const r = routes[`${method} ${input}`] ?? routes[`${method} ${input.split("?")[0]}`];
    if (!r) return new Response("not found", { status: 404 });
    const body = r.body === undefined ? "" : typeof r.body === "string" ? r.body : JSON.stringify(r.body);
    return new Response(body, { status: r.status ?? 200 });
  });
  return { api, calls };
}

// A token whose claims say who: the Gateway verifies tokens, the page only displays them.
export function fakeToken(username: string, roles: string[]): string {
  const enc = (o: unknown) => btoa(JSON.stringify(o)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `${enc({ alg: "HS256" })}.${enc({ sub: "user_1", username, roles, exp: 9999999999 })}.sig`;
}
