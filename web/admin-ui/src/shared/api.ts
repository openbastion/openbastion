// The client of the public API of the Gateway (doc 05), with the bearer token held in memory
// only (ADR-0036 rule 5): never in localStorage, sessionStorage or a cookie — a script injected
// into the page finds nothing to read back.

export class ApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
  }
}

export type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

export class Api {
  private token: string | null = null;
  private readonly fetchFn: Fetch;

  constructor(fetchFn: Fetch = (i, init) => fetch(i, init)) {
    this.fetchFn = fetchFn;
  }

  setToken(token: string | null): void {
    this.token = token;
  }

  hasToken(): boolean {
    return this.token !== null;
  }

  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const resp = await this.fetchFn(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "omit",
      cache: "no-store",
    });
    const text = await resp.text();
    if (!resp.ok) {
      throw new ApiError(resp.status, errorMessage(resp.status, text));
    }
    return (text ? JSON.parse(text) : undefined) as T;
  }
}

// errorMessage: what the API said, short — never a page of HTML.
function errorMessage(status: number, text: string): string {
  let msg = text.trim();
  try {
    const parsed = JSON.parse(msg);
    if (parsed && typeof parsed.message === "string") msg = parsed.message;
  } catch {
    // not JSON: the Gateway answers some refusals as plain text
  }
  if (msg.length > 300) msg = msg.slice(0, 300) + "…";
  return msg || `HTTP ${status}`;
}

export interface TokenClaims {
  sub: string;
  username: string;
  roles: string[];
  exp: number;
}

// claims reads the token for display only: the Gateway verifies it, not this page.
export function claims(token: string): TokenClaims | null {
  const part = token.split(".")[1];
  if (!part) return null;
  try {
    const json = atob(part.replace(/-/g, "+").replace(/_/g, "/"));
    const c = JSON.parse(json);
    return { sub: String(c.sub ?? ""), username: String(c.username ?? ""), roles: Array.isArray(c.roles) ? c.roles.map(String) : [], exp: Number(c.exp ?? 0) };
  } catch {
    return null;
  }
}

export interface Account {
  id: string;
  name: string;
  username: string;
  targetHost: string;
  protocol: string;
  rotationPolicy: string;
  lastRotatedAt?: string;
  createdAt: string;
  disabledAt?: string;
  // The target's pinned host key and its SHA256 fingerprint (ADR-0039); empty: not pinned.
  hostKey?: string;
  hostKeyFingerprint?: string;
  // A scheduled account's cadence and next rotation (ADR-0040); absent for any other.
  rotationIntervalDays?: number;
  nextRotationAt?: string;
}

export interface Page<T> {
  items: T[];
  page: number;
  pageSize: number;
  totalItems: number;
  truncated?: boolean;
}

export interface Session {
  id: string;
  status: string;
  protocol: string;
  requestedBy: string;
  privilegedAccountId: string;
  justification: string;
  breakGlass: boolean;
  expiresAt: string;
  decidedBy?: string;
  decidedAt?: string;
}

export interface RecordingPage {
  sessionId: string;
  entries: { timestamp: string; command: string }[];
  page: number;
  pageSize: number;
  totalEntries: number;
}
