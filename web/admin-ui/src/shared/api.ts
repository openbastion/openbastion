// The client of the public API of the Gateway (docs/api/rest/openapi.yaml), with the bearer token held in memory
// only (ADR-0036 rule 5): never in localStorage, sessionStorage or a cookie — a script injected
// into the page finds nothing to read back.

export class ApiError extends Error {
  // body: the answer decoded as JSON, when it is — a login that needs a second factor carries its
  // challenge there (ADR-0062).
  constructor(public readonly status: number, message: string, public readonly body?: unknown) {
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

  // credentials stays "omit" for everything but the one call that needs a cookie (connectScreen).
  async request<T>(method: string, path: string, body?: unknown, credentials: RequestCredentials = "omit"): Promise<T> {
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const resp = await this.fetchFn(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials,
      cache: "no-store",
    });
    const text = await resp.text();
    if (!resp.ok) {
      throw new ApiError(resp.status, errorMessage(resp.status, text), parseJSON(text));
    }
    return (text ? JSON.parse(text) : undefined) as T;
  }

  // POST /sessions/{id}/connect for a graphical session. The answer sets the HttpOnly cookie that
  // attaches the screen (ADR-0071 §7), and a browser ignores Set-Cookie on a call made with
  // credentials "omit": this one, and only this one, lets it land.
  connectScreen(sessionId: string): Promise<ScreenAttach> {
    return this.request<ScreenAttach>("POST", `/sessions/${encodeURIComponent(sessionId)}/connect`, undefined, "same-origin");
  }
}

function parseJSON(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
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
  // Scheduled rotations failed in a row (ADR-0041); absent at 0.
  rotationFailures?: number;
  // A session on the account ended and left a rotation owed (ADR-0044); absent: none.
  rotationOwedSince?: string;
  // Sessions on the account wait for another person's approval, with a ticket (ADR-0067).
  approvalRequired?: boolean;
  // A graphical target's pinned TLS certificate and the name it is valid for (ADR-0071).
  tlsCertificateSha256?: string;
  targetDomain?: string;
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
  // An ordinary session that waits, or waited, for another person's approval, and its ticket (ADR-0067).
  approvalRequired?: boolean;
  ticket?: string;
  expiresAt: string;
  decidedBy?: string;
  decidedAt?: string;
}

// What connecting to a graphical session gives the page: a path, no ticket and no proxy address.
export interface ScreenAttach {
  protocol: string;
  attach: string;
  expiresAt: string;
}

// One segment of a session's screen recording (GET /sessions/{id}/recording/video/segments/{first}).
export interface VideoRecordingSegment {
  sessionId: string;
  firstSequence: number;
  lastSequence: number;
  complete: boolean;
  frames: { timestamp: string; frameData: string; codec: string }[];
}

export interface RecordingPage {
  sessionId: string;
  entries: { timestamp: string; command: string }[];
  page: number;
  pageSize: number;
  totalEntries: number;
}
