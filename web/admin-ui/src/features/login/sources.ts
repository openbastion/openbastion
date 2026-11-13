import { useEffect, useState } from "react";
import { Api, ApiError } from "../../shared/api";

// A source the Gateway offers: a directory of the organisation (ADR-0061) or a provider of its
// identity federation (ADR-0035). With several, each is named by its id (ADR-0076).
export type Provider = { id: string; label: string };

// The second step of a login whose password was right, when its roles require a second factor
// (ADR-0062, ADR-0065): whichever of these factors the challenge accepts — for a strict role, the
// key only — or, not yet enrolled, the administrator's enrollment code.
export type Challenge = { kind: "required" | "enrollment_required"; challenge: string; factors: string[]; webauthn?: unknown };

// providers reads a listing of the Gateway; null when it does not give one (an older Gateway).
function providers(r: unknown, key: string): Provider[] | null {
  const list = (r as Record<string, unknown> | undefined)?.[key];
  if (!Array.isArray(list)) return null;
  return list.filter((p): p is Provider => typeof p?.id === "string" && typeof p?.label === "string");
}

// mfaChallenge: the challenge a login answers when the password was right and its roles require a
// second factor (ADR-0062) — a 401 that carries it — or null for any other refusal.
export function mfaChallenge(err: unknown): Challenge | null {
  if (!(err instanceof ApiError) || err.status !== 401) return null;
  const b = err.body as { mfa?: unknown; challenge?: unknown; factors?: unknown; webauthn?: unknown } | undefined;
  if ((b?.mfa === "required" || b?.mfa === "enrollment_required") && typeof b.challenge === "string") {
    const factors = Array.isArray(b.factors) ? (b.factors as string[]) : ["totp"]; // before ADR-0065: TOTP only
    return { kind: b.mfa, challenge: b.challenge, factors, webauthn: b.webauthn };
  }
  return null;
}

// Which sources the Gateway turns on. Unknown — an older Gateway, or any refusal — leaves the page
// as it was before their listing: local login only, one federated button.
export function useLoginSources(api: Api): { directories: Provider[]; oidc: Provider[] | null } {
  const [directories, setDirectories] = useState<Provider[]>([]);
  // null: the Gateway did not list its providers — one button, as before ADR-0076.
  const [oidc, setOidc] = useState<Provider[] | null>(null);

  useEffect(() => {
    let live = true;
    api
      .request<{ enabled: boolean; directories?: Provider[] }>("GET", "/auth/ldap")
      .then((r) => {
        if (!live || !r.enabled) return;
        // An older Gateway says enabled without the list: its one directory, of id "".
        setDirectories(providers(r, "directories") ?? [{ id: "", label: "" }]);
      })
      .catch(() => {}); // unknown: local login only, as before
    api
      .request<{ enabled: boolean; providers?: Provider[] }>("GET", "/auth/oidc")
      .then((r) => {
        if (!live) return;
        const list = providers(r, "providers");
        if (list !== null) setOidc(r.enabled ? list : []);
      })
      .catch(() => {}); // unknown: one button, as before
    return () => {
      live = false;
    };
  }, [api]);

  return { directories, oidc };
}
