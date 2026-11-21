import { createContext, useContext } from "react";

// ADR-0131: what the caller's policies open to them in the Admin UI, as GET /auth/me/capabilities
// says. A picture of the policies, never a grant: every action is still decided by the server on
// its own resource. The page uses it two ways (the owner's rule, 2026-11-20):
//
//   - a page or a tab with nothing for the caller is absent (`visible`);
//   - an action the caller may not take is shown greyed, with what it needs (`can`).
//
// Fail closed for actions: while the capabilities load, or when they could not be read, `can`
// is false and every gated action is greyed. Pages stay visible then (`visible` is true): their
// reads are refused by the server anyway, and an empty navigation would hide the reason.

export const capabilityNames = [
  "accounts.list",
  "accounts.onboard",
  "accounts.rotate",
  "accounts.disable",
  "accounts.pin",
  "accounts.approval",
  "accounts.screenProfile",
  "accounts.kerberos",
  "policies.create",
  "sessions.create",
  "sessions.breakglass",
  "sessions.approve",
  "sessions.read",
  "sessions.terminate",
  "secrets.inject",
  "recordings.read",
  "audit.secretInjections",
] as const;

export type Capability = (typeof capabilityNames)[number];

export type CapabilityStatus = "loading" | "ready" | "unavailable";

export interface Capabilities {
  status: CapabilityStatus;
  // can: may the caller take this action? False unless the server said so.
  can: (name: Capability) => boolean;
  // visible: should a page or tab that serves only these capabilities be shown? True while the
  // answer is unknown, and when any of them is allowed.
  visible: (...names: Capability[]) => boolean;
}

export function capabilitiesFrom(status: CapabilityStatus, granted: Partial<Record<string, boolean>> = {}): Capabilities {
  const can = (name: Capability) => status === "ready" && granted[name] === true;
  return {
    status,
    can,
    visible: (...names) => status !== "ready" || names.some(can),
  };
}

// Outside a provider (a screen rendered on its own, in a unit test) nothing is gated: the App
// always provides the caller's capabilities, and the server decides every action in any case.
const unrestricted: Capabilities = { status: "ready", can: () => true, visible: () => true };

export const CapabilitiesContext = createContext<Capabilities>(unrestricted);

export function useCapabilities(): Capabilities {
  return useContext(CapabilitiesContext);
}

// parseCapabilities keeps only the known names whose value is a boolean: anything else from the
// server is ignored, never taken as a grant.
export function parseCapabilities(body: unknown): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  const caps = (body as { capabilities?: unknown } | null)?.capabilities;
  if (!caps || typeof caps !== "object") return out;
  for (const name of capabilityNames) {
    const value = (caps as Record<string, unknown>)[name];
    if (typeof value === "boolean") out[name] = value;
  }
  return out;
}
