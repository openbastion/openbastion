import type { Tab } from "./AppShell";
import type { Capabilities, Capability } from "../shared/capabilities";

// ADR-0131: a page that serves only some capabilities is absent when the caller has none of
// them. Pages not listed here are for everyone signed in (their reads are decided by the server).
const tabNeeds: Partial<Record<Tab, Capability[]>> = {
  accounts: ["accounts.list", "accounts.onboard", "policies.create", "sessions.approve"],
  posture: ["accounts.list"],
};

export function tabAllowed(capabilities: Capabilities, tab: Tab): boolean {
  const needs = tabNeeds[tab];
  return !needs || capabilities.visible(...needs);
}
