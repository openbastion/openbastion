import {
  Dashboard,
  Infrastructure,
  Security,
  Session,
  Settings,
  Shield,
  Users,
} from "@openbastion/icons";
import type { Capabilities, Capability } from "../shared/capabilities";
import type { AdminTab } from "../shared/operatorPreferences";

// ADR-0137 §3: the ONE declaration of the Admin UI destinations. The sidebar, the command
// palette, the shortcuts (Alt+Shift+1..6) and the route table all derive from it; there is no
// second navigation table.
//
// The identifiers are the stored ones (favorites and default screen live in localStorage, v1):
// `security` is the Audit & compliance page and `posture` the security centre, the inverse of
// their URLs. Renaming them needs a preference migration and is left to a later increment.
export type Tab = AdminTab;

export interface Destination {
  id: Tab;
  // Path below the router basename (`/ui/` served by the Gateway, `/` in the preview).
  path: string;
  icon: typeof Dashboard;
  group: "workspace";
  // ADR-0131: capabilities of which the caller needs at least one; absent = every signed-in caller.
  needs?: Capability[];
  // Sub-routes (the tabs of the page), the first being the default one: `/access` redirects to
  // `/access/resources`. Absent = the destination has no sub-route.
  views?: readonly DestinationView[];
}

export interface DestinationView {
  id: string;
  // Capabilities of which the caller needs at least one to open this view; absent = the destination's.
  needs?: Capability[];
}

// Sidebar order: Vue d'ensemble, Accès privilégiés, Sessions, Infrastructure, Audit & conformité,
// Sécurité, Paramètres. Policies and the recording screen are tabs of those pages, not destinations.
export const destinations: readonly Destination[] = [
  { id: "overview", path: "/overview", icon: Dashboard, group: "workspace" },
  {
    id: "accounts",
    path: "/access",
    icon: Users,
    group: "workspace",
    needs: ["accounts.list", "accounts.onboard", "policies.create", "sessions.approve"],
    views: [
      { id: "resources", needs: ["accounts.list"] },
      { id: "accounts", needs: ["accounts.list"] },
      { id: "policies", needs: ["policies.create"] },
      { id: "requests", needs: ["sessions.approve"] },
      { id: "hierarchy", needs: ["approvalHierarchy.read", "approvalHierarchy.manage", "approvalHierarchy.reports"] },
    ],
  },
  {
    id: "sessions",
    path: "/sessions",
    icon: Session,
    group: "workspace",
    views: [{ id: "live" }, { id: "history" }, { id: "recordings", needs: ["recordings.read"] }, { id: "alerts" }],
  },
  { id: "infrastructure", path: "/infrastructure", icon: Infrastructure, group: "workspace" },
  {
    id: "security",
    path: "/audit",
    icon: Shield,
    group: "workspace",
    views: [{ id: "journal" }, { id: "reports" }, { id: "evidence" }, { id: "retention" }],
  },
  { id: "posture", path: "/security", icon: Security, group: "workspace", needs: ["accounts.list"] },
  {
    id: "settings",
    path: "/settings",
    icon: Settings,
    group: "workspace",
    views: [{ id: "general" }, { id: "security" }, { id: "identities" }, { id: "integrations" }, { id: "notifications" }],
  },
];

export const groups = ["workspace"] as const;
export const tabOrder: Tab[] = destinations.map((destination) => destination.id);

export function destinationOf(tab: Tab): Destination {
  return destinations.find((destination) => destination.id === tab)!;
}

export function tabPath(tab: Tab): string {
  return destinationOf(tab).path;
}

// The destination whose path is the first segment of `pathname` (sub-routes arrive with the
// following increments); undefined for an unknown address, which the router answers with a 404.
export function tabFromPath(pathname: string): Tab | undefined {
  const [, first = "", second] = pathname.split("/");
  const destination = destinations.find((candidate) => candidate.path === `/${first}`);
  // An unknown tab of a destination is an unknown address (404), not that destination.
  if (destination && second && destination.views && !destination.views.some((view) => view.id === second)) return undefined;
  return destination?.id;
}

export function tabAllowed(capabilities: Capabilities, tab: Tab): boolean {
  const needs = destinationOf(tab).needs;
  return !needs || capabilities.visible(...needs);
}

export function tabNeeds(tab: Tab): Capability[] {
  return destinationOf(tab).needs ?? [];
}

// The sub-route of a destination (undefined when the destination has none or the id is unknown,
// which the router answers with a 404).
export function viewOf(tab: Tab, view: string | undefined): DestinationView | undefined {
  return destinationOf(tab).views?.find((candidate) => candidate.id === view);
}

export function viewPath(tab: Tab, view: string): string {
  return `${tabPath(tab)}/${view}`;
}

// react-router wants a basename without trailing slash: Vite's BASE_URL is `/ui/` or `/`.
export const routerBasename = import.meta.env.BASE_URL.replace(/\/$/, "") || "/";
