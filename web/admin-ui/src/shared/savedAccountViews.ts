export type AccountProtocolFilter = "all" | "ssh" | "rdp" | "vnc";
export type AccountApprovalFilter = "all" | "required" | "not-required";
export type AccountIdentityFilter = "all" | "pinned" | "missing";
export type AccountRotationFilter = "all" | "due" | "failed";

export interface AccountViewFilters {
  protocol: AccountProtocolFilter;
  approval: AccountApprovalFilter;
  identity: AccountIdentityFilter;
  rotation: AccountRotationFilter;
}

export interface SavedAccountView {
  name: string;
  filters: AccountViewFilters;
}

export const savedAccountViewsKey = "openbastion.admin-ui.account-views.v1";

export const emptyAccountViewFilters: AccountViewFilters = {
  protocol: "all",
  approval: "all",
  identity: "all",
  rotation: "all",
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseFilters(value: unknown): AccountViewFilters | undefined {
  if (!isRecord(value)) return undefined;
  const protocol = ["all", "ssh", "rdp", "vnc"].includes(String(value.protocol))
    ? value.protocol as AccountProtocolFilter : undefined;
  const approval = ["all", "required", "not-required"].includes(String(value.approval))
    ? value.approval as AccountApprovalFilter : undefined;
  const identity = ["all", "pinned", "missing"].includes(String(value.identity))
    ? value.identity as AccountIdentityFilter : undefined;
  const rotation = ["all", "due", "failed"].includes(String(value.rotation))
    ? value.rotation as AccountRotationFilter : undefined;
  if (!protocol || !approval || !identity || !rotation) return undefined;
  return { protocol, approval, identity, rotation };
}

export function parseSavedAccountViews(value: unknown): SavedAccountView[] {
  if (!Array.isArray(value)) return [];
  const views: SavedAccountView[] = [];
  const names = new Set<string>();
  for (const item of value) {
    if (!isRecord(item) || typeof item.name !== "string") continue;
    const name = item.name.trim().slice(0, 32);
    const filters = parseFilters(item.filters);
    const normalized = name.toLocaleLowerCase("fr");
    if (name.length < 2 || !filters || names.has(normalized)) continue;
    names.add(normalized);
    views.push({ name, filters });
    if (views.length === 12) break;
  }
  return views;
}

export function readSavedAccountViews(storage?: Pick<Storage, "getItem">): SavedAccountView[] {
  try {
    const target = storage ?? (typeof window !== "undefined" ? window.localStorage : undefined);
    if (!target) return [];
    const raw = target.getItem(savedAccountViewsKey);
    if (!raw) return [];
    const envelope: unknown = JSON.parse(raw);
    if (!isRecord(envelope) || envelope.version !== 1) return [];
    return parseSavedAccountViews(envelope.views);
  } catch {
    return [];
  }
}

export function writeSavedAccountViews(
  views: SavedAccountView[],
  storage?: Pick<Storage, "setItem">,
): boolean {
  try {
    const target = storage ?? (typeof window !== "undefined" ? window.localStorage : undefined);
    if (!target) return false;
    const safeViews = parseSavedAccountViews(views);
    target.setItem(savedAccountViewsKey, JSON.stringify({ version: 1, views: safeViews }));
    return true;
  } catch {
    return false;
  }
}
