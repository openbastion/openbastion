import type { Account } from "./api";

export type AccountFilterField = "protocol" | "approval" | "identity" | "rotation";
export type AccountFilterComparison = "is" | "is-not";
export type AccountFilterJoin = "AND" | "OR";

export const accountFilterFields: readonly AccountFilterField[] = [
  "protocol", "approval", "identity", "rotation",
];
export const maxAccountFilterRules = accountFilterFields.length;

export interface AccountFilterRule {
  field: AccountFilterField;
  comparison: AccountFilterComparison;
  value: string;
  join: AccountFilterJoin;
}

export interface SavedAccountView {
  name: string;
  rules: AccountFilterRule[];
}

export const savedAccountViewsKey = "openbastion.admin-ui.account-views.v1";

const allowedValues: Record<AccountFilterField, readonly string[]> = {
  protocol: ["ssh", "rdp", "vnc"],
  approval: ["required", "not-required"],
  identity: ["pinned", "missing"],
  rotation: ["due", "failed", "none"],
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isAccountFilterField(value: unknown): value is AccountFilterField {
  return value === "protocol" || value === "approval" || value === "identity" || value === "rotation";
}

export function defaultAccountFilterValue(field: AccountFilterField): string {
  return allowedValues[field][0];
}

export function parseAccountFilterRules(value: unknown): AccountFilterRule[] | undefined {
  if (!Array.isArray(value) || value.length > maxAccountFilterRules) return undefined;
  const rules: AccountFilterRule[] = [];
  const usedFields = new Set<AccountFilterField>();
  for (const item of value) {
    if (!isRecord(item) || !isAccountFilterField(item.field)) return undefined;
    const comparison = item.comparison === "is-not" ? "is-not" : item.comparison === "is" ? "is" : undefined;
    const join = item.join === "OR" ? "OR" : item.join === "AND" ? "AND" : undefined;
    if (!comparison || !join || usedFields.has(item.field) || typeof item.value !== "string" || !allowedValues[item.field].includes(item.value)) return undefined;
    usedFields.add(item.field);
    rules.push({ field: item.field, comparison, value: item.value, join });
  }
  return rules;
}

function migrateLegacyFilters(value: unknown): AccountFilterRule[] | undefined {
  if (!isRecord(value)) return undefined;
  const legacy: Array<[AccountFilterField, string]> = [
    ["protocol", String(value.protocol ?? "all")],
    ["approval", String(value.approval ?? "all")],
    ["identity", String(value.identity ?? "all")],
    ["rotation", String(value.rotation ?? "all")],
  ];
  if (legacy.some(([field, selected]) => selected !== "all" && !allowedValues[field].includes(selected))) return undefined;
  return legacy.filter(([, selected]) => selected !== "all").map(([field, selected]) => ({
    field, comparison: "is", value: selected, join: "AND",
  }));
}

export function parseSavedAccountViews(value: unknown): SavedAccountView[] {
  if (!Array.isArray(value)) return [];
  const views: SavedAccountView[] = [];
  const names = new Set<string>();
  for (const item of value) {
    if (!isRecord(item) || typeof item.name !== "string") continue;
    const name = item.name.trim().slice(0, 32);
    const rules = item.rules !== undefined ? parseAccountFilterRules(item.rules) : migrateLegacyFilters(item.filters);
    const normalized = name.toLocaleLowerCase("fr");
    if (name.length < 2 || !rules || names.has(normalized)) continue;
    names.add(normalized);
    views.push({ name, rules });
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
    if (!isRecord(envelope) || (envelope.version !== 1 && envelope.version !== 2)) return [];
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
    target.setItem(savedAccountViewsKey, JSON.stringify({ version: 2, views: safeViews }));
    return true;
  } catch {
    return false;
  }
}

export function accountMatchesFilterRule(account: Account, rule: AccountFilterRule): boolean {
  const identityPinned = account.protocol === "ssh"
    ? Boolean(account.hostKeyFingerprint)
    : Boolean(account.tlsCertificateSha256);
  let matches = false;
  switch (rule.field) {
    case "protocol": matches = account.protocol === rule.value; break;
    case "approval": matches = rule.value === "required" ? Boolean(account.approvalRequired) : !account.approvalRequired; break;
    case "identity": matches = rule.value === "pinned" ? identityPinned : !identityPinned; break;
    case "rotation":
      matches = rule.value === "due" ? Boolean(account.rotationOwedSince)
        : rule.value === "failed" ? (account.rotationFailures ?? 0) > 0
          : !account.rotationOwedSince && (account.rotationFailures ?? 0) === 0;
      break;
  }
  return rule.comparison === "is-not" ? !matches : matches;
}

export function matchesAccountFilterRules(account: Account, rules: AccountFilterRule[]): boolean {
  if (rules.length === 0) return true;
  let result = accountMatchesFilterRule(account, rules[0]);
  for (const rule of rules.slice(1)) {
    const matches = accountMatchesFilterRule(account, rule);
    result = rule.join === "OR" ? result || matches : result && matches;
  }
  return result;
}
