export type AdminTab = "overview" | "accounts" | "policies" | "sessions" | "audit" | "security";
export type ThemePreference = "system" | "light" | "dark";
export type DensityPreference = "comfortable" | "compact";

export interface OperatorPreferences {
  theme: ThemePreference;
  density: DensityPreference;
  sidebarCollapsed: boolean;
  defaultTab: AdminTab;
  favorites: AdminTab[];
}

export const operatorPreferencesKey = "openbastion.admin-ui.preferences.v1";

export const defaultOperatorPreferences: OperatorPreferences = {
  theme: "system",
  density: "comfortable",
  sidebarCollapsed: false,
  defaultTab: "overview",
  favorites: [],
};

const tabs = new Set<AdminTab>(["overview", "accounts", "policies", "sessions", "audit", "security"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseOperatorPreferences(value: unknown): OperatorPreferences {
  if (!isRecord(value) || value.version !== 1 || !isRecord(value.preferences)) {
    return { ...defaultOperatorPreferences };
  }
  const candidate = value.preferences;
  const favorites = Array.isArray(candidate.favorites)
    ? [...new Set(candidate.favorites.filter((item): item is AdminTab => typeof item === "string" && tabs.has(item as AdminTab)))]
    : [];
  return {
    theme: candidate.theme === "light" || candidate.theme === "dark" || candidate.theme === "system"
      ? candidate.theme
      : defaultOperatorPreferences.theme,
    density: candidate.density === "compact" || candidate.density === "comfortable"
      ? candidate.density
      : defaultOperatorPreferences.density,
    sidebarCollapsed: typeof candidate.sidebarCollapsed === "boolean"
      ? candidate.sidebarCollapsed
      : defaultOperatorPreferences.sidebarCollapsed,
    defaultTab: typeof candidate.defaultTab === "string" && tabs.has(candidate.defaultTab as AdminTab)
      ? candidate.defaultTab as AdminTab
      : defaultOperatorPreferences.defaultTab,
    favorites,
  };
}

// Preferences contain presentation choices and navigation identifiers only. They never contain
// credentials, tokens, session IDs, resource names or free-text search terms.
export function readOperatorPreferences(storage?: Pick<Storage, "getItem">): OperatorPreferences {
  try {
    const target = storage ?? (typeof window !== "undefined" ? window.localStorage : undefined);
    if (!target) return { ...defaultOperatorPreferences };
    const raw = target.getItem(operatorPreferencesKey);
    if (!raw) return { ...defaultOperatorPreferences };
    return parseOperatorPreferences(JSON.parse(raw) as unknown);
  } catch {
    return { ...defaultOperatorPreferences };
  }
}

export function writeOperatorPreferences(
  preferences: OperatorPreferences,
  storage?: Pick<Storage, "setItem">,
): boolean {
  try {
    const target = storage ?? (typeof window !== "undefined" ? window.localStorage : undefined);
    if (!target) return false;
    target.setItem(operatorPreferencesKey, JSON.stringify({ version: 1, preferences }));
    return true;
  } catch {
    return false;
  }
}
