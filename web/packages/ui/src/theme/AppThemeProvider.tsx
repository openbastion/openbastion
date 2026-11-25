import { createContext, ReactNode, useContext, useEffect, useState } from "react";

export type AppThemePreference = "light" | "dark" | "system";
export type AppEffectiveTheme = "light" | "dark";

export interface AppThemeSettings {
  /** The operator's choice; "system" follows `prefers-color-scheme`. Stored by the application. */
  theme: AppThemePreference;
  /** Free-form density token written to `data-density` (the application owns its vocabulary). */
  density: string;
}

const darkQuery = "(prefers-color-scheme: dark)";

/**
 * Applies the theme and density to the document root (`data-theme`, `data-density`) and returns the
 * resolved light/dark theme. The preference itself is not stored here: the application passes it.
 */
export function useAppTheme({ theme, density }: AppThemeSettings): AppEffectiveTheme {
  const [systemDark, setSystemDark] = useState(() => window.matchMedia?.(darkQuery).matches ?? false);
  const effective: AppEffectiveTheme = theme === "system" ? (systemDark ? "dark" : "light") : theme;

  useEffect(() => {
    const media = window.matchMedia?.(darkQuery);
    if (!media) return;
    const update = () => setSystemDark(media.matches);
    update();
    media.addEventListener?.("change", update);
    return () => media.removeEventListener?.("change", update);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = effective;
    return () => { delete document.documentElement.dataset.theme; };
  }, [effective]);

  useEffect(() => {
    document.documentElement.dataset.density = density;
    return () => { delete document.documentElement.dataset.density; };
  }, [density]);

  return effective;
}

const AppThemeContext = createContext<AppEffectiveTheme | null>(null);

export interface AppThemeProviderProps extends AppThemeSettings {
  children: ReactNode;
}

export function AppThemeProvider({ theme, density, children }: AppThemeProviderProps) {
  const effective = useAppTheme({ theme, density });
  return <AppThemeContext.Provider value={effective}>{children}</AppThemeContext.Provider>;
}

/** The resolved light/dark theme under an `AppThemeProvider`. */
export function useEffectiveTheme(): AppEffectiveTheme {
  const value = useContext(AppThemeContext);
  if (!value) throw new Error("useEffectiveTheme must be used inside AppThemeProvider");
  return value;
}
