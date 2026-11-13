import { ReactNode, useEffect, useRef, useState } from "react";
import { Audit, Dashboard, Policies as PoliciesIcon, Session, Settings, Shield, Users } from "@openbastion/icons";
import { TokenClaims } from "../shared/api";
import {
  OperatorPreferences,
  readOperatorPreferences,
  writeOperatorPreferences,
} from "../shared/operatorPreferences";
import { BrandMark } from "../shared/BrandMark";
import { CommandPalette } from "../shared/ui/CommandPalette";
import { OperatorPreferencesDialog } from "../shared/ui/OperatorPreferencesDialog";

const tabs = {
  overview: { label: "Vue générale", description: "Synthèse opérationnelle", icon: Dashboard, group: "Pilotage" },
  accounts: { label: "Comptes", description: "Comptes privilégiés", icon: Users, group: "Accès privilégiés" },
  policies: { label: "Politiques", description: "Politiques d'accès", icon: PoliciesIcon, group: "Accès privilégiés" },
  sessions: { label: "Sessions", description: "Sessions privilégiées", icon: Session, group: "Opérations" },
  audit: { label: "Enregistrements", description: "Enregistrements de sessions", icon: Audit, group: "Opérations" },
  security: { label: "Centre de sécurité", description: "Posture des comptes", icon: Shield, group: "Sécurité" },
} as const;

export type Tab = keyof typeof tabs;
const tabOrder: Tab[] = ["overview", "accounts", "policies", "sessions", "audit", "security"];

function isTextEntry(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return target.isContentEditable || target.closest("input, textarea, select, [contenteditable=true]") !== null;
}

// Navigation contains only capabilities backed by an implemented Admin UI screen and public API.
export function AppShell({
  who,
  tab,
  onTab,
  onDefaultTabChange,
  onSignOut,
  onFindSession,
  children,
}: {
  who: TokenClaims | null;
  tab: Tab;
  onTab: (tab: Tab) => void;
  onDefaultTabChange?: (tab: Tab) => void;
  onSignOut: () => void;
  onFindSession: (id: string) => void;
  children: ReactNode;
}) {
  const [preferences, setPreferences] = useState<OperatorPreferences>(readOperatorPreferences);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [preferencesOpen, setPreferencesOpen] = useState(false);
  const [systemDark, setSystemDark] = useState(() => window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false);
  const menuButton = useRef<HTMLButtonElement>(null);
  const paletteButton = useRef<HTMLButtonElement>(null);
  const preferencesButton = useRef<HTMLButtonElement>(null);
  const mainRef = useRef<HTMLElement>(null);
  const sidebarRef = useRef<HTMLElement>(null);
  const mobileWasOpen = useRef(false);
  const paletteWasOpen = useRef(false);
  const preferencesWereOpen = useRef(false);
  const initials = who?.username ? who.username.replace(/^oidc:/, "").slice(0, 2).toUpperCase() : "?";
  const collapsed = preferences.sidebarCollapsed;
  const favoriteTabs = tabOrder.filter((key) => preferences.favorites.includes(key));

  function updatePreferences(next: OperatorPreferences): boolean {
    setPreferences(next);
    return writeOperatorPreferences(next);
  }

  function savePreferences(next: OperatorPreferences): boolean {
    if (!writeOperatorPreferences(next)) return false;
    setPreferences(next);
    return true;
  }

  function toggleFavorite(key: Tab) {
    const favorites = preferences.favorites.includes(key)
      ? preferences.favorites.filter((item) => item !== key)
      : [...preferences.favorites, key];
    updatePreferences({ ...preferences, favorites });
  }

  function chooseTab(next: Tab) {
    onTab(next);
    setMobileOpen(false);
  }

  function effectiveTheme(): "light" | "dark" {
    if (preferences.theme !== "system") return preferences.theme;
    return systemDark ? "dark" : "light";
  }

  useEffect(() => {
    const media = window.matchMedia?.("(prefers-color-scheme: dark)");
    if (!media) return;
    const update = () => setSystemDark(media.matches);
    update();
    media.addEventListener?.("change", update);
    return () => media.removeEventListener?.("change", update);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = preferences.theme === "system"
      ? systemDark ? "dark" : "light"
      : preferences.theme;
    return () => { delete document.documentElement.dataset.theme; };
  }, [preferences.theme, systemDark]);

  useEffect(() => {
    document.documentElement.dataset.density = preferences.density;
    return () => { delete document.documentElement.dataset.density; };
  }, [preferences.density]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen(true);
        return;
      }
      if (isTextEntry(event.target) || paletteOpen || preferencesOpen) return;
      if (event.altKey && event.shiftKey && /^[1-6]$/.test(event.key)) {
        event.preventDefault();
        chooseTab(tabOrder[Number(event.key) - 1]);
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onTab, paletteOpen, preferencesOpen]);

  useEffect(() => {
    mainRef.current?.focus();
  }, [tab]);

  useEffect(() => {
    if (paletteWasOpen.current && !paletteOpen) paletteButton.current?.focus();
    paletteWasOpen.current = paletteOpen;
  }, [paletteOpen]);

  useEffect(() => {
    if (preferencesWereOpen.current && !preferencesOpen) preferencesButton.current?.focus();
    preferencesWereOpen.current = preferencesOpen;
  }, [preferencesOpen]);

  useEffect(() => {
    if (mobileWasOpen.current && !mobileOpen) menuButton.current?.focus();
    mobileWasOpen.current = mobileOpen;
  }, [mobileOpen]);

  useEffect(() => {
    if (!mobileOpen) return;
    const sidebar = sidebarRef.current;
    const focusable = () => Array.from(sidebar?.querySelectorAll<HTMLElement>(
      'button:not([disabled]):not(.sidebar-collapse-toggle), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    ) ?? []);
    focusable()[0]?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setMobileOpen(false);
        return;
      }
      if (event.key !== "Tab") return;
      const items = focusable();
      if (items.length === 0) {
        event.preventDefault();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && (document.activeElement === first || !sidebar?.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !sidebar?.contains(document.activeElement))) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [mobileOpen]);

  function renderNavItem(key: Tab) {
    const Icon = tabs[key].icon;
    const favorite = preferences.favorites.includes(key);
    return (
      <div className="nav-entry" key={key}>
        <button
          type="button"
          className="nav-item"
          aria-label={tabs[key].label}
          aria-current={tab === key ? "page" : undefined}
          title={collapsed ? `${tabs[key].label} — ${tabs[key].description}` : undefined}
          onClick={() => chooseTab(key)}
        >
          <Icon size={18} />
          <span className="nav-item-label">{tabs[key].label}</span>
        </button>
        <button
          type="button"
          className="nav-favorite-toggle"
          aria-label={(favorite ? "Retirer " : "Ajouter ") + tabs[key].label + (favorite ? " des favoris" : " aux favoris")}
          aria-pressed={favorite}
          title={favorite ? "Retirer des favoris" : "Ajouter aux favoris"}
          onClick={() => toggleFavorite(key)}
        >
          <span aria-hidden="true">{favorite ? "★" : "☆"}</span>
        </button>
      </div>
    );
  }

  return (
    <>
      <a className="skip-link" href="#main-content" inert={mobileOpen}>Aller au contenu principal</a>
      <header className="app-header" inert={mobileOpen}>
        <div className="brand">
          <BrandMark />
          <span className="brand-name">OpenBastion</span>
          <span className="brand-tag">Admin</span>
        </div>
        <div className="header-actions">
          <button
            ref={paletteButton}
            type="button"
            className="command-trigger"
            onClick={() => setPaletteOpen(true)}
            aria-haspopup="dialog"
            aria-keyshortcuts="Control+K Meta+K"
            aria-label="Ouvrir la recherche et les commandes"
          >
            <span aria-hidden="true">⌕</span>
            <span>Rechercher</span>
            <kbd>Ctrl K</kbd>
          </button>
          <button
            ref={preferencesButton}
            type="button"
            className="preferences-trigger"
            onClick={() => setPreferencesOpen(true)}
            aria-haspopup="dialog"
            aria-label="Ouvrir les préférences"
          >
            <Settings size={17} />
            <span>Préférences</span>
          </button>
          <button
            ref={menuButton}
            type="button"
            className="icon-button mobile-menu-toggle"
            aria-label={mobileOpen ? "Fermer la navigation" : "Ouvrir la navigation"}
            aria-expanded={mobileOpen}
            aria-controls="admin-navigation"
            onClick={() => setMobileOpen((open) => !open)}
          >
            <span aria-hidden="true">☰</span>
          </button>
          <button
            type="button"
            className="theme-toggle"
            onClick={() => updatePreferences({ ...preferences, theme: effectiveTheme() === "light" ? "dark" : "light" })}
            aria-label={effectiveTheme() === "light" ? "Activer le thème sombre" : "Activer le thème clair"}
            aria-pressed={effectiveTheme() === "dark"}
          >
            <span aria-hidden="true">{effectiveTheme() === "light" ? "◐" : "☀"}</span>
            <span className="theme-toggle-label">{effectiveTheme() === "light" ? "Thème sombre" : "Thème clair"}</span>
          </button>
          <div className="session-chip">
            <span className="avatar" aria-hidden="true">{initials}</span>
            <span className="who" title={who ? `${who.username}${who.roles.length ? " (" + who.roles.join(", ") + ")" : ""}` : undefined}>
              {who?.username} {who?.roles.length ? "(" + who.roles.join(", ") + ")" : ""}
            </span>
            <button type="button" className="ghost" onClick={onSignOut}>Se déconnecter</button>
          </div>
        </div>
      </header>
      {paletteOpen ? (
        <CommandPalette
          onClose={() => setPaletteOpen(false)}
          onNavigate={chooseTab}
          onFindSession={onFindSession}
        />
      ) : null}
      {preferencesOpen ? (
        <OperatorPreferencesDialog
          preferences={preferences}
          onClose={() => setPreferencesOpen(false)}
          onSave={(next) => {
            const stored = savePreferences(next);
            if (stored && next.defaultTab !== preferences.defaultTab) onDefaultTabChange?.(next.defaultTab);
            return stored;
          }}
        />
      ) : null}
      <div className={"app-workspace" + (collapsed ? " sidebar-collapsed" : "") + (mobileOpen ? " mobile-navigation-open" : "")}>
        {mobileOpen && (
          <button
            type="button"
            className="navigation-backdrop"
            aria-hidden="true"
            tabIndex={-1}
            onClick={() => setMobileOpen(false)}
          />
        )}
        <aside
          ref={sidebarRef}
          id="admin-navigation"
          className="app-sidebar"
          aria-label="Navigation principale"
          role={mobileOpen ? "dialog" : undefined}
          aria-modal={mobileOpen ? "true" : undefined}
        >
          <div className="sidebar-heading">
            <span className="sidebar-heading-label">ESPACE DE TRAVAIL</span>
            <button
              type="button"
              className="sidebar-collapse-toggle"
              aria-label={collapsed ? "Développer la navigation" : "Réduire la navigation"}
              aria-controls="admin-navigation"
              aria-expanded={!collapsed}
              onClick={() => updatePreferences({ ...preferences, sidebarCollapsed: !collapsed })}
            >
              <span aria-hidden="true">{collapsed ? "›" : "‹"}</span>
            </button>
          </div>
          <nav aria-label="Sections">
            {favoriteTabs.length > 0 ? (
              <div className="nav-group">
                <h2 className="nav-group-title">Favoris</h2>
                {favoriteTabs.map(renderNavItem)}
              </div>
            ) : null}
            {(["Pilotage", "Accès privilégiés", "Opérations", "Sécurité"] as const).map((group) => (
              <div className="nav-group" key={group}>
                <h2 className="nav-group-title">{group}</h2>
                {tabOrder.filter((key) => tabs[key].group === group).map(renderNavItem)}
              </div>
            ))}
          </nav>
          <div className="sidebar-footer">
            <span className="sidebar-status-dot" aria-hidden="true" />
            <span className="sidebar-status-label">Console d'administration</span>
          </div>
        </aside>
        <main ref={mainRef} id="main-content" className="app-main" tabIndex={-1} inert={mobileOpen}>
          {children}
        </main>
      </div>
    </>
  );
}
