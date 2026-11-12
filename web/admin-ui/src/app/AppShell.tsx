import { ReactNode, useEffect, useRef, useState } from "react";
import { Audit, Policies as PoliciesIcon, Session, Users } from "@openbastion/icons";
import { TokenClaims } from "../shared/api";
import { BrandMark } from "../shared/BrandMark";
import { CommandPalette } from "../shared/ui/CommandPalette";

const tabs = {
  accounts: { label: "Comptes", description: "Comptes privilégiés", icon: Users, group: "Accès privilégiés" },
  policies: { label: "Politiques", description: "Politiques d'accès", icon: PoliciesIcon, group: "Accès privilégiés" },
  sessions: { label: "Sessions", description: "Sessions privilégiées", icon: Session, group: "Opérations" },
  audit: { label: "Enregistrements", description: "Enregistrements de sessions", icon: Audit, group: "Opérations" },
} as const;

export type Tab = keyof typeof tabs;

type Theme = "light" | "dark";

// Navigation contains only capabilities backed by an implemented Admin UI screen and public API.
export function AppShell({
  who,
  tab,
  onTab,
  onSignOut,
  onFindSession,
  children,
}: {
  who: TokenClaims | null;
  tab: Tab;
  onTab: (tab: Tab) => void;
  onSignOut: () => void;
  onFindSession: (id: string) => void;
  children: ReactNode;
}) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [theme, setTheme] = useState<Theme>(() =>
    window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light",
  );
  const menuButton = useRef<HTMLButtonElement>(null);
  const paletteButton = useRef<HTMLButtonElement>(null);
  const paletteWasOpen = useRef(false);
  const initials = who?.username ? who.username.replace(/^oidc:/, "").slice(0, 2).toUpperCase() : "?";

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    return () => {
      delete document.documentElement.dataset.theme;
    };
  }, [theme]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen(true);
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    if (paletteWasOpen.current && !paletteOpen) paletteButton.current?.focus();
    paletteWasOpen.current = paletteOpen;
  }, [paletteOpen]);

  useEffect(() => {
    if (!mobileOpen) return;
    const firstItem = document.querySelector<HTMLElement>(".app-sidebar nav button");
    firstItem?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setMobileOpen(false);
        menuButton.current?.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [mobileOpen]);

  const chooseTab = (next: Tab) => {
    onTab(next);
    setMobileOpen(false);
    menuButton.current?.focus();
  };

  return (
    <>
      <a className="skip-link" href="#main-content">Aller au contenu principal</a>
      <header className="app-header">
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
            onClick={() => setTheme((current) => (current === "light" ? "dark" : "light"))}
            aria-label={theme === "light" ? "Activer le thème sombre" : "Activer le thème clair"}
            aria-pressed={theme === "dark"}
          >
            <span aria-hidden="true">{theme === "light" ? "◐" : "☀"}</span>
            <span className="theme-toggle-label">{theme === "light" ? "Thème sombre" : "Thème clair"}</span>
          </button>
          <div className="session-chip">
            <span className="avatar" aria-hidden="true">{initials}</span>
            <span className="who">{who?.username} {who?.roles.length ? `(${who.roles.join(", ")})` : ""}</span>
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
      <div className={`app-workspace${collapsed ? " sidebar-collapsed" : ""}${mobileOpen ? " mobile-navigation-open" : ""}`}>
        {mobileOpen && (
          <button
            type="button"
            className="navigation-backdrop"
            aria-label="Fermer le panneau de navigation"
            onClick={() => {
              setMobileOpen(false);
              menuButton.current?.focus();
            }}
          />
        )}
        <aside id="admin-navigation" className="app-sidebar" aria-label="Navigation principale">
          <div className="sidebar-heading">
            <span className="sidebar-heading-label">ESPACE DE TRAVAIL</span>
            <button
              type="button"
              className="sidebar-collapse-toggle"
              aria-label={collapsed ? "Développer la navigation" : "Réduire la navigation"}
              aria-controls="admin-navigation"
              aria-expanded={!collapsed}
              onClick={() => setCollapsed((value) => !value)}
            >
              <span aria-hidden="true">{collapsed ? "›" : "‹"}</span>
            </button>
          </div>
          <nav aria-label="Sections">
            {(["Accès privilégiés", "Opérations"] as const).map((group) => (
              <div className="nav-group" key={group}>
                <h2 className="nav-group-title">{group}</h2>
                {(Object.keys(tabs) as Tab[]).filter((key) => tabs[key].group === group).map((key) => {
                  const Icon = tabs[key].icon;
                  return (
                    <button
                      type="button"
                      key={key}
                      className="nav-item"
                      aria-current={tab === key ? "page" : undefined}
                      aria-label={tabs[key].label}
                      title={collapsed ? tabs[key].description : undefined}
                      onClick={() => chooseTab(key)}
                    >
                      <Icon size={18} />
                      <span className="nav-item-label">{tabs[key].label}</span>
                    </button>
                  );
                })}
              </div>
            ))}
          </nav>
          <div className="sidebar-footer">
            <span className="sidebar-status-dot" aria-hidden="true" />
            <span className="sidebar-status-label">Console d'administration</span>
          </div>
        </aside>
        <main id="main-content" className="app-main" tabIndex={-1}>
          {children}
        </main>
      </div>
    </>
  );
}
