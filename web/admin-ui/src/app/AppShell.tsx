import { ReactNode, useEffect, useLayoutEffect, useRef, useState } from "react";
import { AppMobileNavigation, AppUserMenu, useAppDismissable, useAppShortcuts, useAppTheme } from "@openbastion/ui";
import {
  ApiDocumentation,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Dashboard,
  HelpCircle,
  Infrastructure,
  Menu,
  Moon,
  Notifications,
  Search,
  Session,
  Security,
  Settings,
  Shield,
  Star,
  StarFilled,
  Sun,
  Users,
} from "@openbastion/icons";
import { TokenClaims } from "../shared/api";
import {
  OperatorPreferences,
  readOperatorPreferences,
  writeOperatorPreferences,
} from "../shared/operatorPreferences";
import { BrandMark } from "../shared/BrandMark";
import { CommandPalette } from "../shared/ui/CommandPalette";
import { OperatorPreferencesDialog } from "../shared/ui/OperatorPreferencesDialog";
import { LanguageSwitcher } from "../shared/ui/LanguageSwitcher";
import { useAppTranslation } from "../shared/i18n";
import { LegalNotice } from "../shared/LegalNotice";
import { useCapabilities } from "../shared/capabilities";
import { tabAllowed } from "./tabAccess";
import { InlineNotice } from "../shared/ui/InlineNotice";

// Labels and descriptions live in the translation files (locales/*.ts), one key per tab: the
// navigation is translated like the screens it opens, and the groups keep the same order.
const tabs = {
  overview: { icon: Dashboard, group: "workspace" },
  accounts: { icon: Users, group: "workspace" },
  sessions: { icon: Session, group: "workspace" },
  infrastructure: { icon: Infrastructure, group: "workspace" },
  security: { icon: Shield, group: "workspace" },
  posture: { icon: Security, group: "workspace" },
  settings: { icon: Settings, group: "workspace" },
} as const;

const groups = ["workspace"] as const;

export type Tab = keyof typeof tabs;
// The reference sidebar order (Vue d'ensemble, Accès privilégiés, Sessions, Infrastructure,
// Audit & conformité, Paramètres). Policies and the recording screen are tabs of those pages,
// not destinations of their own.
const tabOrder: Tab[] = [
  "overview",
  "accounts",
  "sessions",
  "infrastructure",
  "security",
  "posture",
  "settings",
];

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
  const { t } = useAppTranslation();
  const capabilities = useCapabilities();
  const shownTabs = tabOrder.filter((key) => tabAllowed(capabilities, key));
  const [preferences, setPreferences] = useState<OperatorPreferences>(readOperatorPreferences);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [preferencesOpen, setPreferencesOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [workspaceMenuOpen, setWorkspaceMenuOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const theme = useAppTheme({ theme: preferences.theme, density: preferences.density });
  const menuButton = useRef<HTMLButtonElement>(null);
  const paletteButton = useRef<HTMLButtonElement>(null);
  const userMenuButton = useRef<HTMLButtonElement>(null);
  const notificationsRef = useRef<HTMLDivElement>(null);
  const notificationsButton = useRef<HTMLButtonElement>(null);
  const mainRef = useRef<HTMLElement>(null);
  const sidebarRef = useRef<HTMLElement>(null);
  const paletteWasOpen = useRef(false);
  const preferencesWereOpen = useRef(false);
  const initials = who?.username ? who.username.replace(/^oidc:/, "").slice(0, 2).toUpperCase() : "?";
  const collapsed = preferences.sidebarCollapsed;
  const favoriteTabs = shownTabs.filter((key) => preferences.favorites.includes(key));

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

  useAppShortcuts({
    onCommandPalette: () => setPaletteOpen(true),
    onDestination: (index) => {
      const next = tabOrder[index];
      if (next && tabAllowed(capabilities, next)) chooseTab(next);
    },
    destinationCount: 6,
    suspended: paletteOpen || preferencesOpen,
  });

  // A layout effect: it must run before the passive focus restorations of the child components
  // (mobile navigation, user menu), which come after a navigation and win when both apply.
  useLayoutEffect(() => {
    mainRef.current?.focus();
  }, [tab]);

  useEffect(() => {
    if (paletteWasOpen.current && !paletteOpen) paletteButton.current?.focus();
    paletteWasOpen.current = paletteOpen;
  }, [paletteOpen]);

  useEffect(() => {
    if (preferencesWereOpen.current && !preferencesOpen) userMenuButton.current?.focus();
    preferencesWereOpen.current = preferencesOpen;
  }, [preferencesOpen]);

  useEffect(() => {
    if (!workspaceMenuOpen) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setWorkspaceMenuOpen(false);
    };
    const closeOnOutsidePointer = (event: PointerEvent) => {
      if (event.target instanceof Element && !event.target.closest(".sidebar-workspace-selector")) setWorkspaceMenuOpen(false);
    };
    document.addEventListener("keydown", closeOnEscape);
    document.addEventListener("pointerdown", closeOnOutsidePointer);
    return () => {
      document.removeEventListener("keydown", closeOnEscape);
      document.removeEventListener("pointerdown", closeOnOutsidePointer);
    };
  }, [workspaceMenuOpen]);

  useAppDismissable({
    open: notificationsOpen,
    onClose: () => setNotificationsOpen(false),
    containerRef: notificationsRef,
    onEscape: () => {
      setNotificationsOpen(false);
      notificationsButton.current?.focus();
    },
  });

  function renderNavItem(key: Tab) {
    const Icon = tabs[key].icon;
    const favorite = preferences.favorites.includes(key);
    const label = t(`shell.nav.${key}.label`);
    return (
      <div className="nav-entry" key={key}>
        <button
          type="button"
          className="nav-item"
          aria-label={label}
          aria-current={tab === key ? "page" : undefined}
          title={collapsed ? `${label} — ${t(`shell.nav.${key}.description`)}` : undefined}
          onClick={() => chooseTab(key)}
        >
          <Icon size={18} />
          <span className="nav-item-label">{label}</span>
        </button>
        <button
          type="button"
          className="nav-favorite-toggle"
          aria-label={t(favorite ? "shell.removeFavorite" : "shell.addFavorite", { label })}
          aria-pressed={favorite}
          title={t(favorite ? "shell.favoriteTitle.remove" : "shell.favoriteTitle.add")}
          onClick={() => toggleFavorite(key)}
        >
          {favorite ? <StarFilled size={15} /> : <Star size={15} />}
        </button>
      </div>
    );
  }

  return (
    <>
      <a className="skip-link" href="#main-content" inert={mobileOpen}>{t("shell.skipToContent")}</a>
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
        <AppMobileNavigation
          open={mobileOpen}
          onClose={() => setMobileOpen(false)}
          containerRef={sidebarRef}
          returnFocusRef={menuButton}
          excludeSelector=".sidebar-collapse-toggle"
        />
        <aside
          ref={sidebarRef}
          id="admin-navigation"
          className="app-sidebar"
          aria-label={t("shell.navigation.main")}
          role={mobileOpen ? "dialog" : undefined}
          aria-modal={mobileOpen ? "true" : undefined}
        >
          <div className="sidebar-brand">
            <BrandMark />
            <span className="sidebar-brand-copy">
              <strong>OpenBastion</strong>
              <small>{t("shell.sidebar.brandTag")}</small>
            </span>
            <button
              type="button"
              className="sidebar-collapse-toggle"
              aria-label={collapsed ? t("shell.sidebar.expand") : t("shell.sidebar.collapse")}
              aria-controls="admin-navigation"
              aria-expanded={!collapsed}
              onClick={() => updatePreferences({ ...preferences, sidebarCollapsed: !collapsed })}
            >
              {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
            </button>
          </div>
          <div className="sidebar-workspace-selector">
            <span className="sidebar-workspace-label">{t("shell.sidebar.workspace")}</span>
            <button
              type="button"
              className="sidebar-workspace-card"
              aria-expanded={workspaceMenuOpen}
              aria-controls="workspace-menu"
              onClick={() => setWorkspaceMenuOpen((open) => !open)}
            >
              <span className="workspace-environment-mark" aria-hidden="true" />
              <span className="sidebar-workspace-copy">
                <strong>{t("shell.environment.production")}</strong>
                <small>{t("shell.sidebar.workspaceContext")}</small>
              </span>
              <ChevronDown className="workspace-selector-chevron" size={16} />
            </button>
            {workspaceMenuOpen ? (
              <div className="workspace-menu" id="workspace-menu" role="region" aria-label={t("shell.environment.menuLabel")}>
                <span className="workspace-menu-caption">{t("shell.environment.configured")}</span>
                <span className="workspace-menu-current"><span className="workspace-environment-mark" aria-hidden="true" />{t("shell.environment.production")}<Check size={15} /></span>
                <p>{t("shell.environment.singleWorkspace")}</p>
              </div>
            ) : null}
          </div>
          <nav aria-label={t("shell.navigation.sections")}>
            {favoriteTabs.length > 0 ? (
              <div className="nav-group">
                <h2 className="nav-group-title">{t("shell.favorites")}</h2>
                {favoriteTabs.map(renderNavItem)}
              </div>
            ) : null}
            {groups.map((group) => (
              <div className="nav-group" key={group}>
                <h2 className="nav-group-title">{t(`shell.groups.${group}`)}</h2>
                {shownTabs.filter((key) => tabs[key].group === group).map(renderNavItem)}
              </div>
            ))}
            <div className="nav-group nav-resources">
              <h2 className="nav-group-title">{t("shell.sidebar.resources")}</h2>
              <a className="sidebar-resource-link" href="https://github.com/openbastion/openbastion/tree/main/docs" target="_blank" rel="noreferrer">
                <ApiDocumentation size={16} />{t("shell.sidebar.documentation")}
              </a>
              <a className="sidebar-resource-link" href="https://github.com/openbastion/openbastion/tree/main/docs/user-guide" target="_blank" rel="noreferrer">
                <HelpCircle size={16} />{t("shell.sidebar.helpCentre")}
              </a>
            </div>
          </nav>
          <div className="sidebar-footer">
            <div className="sidebar-footer-heading">
              <span className="sidebar-status-dot" aria-hidden="true" />
              <strong>{t("shell.sidebar.console")}</strong>
            </div>
            <p>{t("shell.sidebar.statusDetail")}</p>
          </div>
          <AppUserMenu
            open={userMenuOpen}
            onOpenChange={setUserMenuOpen}
            triggerRef={userMenuButton}
            restoreFocus={!paletteOpen && !preferencesOpen}
            label={t("shell.user.menuLabel")}
            trigger={(
              <>
                <span className="avatar" aria-hidden="true">{initials}</span>
                <span className="user-menu-identity">
                  <strong>{who?.username}</strong>
                  <small>{who?.roles[0] ?? t("shell.user.defaultRole")}</small>
                </span>
                <ChevronDown className="user-menu-chevron" size={16} />
              </>
            )}
          >
            <div className="user-menu-summary">
              <strong>{who?.username}</strong>
              <span>{who?.roles.join(", ") || t("shell.user.defaultRole")}</span>
            </div>
            <div className="user-menu-section">
              <span>{t("common.language.label")}</span>
              <LanguageSwitcher />
            </div>
            <div className="user-menu-section">
              <span>{t("shell.theme.label")}</span>
              <button type="button" className="user-menu-item" aria-label={theme === "light" ? t("shell.theme.enableDark") : t("shell.theme.enableLight")} onClick={() => updatePreferences({ ...preferences, theme: theme === "light" ? "dark" : "light" })}>
                {theme === "light" ? <Moon size={17} /> : <Sun size={17} />}
                {theme === "light" ? t("shell.theme.dark") : t("shell.theme.light")}
              </button>
            </div>
            <button type="button" className="user-menu-item" onClick={() => { setPreferencesOpen(true); setUserMenuOpen(false); }}>
              <Settings size={17} />{t("shell.preferences.label")}
            </button>
            <button type="button" className="user-menu-item user-menu-signout" onClick={() => { setUserMenuOpen(false); onSignOut(); }}>
              {t("shell.signOut")}
            </button>
          </AppUserMenu>
        </aside>
        <div className="app-content">
          <header className="app-header" inert={mobileOpen}>
            <div className="topbar-breadcrumb" aria-label={t("shell.breadcrumb.aria")}>
              <span>{t("shell.breadcrumb.workspace")}</span>
              <span aria-hidden="true">/</span>
              <strong>{t(`shell.nav.${tab}.label`)}</strong>
            </div>
            <button
              ref={paletteButton}
              type="button"
              className="command-trigger"
              aria-label={t("shell.search.open")}
              onClick={() => setPaletteOpen(true)}
            >
              <Search size={16} />
              <span>{t("shell.search.placeholder")}</span>
              <kbd>Ctrl K</kbd>
            </button>
            <div className="header-actions">
              <span className="environment-badge"><span className="workspace-environment-mark" aria-hidden="true" />{t("shell.environment.production")}</span>
              <div className="notifications-menu" ref={notificationsRef}>
                <button
                  ref={notificationsButton}
                  type="button"
                  className="icon-button"
                  aria-label={t("shell.notifications.open")}
                  aria-haspopup="true"
                  aria-expanded={notificationsOpen}
                  aria-controls="global-notifications"
                  onClick={() => setNotificationsOpen((open) => !open)}
                >
                  <Notifications size={18} />
                </button>
                {notificationsOpen ? (
                  <section className="notifications-panel" id="global-notifications" aria-label={t("shell.notifications.title")}>
                    <div className="notifications-panel-heading">
                      <strong>{t("shell.notifications.title")}</strong>
                      <span>{t("shell.notifications.all")}</span>
                    </div>
                    <div className="notifications-empty" role="status">
                      <Notifications size={22} />
                      <strong>{t("shell.notifications.emptyTitle")}</strong>
                      <p>{t("shell.notifications.unavailable")}</p>
                    </div>
                  </section>
                ) : null}
              </div>
              <a className="icon-button header-help-link" href="https://github.com/openbastion/openbastion/tree/main/docs" target="_blank" rel="noreferrer" aria-label={t("shell.help.open")} title={t("shell.help.open")}>
                <ApiDocumentation size={18} />
              </a>
              <button
                ref={menuButton}
                type="button"
                className="icon-button mobile-menu-toggle"
                aria-label={mobileOpen ? t("shell.menu.close") : t("shell.menu.open")}
                aria-expanded={mobileOpen}
                aria-controls="admin-navigation"
                onClick={() => setMobileOpen((open) => !open)}
              >
                <Menu size={18} />
              </button>
            </div>
          </header>
          <main ref={mainRef} id="main-content" className="app-main" tabIndex={-1} inert={mobileOpen}>
            {capabilities.status === "unavailable" ? <InlineNotice tone="warning">{t("capabilities.unavailableBanner")}</InlineNotice> : null}
            {children}
          </main>
        </div>
        <LegalNotice />
      </div>
    </>
  );
}
