import { ReactNode, useEffect, useLayoutEffect, useRef, useState } from "react";
import { ApiDocumentation, Audit, Dashboard, Notifications, Policies as PoliciesIcon, Search, Session, Settings, Shield, Users } from "@openbastion/icons";
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

// Labels and descriptions live in the translation files (locales/*.ts), one key per tab: the
// navigation is translated like the screens it opens, and the groups keep the same order.
const tabs = {
  overview: { icon: Dashboard, group: "workspace" },
  accounts: { icon: Users, group: "workspace" },
  policies: { icon: PoliciesIcon, group: "workspace" },
  sessions: { icon: Session, group: "workspace" },
  audit: { icon: Audit, group: "workspace" },
  security: { icon: Shield, group: "workspace" },
} as const;

const groups = ["workspace"] as const;

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
  const { t } = useAppTranslation();
  const [preferences, setPreferences] = useState<OperatorPreferences>(readOperatorPreferences);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [preferencesOpen, setPreferencesOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [systemDark, setSystemDark] = useState(() => window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false);
  const menuButton = useRef<HTMLButtonElement>(null);
  const paletteButton = useRef<HTMLButtonElement>(null);
  const userMenuButton = useRef<HTMLButtonElement>(null);
  const userMenuRef = useRef<HTMLDivElement>(null);
  const notificationsRef = useRef<HTMLDivElement>(null);
  const notificationsButton = useRef<HTMLButtonElement>(null);
  const mainRef = useRef<HTMLElement>(null);
  const sidebarRef = useRef<HTMLElement>(null);
  const mobileWasOpen = useRef(false);
  const paletteWasOpen = useRef(false);
  const preferencesWereOpen = useRef(false);
  const userMenuWasOpen = useRef(false);
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

  // Global shortcuts must be active as soon as the authenticated shell is committed.
  // A passive effect leaves a brief post-login window where Ctrl/Meta+K can be missed.
  useLayoutEffect(() => {
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
    if (preferencesWereOpen.current && !preferencesOpen) userMenuButton.current?.focus();
    preferencesWereOpen.current = preferencesOpen;
  }, [preferencesOpen]);

  useEffect(() => {
    if (userMenuWasOpen.current && !userMenuOpen && !paletteOpen && !preferencesOpen) userMenuButton.current?.focus();
    userMenuWasOpen.current = userMenuOpen;
  }, [userMenuOpen, paletteOpen, preferencesOpen]);

  useEffect(() => {
    if (!userMenuOpen) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setUserMenuOpen(false);
    };
    const closeOnOutsidePointer = (event: PointerEvent) => {
      if (event.target instanceof Node && !userMenuRef.current?.contains(event.target)) setUserMenuOpen(false);
    };
    document.addEventListener("keydown", closeOnEscape);
    document.addEventListener("pointerdown", closeOnOutsidePointer);
    return () => {
      document.removeEventListener("keydown", closeOnEscape);
      document.removeEventListener("pointerdown", closeOnOutsidePointer);
    };
  }, [userMenuOpen]);

  useEffect(() => {
    if (!notificationsOpen) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setNotificationsOpen(false);
        notificationsButton.current?.focus();
      }
    };
    const closeOnOutsidePointer = (event: PointerEvent) => {
      if (event.target instanceof Node && !notificationsRef.current?.contains(event.target)) setNotificationsOpen(false);
    };
    document.addEventListener("keydown", closeOnEscape);
    document.addEventListener("pointerdown", closeOnOutsidePointer);
    return () => {
      document.removeEventListener("keydown", closeOnEscape);
      document.removeEventListener("pointerdown", closeOnOutsidePointer);
    };
  }, [notificationsOpen]);

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
          <span aria-hidden="true">{favorite ? "★" : "☆"}</span>
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
              <span aria-hidden="true">{collapsed ? "›" : "‹"}</span>
            </button>
          </div>
          <div className="sidebar-workspace-card">
            <span className="sidebar-workspace-label">{t("shell.sidebar.workspace")}</span>
            <strong>{t("shell.sidebar.workspaceName")}</strong>
            <small>{t("shell.sidebar.workspaceContext")}</small>
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
                {tabOrder.filter((key) => tabs[key].group === group).map(renderNavItem)}
              </div>
            ))}
            <div className="nav-group nav-resources">
              <h2 className="nav-group-title">{t("shell.sidebar.resources")}</h2>
              <a className="sidebar-resource-link" href="https://github.com/openbastion/openbastion/tree/main/docs" target="_blank" rel="noreferrer">
                <ApiDocumentation size={16} />{t("shell.sidebar.documentation")}
              </a>
              <a className="sidebar-resource-link" href="https://github.com/openbastion/openbastion/tree/main/docs/user-guide" target="_blank" rel="noreferrer">
                <span className="sidebar-help-glyph" aria-hidden="true">?</span>{t("shell.sidebar.helpCentre")}
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
          <div className="sidebar-user-menu" ref={userMenuRef}>
            <button
              ref={userMenuButton}
              type="button"
              className="user-menu-trigger sidebar-user-menu-trigger"
              aria-haspopup="true"
              aria-expanded={userMenuOpen}
              aria-controls="operator-menu"
              onClick={() => setUserMenuOpen((open) => !open)}
            >
              <span className="avatar" aria-hidden="true">{initials}</span>
              <span className="user-menu-identity">
                <strong>{who?.username}</strong>
                <small>{who?.roles[0] ?? t("shell.user.defaultRole")}</small>
              </span>
              <span className="user-menu-chevron" aria-hidden="true">⌄</span>
            </button>
            {userMenuOpen ? (
              <div className="user-menu-panel sidebar-user-menu-panel" id="operator-menu" aria-label={t("shell.user.menuLabel")}>
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
                  <button type="button" className="user-menu-item" aria-label={effectiveTheme() === "light" ? t("shell.theme.enableDark") : t("shell.theme.enableLight")} onClick={() => updatePreferences({ ...preferences, theme: effectiveTheme() === "light" ? "dark" : "light" })}>
                    <span aria-hidden="true">{effectiveTheme() === "light" ? "◐" : "☀"}</span>
                    {effectiveTheme() === "light" ? t("shell.theme.dark") : t("shell.theme.light")}
                  </button>
                </div>
                <button type="button" className="user-menu-item" onClick={() => { setPreferencesOpen(true); setUserMenuOpen(false); }}>
                  <Settings size={17} />{t("shell.preferences.label")}
                </button>
                <button type="button" className="user-menu-item user-menu-signout" onClick={() => { setUserMenuOpen(false); onSignOut(); }}>
                  {t("shell.signOut")}
                </button>
              </div>
            ) : null}
          </div>
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
                <span aria-hidden="true">☰</span>
              </button>
            </div>
          </header>
          <main ref={mainRef} id="main-content" className="app-main" tabIndex={-1} inert={mobileOpen}>
            {children}
          </main>
        </div>
        <LegalNotice />
      </div>
    </>
  );
}
