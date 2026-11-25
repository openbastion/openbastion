import { ReactNode, useEffect, useLayoutEffect, useRef, useState } from "react";
import {
  AppHeader,
  AppMobileNavigation,
  AppNavigation,
  AppShell as UiAppShell,
  AppSidebar,
  AppSidebarBrand,
  AppSidebarFooter,
  AppUserMenu,
  useAppDismissable,
  useAppShortcuts,
  useAppTheme,
  type AppNavigationItemDescriptor,
  type AppNavigationSection,
} from "@openbastion/ui";
import {
  ApiDocumentation,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  HelpCircle,
  Menu,
  Moon,
  Notifications,
  Search,
  Settings,
  Star,
  StarFilled,
  Sun,
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
import { destinationOf, groups, tabAllowed, tabOrder, type Tab } from "./navigation";
import { InlineNotice } from "../shared/ui/InlineNotice";

export type { Tab };

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
  tab: Tab | null;
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
  const mobileNavigated = useRef(false);
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
    // The mobile navigation restores focus to its own button when it closes; the router applies the
    // new address after that, so the main region must not take the focus back from it.
    if (mobileOpen && next !== tab) mobileNavigated.current = true;
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
    if (mobileNavigated.current) mobileNavigated.current = false;
    else mainRef.current?.focus();
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

  function navItem(key: Tab): AppNavigationItemDescriptor {
    return {
      id: key,
      label: t(`shell.nav.${key}.label`),
      description: t(`shell.nav.${key}.description`),
      icon: destinationOf(key).icon,
      active: tab === key,
      favorite: preferences.favorites.includes(key),
    };
  }
  const sections: AppNavigationSection[] = groups.map((group) => ({
    id: group,
    label: t(`shell.groups.${group}`),
    items: shownTabs.filter((key) => destinationOf(key).group === group).map(navItem),
  }));

  return (
    <>
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
      <UiAppShell
        collapsed={collapsed}
        mobileOpen={mobileOpen}
        mainRef={mainRef}
        skipLink={<a className="skip-link" href="#main-content" inert={mobileOpen}>{t("shell.skipToContent")}</a>}
        mobileBehavior={(
          <AppMobileNavigation
            open={mobileOpen}
            onClose={() => setMobileOpen(false)}
            containerRef={sidebarRef}
            returnFocusRef={menuButton}
            excludeSelector=".sidebar-collapse-toggle"
          />
        )}
        banner={capabilities.status === "unavailable" ? <InlineNotice tone="warning">{t("capabilities.unavailableBanner")}</InlineNotice> : null}
        footer={<LegalNotice />}
        sidebar={(
          <AppSidebar
            ref={sidebarRef}
            label={t("shell.navigation.main")}
            collapsed={collapsed}
            mobileOpen={mobileOpen}
            brand={(
              <AppSidebarBrand
                name="OpenBastion"
                tagline={t("shell.sidebar.brandTag")}
                mark={<BrandMark />}
                collapsed={collapsed}
                expandLabel={t("shell.sidebar.expand")}
                collapseLabel={t("shell.sidebar.collapse")}
                controlsId="admin-navigation"
                expandIcon={<ChevronRight size={16} />}
                collapseIcon={<ChevronLeft size={16} />}
                onToggleCollapse={() => updatePreferences({ ...preferences, sidebarCollapsed: !collapsed })}
              />
            )}
            context={(
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
            )}
            footer={<AppSidebarFooter title={t("shell.sidebar.console")} detail={t("shell.sidebar.statusDetail")} />}
            userMenu={(
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
            )}
          >
            <AppNavigation
              label={t("shell.navigation.sections")}
              sections={sections}
              favorites={{ label: t("shell.favorites"), items: favoriteTabs.map(navItem) }}
              resources={{
                label: t("shell.sidebar.resources"),
                items: [
                  { id: "documentation", label: t("shell.sidebar.documentation"), href: "https://github.com/openbastion/openbastion/tree/main/docs", icon: ApiDocumentation, external: true },
                  { id: "help-centre", label: t("shell.sidebar.helpCentre"), href: "https://github.com/openbastion/openbastion/tree/main/docs/user-guide", icon: HelpCircle, external: true },
                ],
              }}
              collapsed={collapsed}
              onSelect={(id) => chooseTab(id as Tab)}
              onToggleFavorite={(id) => toggleFavorite(id as Tab)}
              favoriteActionLabel={(item) => t(item.favorite ? "shell.removeFavorite" : "shell.addFavorite", { label: item.label })}
              favoriteTitle={(item) => t(item.favorite ? "shell.favoriteTitle.remove" : "shell.favoriteTitle.add")}
              favoriteIcon={<Star size={15} />}
              favoriteIconActive={<StarFilled size={15} />}
            />
          </AppSidebar>
        )}
        header={(
          <AppHeader
            inert={mobileOpen}
            breadcrumbs={(
              <div className="topbar-breadcrumb" aria-label={t("shell.breadcrumb.aria")}>
                <span>{t("shell.breadcrumb.workspace")}</span>
                <span aria-hidden="true">/</span>
                <strong>{t(`shell.nav.${tab}.label`)}</strong>
              </div>
            )}
            search={(
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
            )}
            actions={(
              <>
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
              </>
            )}
          />
        )}
      >
        {children}
      </UiAppShell>
    </>
  );
}
