import { useRoutedView } from "../../shared/useRoutedView";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@openbastion/ui";
import { AdminPage } from "../../shared/ui/AdminPage";
import { Button } from "../../shared/ui/Button";
import { useAppTranslation } from "../../shared/i18n";
import { GeneralSettings } from "./GeneralSettings";
import { SecuritySettings } from "./SecuritySettings";
import { IdentitySettings } from "./IdentitySettings";
import { IntegrationSettings } from "./IntegrationSettings";
import { NotificationSettings } from "./NotificationSettings";

export type SettingsTab = "general" | "security" | "identities" | "integrations" | "notifications";

// Paramètres (docs/ui/reference-screens/openbastion-parametres*.svg): one page header whose
// subtitle follows the selected section, the five sections as tabs, and the read-only state of
// the deployment in each of them. The public API exposes no settings resource: every value here
// is declared at deployment, so the header carries the reference's Save action disabled and each
// panel says where its value comes from rather than offering a write it cannot make.
export function Settings({ view, onViewChange }: {
  // ADR-0137: when the application gives them, the tab is the address (`/settings/<view>`).
  view?: SettingsTab;
  onViewChange?: (view: SettingsTab) => void;
} = {}) {
  const { t } = useAppTranslation();
  const [tab, setTab] = useRoutedView<SettingsTab>("general", view, onViewChange);

  return (
    <AdminPage
      title={t("settings.title")}
      subtitle={t(`settings.subtitle.${tab}`)}
      actions={
        // Only the Général reference carries the save action; the other four sections have none.
        tab === "general" ? (
          <>
            <Button disabled title={t("settings.actions.unavailable")}>{t("settings.actions.cancel")}</Button>
            <Button variant="primary" disabled title={t("settings.actions.unavailable")}>
              {t("settings.actions.save")}
            </Button>
          </>
        ) : undefined
      }
    >
      <Tabs value={tab} onValueChange={(value) => setTab(value as SettingsTab)} className="reference-tabs settings-tabs">
        <TabsList aria-label={t("settings.tabsAria")}>
          <TabsTrigger value="general">{t("settings.tabs.general")}</TabsTrigger>
          <TabsTrigger value="security">{t("settings.tabs.security")}</TabsTrigger>
          <TabsTrigger value="identities">{t("settings.tabs.identities")}</TabsTrigger>
          <TabsTrigger value="integrations">{t("settings.tabs.integrations")}</TabsTrigger>
          <TabsTrigger value="notifications">{t("settings.tabs.notifications")}</TabsTrigger>
        </TabsList>

        <TabsContent value="general">
          <GeneralSettings onOpenIdentities={() => setTab("identities")} />
        </TabsContent>
        <TabsContent value="security">
          <SecuritySettings />
        </TabsContent>
        <TabsContent value="identities">
          <IdentitySettings />
        </TabsContent>
        <TabsContent value="integrations">
          <IntegrationSettings />
        </TabsContent>
        <TabsContent value="notifications">
          <NotificationSettings />
        </TabsContent>
      </Tabs>
    </AdminPage>
  );
}
