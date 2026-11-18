import { useAppTranslation } from "../../shared/i18n";
import { ReferenceCard, ReferenceFact, ReferenceFacts, ReferenceRow, ReferenceState } from "../../shared/ui/ReferenceCard";

// Paramètres — Notifications. Outgoing channels are configured with environment variables in the
// Audit Service and the Session Broker; this screen documents the contract and never displays a
// URL or a key, because neither the API nor this page may read them back.
export function NotificationSettings() {
  const { t } = useAppTranslation();

  return (
    <div className="settings-layout">
      <div className="settings-column">
        <ReferenceCard
          title={t("settings.notifications.channels.title")}
          subtitle={t("settings.notifications.channels.subtitle")}
          footer={t("settings.notifications.channels.note")}
        >
          <ReferenceRow
            mark={t("settings.notifications.channels.audit.mark")}
            title={t("settings.notifications.channels.audit.title")}
            description={t("settings.notifications.channels.audit.description")}
            badge={<ReferenceState tone="success">{t("settings.notifications.badge.supported")}</ReferenceState>}
          />
          <ReferenceRow
            mark={t("settings.notifications.channels.broker.mark")}
            title={t("settings.notifications.channels.broker.title")}
            description={t("settings.notifications.channels.broker.description")}
            badge={<ReferenceState tone="success">{t("settings.notifications.badge.supported")}</ReferenceState>}
          />
        </ReferenceCard>

        <ReferenceCard
          title={t("settings.notifications.config.title")}
          subtitle={t("settings.notifications.config.subtitle")}
          footer={t("settings.notifications.config.note")}
        >
          <div className="settings-fields">
            <label className="settings-field">
              <span>{t("settings.notifications.config.alert")}</span>
              <input value={t("settings.notifications.config.alertValue")} readOnly />
              <small>{t("settings.notifications.config.alertNote")}</small>
            </label>
            <label className="settings-field">
              <span>{t("settings.notifications.config.breakglass")}</span>
              <input value={t("settings.notifications.config.breakglassValue")} readOnly />
              <small>{t("settings.notifications.config.breakglassNote")}</small>
            </label>
          </div>
          <ReferenceFacts className="settings-facts-inline">
            <ReferenceFact label={t("settings.notifications.config.transport")} value={t("settings.notifications.config.transportValue")} />
            <ReferenceFact label={t("settings.notifications.config.retries")} value={t("settings.notifications.config.retriesValue")} />
          </ReferenceFacts>
        </ReferenceCard>

        <ReferenceCard title={t("settings.notifications.content.title")}>
          <p className="settings-promo-body">{t("settings.notifications.content.body")}</p>
        </ReferenceCard>
      </div>

      <div className="settings-column">
        <ReferenceCard title={t("settings.notifications.supported.title")}>
          <ReferenceRow
            mark={t("settings.notifications.supported.webhook.mark")}
            title={t("settings.notifications.supported.webhook.title")}
            description={t("settings.notifications.supported.webhook.description")}
            badge={<ReferenceState>{t("settings.notifications.badge.available")}</ReferenceState>}
          />
          <ReferenceRow
            mark={t("settings.notifications.supported.slack.mark")}
            title={t("settings.notifications.supported.slack.title")}
            description={t("settings.notifications.supported.slack.description")}
            badge={<ReferenceState>{t("settings.notifications.badge.available")}</ReferenceState>}
          />
          <ReferenceRow
            mark={t("settings.notifications.supported.teams.mark")}
            title={t("settings.notifications.supported.teams.title")}
            description={t("settings.notifications.supported.teams.description")}
            badge={<ReferenceState>{t("settings.notifications.badge.available")}</ReferenceState>}
          />
        </ReferenceCard>

        <ReferenceCard title={t("settings.notifications.reliability.title")} subtitle={t("settings.notifications.reliability.subtitle")}>
          <ReferenceFacts stacked>
            <ReferenceFact label={t("settings.notifications.reliability.audit")} value={t("settings.notifications.reliability.auditValue")} />
            <ReferenceFact label={t("settings.notifications.reliability.broker")} value={t("settings.notifications.reliability.brokerValue")} />
          </ReferenceFacts>
        </ReferenceCard>

        <ReferenceCard tone="accent" title={t("settings.notifications.limits.title")}>
          <p className="settings-promo-body">{t("settings.notifications.limits.body")}</p>
        </ReferenceCard>
      </div>
    </div>
  );
}
