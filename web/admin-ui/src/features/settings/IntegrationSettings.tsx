import { useAppTranslation } from "../../shared/i18n";
import { ReferenceCard, ReferenceFact, ReferenceFacts, ReferenceRow, ReferenceState } from "../../shared/ui/ReferenceCard";

// Paramètres — Intégrations. The connectors listed are the ones the services of this build
// actually call; their URLs and keys live in protected files and a secret manager, never here.
export function IntegrationSettings() {
  const { t } = useAppTranslation();

  return (
    <div className="settings-layout">
      <div className="settings-column">
        <ReferenceCard
          title={t("settings.integrations.secrets.title")}
          subtitle={t("settings.integrations.secrets.subtitle")}
          footer={t("settings.integrations.secrets.note")}
        >
          <ReferenceRow
            mark={t("settings.integrations.secrets.transit.mark")}
            title={t("settings.integrations.secrets.transit.title")}
            description={t("settings.integrations.secrets.transit.description")}
            badge={<ReferenceState tone="success">{t("settings.integrations.badge.integrated")}</ReferenceState>}
          />
          <ReferenceRow
            mark={t("settings.integrations.secrets.vault.mark")}
            title={t("settings.integrations.secrets.vault.title")}
            description={t("settings.integrations.secrets.vault.description")}
            badge={<ReferenceState tone="success">{t("settings.integrations.badge.integrated")}</ReferenceState>}
          />
        </ReferenceCard>

        <ReferenceCard
          title={t("settings.integrations.channels.title")}
          subtitle={t("settings.integrations.channels.subtitle")}
          footer={t("settings.integrations.channels.note")}
        >
          <ReferenceRow
            mark={t("settings.integrations.channels.webhook.mark")}
            title={t("settings.integrations.channels.webhook.title")}
            description={t("settings.integrations.channels.webhook.description")}
            badge={<ReferenceState tone="success">{t("settings.integrations.badge.supported")}</ReferenceState>}
          />
          <ReferenceRow
            mark={t("settings.integrations.channels.slack.mark")}
            title={t("settings.integrations.channels.slack.title")}
            description={t("settings.integrations.channels.slack.description")}
            badge={<ReferenceState tone="success">{t("settings.integrations.badge.supported")}</ReferenceState>}
          />
          <ReferenceRow
            mark={t("settings.integrations.channels.teams.mark")}
            title={t("settings.integrations.channels.teams.title")}
            description={t("settings.integrations.channels.teams.description")}
            badge={<ReferenceState tone="success">{t("settings.integrations.badge.supported")}</ReferenceState>}
          />
        </ReferenceCard>

        <ReferenceCard title={t("settings.integrations.others.title")} footer={t("settings.integrations.others.note")}>
          <p className="settings-promo-body">{t("settings.integrations.others.body")}</p>
        </ReferenceCard>
      </div>

      <div className="settings-column">
        <ReferenceCard
          title={t("settings.integrations.exchange.title")}
          subtitle={t("settings.integrations.exchange.subtitle")}
          badge={<ReferenceState>{t("settings.integrations.exchange.badge")}</ReferenceState>}
          footer={t("settings.integrations.exchange.note")}
        >
          <ReferenceFacts>
            <ReferenceFact label={t("settings.integrations.exchange.internal")} value={t("settings.integrations.exchange.internalValue")} />
            <ReferenceFact label={t("settings.integrations.exchange.webhooks")} value={t("settings.integrations.exchange.webhooksValue")} />
          </ReferenceFacts>
        </ReferenceCard>

        <ReferenceCard title={t("settings.integrations.connectionSecrets.title")} footer={t("settings.integrations.connectionSecrets.note")}>
          <ReferenceFacts stacked>
            <ReferenceFact label={t("settings.integrations.connectionSecrets.url")} value={t("settings.integrations.connectionSecrets.urlDetail")} />
            <ReferenceFact label={t("settings.integrations.connectionSecrets.hmac")} value={t("settings.integrations.connectionSecrets.hmacDetail")} />
          </ReferenceFacts>
        </ReferenceCard>

        <ReferenceCard tone="accent" title={t("settings.integrations.webhooks.title")} footer={t("settings.integrations.webhooks.note")}>
          <p className="settings-promo-body">{t("settings.integrations.webhooks.body1")}</p>
          <p className="settings-promo-body">{t("settings.integrations.webhooks.body2")}</p>
        </ReferenceCard>
      </div>
    </div>
  );
}
