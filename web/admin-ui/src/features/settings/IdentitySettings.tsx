import { Input, Label } from "@openbastion/ui";
import { useAppTranslation } from "../../shared/i18n";
import { ReferenceCard, ReferenceFact, ReferenceFacts, ReferenceRow, ReferenceState } from "../../shared/ui/ReferenceCard";

// Paramètres — Identités & SSO. The identity sources are declared in one protected file read by
// the Authentication service at startup; nothing here writes to it. The screen states what the
// build supports and what it does not, so a directory that is absent from the list is a fact,
// not an untested control.
export function IdentitySettings() {
  const { t } = useAppTranslation();

  return (
    <div className="settings-layout">
      <div className="settings-column">
        <ReferenceCard
          title={t("settings.identities.providers.title")}
          subtitle={t("settings.identities.providers.subtitle")}
          footer={t("settings.identities.providers.note")}
        >
          <ReferenceRow
            mark={t("settings.identities.providers.oidc.mark")}
            title={t("settings.identities.providers.oidc.title")}
            description={t("settings.identities.providers.oidc.description")}
            badge={<ReferenceState tone="success">{t("settings.identities.badge.supported")}</ReferenceState>}
          />
          <ReferenceRow
            mark={t("settings.identities.providers.ad.mark")}
            title={t("settings.identities.providers.ad.title")}
            description={t("settings.identities.providers.ad.description")}
            badge={<ReferenceState tone="success">{t("settings.identities.badge.supported")}</ReferenceState>}
          />
          <ReferenceRow
            mark={t("settings.identities.providers.ldap.mark")}
            title={t("settings.identities.providers.ldap.title")}
            description={t("settings.identities.providers.ldap.description")}
            badge={<ReferenceState tone="success">{t("settings.identities.badge.supported")}</ReferenceState>}
          />
          <ReferenceRow
            mark={t("settings.identities.providers.entra.mark")}
            title={t("settings.identities.providers.entra.title")}
            description={t("settings.identities.providers.entra.description")}
            badge={<ReferenceState tone="success">{t("settings.identities.badge.supported")}</ReferenceState>}
          />
        </ReferenceCard>

        <ReferenceCard title={t("settings.identities.mapping.title")} subtitle={t("settings.identities.mapping.subtitle")}>
          <div className="settings-fields settings-fields--single">
            <Label className="settings-field">
              <span>{t("settings.identities.mapping.variable")}</span>
              <Input value={t("settings.identities.mapping.variableValue")} readOnly />
            </Label>
          </div>
          <p className="settings-inline-note">{t("settings.identities.mapping.variableNote")}</p>
          <p className="settings-inline-fact">
            <span>{t("settings.identities.mapping.unmapped")}</span>
            <strong>{t("settings.identities.mapping.unmappedValue")}</strong>
          </p>
        </ReferenceCard>

        <ReferenceCard title={t("settings.identities.provisioning.title")} footer={t("settings.identities.provisioning.note")}>
          <p className="settings-promo-body">{t("settings.identities.provisioning.body")}</p>
        </ReferenceCard>
      </div>

      <div className="settings-column">
        <ReferenceCard
          title={t("settings.identities.overview.title")}
          subtitle={t("settings.identities.overview.subtitle")}
          badge={<ReferenceState>{t("settings.identities.overview.badge")}</ReferenceState>}
          footer={t("settings.identities.overview.note")}
        >
          <ReferenceFacts>
            <ReferenceFact label={t("settings.identities.overview.oidc")} value={t("settings.identities.overview.oidcValue")} />
            <ReferenceFact label={t("settings.identities.overview.directories")} value={t("settings.identities.overview.directoriesValue")} />
            <ReferenceFact label={t("settings.identities.overview.accounts")} value={t("settings.identities.overview.accountsValue")} />
          </ReferenceFacts>
        </ReferenceCard>

        <ReferenceCard
          title={t("settings.identities.factors.title")}
          subtitle={t("settings.identities.factors.subtitle")}
          footer={t("settings.identities.factors.note")}
        >
          <ReferenceRow
            mark={t("settings.identities.factors.totp.mark")}
            title={t("settings.identities.factors.totp.title")}
            description={t("settings.identities.factors.totp.description")}
            badge={<ReferenceState tone="success">{t("settings.identities.badge.shipped")}</ReferenceState>}
          />
          <ReferenceRow
            mark={t("settings.identities.factors.webauthn.mark")}
            title={t("settings.identities.factors.webauthn.title")}
            description={t("settings.identities.factors.webauthn.description")}
            badge={<ReferenceState tone="success">{t("settings.identities.badge.shipped")}</ReferenceState>}
          />
        </ReferenceCard>

        <ReferenceCard tone="accent" title={t("settings.identities.limits.title")}>
          <p className="settings-promo-body">{t("settings.identities.limits.body")}</p>
        </ReferenceCard>
      </div>
    </div>
  );
}
