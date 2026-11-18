import { useAppTranslation } from "../../shared/i18n";
import { ReferenceCard, ReferenceFact, ReferenceFacts, ReferenceRow, ReferenceState } from "../../shared/ui/ReferenceCard";

// Paramètres — Sécurité. The screens describe what this build enforces, not a set of editable
// switches: the factors, the default-deny engine and the record-or-refuse rule are decided at
// deployment (environment variables, ADRs) and the public API exposes no settings write.
export function SecuritySettings() {
  const { t } = useAppTranslation();

  return (
    <div className="settings-layout">
      <div className="settings-column">
        <ReferenceCard
          title={t("settings.security.auth.title")}
          subtitle={t("settings.security.auth.subtitle")}
          footer={t("settings.security.auth.note")}
        >
          <ReferenceRow
            title={t("settings.security.auth.totp.title")}
            description={t("settings.security.auth.totp.description")}
            badge={<ReferenceState>{t("settings.security.badge.byRole")}</ReferenceState>}
          />
          <ReferenceRow
            title={t("settings.security.auth.webauthn.title")}
            description={t("settings.security.auth.webauthn.description")}
            badge={<ReferenceState>{t("settings.security.badge.byRole")}</ReferenceState>}
          />
        </ReferenceCard>

        <ReferenceCard
          title={t("settings.security.access.title")}
          subtitle={t("settings.security.access.subtitle")}
          footer={t("settings.security.access.note")}
        >
          <ReferenceRow
            mark={t("settings.security.access.rbac.mark")}
            title={t("settings.security.access.rbac.title")}
            description={t("settings.security.access.rbac.description")}
            badge={<ReferenceState tone="success">{t("settings.security.badge.active")}</ReferenceState>}
          />
          <ReferenceRow
            mark={t("settings.security.access.action.mark")}
            title={t("settings.security.access.action.title")}
            description={t("settings.security.access.action.description")}
            badge={<ReferenceState tone="success">{t("settings.security.badge.active")}</ReferenceState>}
          />
          <ReferenceRow
            mark={t("settings.security.access.approval.mark")}
            title={t("settings.security.access.approval.title")}
            description={t("settings.security.access.approval.description")}
            badge={<ReferenceState tone="success">{t("settings.security.badge.active")}</ReferenceState>}
          />
        </ReferenceCard>

        <ReferenceCard
          title={t("settings.security.recording.title")}
          footer={t("settings.security.recording.note")}
        >
          <ReferenceRow
            title={t("settings.security.recording.policy.title")}
            description={t("settings.security.recording.policy.description")}
            badge={<ReferenceState tone="success">{t("settings.security.badge.required")}</ReferenceState>}
          />
        </ReferenceCard>
      </div>

      <div className="settings-column">
        <ReferenceCard title={t("settings.security.state.title")} subtitle={t("settings.security.state.subtitle")}>
          <ReferenceFacts>
            <ReferenceFact label={t("settings.security.state.auth")} value={t("settings.security.state.authValue")} />
            <ReferenceFact label={t("settings.security.state.authorization")} value={t("settings.security.state.authorizationValue")} />
            <ReferenceFact label={t("settings.security.state.sessions")} value={t("settings.security.state.sessionsValue")} />
            <ReferenceFact label={t("settings.security.state.audit")} value={t("settings.security.state.auditValue")} />
          </ReferenceFacts>
        </ReferenceCard>

        <ReferenceCard
          title={t("settings.security.integrity.title")}
          subtitle={t("settings.security.integrity.subtitle")}
          badge={<ReferenceState tone="success">{t("settings.security.integrity.badge")}</ReferenceState>}
          footer={t("settings.security.integrity.note")}
        >
          <ReferenceRow
            title={t("settings.security.integrity.rowTitle")}
            description={t("settings.security.integrity.rowDescription")}
          />
        </ReferenceCard>

        <ReferenceCard
          title={t("settings.security.deployment.title")}
          subtitle={t("settings.security.deployment.subtitle")}
        >
          <ReferenceFacts stacked>
            <ReferenceFact label={t("settings.security.deployment.mfaKey")} value={t("settings.security.deployment.mfaDetail")} />
            <ReferenceFact label={t("settings.security.deployment.auditKey")} value={t("settings.security.deployment.auditDetail")} />
          </ReferenceFacts>
        </ReferenceCard>

        <ReferenceCard tone="accent" title={t("settings.security.limits.title")} hideTitle>
          <p className="settings-promo-body">{t("settings.security.limits.body")}</p>
        </ReferenceCard>
      </div>
    </div>
  );
}
