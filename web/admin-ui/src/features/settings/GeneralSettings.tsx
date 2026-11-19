import { Button, Input, Label } from "@openbastion/ui";
import { useAppTranslation } from "../../shared/i18n";
import { ReferenceCard, ReferenceFact, ReferenceFacts, ReferenceState, ReferenceSwitch } from "../../shared/ui/ReferenceCard";

const releaseNotesUrl = "https://github.com/openbastion/openbastion/releases";

// Paramètres — Général. What this deployment declares about its own workspace. The organisation
// name, its region and its version are not exposed by the public API: the fields keep the
// reference's shape and say they are unavailable rather than showing an invented value. The
// browser does know the origin and the operator's time zone, so those two are real.
export function GeneralSettings({ onOpenIdentities }: { onOpenIdentities?: () => void }) {
  const { t } = useAppTranslation();
  const origin = typeof window === "undefined" ? "" : window.location.origin;
  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const unavailable = t("common.noApiContract");

  return (
    <div className="settings-layout">
      <div className="settings-column">
        <ReferenceCard
          title={t("settings.general.workspace.title")}
          subtitle={t("settings.general.workspace.subtitle")}
          footer={t("settings.general.workspace.note")}
        >
          <div className="settings-fields">
            <Label className="settings-field">
              <span>{t("settings.general.workspace.organisation")}</span>
              <Input value={t("settings.general.unavailable")} readOnly title={unavailable} />
            </Label>
            <Label className="settings-field">
              <span>{t("settings.general.workspace.space")}</span>
              <Input value={t("shell.environment.production")} readOnly />
            </Label>
            <Label className="settings-field">
              <span>{t("settings.general.workspace.url")}</span>
              <Input value={origin} readOnly title={origin} />
            </Label>
            <Label className="settings-field">
              <span>{t("settings.general.workspace.timezone")}</span>
              <Input value={timeZone} readOnly />
            </Label>
          </div>
        </ReferenceCard>

        <ReferenceCard
          title={t("settings.general.defaultSecurity.title")}
          subtitle={t("settings.general.defaultSecurity.subtitle")}
          footer={t("settings.general.defaultSecurity.note")}
        >
          <div className="settings-toggle">
            <div className="settings-toggle-copy">
              <p className="reference-row-title">{t("settings.general.defaultSecurity.mfa.title")}</p>
              <p className="reference-row-description">{t("settings.general.defaultSecurity.mfa.description")}</p>
            </div>
            <ReferenceSwitch checked label={t("settings.general.defaultSecurity.mfa.state")} />
          </div>
          <div className="settings-toggle">
            <div className="settings-toggle-copy">
              <p className="reference-row-title">{t("settings.general.defaultSecurity.recording.title")}</p>
              <p className="reference-row-description">{t("settings.general.defaultSecurity.recording.description")}</p>
            </div>
            <ReferenceSwitch checked label={t("settings.general.defaultSecurity.recording.state")} />
          </div>
          <div className="settings-toggle">
            <div className="settings-toggle-copy">
              <p className="reference-row-title">{t("settings.general.defaultSecurity.approval.title")}</p>
              <p className="reference-row-description">{t("settings.general.defaultSecurity.approval.description")}</p>
            </div>
            <ReferenceSwitch checked label={t("settings.general.defaultSecurity.approval.state")} />
          </div>
          <p className="ob-visually-hidden">{t("settings.general.defaultSecurity.readonly")}</p>
        </ReferenceCard>

        <p className="settings-footnote">{t("settings.general.lastChange")}</p>
      </div>

      <div className="settings-column">
        <ReferenceCard
          tone="chrome"
          title={t("settings.general.instance.title")}
          badge={<ReferenceState tone="chrome">{t("settings.general.instance.status")}</ReferenceState>}
          footer={
            <a className="reference-link--chrome" href={releaseNotesUrl} target="_blank" rel="noreferrer">
              {t("settings.general.instance.releaseNotes")} <span aria-hidden="true">↗</span>
            </a>
          }
        >
          <ReferenceFacts>
            <ReferenceFact label={t("settings.general.instance.version")} value={t("settings.general.unavailable")} unavailable />
            <ReferenceFact label={t("settings.general.instance.deployment")} value={t("settings.general.unavailable")} unavailable />
            <ReferenceFact label={t("settings.general.instance.region")} value={t("settings.general.unavailable")} unavailable />
            <ReferenceFact label={t("settings.general.instance.licence")} value={t("settings.general.instance.licenceValue")} />
          </ReferenceFacts>
        </ReferenceCard>

        <ReferenceCard
          title={t("settings.general.identity.title")}
          badge={<ReferenceState tone="quiet">{t("settings.general.identity.status")}</ReferenceState>}
        >
          <ReferenceFacts>
            <ReferenceFact label={t("settings.general.identity.kind")} value={t("settings.general.identity.kindValue")} />
            <ReferenceFact label={t("settings.general.identity.lastSync")} value={t("settings.general.unavailable")} unavailable />
            <ReferenceFact label={t("settings.general.identity.synced")} value={t("settings.general.unavailable")} unavailable />
          </ReferenceFacts>
          {onOpenIdentities ? (
            <Button variant="ghost" className="reference-link reference-facts-action" onClick={onOpenIdentities}>
              {t("settings.general.identity.configure")} <span aria-hidden="true">→</span>
            </Button>
          ) : null}
        </ReferenceCard>

        <ReferenceCard tone="accent" title={t("settings.general.design.title")} footer={
          <a className="reference-link" href="https://github.com/openbastion/openbastion/blob/main/docs/security/hardening.md" target="_blank" rel="noreferrer">
            {t("settings.general.design.action")} <span aria-hidden="true">↗</span>
          </a>
        }>
          <p className="settings-promo-body">{t("settings.general.design.body")}</p>
        </ReferenceCard>
      </div>
    </div>
  );
}
