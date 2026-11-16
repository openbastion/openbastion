import { useAppTranslation } from "./i18n";

const configuredRepository = __OPENBASTION_SOURCE_REPOSITORY__;
const hasValidRepository = /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(configuredRepository);
const repository = hasValidRepository ? configuredRepository : "https://github.com/openbastion/openbastion";
const revision = __OPENBASTION_SOURCE_REVISION__;
const hasExactRevision = hasValidRepository && /^[0-9a-f]{40}$/i.test(revision);
const sourceURL = hasExactRevision ? `${repository}/tree/${revision}` : repository;
const licenseURL = hasExactRevision ? `${repository}/blob/${revision}/LICENSE` : `${repository}/blob/main/LICENSE`;

export function LegalLinks({ className = "" }: { className?: string }) {
  const { t } = useAppTranslation();
  return (
    <nav className={className} aria-label={t("legal.licenseAria")}>
      <a href={sourceURL} target="_blank" rel="noopener noreferrer">
        {hasExactRevision
          ? t("legal.source", { revision: revision.slice(0, 12) })
          : t("legal.sourceUnknown")}
      </a>
      <a href={licenseURL} target="_blank" rel="noopener noreferrer">{t("legal.license")}</a>
    </nav>
  );
}

export function LegalNotice() {
  const { t } = useAppTranslation();
  return (
    <footer className="legal-notice" aria-label={t("legal.aria")}>
      <span>© 2026 OpenBastion — GNU Affero General Public License v3.0 (AGPL-3.0-only)</span>
      <LegalLinks />
    </footer>
  );
}
