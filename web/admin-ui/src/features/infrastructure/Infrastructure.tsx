import { useEffect, useState } from "react";
import { Select } from "@openbastion/ui";
import { ChevronDown, Search } from "@openbastion/icons";
import { Account, ApiError, Page } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { Notice } from "../../shared/Notice";
import { AdminPage } from "../../shared/ui/AdminPage";
import { Button } from "../../shared/ui/Button";
import { ReferenceMetric } from "../../shared/ui/ReferenceMetric";
import { ReferenceCard, ReferenceFact, ReferenceFacts, ReferenceState } from "../../shared/ui/ReferenceCard";
import { useAppTranslation } from "../../shared/i18n";

// Infrastructure (docs/ui/reference-screens/openbastion-infrastructure.svg). The Vault is the only
// system of this deployment the public API describes: the resource count and the topology's
// target side come from GET /vault/accounts. Connectors, cluster health and availability have no
// public route today, so their cards keep the reference's shape and name what is missing instead
// of showing plausible figures.
export function Infrastructure({ onNavigate }: { onNavigate?: (tab: "accounts") => void } = {}) {
  const { t } = useAppTranslation();
  const { api } = useSignedIn();
  const [data, setData] = useState<Page<Account>>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>();

  useEffect(() => {
    let current = true;
    setLoading(true);
    api.request<Page<Account>>("GET", "/vault/accounts?page=1&pageSize=1")
      .then((result) => { if (current) { setData(result); setError(undefined); } })
      .catch((reason: unknown) => { if (current) { setData(undefined); setError(reason); } })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [api]);

  const unavailable = t("common.noApiContract");
  const targets = ["cloud", "kubernetes", "onPremise"] as const;

  return (
    <AdminPage
      title={t("infrastructure.title")}
      subtitle={t("infrastructure.subtitle")}
      actions={
        <Button variant="primary" onClick={onNavigate ? () => onNavigate("accounts") : undefined}>
          <Search size={16} aria-hidden="true" />
          {t("infrastructure.discover")}
        </Button>
      }
    >
      <Notice
        error={error instanceof ApiError ? `${error.status} — ${error.message}` : error ? String((error as Error)?.message ?? error) : undefined}
      />

      <div className="reference-metrics infrastructure-metrics" role="group" aria-label={t("infrastructure.metricsAria")}>
        <ReferenceMetric
          label={t("infrastructure.metrics.resources")}
          value={data?.totalItems}
          loading={loading}
          detail={t("infrastructure.metrics.resourcesDetail")}
        />
        <ReferenceMetric label={t("infrastructure.metrics.connectors")} detail={t("infrastructure.metrics.connectorsDetail")} />
        <ReferenceMetric label={t("infrastructure.metrics.bastions")} detail={t("infrastructure.metrics.bastionsDetail")} />
        <ReferenceMetric label={t("infrastructure.metrics.availability")} detail={t("infrastructure.metrics.availabilityDetail")} />
      </div>

      <div className="infrastructure-panels">
        <ReferenceCard
          title={t("infrastructure.topology.title")}
          subtitle={t("infrastructure.topology.subtitle")}
          badge={
            <span className="reference-select is-unavailable">
              <Select disabled aria-label={t("infrastructure.topology.environment")} title={unavailable}>
                <option>{t("shell.environment.production")}</option>
              </Select>
              <ChevronDown size={14} aria-hidden="true" />
            </span>
          }
        >
          <div className="topology-flow">
            <div className="topology-node">
              <strong className="is-unavailable">{t("infrastructure.topology.identitiesValue")}</strong>
              <small>{t("infrastructure.topology.identitiesDetail")}</small>
            </div>
            <span className="topology-link" aria-hidden="true" />
            <div className="topology-node topology-node--bastion">
              <strong>{t("infrastructure.topology.bastion")}</strong>
              <small>{t("infrastructure.topology.bastionDetail")}</small>
            </div>
            <span className="topology-branch" aria-hidden="true" />
            <div className="topology-targets">
              {targets.map((target) => (
                <div className="topology-node topology-node--target" key={target}>
                  <strong>{t(`infrastructure.topology.${target}`)}</strong>
                  <small className="is-unavailable">{t("infrastructure.topology.resourcesValue")}</small>
                </div>
              ))}
            </div>
          </div>
          <p className="settings-inline-note">{t("infrastructure.topology.note")}</p>
        </ReferenceCard>

        <ReferenceCard
          title={t("infrastructure.health.title")}
          badge={<ReferenceState tone="quiet">{t("infrastructure.health.status")}</ReferenceState>}
        >
          <div className="cluster-health">
            {(["cpu", "memory", "storage"] as const).map((metric) => (
              <div className="cluster-health-row" key={metric}>
                <div className="cluster-health-head">
                  <span>{t(`infrastructure.health.${metric}`)}</span>
                  <strong className="is-unavailable">{t("infrastructure.health.unavailableValue")}</strong>
                </div>
                <span className="cluster-health-track" aria-hidden="true" />
              </div>
            ))}
          </div>
          <ReferenceFacts className="cluster-health-latency">
            <ReferenceFact label={t("infrastructure.health.latency")} value={t("infrastructure.health.unavailableValue")} unavailable />
          </ReferenceFacts>
          <p className="settings-inline-note">{t("infrastructure.health.note")}</p>
        </ReferenceCard>
      </div>

      <ReferenceCard
        title={t("infrastructure.connectors.title")}
        className="infrastructure-connectors"
        badge={
          onNavigate ? (
            <Button variant="ghost" className="reference-link" onClick={() => onNavigate("accounts")}>
              {t("infrastructure.connectors.action")} <span aria-hidden="true">→</span>
            </Button>
          ) : undefined
        }
        footer={t("infrastructure.connectors.note")}
      >
        <div className="reference-table-wrap">
          <table className="reference-table infrastructure-table">
            <thead>
              <tr>
                <th scope="col">{t("infrastructure.connectors.columns.connector")}</th>
                <th scope="col">{t("infrastructure.connectors.columns.type")}</th>
                <th scope="col">{t("infrastructure.connectors.columns.resources")}</th>
                <th scope="col">{t("infrastructure.connectors.columns.sync")}</th>
                <th scope="col">{t("infrastructure.connectors.columns.state")}</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td colSpan={5} className="infrastructure-table-empty">
                  <strong>{t("infrastructure.connectors.unavailableTitle")}</strong>
                  <span>{t("infrastructure.connectors.unavailable")}</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </ReferenceCard>
    </AdminPage>
  );
}
