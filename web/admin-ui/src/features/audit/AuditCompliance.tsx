import { useEffect, useMemo, useState } from "react";
import { Account, ApiError, Page } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { AdminPage } from "../../shared/ui/AdminPage";
import { Notice } from "../../shared/Notice";
import { ReferenceMetric } from "../../shared/ui/ReferenceMetric";
import { ReferencePager } from "../../shared/ui/ReferencePager";
import { useRoutedView } from "../../shared/useRoutedView";
import { useAppTranslation } from "../../shared/i18n";
import { SimulatedAuditEvents } from "../mockup/SimulatedAuditEvents";
import { Button, Input, Label, Select, Tabs, TabsContent, TabsList, TabsTrigger } from "@openbastion/ui";
import { ChevronDown, Download, Search } from "@openbastion/icons";
import { countByKind, findingsFor } from "./posture";

const frameworks = ["ISO 27001", "SOC 2", "NIS2"] as const;
const pageSize = 20;

// The reference screen ("Audit & conformité") shows the audit posture in one page: what the
// journal holds, how the controls are covered, what to fix, and the journal itself.
//
// The public API does not expose it all today, and this screen says so instead of showing
// plausible figures: GET /audit/events is documented but the Gateway does not route it, no route
// counts events or denied access, and no route publishes a retention policy. What is real here is
// the recording guarantee (every admitted session is recorded or refused, ADR-0008) and the
// configuration signals computed from the accounts the Vault returns.
export type View = "journal" | "reports" | "evidence" | "retention";

export function AuditCompliance({
  onNavigate,
  view: routedView,
  onViewChange,
}: {
  onNavigate?: (tab: "accounts" | "sessions") => void;
  // ADR-0137: when the application gives them, the tab is the address (`/audit/<view>`).
  view?: View;
  onViewChange?: (view: View) => void;
} = {}) {
  const [view, setView] = useRoutedView<View>("journal", routedView, onViewChange);
  const { t } = useAppTranslation();
  const { api } = useSignedIn();
  const [data, setData] = useState<Page<Account>>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>();

  useEffect(() => {
    let current = true;
    setLoading(true);
    api.request<Page<Account>>("GET", "/vault/accounts?page=1&pageSize=100")
      .then((result) => { if (current) { setData(result); setError(undefined); } })
      .catch((reason: unknown) => { if (current) { setData(undefined); setError(reason); } })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [api]);

  const findings = useMemo(() => findingsFor(data?.items ?? [], Date.now(), t), [data, t]);
  const counts = countByKind(findings);
  const recommendationCount = Number(counts.unpinned > 0) + Number(counts.rotation > 0);

  return (
    <AdminPage
      title={t("auditCompliance.title")}
      subtitle={t("auditCompliance.subtitle")}
      actions={
        <Button type="button" variant="primary" disabled title={t("auditCompliance.report.unavailable")}>
          <Download size={16} aria-hidden="true" />
          {t("auditCompliance.report.label")}
        </Button>
      }
      hints={[t("auditCompliance.hint")]}
    >
      <Notice
        error={error instanceof ApiError ? `${error.status} — ${error.message}` : error ? String((error as Error)?.message ?? error) : undefined}
      />

      <div className="reference-metrics" role="group" aria-label={t("auditCompliance.metricsAria")}>
        <ReferenceMetric
          size="compact"
          label={t("auditCompliance.metrics.events")}
          detail={t("auditCompliance.metrics.eventsDetail")}
        />
        <ReferenceMetric
          size="compact"
          label={t("auditCompliance.metrics.recorded")}
          value={t("auditCompliance.metrics.recordedValue")}
          detail={t("auditCompliance.metrics.recordedDetail")}
        />
        <ReferenceMetric
          size="compact"
          label={t("auditCompliance.metrics.denied")}
          detail={t("auditCompliance.metrics.deniedDetail")}
        />
        <ReferenceMetric
          size="compact"
          label={t("auditCompliance.metrics.retention")}
          detail={t("auditCompliance.metrics.retentionDetail")}
        />
      </div>

      <div className="audit-panels">
        <section className="ob-surface reference-panel audit-coverage" aria-labelledby="audit-coverage-title">
          <h3 id="audit-coverage-title">{t("auditCompliance.coverage.title")}</h3>
          <p className="audit-panel-note">{t("auditCompliance.coverage.note")}</p>
          <div className="audit-coverage-grid">
            {frameworks.map((framework) => (
              <div className="audit-coverage-item" key={framework}>
                <span className="audit-coverage-label">{framework}</span>
                <span className="audit-coverage-value">—</span>
                <span className="audit-coverage-track" aria-hidden="true" />
                <span className="audit-coverage-detail">{t("auditCompliance.coverage.notEvaluated")}</span>
              </div>
            ))}
          </div>
          <p className="audit-panel-footnote">{t("auditCompliance.coverage.unavailable")}</p>
        </section>

        <section className="audit-recommendations" aria-labelledby="audit-recommendations-title">
          <div className="audit-recommendations-heading">
            <h3 id="audit-recommendations-title">{t("auditCompliance.recommendations.title")}</h3>
            <span className="audit-recommendations-badge">{String(recommendationCount).padStart(2, "0")}</span>
          </div>
          {loading ? <p className="audit-recommendations-state" role="status">{t("common.loading")}</p> : null}
          {!loading && findings.length === 0 ? (
            <p className="audit-recommendations-state">{error ? t("auditCompliance.recommendations.unavailable") : t("auditCompliance.recommendations.none")}</p>
          ) : null}
          {!loading && counts.unpinned > 0 ? (
            <div className="audit-recommendation">
              <strong>{t("auditCompliance.recommendations.unpinned", { count: counts.unpinned })}</strong>
              <span>{t("auditCompliance.recommendations.unpinnedDetail")}</span>
            </div>
          ) : null}
          {!loading && counts.rotation > 0 ? (
            <div className="audit-recommendation">
              <strong>{t("auditCompliance.recommendations.rotation", { count: counts.rotation })}</strong>
              <span>{t("auditCompliance.recommendations.rotationDetail")}</span>
            </div>
          ) : null}
          {onNavigate ? (
            <Button variant="ghost" className="audit-recommendations-link" onClick={() => onNavigate("accounts")}>
              {t("auditCompliance.recommendations.action")} <span aria-hidden="true">→</span>
            </Button>
          ) : null}
        </section>
      </div>

      <Tabs value={view} onValueChange={(next) => setView(next as View)} className="reference-tabs audit-tabs">
        <TabsList aria-label={t("auditCompliance.tabsAria")}>
          <TabsTrigger value="journal">{t("auditCompliance.tabs.journal")}</TabsTrigger>
          <TabsTrigger value="reports">{t("auditCompliance.tabs.reports")}</TabsTrigger>
          <TabsTrigger value="evidence">{t("auditCompliance.tabs.evidence")}</TabsTrigger>
          <TabsTrigger value="retention">{t("auditCompliance.tabs.retention")}</TabsTrigger>
        </TabsList>

        <TabsContent value="journal">
          <section className="ob-surface reference-panel audit-journal" aria-label={t("auditCompliance.journal.title")}>
            <div className="reference-table-toolbar">
              <Label className="reference-search is-unavailable">
                <Search size={15} aria-hidden="true" />
                <Input
                  type="search"
                  disabled
                  aria-label={t("auditCompliance.journal.searchAria")}
                  title={t("auditCompliance.journal.unavailable")}
                  placeholder={t("auditCompliance.journal.searchPlaceholder")}
                />
              </Label>
              <Label className="reference-select is-unavailable">
                <Select disabled aria-label={t("auditCompliance.journal.period")} title={t("auditCompliance.journal.unavailable")}>
                  <option>{t("auditCompliance.journal.periodToday")}</option>
                </Select>
                <ChevronDown size={14} aria-hidden="true" />
              </Label>
              <Label className="reference-select is-unavailable">
                <Select disabled aria-label={t("auditCompliance.journal.eventType")} title={t("auditCompliance.journal.unavailable")}>
                  <option>{t("auditCompliance.journal.allEvents")}</option>
                </Select>
                <ChevronDown size={14} aria-hidden="true" />
              </Label>
              <Button variant="ghost" className="reference-toolbar-action" disabled title={t("auditCompliance.journal.unavailable")}>
                <Download size={15} aria-hidden="true" />
                {t("auditCompliance.journal.export")}
              </Button>
            </div>
            <div className="ob-table-wrap reference-table-wrap">
              <table className="ob-data-table reference-table audit-journal-table">
                <caption className="ob-visually-hidden">{t("auditCompliance.journal.title")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("auditCompliance.journal.columns.timestamp")}</th>
                    <th scope="col">{t("auditCompliance.journal.columns.actor")}</th>
                    <th scope="col">{t("auditCompliance.journal.columns.event")}</th>
                    <th scope="col">{t("auditCompliance.journal.columns.resource")}</th>
                    <th scope="col">{t("auditCompliance.journal.columns.result")}</th>
                    <th scope="col"><span className="ob-visually-hidden">{t("auditCompliance.journal.columns.details")}</span></th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td colSpan={6} className="audit-journal-state">
                      <strong>{t("auditCompliance.journal.unavailableTitle")}</strong>
                      <p>{t("auditCompliance.journal.unavailable")}</p>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <ReferencePager page={1} pageSize={pageSize} totalItems={0} noun={t("auditCompliance.journal.noun")} onPage={() => undefined} />
          </section>
          <SimulatedAuditEvents />
        </TabsContent>

        <TabsContent value="reports">
          <section className="ob-surface reference-panel reference-unavailable" aria-label={t("auditCompliance.tabs.reports")}>
            <h3>{t("auditCompliance.reports.title")}</h3>
            <p>{t("auditCompliance.reports.body")}</p>
          </section>
        </TabsContent>

        <TabsContent value="evidence">
          <section className="ob-surface reference-panel reference-unavailable" aria-label={t("auditCompliance.tabs.evidence")}>
            <h3>{t("auditCompliance.evidence.title")}</h3>
            <p>{t("auditCompliance.evidence.body")}</p>
            {onNavigate
              ? <Button onClick={() => onNavigate("sessions")}>{t("auditCompliance.evidence.action")}</Button>
              : null}
          </section>
        </TabsContent>

        <TabsContent value="retention">
          <section className="ob-surface reference-panel reference-unavailable" aria-label={t("auditCompliance.tabs.retention")}>
            <h3>{t("auditCompliance.retention.title")}</h3>
            <p>{t("auditCompliance.retention.body")}</p>
          </section>
        </TabsContent>
      </Tabs>
    </AdminPage>
  );
}
