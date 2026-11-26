import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { ApiError, SessionAlert, SessionAlertPage, SessionAlertSummary } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { useAppTranslation } from "../../shared/i18n";
import { Notice } from "../../shared/Notice";
import { AppConfirmDialog, Badge, Button, Form, Label, Select } from "@openbastion/ui";

const PAGE_SIZE = 50;

type Filters = { status: string; severity: string };

function severityTone(severity: SessionAlert["severity"]): "neutral" | "info" | "warning" | "danger" {
  if (severity === "critical" || severity === "high") return "danger";
  if (severity === "medium") return "warning";
  if (severity === "low") return "info";
  return "neutral";
}

function alertError(error: unknown): string {
  return error instanceof ApiError ? `${error.status} — ${error.message}` : String((error as Error)?.message ?? error);
}

// The public Gateway is the only source for this queue. Alert visibility and acknowledgement
// remain separate server-side ABAC decisions; the UI never infers rights from token claims.
export function SessionAlerts({ onSummaryChange }: { onSummaryChange?: (summary: SessionAlertSummary | undefined) => void }) {
  const { t, i18n } = useAppTranslation();
  const { api } = useSignedIn();
  const [filters, setFilters] = useState<Filters>({ status: "unacknowledged", severity: "" });
  const [appliedFilters, setAppliedFilters] = useState<Filters>({ status: "unacknowledged", severity: "" });
  const [page, setPage] = useState<SessionAlertPage>();
  const [summary, setSummary] = useState<SessionAlertSummary>();
  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>();
  const [success, setSuccess] = useState<string>();
  const [acknowledging, setAcknowledging] = useState<string>();
  const [confirmAlert, setConfirmAlert] = useState<SessionAlert>();
  const [confirmError, setConfirmError] = useState<string>();
  const loadSequence = useRef(0);

  const load = useCallback(async (cursor = "", preserveError = false) => {
    const sequence = ++loadSequence.current;
    setLoading(true);
    if (!preserveError) setError(undefined);
    const params = new URLSearchParams({ limit: String(PAGE_SIZE) });
    if (appliedFilters.status) params.set("status", appliedFilters.status);
    if (appliedFilters.severity) params.set("severity", appliedFilters.severity);
    if (cursor) params.set("cursor", cursor);
    const [pageResult, summaryResult] = await Promise.allSettled([
      api.request<SessionAlertPage>("GET", `/session-alerts?${params.toString()}`),
      api.request<SessionAlertSummary>("GET", "/session-alerts/summary"),
    ]);
    if (sequence !== loadSequence.current) return;
    if (pageResult.status === "fulfilled") setPage(pageResult.value);
    else {
      setPage(undefined);
      if (!preserveError) setError(pageResult.reason);
    }
    if (summaryResult.status === "fulfilled") {
      setSummary(summaryResult.value);
      onSummaryChange?.(summaryResult.value);
    } else {
      setSummary(undefined);
      onSummaryChange?.(undefined);
      if (pageResult.status === "fulfilled" && !preserveError) setError(summaryResult.reason);
    }
    setLoading(false);
  }, [api, appliedFilters, onSummaryChange]);

  useEffect(() => {
    void load();
    return () => { loadSequence.current += 1; };
  }, [load]);

  function applyFilters(event: FormEvent) {
    event.preventDefault();
    setCursorStack([]);
    setSuccess(undefined);
    setAppliedFilters(filters);
  }

  function refresh() {
    setSuccess(undefined);
    void load(cursorStack[cursorStack.length - 1] ?? "");
  }

  function nextPage() {
    if (!page?.has_more || !page.next_cursor) return;
    const stack = [...cursorStack, page.next_cursor];
    setCursorStack(stack);
    void load(page.next_cursor);
  }

  function previousPage() {
    if (cursorStack.length === 0) return;
    const stack = cursorStack.slice(0, -1);
    setCursorStack(stack);
    void load(stack[stack.length - 1] ?? "");
  }

  async function acknowledge(): Promise<boolean> {
    if (!confirmAlert || acknowledging) return false;
    const alert = confirmAlert;
    setAcknowledging(alert.id);
    setConfirmError(undefined);
    setError(undefined);
    setSuccess(undefined);
    try {
      await api.request("POST", `/session-alerts/${encodeURIComponent(alert.id)}/acknowledge`, {
        expected_revision: alert.revision,
      });
      setConfirmAlert(undefined);
      setSuccess(t("sessions.alerts.acknowledged", { id: alert.id }));
      await load(cursorStack[cursorStack.length - 1] ?? "");
      return true;
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        // Another operator changed this occurrence. Close the stale confirmation and reload the
        // current cursor; never retry with a revision the server has not supplied.
        setConfirmAlert(undefined);
        setError(err);
        await load(cursorStack[cursorStack.length - 1] ?? "", true);
        return true;
      }
      setConfirmError(alertError(err));
      return false;
    } finally {
      setAcknowledging(undefined);
    }
  }

  function detectedAt(value: string): string {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString(i18n.language, { dateStyle: "medium", timeStyle: "short" });
  }

  return (
    <section className="ob-surface reference-panel session-alerts" aria-labelledby="session-alerts-title">
      <div className="reference-panel-heading">
        <div>
          <h3 id="session-alerts-title">{t("sessions.alerts.recentTitle")}</h3>
          <p>{t("sessions.alerts.description")}</p>
        </div>
        <Button variant="secondary" disabled={loading} onClick={refresh}>
          {t("sessions.alerts.refresh")}
        </Button>
      </div>

      {summary && !summary.durable ? <p className="ob-hint" role="status">{t("sessions.alerts.notDurable")}</p> : null}
      <Notice error={error} ok={success} />

      <Form className="reference-table-toolbar session-alerts-toolbar" onSubmit={applyFilters} aria-label={t("sessions.alerts.filtersAria")}>
        <Label className="reference-select">
          <span>{t("sessions.alerts.statusLabel")}</span>
          <Select aria-label={t("sessions.alerts.statusLabel")} value={filters.status} onChange={(event) => setFilters((current) => ({ ...current, status: event.target.value }))}>
            <option value="unacknowledged">{t("sessions.alerts.status.unacknowledged")}</option>
            <option value="acknowledged">{t("sessions.alerts.status.acknowledged")}</option>
            <option value="">{t("sessions.alerts.status.all")}</option>
          </Select>
        </Label>
        <Label className="reference-select">
          <span>{t("sessions.alerts.severityLabel")}</span>
          <Select aria-label={t("sessions.alerts.severityLabel")} value={filters.severity} onChange={(event) => setFilters((current) => ({ ...current, severity: event.target.value }))}>
            <option value="">{t("sessions.alerts.severity.all")}</option>
            {(["critical", "high", "medium", "low", "info"] as const).map((severity) => (
              <option key={severity} value={severity}>{t(`sessions.alerts.severity.${severity}`)}</option>
            ))}
          </Select>
        </Label>
        <Button type="submit" variant="primary" disabled={loading}>{t("sessions.alerts.applyFilters")}</Button>
      </Form>

      {loading ? <p className="ob-empty-state" role="status">{t("sessions.alerts.loading")}</p> : null}
      {!loading && page && page.alerts.length === 0 ? <p className="ob-empty-state">{t("sessions.alerts.empty")}</p> : null}
      {!loading && page && page.alerts.length > 0 ? (
        <div className="reference-table-wrap">
          <table className="reference-table session-alerts-table">
            <caption className="ob-visually-hidden">{t("sessions.alerts.caption")}</caption>
            <thead><tr>
              <th scope="col">{t("sessions.alerts.columns.severity")}</th>
              <th scope="col">{t("sessions.alerts.columns.alert")}</th>
              <th scope="col">{t("sessions.alerts.columns.session")}</th>
              <th scope="col">{t("sessions.alerts.columns.detected")}</th>
              <th scope="col">{t("sessions.alerts.columns.status")}</th>
              <th scope="col"><span className="ob-visually-hidden">{t("sessions.alerts.columns.actions")}</span></th>
            </tr></thead>
            <tbody>{page.alerts.map((alert) => (
              <tr key={alert.id}>
                <td><Badge tone={severityTone(alert.severity)}>{t(`sessions.alerts.severity.${alert.severity}`)}</Badge></td>
                <td>
                  <span className="reference-identifier">{alert.summary}</span>
                  <span className="reference-cell-note">{alert.rule_id} · <code>{alert.id}</code></span>
                </td>
                <td><code>{alert.session_id}</code></td>
                <td><time dateTime={alert.detected_at}>{detectedAt(alert.detected_at)}</time></td>
                <td>
                  <Badge tone={alert.status === "acknowledged" ? "success" : "warning"}>
                    {t(`sessions.alerts.status.${alert.status}`)}
                  </Badge>
                  {alert.acknowledged_at ? <span className="reference-cell-note">{t("sessions.alerts.acknowledgedBy", { actor: alert.acknowledged_by, date: detectedAt(alert.acknowledged_at) })}</span> : null}
                </td>
                <td>
                  {alert.status === "unacknowledged" ? (
                    <Button variant="secondary" disabled={acknowledging === alert.id} onClick={() => { setConfirmError(undefined); setConfirmAlert(alert); }}>
                      {t("sessions.alerts.acknowledge")}
                    </Button>
                  ) : "—"}
                </td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      ) : null}

      {!loading && page ? (
        <div className="reference-table-footer">
          <p className="reference-table-range">{t("sessions.alerts.page", { count: page.alerts.length, page: cursorStack.length + 1 })}</p>
          <nav className="reference-pager" aria-label={t("common.pager.aria")}>
            <Button variant="ghost" aria-label={t("sessions.alerts.previous")} disabled={cursorStack.length === 0} onClick={previousPage}>‹</Button>
            <Button variant="ghost" aria-current="page">{cursorStack.length + 1}</Button>
            <Button variant="ghost" aria-label={t("sessions.alerts.next")} disabled={!page.has_more || !page.next_cursor} onClick={nextPage}>›</Button>
          </nav>
        </div>
      ) : null}

      {confirmAlert ? (
        <AppConfirmDialog
          cancelLabel={t("common.actions.cancel")}
          workingLabel={t("common.actions.working")}
          title={t("sessions.alerts.confirmTitle")}
          description={t("sessions.alerts.confirmBody", { id: confirmAlert.id })}
          confirmLabel={t("sessions.alerts.confirmAcknowledge")}
          danger={false}
          error={confirmError}
          onCancel={() => { setConfirmAlert(undefined); setConfirmError(undefined); }}
          onConfirm={acknowledge}
        />
      ) : null}
    </section>
  );
}
