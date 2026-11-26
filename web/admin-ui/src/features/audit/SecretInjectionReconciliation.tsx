import { useCallback, useState } from "react";
import { useCapabilities } from "../../shared/capabilities";
import { ApiError, SecretInjectionReconciliation as Result, SecretInjectionOutcome } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { useAppTranslation } from "../../shared/i18n";
import { Badge, Button } from "@openbastion/ui";

const limit = 100;

function validResult(value: unknown): value is Result {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (!Array.isArray(v.outcomes) || !["retained_audit_chain", "verified_archives_and_retained_chain"].includes(String(v.coverage))) return false;
  if (v.archived_history_excluded !== false || typeof v.has_more !== "boolean" ||
      !Number.isSafeInteger(v.scanned_events) || Number(v.scanned_events) < 0 ||
      !Number.isSafeInteger(v.archived_events) || Number(v.archived_events) < 0 || Number(v.archived_events) > Number(v.scanned_events)) return false;
  if (v.has_more && (typeof v.next_before !== "string" || !/^[0-9a-f]{32}$/.test(v.next_before))) return false;
  return v.outcomes.every((item) => {
    if (!item || typeof item !== "object") return false;
    const o = item as Record<string, unknown>;
    return typeof o.injection_id === "string" && /^[0-9a-f]{32}$/.test(o.injection_id) &&
      typeof o.session_id === "string" && typeof o.account_id === "string" &&
      ["ssh", "rdp", "vnc"].includes(String(o.protocol)) &&
      ["completed", "failed", "outcome_unknown"].includes(String(o.status));
  });
}

function errorLabel(error: unknown, t: (key: string) => string): string {
  if (error instanceof ApiError && error.status === 403) return t("auditInjections.errors.forbidden");
  if (error instanceof ApiError && error.status === 503) return t("auditInjections.errors.unavailable");
  return t("auditInjections.errors.generic");
}

export function SecretInjectionReconciliation() {
  const { api } = useSignedIn();
  const { t } = useAppTranslation();
  const { visible } = useCapabilities();
  const [result, setResult] = useState<Result>();
  const [cursor, setCursor] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>();
  const [started, setStarted] = useState(false);

  const read = useCallback(async (before = "") => {
    setLoading(true);
    setError(undefined);
    try {
      const query = new URLSearchParams({ limit: String(limit) });
      if (before) query.set("before", before);
      const response = await api.request<unknown>("GET", `/audit/secret-injections?${query.toString()}`);
      if (!validResult(response)) throw new Error("invalid or incomplete audit coverage");
      setResult(response);
      setCursor(before);
      setStarted(true);
    } catch (err) {
      setResult(undefined);
      setError(err);
      setStarted(true);
    } finally {
      setLoading(false);
    }
  }, [api]);


  // ADR-0131: the reconciliation is for those whose policies open it; for the others it is absent.
  if (!visible("audit.secretInjections")) return null;
  return (
    <section className="ob-surface" aria-labelledby="secret-injection-audit-title">
      <div className="ob-section-heading">
        <h3 id="secret-injection-audit-title">{t("auditInjections.title")}</h3>
        <Badge>{t("auditInjections.readOnly")}</Badge>
      </div>
      <p>{t("auditInjections.description")}</p>
      {!started && !loading ? <Button onClick={() => void read()}>{t("auditInjections.load")}</Button> : null}
      {loading ? <p role="status" className="ob-empty-state">{t("auditInjections.loading")}</p> : null}
      {!loading && error ? <div role="alert" className="ob-notice ob-notice--error"><p>{errorLabel(error, t)}</p><Button onClick={() => void read(cursor)}>{t("common.actions.retry")}</Button></div> : null}
      {!loading && result ? <>
        <p className="ob-muted">{t("auditInjections.coverage", { coverage: result.coverage, archived: result.archived_events, scanned: result.scanned_events })}</p>
        {result.outcomes.length === 0 ? <p className="ob-empty-state">{t("auditInjections.empty")}</p> :
          <div className="ob-table-wrap"><table>
            <thead><tr><th>{t("auditInjections.columns.started")}</th><th>{t("auditInjections.columns.session")}</th><th>{t("auditInjections.columns.account")}</th><th>{t("auditInjections.columns.protocol")}</th><th>{t("auditInjections.columns.status")}</th></tr></thead>
            <tbody>{result.outcomes.map((item: SecretInjectionOutcome) => <tr key={item.injection_id}>
              <td>{item.started_at ? <time dateTime={item.started_at}>{new Date(item.started_at).toLocaleString()}</time> : t("auditInjections.unknownTime")}</td>
              <td><code>{item.session_id || "—"}</code></td><td><code>{item.account_id || "—"}</code></td><td>{item.protocol}</td>
              <td><strong>{t(`auditInjections.status.${item.status}`)}</strong>{item.status !== "completed" ? <p className="ob-muted">{t("auditInjections.manualCheck")}</p> : null}</td>
            </tr>)}</tbody>
          </table></div>}
        {result.has_more && result.next_before ? <div className="ob-pager"><Button disabled={loading} onClick={() => void read(result.next_before)}>{t("auditInjections.nextPage")}</Button></div> : null}
      </> : null}
      {!loading && started && !result && !error ? <p className="ob-empty-state">{t("auditInjections.empty")}</p> : null}
      <p className="ob-muted">{t("auditInjections.noRetry")}</p>
    </section>
  );
}
