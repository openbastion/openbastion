import { useEffect, useState } from "react";
import { Account, Page, Session } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { AdminPage } from "../../shared/ui/AdminPage";
import { useAppTranslation } from "../../shared/i18n";

type Widget<T> = { data?: Page<T>; error?: unknown; loading: boolean };

// A count with a way to reach what it counts: a dashboard number an operator cannot act on is a
// dead end. The card stays an article when there is nothing to open (loading, refusal, no route).
function Metric({
  label,
  value,
  detail,
  loading,
  error,
  action,
}: {
  label: string;
  value?: number;
  detail: string;
  loading: boolean;
  error?: unknown;
  action?: { label: string; onClick: () => void };
}) {
  const { t } = useAppTranslation();
  const body = (
    <>
      <p className="ob-stat-label">{label}</p>
      {loading ? <p className="ob-stat-value" role="status">…</p>
        : error ? <p className="ob-stat-unavailable">{t("common.unavailable")}</p>
        : <p className="ob-stat-value">{value ?? "—"}</p>}
      <p className="ob-stat-detail">{error ? t("overview.apiUnavailable") : detail}</p>
      {action && !loading && !error ? (
        <span className="ob-stat-link">
          {action.label} <span aria-hidden="true">→</span>
        </span>
      ) : null}
    </>
  );
  if (!action || loading || error) return <article className="ob-stat-card">{body}</article>;
  return (
    <button type="button" className="ob-stat-card ob-stat-card-action" onClick={action.onClick}>
      {body}
    </button>
  );
}

// A small operational overview, composed only from public Gateway responses. Each source keeps
// its own loading/error state: a permission refusal on one domain must not hide another domain.
export function Overview({ onNavigate }: { onNavigate?: (tab: "accounts" | "sessions") => void } = {}) {
  const { t } = useAppTranslation();
  const { api } = useSignedIn();
  const [accounts, setAccounts] = useState<Widget<Account>>({ loading: true });
  const [approvals, setApprovals] = useState<Widget<Session>>({ loading: true });

  useEffect(() => {
    let current = true;
    api.request<Page<Account>>("GET", "/vault/accounts?page=1&pageSize=100")
      .then((data) => { if (current) setAccounts({ data, loading: false }); })
      .catch((error: unknown) => { if (current) setAccounts({ error, loading: false }); });
    api.request<Page<Session>>("GET", "/sessions?status=pending_approval&page=1&pageSize=100")
      .then((data) => { if (current) setApprovals({ data, loading: false }); })
      .catch((error: unknown) => { if (current) setApprovals({ error, loading: false }); });
    return () => { current = false; };
  }, [api]);

  const rotationAttention = (accounts.data?.items ?? []).filter((account) =>
    Boolean(account.rotationOwedSince) || (account.rotationFailures ?? 0) > 0,
  ).length;

  return (
    <AdminPage title={t("overview.title")} hints={[t("overview.hint")]}>
      <div className="ob-stat-grid" role="group" aria-label={t("overview.metricsAria")}>
        <Metric
          label={t("overview.accounts.label")}
          value={accounts.data?.totalItems}
          detail={t("overview.accounts.detail")}
          loading={accounts.loading}
          error={accounts.error}
          action={onNavigate ? { label: t("overview.accounts.action"), onClick: () => onNavigate("accounts") } : undefined}
        />
        <Metric
          label={t("overview.approvals.label")}
          value={approvals.data?.totalItems}
          detail={t("overview.approvals.detail")}
          loading={approvals.loading}
          error={approvals.error}
          action={onNavigate ? { label: t("overview.approvals.action"), onClick: () => onNavigate("sessions") } : undefined}
        />
        <Metric
          label={t("overview.rotations.label")}
          value={rotationAttention}
          detail={t("overview.rotations.detail")}
          loading={accounts.loading}
          error={accounts.error}
          action={onNavigate ? { label: t("overview.accounts.action"), onClick: () => onNavigate("accounts") } : undefined}
        />
      </div>
      <section className="ob-surface ob-panel overview-guidance" aria-labelledby="overview-scope-title">
        <h3 id="overview-scope-title">{t("overview.scope.title")}</h3>
        <p>{t("overview.scope.body")}</p>
        {accounts.data && accounts.data.totalItems > accounts.data.items.length ? (
          <p className="ob-note">{t("overview.scope.rotationNote", { loaded: accounts.data.items.length, total: accounts.data.totalItems })}</p>
        ) : null}
        {approvals.data?.truncated ? <p className="ob-note">{t("overview.scope.truncated")}</p> : null}
      </section>
    </AdminPage>
  );
}
