import { useEffect, useMemo, useState } from "react";
import { Account, ApiError, Page } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { useSignedIn } from "../../shared/session";
import { AdminPage } from "../../shared/ui/AdminPage";
import { Badge } from "../../shared/ui/Badge";
import { useAppTranslation } from "../../shared/i18n";
import type { TFunction } from "i18next";

// `rotation` marks the reasons that concern a rotation: the "rotations in anomaly" counter reads
// that flag instead of searching a translated sentence, which a translation would break.
type Reason = { text: string; rotation: boolean };
type Finding = { account: Account; reasons: Reason[] };

function findingsFor(accounts: Account[], now: number, t: TFunction): Finding[] {
  return accounts.flatMap((account) => {
    const reasons: Reason[] = [];
    const protocol = account.protocol.toLowerCase();
    if (protocol === "ssh" && !account.hostKeyFingerprint) {
      reasons.push({ text: t("security.reasons.hostKey"), rotation: false });
    }
    if ((protocol === "vnc" || protocol === "rdp") && (!account.tlsCertificateSha256 || !account.targetDomain)) {
      reasons.push({ text: t("security.reasons.tls"), rotation: false });
    }
    if (account.rotationOwedSince) {
      reasons.push({ text: t("security.reasons.rotationOwed"), rotation: true });
    }
    if ((account.rotationFailures ?? 0) > 0) {
      reasons.push({ text: t("security.reasons.rotationFailures", { count: account.rotationFailures }), rotation: true });
    }
    if (account.rotationPolicy === "scheduled" && account.nextRotationAt && Date.parse(account.nextRotationAt) <= now) {
      reasons.push({ text: t("security.reasons.rotationOverdue"), rotation: true });
    }
    return reasons.length ? [{ account, reasons }] : [];
  });
}

// This view reports concrete account metadata only. It deliberately has no aggregate risk score,
// no audit feed (the Gateway does not expose GET /audit/events), and no claim of full coverage
// when the public Vault page is truncated by pagination.
export function SecurityCenter() {
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
      .catch((reason: unknown) => { if (current) setError(reason); })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [api]);

  const findings = useMemo(() => findingsFor(data?.items ?? [], Date.now(), t), [data, t]);
  const incomplete = Boolean(data && data.totalItems > data.items.length);

  return (
    <AdminPage title={t("security.title")} hints={[t("security.hint")]}>
      <Notice error={error instanceof ApiError ? `${error.status} — ${error.message}` : error ? String((error as Error)?.message ?? error) : undefined} />
      {loading ? <p className="ob-empty-state" role="status">{t("security.analysing")}</p> : null}
      {!loading && data ? (
        <>
          <div className="ob-stat-grid" role="group" aria-label={t("security.metricsAria")}>
            <article className="ob-stat-card">
              <p className="ob-stat-label">{t("security.examined.label")}</p>
              <p className="ob-stat-value">{data.items.length}<span className="ob-stat-total"> / {data.totalItems}</span></p>
              <p className="ob-stat-detail">{incomplete ? t("security.examined.partial") : t("security.examined.complete")}</p>
            </article>
            <article className="ob-stat-card">
              <p className="ob-stat-label">{t("security.toFix.label")}</p>
              <p className="ob-stat-value">{findings.length}</p>
              <p className="ob-stat-detail">{t("security.toFix.detail")}</p>
            </article>
            <article className="ob-stat-card">
              <p className="ob-stat-label">{t("security.rotation.label")}</p>
              <p className="ob-stat-value">{findings.filter((finding) => finding.reasons.some((reason) => reason.rotation)).length}</p>
              <p className="ob-stat-detail">{t("security.rotation.detail")}</p>
            </article>
          </div>
          <section className="ob-surface ob-panel" aria-labelledby="security-findings-title">
            <div className="ob-section-heading">
              <div>
                <h3 id="security-findings-title">{t("security.findings.title")}</h3>
                <p className="ob-hint">{t("security.findings.hint")}</p>
              </div>
              <Badge>{t("security.findings.count", { count: findings.length })}</Badge>
            </div>
            {findings.length ? (
              <ul className="security-findings">
                {findings.map(({ account, reasons }) => (
                  <li key={account.id}>
                    <div className="security-finding-title">
                      <strong>{account.name || account.id}</strong>
                      <code>{account.id}</code>
                    </div>
                    <p className="cell-note">{account.protocol.toUpperCase()} · {account.targetHost}</p>
                    <ul>{reasons.map((reason) => <li key={reason.text}>{reason.text}</li>)}</ul>
                  </li>
                ))}
              </ul>
            ) : <p className="ob-empty-state">{t("security.findings.none")}</p>}
          </section>
          {incomplete ? <p className="ob-note" role="note">{t("security.incomplete", { loaded: data.items.length, total: data.totalItems })}</p> : null}
          <section className="ob-surface ob-panel security-limitations">
            <h3>{t("security.limitations.title")}</h3>
            <p>{t("security.limitations.body")}</p>
          </section>
        </>
      ) : null}
      {!loading && !data && !error ? <p className="ob-empty-state">{t("security.noData")}</p> : null}
    </AdminPage>
  );
}
