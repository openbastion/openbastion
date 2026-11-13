import { useEffect, useMemo, useState } from "react";
import { Account, ApiError, Page } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { useSignedIn } from "../../shared/session";
import { AdminPage } from "../../shared/ui/AdminPage";
import { Badge } from "../../shared/ui/Badge";

type Finding = { account: Account; reasons: string[] };

function findingsFor(accounts: Account[], now: number): Finding[] {
  return accounts.flatMap((account) => {
    const reasons: string[] = [];
    const protocol = account.protocol.toLowerCase();
    if (protocol === "ssh" && !account.hostKeyFingerprint) reasons.push("Clé d’hôte SSH non épinglée");
    if ((protocol === "vnc" || protocol === "rdp") && (!account.tlsCertificateSha256 || !account.targetDomain)) {
      reasons.push("Identité TLS de la cible incomplète");
    }
    if (account.rotationOwedSince) reasons.push("Rotation après utilisation à effectuer");
    if ((account.rotationFailures ?? 0) > 0) reasons.push(`Échecs de rotation consécutifs : ${account.rotationFailures}`);
    if (account.rotationPolicy === "scheduled" && account.nextRotationAt && Date.parse(account.nextRotationAt) <= now) {
      reasons.push("Rotation planifiée échue");
    }
    return reasons.length ? [{ account, reasons }] : [];
  });
}

// This view reports concrete account metadata only. It deliberately has no aggregate risk score,
// no audit feed (the Gateway does not expose GET /audit/events), and no claim of full coverage
// when the public Vault page is truncated by pagination.
export function SecurityCenter() {
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

  const findings = useMemo(() => findingsFor(data?.items ?? [], Date.now()), [data]);
  const incomplete = Boolean(data && data.totalItems > data.items.length);

  return (
    <AdminPage title="Centre de sécurité" hints={["Contrôles de configuration calculés à partir des métadonnées des comptes retournées par le Vault. Ce centre n’est ni un score de risque ni un audit de conformité."]}>
      <Notice error={error instanceof ApiError ? `${error.status} — ${error.message}` : error ? String((error as Error)?.message ?? error) : undefined} />
      {loading ? <p className="ob-empty-state" role="status">Analyse des métadonnées des comptes…</p> : null}
      {!loading && data ? (
        <>
          <div className="ob-stat-grid" role="group" aria-label="Indicateurs de sécurité">
            <article className="ob-stat-card">
              <p className="ob-stat-label">Comptes examinés</p>
              <p className="ob-stat-value">{data.items.length}<span className="ob-stat-total"> / {data.totalItems}</span></p>
              <p className="ob-stat-detail">{incomplete ? "Échantillon partiel — première page uniquement." : "Inventaire complet retourné par le Vault."}</p>
            </article>
            <article className="ob-stat-card">
              <p className="ob-stat-label">Configurations à corriger</p>
              <p className="ob-stat-value">{findings.length}</p>
              <p className="ob-stat-detail">Comptes avec au moins un signal explicite ci-dessous.</p>
            </article>
            <article className="ob-stat-card">
              <p className="ob-stat-label">Rotations en anomalie</p>
              <p className="ob-stat-value">{findings.filter((finding) => finding.reasons.some((reason) => reason.toLocaleLowerCase("fr").includes("rotation"))).length}</p>
              <p className="ob-stat-detail">Rotation due, échouée ou échue selon les champs du Vault.</p>
            </article>
          </div>
          <section className="ob-surface ob-panel" aria-labelledby="security-findings-title">
            <div className="ob-section-heading">
              <div>
                <h3 id="security-findings-title">Points à examiner</h3>
                <p className="ob-hint">Les signaux sont présentés sans pondération ni interprétation supplémentaire.</p>
              </div>
              <Badge>{findings.length} compte(s)</Badge>
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
                    <ul>{reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
                  </li>
                ))}
              </ul>
            ) : <p className="ob-empty-state">Aucun signal parmi les métadonnées des comptes examinés.</p>}
          </section>
          {incomplete ? <p className="ob-note" role="note">Analyse incomplète : {data.items.length} comptes examinés sur {data.totalItems}. Les comptes des pages suivantes ne sont pas inclus dans ces résultats.</p> : null}
          <section className="ob-surface ob-panel security-limitations">
            <h3>Ce que cette vue ne mesure pas</h3>
            <p>Le journal d’audit, les alertes comportementales, la conformité, la santé des proxies et les scores de risque ne sont pas exposés ici. La Gateway ne fournit actuellement aucune route publique de recherche d’événements d’audit ; aucune requête directe vers le service Audit ou sa base n’est effectuée.</p>
          </section>
        </>
      ) : null}
      {!loading && !data && !error ? <p className="ob-empty-state">Aucune donnée de compte disponible.</p> : null}
    </AdminPage>
  );
}
