import { useEffect, useState } from "react";
import { Account, Page, Session } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { AdminPage } from "../../shared/ui/AdminPage";

type Widget<T> = { data?: Page<T>; error?: unknown; loading: boolean };

function Metric({ label, value, detail, loading, error }: { label: string; value?: number; detail: string; loading: boolean; error?: unknown }) {
  return (
    <article className="card overview-metric">
      <p className="overview-metric-label">{label}</p>
      {loading ? <p className="overview-metric-value" role="status">…</p>
        : error ? <p className="overview-metric-unavailable">Indisponible</p>
        : <p className="overview-metric-value">{value ?? "—"}</p>}
      <p className="overview-metric-detail">{error ? "L’API n’a pas fourni cette donnée." : detail}</p>
    </article>
  );
}

// A small operational overview, composed only from public Gateway responses. Each source keeps
// its own loading/error state: a permission refusal on one domain must not hide another domain.
export function Overview() {
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
    <AdminPage title="Vue générale" hints={["Synthèse des données que votre identité est autorisée à consulter. Chaque indicateur est fourni par l’API publique ; aucune estimation ni score de risque n’est calculé ici."]}>
      <div className="overview-grid" aria-label="Indicateurs opérationnels">
        <Metric label="Comptes privilégiés" value={accounts.data?.totalItems} detail="Comptes actifs visibles dans le coffre-fort." loading={accounts.loading} error={accounts.error} />
        <Metric label="Approbations en attente" value={approvals.data?.totalItems} detail="Demandes que votre identité peut décider maintenant." loading={approvals.loading} error={approvals.error} />
        <Metric label="Rotations à examiner" value={rotationAttention} detail="Comptes chargés avec rotation due ou échecs signalés." loading={accounts.loading} error={accounts.error} />
      </div>
      <section className="card panel overview-guidance" aria-labelledby="overview-scope-title">
        <h3 id="overview-scope-title">Périmètre des données</h3>
        <p>Les comptes et les demandes d’approbation sont lus séparément via la Gateway. Un refus ou une indisponibilité est indiqué sur le widget concerné, sans être transformé en valeur nulle.</p>
        {accounts.data && accounts.data.totalItems > accounts.data.items.length ? (
          <p className="scope-note">L’indicateur de rotation porte sur {accounts.data.items.length} comptes chargés sur {accounts.data.totalItems} ; ouvrez le coffre-fort pour parcourir les pages restantes.</p>
        ) : null}
        {approvals.data?.truncated ? <p className="scope-note">La liste des demandes est tronquée par le service ; elle ne représente pas nécessairement toutes les demandes éligibles.</p> : null}
      </section>
    </AdminPage>
  );
}
