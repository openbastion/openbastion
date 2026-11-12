import { useCallback, useEffect, useState } from "react";
import { Account, Page, accountPath } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { useSignedIn } from "../../shared/session";
import { AdminPage } from "../../shared/ui/AdminPage";
import { Pager } from "../../shared/ui/Pager";
import { AccountActions, AccountTable } from "./AccountTable";
import { OnboardAccount } from "./OnboardAccount";
import { askHostKey, askTlsPin } from "./pinPrompts";

const pageSize = 20;

// Privileged accounts of the Vault: list, onboard, rotate, disable. A secret is typed once at
// onboarding and never shown again: the API never returns one. A rotation changes the secret on
// the target, through the account's reconciliation account (ADR-0037). Each account pins its
// target's host key (ADR-0039): the secret goes only to the server that presents it. An account
// may require another person's approval, with a ticket, for every session on it (ADR-0067). A VNC
// account pins its target's TLS certificate instead of a host key (ADR-0071), and is not rotated.
export function Accounts() {
  const { api } = useSignedIn();
  const [page, setPage] = useState(1);
  const [data, setData] = useState<Page<Account>>();
  const [error, setError] = useState<unknown>();
  const [ok, setOk] = useState<string>();
  const [filter, setFilter] = useState("");

  const load = useCallback(() => {
    api.request<Page<Account>>("GET", `/vault/accounts?page=${page}&pageSize=${pageSize}`).then(setData, setError);
  }, [api, page]);
  useEffect(load, [load]);

  async function act(what: string | ((result: unknown) => string), run: () => Promise<unknown>) {
    setError(undefined);
    setOk(undefined);
    try {
      const result = await run();
      setOk(typeof what === "string" ? what : what(result));
      load();
    } catch (err) {
      setError(err);
    }
  }

  // Filtering is deliberately limited to the server page already loaded; it never implies a
  // complete inventory when the public API has not defined a search contract.
  const filteredAccounts = (data?.items ?? []).filter((account) => {
    const query = filter.trim().toLocaleLowerCase("fr");
    if (!query) return true;
    return [account.id, account.name, account.username, account.targetHost, account.protocol]
      .some((value) => value.toLocaleLowerCase("fr").includes(query));
  });

  const actions: AccountActions = {
    pinKey(a) {
      const key = askHostKey(a);
      if (!key) return;
      act(
        (r) => `Clé d'hôte de ${a.id} épinglée : ${(r as { hostKeyFingerprint?: string } | undefined)?.hostKeyFingerprint ?? ""}`,
        () => api.request("PUT", `${accountPath(a.id)}/host-key`, { hostKey: key }),
      );
    },
    pinTls(a) {
      const pin = askTlsPin(a);
      if (!pin) return;
      act(`Certificat TLS de ${a.id} épinglé`, () =>
        api.request("PUT", `${accountPath(a.id)}/tls-pin`, { tlsCertificateSha256: pin.fingerprint, targetDomain: pin.domain }),
      );
    },
    toggleApproval(a) {
      act(a.approvalRequired ? `${a.id} : sessions sans approbation` : `${a.id} : approbation requise`, () =>
        api.request("PUT", `${accountPath(a.id)}/approval`, { approvalRequired: !a.approvalRequired }),
      );
    },
    rotate(a) {
      act(`Secret de ${a.id} renouvelé sur la cible`, () => api.request("POST", `${accountPath(a.id)}/rotate`));
    },
    disable(a) {
      if (window.confirm(`Désactiver ${a.id} ?`)) act(`${a.id} désactivé`, () => api.request("DELETE", accountPath(a.id)));
    },
  };

  return (
    <AdminPage
      title="Comptes privilégiés"
      hints={[
        "Renouveler un secret le change sur la cible, par le compte de réconciliation du compte, et le vérifie avant de l'adopter : un compte sans compte de réconciliation ne peut pas être renouvelé.",
        "Le secret n'est envoyé qu'au serveur qui présente la clé d'hôte épinglée : un compte sans clé n'ouvre aucune session et n'est pas renouvelé. Relevez la clé sur la cible elle-même, pas par le réseau que vous voulez protéger.",
        "Un compte VNC ou RDP épingle de même le certificat TLS de sa cible : sans empreinte, il n'ouvre aucune session.",
      ]}
    >
      <Notice error={error} ok={ok} />
      <div className="card">
        {data && data.items.length === 0 ? <p className="empty">Aucun compte privilégié pour l'instant — enregistrez-en un ci-dessous.</p> : null}
        {data && data.items.length > 0 ? (
          <div className="page-filter">
            <label htmlFor="account-page-filter">Filtrer les comptes de cette page</label>
            <input
              id="account-page-filter"
              type="search"
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              placeholder="Identifiant, nom, utilisateur, cible ou protocole…"
            />
            <p className="filter-help">Filtre local limité aux {data.items.length} comptes chargés sur cette page ; il ne lance pas de recherche globale.</p>
            <p className="filter-count" aria-live="polite" aria-atomic="true">{filteredAccounts.length} sur {data.items.length} compte(s) affiché(s) sur cette page</p>
          </div>
        ) : null}
        {data && filteredAccounts.length > 0 ? <AccountTable accounts={filteredAccounts} actions={actions} /> : null}
        {data && data.items.length > 0 && filteredAccounts.length === 0 ? <p className="empty">Aucun compte de cette page ne correspond à ce filtre.</p> : null}
        {data ? <Pager page={data.page} pageSize={pageSize} totalItems={data.totalItems} noun="compte(s)" onPage={setPage} /> : null}
      </div>
      <OnboardAccount onDone={(id) => act(`${id} enregistré`, async () => undefined)} />
    </AdminPage>
  );
}
