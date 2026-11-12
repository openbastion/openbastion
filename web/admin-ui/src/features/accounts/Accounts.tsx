import { FormEvent, useCallback, useEffect, useState } from "react";
import { Account, ApiError, Page, accountPath } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { useSignedIn } from "../../shared/session";
import { AdminPage } from "../../shared/ui/AdminPage";
import { Pager } from "../../shared/ui/Pager";
import { ConfirmDialog } from "../../shared/ui/ConfirmDialog";
import { Button } from "../../shared/ui/Button";
import { InlineNotice } from "../../shared/ui/InlineNotice";
import { AccountActions, AccountTable } from "./AccountTable";
import { OnboardAccount } from "./OnboardAccount";
import { askHostKey, askTlsPin } from "./pinPrompts";
import {
  AccountFilterRule,
  accountFilterFields,
  defaultAccountFilterValue,
  maxAccountFilterRules,
  isAccountFilterField,
  matchesAccountFilterRules,
  readSavedAccountViews,
  SavedAccountView,
  writeSavedAccountViews,
} from "../../shared/savedAccountViews";

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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>();
  const [ok, setOk] = useState<string>();
  const [filter, setFilter] = useState("");
  const [filtersOpen, setFiltersOpen] = useState(true);
  const [filterRules, setFilterRules] = useState<AccountFilterRule[]>([]);
  const [savedViews, setSavedViews] = useState<SavedAccountView[]>(readSavedAccountViews);
  const [selectedSavedView, setSelectedSavedView] = useState("");
  const [newViewName, setNewViewName] = useState("");
  const [viewNotice, setViewNotice] = useState<string>();
  const [accountAction, setAccountAction] = useState<{ kind: "disable" | "rotate"; account: Account }>();

  const load = useCallback(() => {
    setLoading(true);
    api.request<Page<Account>>("GET", `/vault/accounts?page=${page}&pageSize=${pageSize}`)
      .then((result) => { setData(result); setError(undefined); })
      .catch(setError)
      .finally(() => setLoading(false));
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
  const activeFilterCount = Number(filter.trim().length > 0) + filterRules.length;

  const filteredAccounts = (data?.items ?? []).filter((account) => {
    const query = filter.trim().toLocaleLowerCase("fr");
    if (query && ![account.id, account.name, account.username, account.targetHost, account.protocol]
      .some((value) => value.toLocaleLowerCase("fr").includes(query))) return false;
    return matchesAccountFilterRules(account, filterRules);
  });

  function updateFilterRule(index: number, patch: Partial<AccountFilterRule>) {
    setFilterRules((current) => current.map((rule, position) => position === index ? { ...rule, ...patch } : rule));
  }

  function addFilterRule() {
    setFilterRules((current) => {
      const nextField = accountFilterFields.find((field) => !current.some((rule) => rule.field === field));
      if (!nextField || current.length >= maxAccountFilterRules) return current;
      return [...current, {
        field: nextField,
        comparison: "is",
        value: defaultAccountFilterValue(nextField),
        join: "AND",
      }];
    });
  }

  function removeFilterRule(index: number) {
    setFilterRules((current) => current.filter((_, position) => position !== index));
  }

  function saveCurrentView(event: FormEvent) {
    event.preventDefault();
    const name = newViewName.trim().slice(0, 32);
    if (name.length < 2) {
      setViewNotice(undefined);
      setError("Donnez un nom de deux caractères au minimum.");
      return;
    }
    const next = [
      ...savedViews.filter((view) => view.name.toLocaleLowerCase("fr") !== name.toLocaleLowerCase("fr")),
      { name, rules: filterRules },
    ].slice(-12);
    setViewNotice(undefined);
    if (!writeSavedAccountViews(next)) {
      setError("Impossible d'enregistrer cette vue dans le stockage local du navigateur.");
      return;
    }
    setError(undefined);
    setSavedViews(next);
    setSelectedSavedView(name);
    setNewViewName("");
    setViewNotice("Vue enregistrée dans ce navigateur.");
  }

  function applySavedView(name: string) {
    setSelectedSavedView(name);
    const view = savedViews.find((item) => item.name === name);
    if (view) {
      setFilterRules(view.rules);
      setFilter("");
    }
  }

  function deleteSavedView() {
    const next = savedViews.filter((view) => view.name !== selectedSavedView);
    setViewNotice(undefined);
    if (!writeSavedAccountViews(next)) {
      setError("Impossible de supprimer cette vue du stockage local du navigateur.");
      return;
    }
    setError(undefined);
    setSavedViews(next);
    setSelectedSavedView("");
    setViewNotice("Vue supprimée de ce navigateur.");
  }

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
      setError(undefined);
      setOk(undefined);
      setAccountAction({ kind: "rotate", account: a });
    },
    disable(a) {
      setError(undefined);
      setOk(undefined);
      setAccountAction({ kind: "disable", account: a });
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
      <Notice error={accountAction ? undefined : error} ok={accountAction ? undefined : ok} />
      <section className="ob-surface account-inventory" aria-label="Inventaire des comptes privilégiés">
        {loading ? <p className="ob-empty-state" role="status">Chargement des comptes privilégiés…</p> : null}
        {!loading && data && data.items.length === 0 ? <p className="ob-empty-state">Aucun compte privilégié pour l'instant — enregistrez-en un ci-dessous.</p> : null}
        {!loading && data && data.items.length > 0 ? (
          <div className="ob-filter-bar account-filter-bar">
            <div className="account-filter-toolbar">
              <button
                className="account-filter-trigger"
                type="button"
                aria-expanded={filtersOpen}
                aria-controls="account-filter-builder"
                onClick={() => setFiltersOpen((open) => !open)}
              >
                <span className="account-filter-trigger-icon" aria-hidden="true">☷</span>
                <span>Filtres avancés</span>
                <span className="account-filter-count" aria-label={`${activeFilterCount} filtre(s) actif(s)`}>{activeFilterCount}</span>
                <span className="account-filter-chevron" aria-hidden="true">{filtersOpen ? "⌃" : "⌄"}</span>
              </button>
              {activeFilterCount > 0 ? <Button type="button" onClick={() => { setFilter(""); setFilterRules([]); setSelectedSavedView(""); }}>Réinitialiser</Button> : null}
            </div>
            {filtersOpen ? (
              <div id="account-filter-builder" className="account-filter-builder" aria-label="Constructeur de filtres">
                <div className="account-filter-context">
                  <span className="account-filter-where">OÙ</span>
                  <label className="account-filter-search">
                    <span>Filtrer les comptes de cette page</span>
                    <input
                      id="account-page-filter"
                      type="search"
                      value={filter}
                      onChange={(event) => setFilter(event.target.value)}
                      placeholder="Identifiant, nom, utilisateur, cible ou protocole…"
                    />
                  </label>
                </div>
                <p className="ob-filter-help">La recherche et les critères ci-dessous s'appliquent uniquement aux {data.items.length} comptes chargés sur cette page ; aucune recherche globale n'est lancée. Le texte saisi n'est jamais enregistré dans une vue.</p>
                <div className="account-filter-rules" aria-label="Règles de filtrage">
                  {filterRules.map((rule, index) => (
                    <div className="account-filter-rule" key={index}>
                      {index > 0 ? (
                        <label className="account-filter-join-control">
                          <span>Combinaison</span>
                          <select
                            aria-label={`Combinaison avant la règle ${index + 1}`}
                            value={rule.join}
                            onChange={(event) => updateFilterRule(index, { join: event.target.value as AccountFilterRule["join"] })}
                          >
                            <option value="AND">ET</option>
                            <option value="OR">OU</option>
                          </select>
                        </label>
                      ) : <span className="account-filter-join-placeholder" aria-hidden="true">OÙ</span>}
                      <label className="account-filter-field">
                        <span>Champ</span>
                        <select
                          aria-label={`Champ de la règle ${index + 1}`}
                          value={rule.field}
                          onChange={(event) => {
                            if (!isAccountFilterField(event.target.value)) return;
                            updateFilterRule(index, { field: event.target.value, value: defaultAccountFilterValue(event.target.value) });
                          }}
                        >
                          <option value="protocol" disabled={filterRules.some((other, position) => position !== index && other.field === "protocol")}>Protocole</option>
                          <option value="approval" disabled={filterRules.some((other, position) => position !== index && other.field === "approval")}>Approbation</option>
                          <option value="identity" disabled={filterRules.some((other, position) => position !== index && other.field === "identity")}>Identité de la cible</option>
                          <option value="rotation" disabled={filterRules.some((other, position) => position !== index && other.field === "rotation")}>Rotation</option>
                        </select>
                      </label>
                      <label className="account-filter-operator">
                        <span>Opérateur</span>
                        <select
                          aria-label={`Opérateur de la règle ${index + 1}`}
                          value={rule.comparison}
                          onChange={(event) => updateFilterRule(index, { comparison: event.target.value as AccountFilterRule["comparison"] })}
                        >
                          <option value="is">est</option>
                          <option value="is-not">n'est pas</option>
                        </select>
                      </label>
                      <label className="account-filter-value">
                        <span>Valeur</span>
                        <select
                          aria-label={`Valeur de la règle ${index + 1}`}
                          value={rule.value}
                          onChange={(event) => updateFilterRule(index, { value: event.target.value })}
                        >
                          {rule.field === "protocol" ? <>
                            <option value="ssh">SSH</option><option value="rdp">RDP</option><option value="vnc">VNC</option>
                          </> : null}
                          {rule.field === "approval" ? <>
                            <option value="required">Requise</option><option value="not-required">Non requise</option>
                          </> : null}
                          {rule.field === "identity" ? <>
                            <option value="pinned">Épinglée</option><option value="missing">Non épinglée</option>
                          </> : null}
                          {rule.field === "rotation" ? <>
                            <option value="due">À renouveler</option><option value="failed">En échec</option><option value="none">Aucune rotation en attente</option>
                          </> : null}
                        </select>
                      </label>
                      <button className="account-filter-remove" type="button" aria-label={`Supprimer la règle ${index + 1}`} onClick={() => removeFilterRule(index)}>×</button>
                    </div>
                  ))}
                </div>
                <div className="account-filter-actions">
                  <Button type="button" disabled={filterRules.length >= maxAccountFilterRules} onClick={addFilterRule}>+ Ajouter un filtre</Button>
                  {filterRules.length > 0 ? <span className="ob-filter-help">4 blocs maximum, un par champ. Les combinaisons sont évaluées de gauche à droite.</span> : <span className="ob-filter-help">Ajoutez une règle pour affiner les comptes affichés.</span>}
                </div>
                <div className="account-filter-builder-footer">
                  <span className="ob-filter-help">La recherche textuelle est toujours combinée aux règles avec ET.</span>
                  <span className="ob-filter-count" aria-live="polite" aria-atomic="true">{filteredAccounts.length} sur {data.items.length} compte(s) affiché(s) sur cette page</span>
                </div>
                <div className="ob-saved-views">
                  <label>
                    Vues enregistrées
                    <select value={selectedSavedView} onChange={(event) => applySavedView(event.target.value)}>
                      <option value="">Choisir une vue…</option>
                      {savedViews.map((view) => <option key={view.name} value={view.name}>{view.name}</option>)}
                    </select>
                  </label>
                  <form className="ob-saved-view-form" onSubmit={saveCurrentView}>
                    <label>
                      Nom de la vue
                      <input value={newViewName} onChange={(event) => setNewViewName(event.target.value)} maxLength={32} minLength={2} required placeholder="Ex. SSH à renouveler" />
                    </label>
                    <Button type="submit">Enregistrer la vue</Button>
                  </form>
                  <Button disabled={!selectedSavedView} onClick={deleteSavedView}>Supprimer la vue</Button>
                </div>
                {viewNotice ? <InlineNotice tone="success">{viewNotice}</InlineNotice> : null}
                <p className="ob-filter-help">Les vues conservent uniquement les règles de filtrage et leur nom sur ce navigateur. N'y inscrivez aucune information sensible.</p>
              </div>
            ) : null}
          </div>
        ) : null}
        {!loading && data && filteredAccounts.length > 0 ? <AccountTable accounts={filteredAccounts} actions={actions} /> : null}
        {!loading && data && data.items.length > 0 && filteredAccounts.length === 0 ? <p className="ob-empty-state">Aucun compte de cette page ne correspond aux filtres actuels.</p> : null}
        {!loading && data ? <Pager page={data.page} pageSize={pageSize} totalItems={data.totalItems} noun="compte(s)" onPage={setPage} /> : null}
      </section>
      <OnboardAccount onDone={(id) => act(`${id} enregistré`, async () => undefined)} />
      {accountAction ? (
        <ConfirmDialog
          title={accountAction.kind === "disable" ? "Désactiver ce compte privilégié ?" : "Renouveler le secret de ce compte ?"}
          description={accountAction.kind === "disable"
            ? `Le compte ${accountAction.account.id} ne pourra plus être utilisé pour ouvrir de nouvelles sessions. Cette action sera auditée par la plateforme.`
            : `Le Vault va renouveler le secret de ${accountAction.account.id} sur la cible via son compte de réconciliation, vérifier le nouveau secret puis l'adopter. Le secret ne sera jamais affiché. Cette opération peut être refusée si la cible ou l'identité épinglée n'est pas vérifiable.`}
          confirmLabel={accountAction.kind === "disable" ? "Désactiver le compte" : "Renouveler le secret"}
          danger={accountAction.kind === "disable"}
          error={error instanceof ApiError ? `${error.status} — ${error.message}` : error ? String((error as Error)?.message ?? error) : undefined}
          onCancel={() => setAccountAction(undefined)}
          onConfirm={async () => {
            const { kind, account } = accountAction;
            try {
              await api.request(kind === "disable" ? "DELETE" : "POST", kind === "disable" ? accountPath(account.id) : `${accountPath(account.id)}/rotate`);
              setOk(kind === "disable" ? `${account.id} désactivé` : `Secret de ${account.id} renouvelé sur la cible`);
              setError(undefined);
              setAccountAction(undefined);
              load();
              return true;
            } catch (err) {
              setError(err);
              return false;
            }
          }}
        />
      ) : null}
    </AdminPage>
  );
}
