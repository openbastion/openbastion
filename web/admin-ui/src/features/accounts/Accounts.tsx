import { FormEvent, useCallback, useEffect, useState } from "react";
import { Account, Page } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { useSignedIn } from "../../shared/session";

const pageSize = 20;

// Privileged accounts of the Vault: list, onboard, rotate, disable. A secret is typed once at
// onboarding and never shown again: the API never returns one. A rotation changes the secret on
// the target, through the account's reconciliation account (ADR-0037).
export function Accounts() {
  const { api } = useSignedIn();
  const [page, setPage] = useState(1);
  const [data, setData] = useState<Page<Account>>();
  const [error, setError] = useState<unknown>();
  const [ok, setOk] = useState<string>();

  const load = useCallback(() => {
    api.request<Page<Account>>("GET", `/vault/accounts?page=${page}&pageSize=${pageSize}`).then(setData, setError);
  }, [api, page]);
  useEffect(load, [load]);

  async function act(what: string, run: () => Promise<unknown>) {
    setError(undefined);
    setOk(undefined);
    try {
      await run();
      setOk(what);
      load();
    } catch (err) {
      setError(err);
    }
  }

  return (
    <section className="page">
      <div className="page-head">
        <h2>Comptes privilégiés</h2>
        <p className="hint">Renouveler un secret le change sur la cible, par le compte de réconciliation du compte, et le vérifie avant de l'adopter : un compte sans compte de réconciliation ne peut pas être renouvelé.</p>
      </div>
      <Notice error={error} ok={ok} />
      <div className="card">
        {data && data.items.length === 0 ? <p className="empty">Aucun compte privilégié pour l'instant — enregistrez-en un ci-dessous.</p> : null}
        {data && data.items.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Identifiant</th><th>Nom</th><th>Cible</th><th>Utilisateur</th><th>Rotation</th><th>Dernière rotation</th><th /></tr>
              </thead>
              <tbody>
                {data.items.map((a) => (
                  <tr key={a.id}>
                    <td><code>{a.id}</code></td>
                    <td>{a.name}</td>
                    <td>{a.targetHost}</td>
                    <td>{a.username}</td>
                    <td><span className="badge">{a.rotationPolicy}</span></td>
                    <td>{a.lastRotatedAt ?? "—"}</td>
                    <td className="actions">
                      <button type="button" onClick={() => act(`Secret de ${a.id} renouvelé sur la cible`, () => api.request("POST", `/vault/accounts/${encodeURIComponent(a.id)}/rotate`))}>Renouveler le secret</button>
                      <button type="button" className="danger" onClick={() => window.confirm(`Désactiver ${a.id} ?`) && act(`${a.id} désactivé`, () => api.request("DELETE", `/vault/accounts/${encodeURIComponent(a.id)}`))}>Désactiver</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
        {data ? (
          <p className="pager">
            <button type="button" disabled={page <= 1} onClick={() => setPage(page - 1)}>Précédent</button>
            <span>page {data.page} — {data.totalItems} compte(s)</span>
            <button type="button" disabled={page * pageSize >= data.totalItems} onClick={() => setPage(page + 1)}>Suivant</button>
          </p>
        ) : null}
      </div>
      <Onboard onDone={(id) => act(`${id} enregistré`, async () => undefined)} />
    </section>
  );
}

function Onboard({ onDone }: { onDone: (id: string) => void }) {
  const { api } = useSignedIn();
  const [f, setF] = useState({ id: "", name: "", username: "", targetHost: "", rotationPolicy: "manual", initialSecret: "", reconciliationAccountId: "" });
  const [error, setError] = useState<unknown>();
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(undefined);
    try {
      // The API takes the secret as bytes (base64 in JSON); it is never sent anywhere else.
      const bytes = new TextEncoder().encode(f.initialSecret);
      let bin = "";
      bytes.forEach((b) => (bin += String.fromCharCode(b)));
      await api.request("POST", "/vault/accounts", { ...f, protocol: "ssh", initialSecret: btoa(bin) });
      setF({ ...f, id: "", name: "", initialSecret: "" });
      onDone(f.id);
    } catch (err) {
      setError(err);
    }
  }

  return (
    <form onSubmit={submit} aria-label="Enregistrer un compte" className="card form-card">
      <h3>Enregistrer un compte</h3>
      <div className="fields">
        <label>Identifiant<input value={f.id} onChange={set("id")} required pattern="[A-Za-z0-9_.\-]+" /></label>
        <label>Nom<input value={f.name} onChange={set("name")} required /></label>
        <label>Cible (hôte:port)<input value={f.targetHost} onChange={set("targetHost")} required /></label>
        <label>Utilisateur sur la cible<input value={f.username} onChange={set("username")} required /></label>
        <label>
          Rotation
          <select value={f.rotationPolicy} onChange={set("rotationPolicy")}>
            <option value="manual">manuelle</option>
            <option value="post_use">après usage</option>
            <option value="scheduled">planifiée</option>
          </select>
        </label>
        <label>Compte de réconciliation (même cible ; vide : pas de rotation)<input value={f.reconciliationAccountId} onChange={set("reconciliationAccountId")} /></label>
        <label>Secret initial<input type="password" autoComplete="new-password" value={f.initialSecret} onChange={set("initialSecret")} required /></label>
      </div>
      <Notice error={error} />
      <div className="form-actions">
        <button type="submit" className="primary">Enregistrer</button>
      </div>
    </form>
  );
}
