import { FormEvent, useCallback, useEffect, useState } from "react";
import { Account, Page } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { useSignedIn } from "../../shared/session";

const pageSize = 20;

// Privileged accounts of the Vault: list, onboard, disable. A secret is typed once at
// onboarding and never shown again: the API never returns one. No "rotate" button: a rotation
// today changes the secret in the Vault only, not on the target, and would lock the account
// out (NOTES_SANDBOX.md) — it comes back when rotation reaches the target.
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
    <section>
      <h2>Comptes privilégiés</h2>
      <p className="hint">Pas de rotation depuis cette page : aujourd'hui, une rotation ne change le secret que dans le coffre, pas sur la cible.</p>
      <Notice error={error} ok={ok} />
      <table>
        <thead>
          <tr><th>Identifiant</th><th>Nom</th><th>Cible</th><th>Utilisateur</th><th>Rotation</th><th>Dernière rotation</th><th /></tr>
        </thead>
        <tbody>
          {data?.items.map((a) => (
            <tr key={a.id}>
              <td><code>{a.id}</code></td>
              <td>{a.name}</td>
              <td>{a.targetHost}</td>
              <td>{a.username}</td>
              <td>{a.rotationPolicy}</td>
              <td>{a.lastRotatedAt ?? "—"}</td>
              <td className="actions">
                <button type="button" className="danger" onClick={() => window.confirm(`Désactiver ${a.id} ?`) && act(`${a.id} désactivé`, () => api.request("DELETE", `/vault/accounts/${encodeURIComponent(a.id)}`))}>Désactiver</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {data ? (
        <p className="pager">
          <button type="button" disabled={page <= 1} onClick={() => setPage(page - 1)}>Précédent</button>
          <span>page {data.page} — {data.totalItems} compte(s)</span>
          <button type="button" disabled={page * pageSize >= data.totalItems} onClick={() => setPage(page + 1)}>Suivant</button>
        </p>
      ) : null}
      <Onboard onDone={(id) => act(`${id} enregistré`, async () => undefined)} />
    </section>
  );
}

function Onboard({ onDone }: { onDone: (id: string) => void }) {
  const { api } = useSignedIn();
  const [f, setF] = useState({ id: "", name: "", username: "", targetHost: "", rotationPolicy: "manual", initialSecret: "" });
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
    <form onSubmit={submit} aria-label="Enregistrer un compte">
      <h3>Enregistrer un compte</h3>
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
      <label>Secret initial<input type="password" autoComplete="new-password" value={f.initialSecret} onChange={set("initialSecret")} required /></label>
      <button type="submit">Enregistrer</button>
      <Notice error={error} />
    </form>
  );
}
