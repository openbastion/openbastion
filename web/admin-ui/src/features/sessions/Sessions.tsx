import { FormEvent, useCallback, useEffect, useState } from "react";
import { Page, Session } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { useSignedIn } from "../../shared/session";

// Break-glass requests waiting for this user's decision, and a session by its identifier.
export function Sessions() {
  const { api } = useSignedIn();
  const [pending, setPending] = useState<Page<Session>>();
  const [error, setError] = useState<unknown>();
  const [ok, setOk] = useState<string>();
  const [lookup, setLookup] = useState("");
  const [found, setFound] = useState<Session>();

  const load = useCallback(() => {
    api.request<Page<Session>>("GET", "/sessions?status=pending_approval").then(setPending, setError);
  }, [api]);
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

  async function find(e: FormEvent) {
    e.preventDefault();
    setFound(undefined);
    setError(undefined);
    try {
      setFound(await api.request<Session>("GET", `/sessions/${encodeURIComponent(lookup)}`));
    } catch (err) {
      setError(err);
    }
  }

  const id = (s: Session) => encodeURIComponent(s.id);
  return (
    <section>
      <h2>Sessions</h2>
      <Notice error={error} ok={ok} />
      <h3>Demandes d'urgence à décider</h3>
      {pending && pending.items.length === 0 ? <p>Aucune demande en attente.</p> : null}
      <table>
        <thead>
          <tr><th>Session</th><th>Demandeur</th><th>Compte</th><th>Justification</th><th>Échéance</th><th /></tr>
        </thead>
        <tbody>
          {pending?.items.map((s) => (
            <tr key={s.id}>
              <td><code>{s.id}</code></td>
              <td>{s.requestedBy}</td>
              <td>{s.privilegedAccountId}</td>
              <td>{s.justification}</td>
              <td>{s.expiresAt}</td>
              <td className="actions">
                <button type="button" onClick={() => act(`${s.id} approuvée`, () => api.request("POST", `/sessions/${id(s)}/approve`))}>Approuver</button>
                <button type="button" className="danger" onClick={() => act(`${s.id} refusée`, () => api.request("POST", `/sessions/${id(s)}/reject`))}>Refuser</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {pending?.truncated ? <p className="hint">D'autres demandes attendent : décidez celles-ci d'abord.</p> : null}
      <h3>Une session</h3>
      <form onSubmit={find} aria-label="Chercher une session">
        <label>Identifiant<input value={lookup} onChange={(e) => setLookup(e.target.value)} required /></label>
        <button type="submit">Afficher</button>
      </form>
      {found ? (
        <dl className="session">
          <dt>Statut</dt><dd>{found.status}</dd>
          <dt>Demandeur</dt><dd>{found.requestedBy}</dd>
          <dt>Compte</dt><dd>{found.privilegedAccountId}</dd>
          <dt>Justification</dt><dd>{found.justification}</dd>
          <dt>Fin</dt><dd>{found.expiresAt}</dd>
          {found.breakGlass ? (<><dt>Urgence</dt><dd>oui{found.decidedBy ? `, décidée par ${found.decidedBy}` : ""}</dd></>) : null}
          {found.status === "active" ? (
            <dd>
              <button type="button" className="danger" onClick={() => window.confirm(`Mettre fin à ${found.id} ?`) && act(`${found.id} terminée`, () => api.request("DELETE", `/sessions/${id(found)}`))}>Mettre fin</button>
            </dd>
          ) : null}
        </dl>
      ) : null}
    </section>
  );
}
