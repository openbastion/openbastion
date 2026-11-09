import { FormEvent, useCallback, useEffect, useState } from "react";
import { Page, Session } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { ScreenViewer } from "../screen/ScreenViewer";
import { useSignedIn } from "../../shared/session";

// A session request — with the ticket an account that requires approval asks for (ADR-0067) —,
// the requests waiting for this user's decision (break-glass, ADR-0012, and approval, ADR-0067),
// and a session by its identifier.
export function Sessions() {
  const { api } = useSignedIn();
  const [pending, setPending] = useState<Page<Session>>();
  const [error, setError] = useState<unknown>();
  const [ok, setOk] = useState<string>();
  const [lookup, setLookup] = useState("");
  const [found, setFound] = useState<Session>();
  // Each connection is another attach: the key restarts the viewer on the new one.
  const [screenAttach, setScreenAttach] = useState<{ sessionId: string; attach: string; key: number }>();

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

  async function openScreen(sessionId: string) {
    setError(undefined);
    setOk(undefined);
    setScreenAttach(undefined);
    try {
      const { attach } = await api.connectScreen(sessionId);
      setScreenAttach((previous) => ({ sessionId, attach, key: (previous?.key ?? 0) + 1 }));
    } catch (err) {
      setError(err);
    }
  }

  const id = (s: Session) => encodeURIComponent(s.id);
  return (
    <section className="page">
      <div className="page-head">
        <h2>Sessions</h2>
      </div>
      <Notice error={error} ok={ok} />
      <Request onDone={(s) => {
        setLookup(s.id);
        setFound(s);
        setScreenAttach(undefined);
        act(s.status === "pending_approval" ? `${s.id} en attente de l'approbation d'une autre personne, jusqu'à ${s.expiresAt}` : `${s.id} ${s.status}`, async () => undefined);
      }} />
      <div className="card">
        <div className="card-head"><h3>Demandes à décider</h3></div>
        {pending && pending.items.length === 0 ? <p className="empty">Aucune demande en attente.</p> : null}
        {pending && pending.items.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Session</th><th>Type</th><th>Demandeur</th><th>Compte</th><th>Justification</th><th>Ticket</th><th>Échéance</th><th /></tr>
              </thead>
              <tbody>
                {pending.items.map((s) => (
                  <tr key={s.id}>
                    <td><code>{s.id}</code></td>
                    <td>{s.breakGlass ? <span className="badge warn">urgence</span> : <span className="badge">approbation</span>}</td>
                    <td>{s.requestedBy}</td>
                    <td>{s.privilegedAccountId}</td>
                    <td>{s.justification}</td>
                    <td>{s.ticket ? <code>{s.ticket}</code> : "—"}</td>
                    <td>{s.expiresAt}</td>
                    <td className="actions">
                      <button type="button" onClick={() => act(`${s.id} approuvée`, () => api.request("POST", `/sessions/${id(s)}/approve`))}>Approuver</button>
                      <button type="button" className="danger" onClick={() => act(`${s.id} refusée`, () => api.request("POST", `/sessions/${id(s)}/reject`))}>Refuser</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
        {pending?.truncated ? <p className="card-foot hint">D'autres demandes attendent : décidez celles-ci d'abord.</p> : null}
      </div>
      <div className="card panel">
        <h3>Une session</h3>
        <form onSubmit={find} aria-label="Chercher une session">
          <div className="fields">
            <label>Identifiant<input value={lookup} onChange={(e) => setLookup(e.target.value)} required /></label>
          </div>
          <div className="form-actions">
            <button type="submit" className="primary">Afficher</button>
          </div>
        </form>
        {found ? (
          <>
            <dl className="session">
              <dt>Statut</dt><dd><span className="badge">{found.status}</span></dd>
              <dt>Protocole</dt><dd>{found.protocol}</dd>
              <dt>Demandeur</dt><dd>{found.requestedBy}</dd>
              <dt>Compte</dt><dd>{found.privilegedAccountId}</dd>
              <dt>Justification</dt><dd>{found.justification}</dd>
              <dt>Fin</dt><dd>{found.expiresAt}</dd>
              {found.ticket ? (<><dt>Ticket</dt><dd><code>{found.ticket}</code></dd></>) : null}
              {found.approvalRequired ? (<><dt>Approbation</dt><dd>{found.decidedBy ? `décidée par ${found.decidedBy}` : "en attente"}</dd></>) : null}
              {found.breakGlass ? (<><dt>Urgence</dt><dd>oui{found.decidedBy ? `, décidée par ${found.decidedBy}` : ""}</dd></>) : null}
            </dl>
            {found.status === "active" ? (
              <div className="form-actions">
                {found.protocol === "vnc" || found.protocol === "rdp" ? <button type="button" className="primary" onClick={() => openScreen(found.id)}>Ouvrir l'écran</button> : null}
                <button type="button" className="danger" onClick={() => window.confirm(`Mettre fin à ${found.id} ?`) && act(`${found.id} terminée`, () => api.request("DELETE", `/sessions/${id(found)}`))}>Mettre fin</button>
              </div>
            ) : null}
          </>
        ) : null}
        {screenAttach ? (
          <ScreenViewer
            key={screenAttach.key}
            attach={screenAttach.attach}
            onReconnect={() => openScreen(screenAttach.sessionId)}
            onClose={() => setScreenAttach(undefined)}
          />
        ) : null}
      </div>
    </section>
  );
}

// A session request (POST /sessions). The ticket is what an account that requires approval asks
// for (ADR-0067), in the format the platform declared; the Broker ignores it on any other account.
function Request({ onDone }: { onDone: (s: Session) => void }) {
  const { api } = useSignedIn();
  const [f, setF] = useState({ targetAccountId: "", protocol: "ssh", justification: "", durationMinutes: "30", ticket: "" });
  const [error, setError] = useState<unknown>();
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(undefined);
    try {
      const { ticket, ...rest } = f;
      // The protocol must be the account's: the Broker refuses any other, and routes on its own.
      const s = await api.request<Session>("POST", "/sessions", { ...rest, ...(ticket ? { ticket } : {}), durationMinutes: Number(f.durationMinutes) });
      setF({ ...f, justification: "", ticket: "" });
      onDone(s);
    } catch (err) {
      setError(err);
    }
  }

  return (
    <form onSubmit={submit} aria-label="Demander une session" className="card form-card">
      <h3>Demander une session</h3>
      <div className="fields">
        <label>Compte<input value={f.targetAccountId} onChange={set("targetAccountId")} required /></label>
        <label>
          Protocole du compte
          <select value={f.protocol} onChange={set("protocol")}>
            <option value="ssh">SSH</option>
            <option value="vnc">VNC</option>
            <option value="rdp">RDP</option>
          </select>
        </label>
        <label>Durée (minutes)<input type="number" min={1} value={f.durationMinutes} onChange={set("durationMinutes")} required /></label>
        <label className="wide">Justification<input value={f.justification} onChange={set("justification")} required /></label>
        <label>Ticket (si le compte exige une approbation)<input value={f.ticket} onChange={set("ticket")} maxLength={128} autoComplete="off" /></label>
      </div>
      <Notice error={error} />
      <div className="form-actions">
        <button type="submit" className="primary">Demander</button>
      </div>
    </form>
  );
}
