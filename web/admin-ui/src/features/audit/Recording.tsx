import { FormEvent, useState } from "react";
import { RecordingPage } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { useSignedIn } from "../../shared/session";

const pageSize = 100;

// Reading back what was typed in a session (GET /sessions/{id}/recording). Each page read is
// itself an audit event (ADR-0022). Commands are shown as text, never interpreted.
export function Recording() {
  const { api } = useSignedIn();
  const [sessionId, setSessionId] = useState("");
  const [page, setPage] = useState<RecordingPage>();
  const [error, setError] = useState<unknown>();

  async function read(n: number) {
    setError(undefined);
    try {
      setPage(await api.request<RecordingPage>("GET", `/sessions/${encodeURIComponent(sessionId)}/recording?page=${n}&pageSize=${pageSize}`));
    } catch (err) {
      setPage(undefined);
      setError(err);
    }
  }

  return (
    <section>
      <h2>Enregistrements</h2>
      <p className="hint">Chaque page relue est un événement d'audit à votre nom.</p>
      <form onSubmit={(e: FormEvent) => { e.preventDefault(); void read(1); }} aria-label="Relire un enregistrement">
        <label>Session<input value={sessionId} onChange={(e) => setSessionId(e.target.value)} required /></label>
        <button type="submit">Relire</button>
      </form>
      <Notice error={error} />
      {page ? (
        <>
          <ol className="commands" start={(page.page - 1) * page.pageSize + 1}>
            {page.entries.map((e, i) => (
              <li key={i}><time>{e.timestamp}</time> <code>{e.command}</code></li>
            ))}
          </ol>
          <p className="pager">
            <button type="button" disabled={page.page <= 1} onClick={() => read(page.page - 1)}>Précédent</button>
            <span>page {page.page} — {page.totalEntries} commande(s)</span>
            <button type="button" disabled={page.page * page.pageSize >= page.totalEntries} onClick={() => read(page.page + 1)}>Suivant</button>
          </p>
        </>
      ) : null}
    </section>
  );
}
