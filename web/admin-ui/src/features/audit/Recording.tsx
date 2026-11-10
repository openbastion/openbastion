import { FormEvent, useState } from "react";
import { RecordingPage, sessionPath } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { AdminPage } from "../../shared/ui/AdminPage";
import { FormCard } from "../../shared/ui/FormCard";
import { Pager } from "../../shared/ui/Pager";
import { VideoReplay } from "./VideoReplay";

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
      setPage(await api.request<RecordingPage>("GET", `${sessionPath(sessionId)}/recording?page=${n}&pageSize=${pageSize}`));
    } catch (err) {
      setPage(undefined);
      setError(err);
    }
  }

  return (
    <AdminPage title="Enregistrements" hints={["Chaque page relue est un événement d'audit à votre nom."]}>
      <FormCard
        label="Relire un enregistrement"
        submitLabel="Relire"
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          void read(1);
        }}
        error={error}
      >
        <label>
          Session
          <input value={sessionId} onChange={(e) => setSessionId(e.target.value)} required />
        </label>
      </FormCard>
      {page ? (
        <div className="card commands-card">
          <ol className="commands" start={(page.page - 1) * page.pageSize + 1}>
            {page.entries.map((e, i) => (
              <li key={i}>
                <time>{e.timestamp}</time> <code>{e.command}</code>
              </li>
            ))}
          </ol>
          <Pager page={page.page} pageSize={page.pageSize} totalItems={page.totalEntries} noun="commande(s)" onPage={read} />
        </div>
      ) : null}
      <VideoReplay />
    </AdminPage>
  );
}
