import { FormEvent, useState } from "react";
import { RecordingPage, sessionPath } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { AdminPage } from "../../shared/ui/AdminPage";
import { FormCard } from "../../shared/ui/FormCard";
import { Pager } from "../../shared/ui/Pager";
import { Badge } from "../../shared/ui/Badge";
import { VideoReplay } from "./VideoReplay";
import { useAppTranslation } from "../../shared/i18n";

const pageSize = 100;

// Reading back what was typed in a session (GET /sessions/{id}/recording). Each page read is
// itself an audit event (ADR-0022). Commands are shown as text, never interpreted.
export function Recording() {
  const { t } = useAppTranslation();
  const { api } = useSignedIn();
  const [sessionId, setSessionId] = useState("");
  const [page, setPage] = useState<RecordingPage>();
  const [loading, setLoading] = useState(false);
  const [hasRead, setHasRead] = useState(false);
  const [error, setError] = useState<unknown>();

  async function read(n: number, targetSessionId = sessionId) {
    setError(undefined);
    setPage(undefined);
    setLoading(true);
    try {
      setPage(await api.request<RecordingPage>("GET", `${sessionPath(targetSessionId)}/recording?page=${n}&pageSize=${pageSize}`));
      setHasRead(true);
    } catch (err) {
      setPage(undefined);
      setError(err);
      setHasRead(true);
    } finally {
      setLoading(false);
    }
  }

  return (
    <AdminPage title={t("recording.title")} hints={[t("recording.hint")]}>
      <FormCard
        label={t("recording.form.label")}
        submitLabel={t("recording.form.submit")}
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          void read(1);
        }}
        error={error}
      >
        <label>
          {t("recording.form.session")}
          <input value={sessionId} onChange={(e) => setSessionId(e.target.value)} required />
        </label>
      </FormCard>
      {loading ? <p className="ob-empty-state" role="status">{t("recording.loading")}</p> : null}
      {!loading && hasRead && page && page.entries.length === 0 ? <p className="ob-empty-state">{t("recording.empty")}</p> : null}
      {!loading && page && page.entries.length > 0 ? (
        <section className="ob-surface commands-card" aria-labelledby="recorded-commands-title">
          <div className="ob-section-heading"><h3 id="recorded-commands-title">{t("recording.sessionCommands")} <code>{page.sessionId}</code></h3><Badge>{t("recording.commandCount", { count: page.totalEntries })}</Badge></div>
          <ol className="commands" start={(page.page - 1) * page.pageSize + 1}>
            {page.entries.map((e, i) => (
              <li key={`${e.timestamp}-${i}`}>
                <time dateTime={e.timestamp}>{e.timestamp}</time> <code>{e.command}</code>
              </li>
            ))}
          </ol>
          <Pager page={page.page} pageSize={page.pageSize} totalItems={page.totalEntries} noun={t("recording.noun")} onPage={(next) => void read(next, page.sessionId)} />
        </section>
      ) : null}
      <VideoReplay />
    </AdminPage>
  );
}
