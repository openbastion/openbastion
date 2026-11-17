import { FormEvent, useState } from "react";
import { RecordingSearchResult } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { useAppTranslation } from "../../shared/i18n";
import { Notice } from "../../shared/Notice";
import { Button } from "../../shared/ui/Button";
import { Badge } from "../../shared/ui/Badge";
import { Input } from "@openbastion/ui";

function datePart(date: Date): string {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

function defaultRange(): { from: string; to: string } {
  const to = new Date();
  const from = new Date(to);
  from.setDate(from.getDate() - 7);
  return { from: datePart(from), to: datePart(to) };
}

function dateTime(value: string, end = false): string {
  const [year, month, day] = value.split("-").map(Number);
  const date = new Date(year, month - 1, day);
  if (end) date.setDate(date.getDate() + 1); // API upper bound is exclusive.
  return date.toISOString();
}

function validRange(from: string, to: string): boolean {
  const start = Date.parse(dateTime(from));
  const end = Date.parse(dateTime(to, true));
  const duration = end - start;
  return Number.isFinite(start) && Number.isFinite(end) && duration > 0 && duration <= 31 * 86_400_000;
}

export function SessionRecordings({ onOpenRecording }: { onOpenRecording: (sessionId: string) => void }) {
  const { t } = useAppTranslation();
  const { api } = useSignedIn();
  const initial = defaultRange();
  const [query, setQuery] = useState("");
  const [from, setFrom] = useState(initial.from);
  const [to, setTo] = useState(initial.to);
  const [result, setResult] = useState<RecordingSearchResult>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>();
  const [searched, setSearched] = useState(false);

  async function search(event: FormEvent) {
    event.preventDefault();
    setError(undefined);
    setResult(undefined);
    setSearched(true);
    if (!validRange(from, to)) {
      setError(new Error(t("sessions.recordings.invalidRange")));
      return;
    }
    if (query.trim().length < 3) {
      setError(new Error(t("sessions.recordings.queryTooShort")));
      return;
    }
    setLoading(true);
    try {
      const params = new URLSearchParams({ q: query.trim(), from: dateTime(from), to: dateTime(to, true) });
      setResult(await api.request<RecordingSearchResult>("GET", `/recordings/search?${params.toString()}`));
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }

  const hitCount = result?.sessions.reduce((count, session) => count + session.hits.length, 0) ?? 0;

  return (
    <section className="session-recordings" aria-labelledby="session-recordings-title">
      <div className="ob-section-heading">
        <div>
          <h3 id="session-recordings-title">{t("sessions.recordings.title")}</h3>
          <p className="ob-hint">{t("sessions.recordings.description")}</p>
        </div>
        {result ? <Badge>{t("sessions.recordings.hitCount", { count: hitCount })}</Badge> : null}
      </div>
      <form className="session-filter-bar session-recording-search" onSubmit={search} aria-label={t("sessions.recordings.formAria")}>
        <label className="session-filter-query">
          {t("sessions.recordings.query")}
          <Input type="search" minLength={3} maxLength={256} value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("sessions.recordings.queryPlaceholder")} required />
        </label>
        <label>
          {t("sessions.history.from")}
          <Input type="date" value={from} onChange={(event) => setFrom(event.target.value)} required />
        </label>
        <label>
          {t("sessions.history.to")}
          <Input type="date" value={to} onChange={(event) => setTo(event.target.value)} required />
        </label>
        <Button type="submit" variant="primary" disabled={loading}>{t("sessions.recordings.search")}</Button>
      </form>
      <p className="ob-hint">{t("sessions.recordings.scope")}</p>
      <Notice error={error} />
      {loading ? <p className="ob-empty-state" role="status">{t("sessions.recordings.loading")}</p> : null}
      {!loading && searched && result && result.sessions.length === 0 ? <p className="ob-empty-state">{t("sessions.recordings.empty")}</p> : null}
      {!loading && result && result.sessions.length > 0 ? (
        <div className="session-recording-results">
          {result.sessions.map((session) => (
            <article className="ob-surface session-recording-result" key={session.sessionId}>
              <div className="ob-section-heading">
                <h4><code>{session.sessionId}</code></h4>
                <Button onClick={() => onOpenRecording(session.sessionId)}>{t("sessions.recordings.open")}</Button>
              </div>
              <ol className="commands">
                {session.hits.map((hit, index) => (
                  <li key={`${hit.timestamp ?? ""}-${index}`}>
                    {hit.timestamp ? <time dateTime={hit.timestamp}>{new Date(hit.timestamp).toLocaleString()}</time> : null}
                    <code>{hit.command ?? ""}</code>
                  </li>
                ))}
              </ol>
            </article>
          ))}
        </div>
      ) : null}
      {!loading && result?.truncated ? <p className="ob-hint" role="status">{t("sessions.recordings.truncated")}</p> : null}
    </section>
  );
}
