import { FormEvent, useState } from "react";
import { RecordingSearchResult } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { useAppTranslation } from "../../shared/i18n";
import { Notice } from "../../shared/Notice";
import { Button } from "../../shared/ui/Button";
import { Badge } from "../../shared/ui/Badge";
import { Form, Input, Label } from "@openbastion/ui";
import { Search } from "@openbastion/icons";

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

// The reference library (docs/ui/reference-screens/openbastion-sessions-enregistrements.svg): the
// list on the left, the selected recording on the right. The only search the public API serves is
// the bounded SSH command search (ADR-0112); storage and retention have no contract, so they say
// so instead of showing a plausible figure.
export function SessionRecordings({ onOpenRecording }: { onOpenRecording: (sessionId: string) => void }) {
  const { t, i18n } = useAppTranslation();
  const { api } = useSignedIn();
  const initial = defaultRange();
  const [query, setQuery] = useState("");
  const [from, setFrom] = useState(initial.from);
  const [to, setTo] = useState(initial.to);
  const [result, setResult] = useState<RecordingSearchResult>();
  const [selected, setSelected] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>();
  const [searched, setSearched] = useState(false);

  async function search(event: FormEvent) {
    event.preventDefault();
    setError(undefined);
    setResult(undefined);
    setSelected("");
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
      const found = await api.request<RecordingSearchResult>("GET", `/recordings/search?${params.toString()}`);
      setResult(found);
      setSelected(found.sessions[0]?.sessionId ?? "");
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }

  const hitCount = result?.sessions.reduce((count, session) => count + session.hits.length, 0) ?? 0;
  const current = result?.sessions.find((session) => session.sessionId === selected);

  return (
    <section className="ob-surface reference-panel session-recordings" aria-labelledby="session-recordings-title">
      <div className="reference-panel-heading">
        <div>
          <h3 id="session-recordings-title">{t("sessions.recordings.libraryTitle")}</h3>
          <p>{t("sessions.recordings.libraryDescription")}</p>
        </div>
      </div>
      <Form className="reference-table-toolbar session-recording-search" onSubmit={search} aria-label={t("sessions.recordings.formAria")}>
        <Label className="reference-search">
          <Search size={15} aria-hidden="true" />
          <Input
            type="search"
            aria-label={t("sessions.recordings.query")}
            minLength={3}
            maxLength={256}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t("sessions.recordings.queryPlaceholder")}
            required
          />
        </Label>
        <Label className="session-toolbar-date">
          <span>{t("sessions.history.from")}</span>
          <Input type="date" value={from} onChange={(event) => setFrom(event.target.value)} required />
        </Label>
        <Label className="session-toolbar-date">
          <span>{t("sessions.history.to")}</span>
          <Input type="date" value={to} onChange={(event) => setTo(event.target.value)} required />
        </Label>
        <Button type="submit" variant="primary" disabled={loading}>{t("sessions.recordings.search")}</Button>
      </Form>
      <Notice error={error} />
      <div className="session-recordings-layout">
        <div className="session-recordings-list" aria-label={t("sessions.recordings.libraryTitle")}>
          {loading ? <p className="ob-empty-state" role="status">{t("sessions.recordings.loading")}</p> : null}
          {!loading && !searched ? <p className="ob-empty-state">{t("sessions.recordings.scope")}</p> : null}
          {!loading && searched && result && result.sessions.length === 0 ? <p className="ob-empty-state">{t("sessions.recordings.empty")}</p> : null}
          {!loading && result && result.sessions.length > 0 ? (
            <ul className="session-recordings-rows">
              {result.sessions.map((session) => (
                <li key={session.sessionId}>
                  <Button
                    variant="ghost"
                    className="session-recording-row"
                    aria-current={selected === session.sessionId ? "true" : undefined}
                    aria-label={t("sessions.recordings.selectAria", { id: session.sessionId })}
                    onClick={() => setSelected(session.sessionId)}
                  >
                    <span className="session-recording-row-id">
                      <span className="reference-identifier"><code>{session.sessionId}</code></span>
                      <span className="reference-cell-note">{t("sessions.recordings.hitsCount", { count: session.hits.length })}</span>
                    </span>
                    <span className="session-recording-row-meta">
                      <Badge className="reference-pill">{t("sessions.recordings.terminal")}</Badge>
                      <span className="reference-cell-muted" title={t("sessions.recordings.storageUnavailable")}>{t("sessions.recordings.storageUnavailable")}</span>
                    </span>
                  </Button>
                </li>
              ))}
            </ul>
          ) : null}
        </div>

        <aside className="session-recording-preview" aria-label={t("sessions.recordings.previewTitle")}>
          <header className="session-recording-preview-heading">
            <h4>{t("sessions.recordings.previewTitle")}</h4>
            <p>{t("sessions.recordings.previewKind")}</p>
          </header>
          {current ? (
            <>
              <ol className="commands session-recording-preview-commands">
                {current.hits.map((hit, index) => (
                  <li key={`${hit.timestamp ?? ""}-${index}`}>
                    {hit.timestamp ? <time dateTime={hit.timestamp}>{new Date(hit.timestamp).toLocaleString(i18n.language)}</time> : null}
                    <code>{hit.command ?? ""}</code>
                  </li>
                ))}
              </ol>
              <footer className="session-recording-preview-footer">
                <span className="reference-cell-note"><code>{current.sessionId}</code></span>
                <Button variant="primary" onClick={() => onOpenRecording(current.sessionId)}>{t("sessions.recordings.play")}</Button>
              </footer>
            </>
          ) : (
            <p className="ob-empty-state">{t("sessions.recordings.previewEmpty")}</p>
          )}
        </aside>
      </div>
      {result ? (
        <p className="session-recording-footer">
          {t("sessions.recordings.shown", { count: result.sessions.length })}
          {" · "}{t("sessions.recordings.hitCount", { count: hitCount })}
        </p>
      ) : null}
      {!loading && result?.truncated ? <p className="ob-hint session-recording-truncated" role="status">{t("sessions.recordings.truncated")}</p> : null}
    </section>
  );
}
