import { FormEvent, useCallback, useEffect, useState } from "react";
import { SessionSearchResult } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { useAppTranslation } from "../../shared/i18n";
import { Notice } from "../../shared/Notice";
import { Button } from "../../shared/ui/Button";
import { Badge } from "../../shared/ui/Badge";
import { StatusBadge } from "../../shared/ui/StatusBadge";
import { Form, Input, Label, Select } from "@openbastion/ui";
import { ChevronDown, Search } from "@openbastion/icons";

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

// The reference table (docs/ui/reference-screens/openbastion-sessions-historique.svg): one panel,
// a filter row, the user/target/protocol/start/status columns. Duration and recording availability
// have no public contract — the Session record carries no end time and no recording reference —
// so those cells stay an em dash with their reason instead of a plausible value.
export function SessionHistory() {
  const { t, i18n } = useAppTranslation();
  const { api } = useSignedIn();
  const initial = defaultRange();
  const [from, setFrom] = useState(initial.from);
  const [to, setTo] = useState(initial.to);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("");
  const [protocol, setProtocol] = useState("");
  const [filters, setFilters] = useState({ from: initial.from, to: initial.to, query: "", status: "", protocol: "" });
  const [page, setPage] = useState<SessionSearchResult>();
  const [pageNumber, setPageNumber] = useState(1);
  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>();

  const load = useCallback(async (criteria: typeof filters, cursor = "") => {
    setLoading(true);
    setError(undefined);
    try {
      const params = new URLSearchParams({ from: dateTime(criteria.from), to: dateTime(criteria.to, true) });
      if (criteria.query.trim().length >= 3) params.set("q", criteria.query.trim());
      if (criteria.status) params.set("status", criteria.status);
      if (criteria.protocol) params.set("protocol", criteria.protocol);
      if (cursor) params.set("cursor", cursor);
      const result = await api.request<SessionSearchResult>("GET", `/sessions/search?${params.toString()}`);
      setPage(result);
    } catch (err) {
      setPage(undefined);
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [api]);

  useEffect(() => { void load(filters); }, [load, filters]);

  function search(event: FormEvent) {
    event.preventDefault();
    if (!validRange(from, to)) {
      setError(new Error(t("sessions.history.invalidRange")));
      return;
    }
    if (query.trim().length > 0 && query.trim().length < 3) {
      setError(new Error(t("sessions.history.queryTooShort")));
      return;
    }
    const criteria = { from, to, query, status, protocol };
    setFilters(criteria);
    setCursorStack([]);
    setPageNumber(1);
  }

  function nextPage() {
    if (!page?.next) return;
    setCursorStack((stack) => [...stack, page.next]);
    setPageNumber((n) => n + 1);
    void load(filters, page.next);
  }

  function previousPage() {
    if (cursorStack.length === 0) return;
    const stack = cursorStack.slice(0, -1);
    setCursorStack(stack);
    setPageNumber((n) => Math.max(1, n - 1));
    void load(filters, stack[stack.length - 1] ?? "");
  }

  function startedAt(value?: string): string {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    return date.toLocaleString(i18n.language, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
  }

  return (
    <section className="ob-surface reference-panel session-history" aria-labelledby="session-history-title">
      <div className="reference-panel-heading">
        <div>
          <h3 id="session-history-title">{t("sessions.history.title")}</h3>
          <p>{t("sessions.history.description")}</p>
        </div>
      </div>
      <Form className="reference-table-toolbar session-history-toolbar" onSubmit={search} aria-label={t("sessions.history.filtersAria")}>
        <Label className="reference-search">
          <Search size={15} aria-hidden="true" />
          <Input
            type="search"
            aria-label={t("sessions.history.query")}
            maxLength={256}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t("sessions.history.queryPlaceholder")}
          />
        </Label>
        <Label className="reference-select">
          <Select aria-label={t("sessions.history.status")} value={status} onChange={(event) => setStatus(event.target.value)}>
            <option value="">{t("sessions.history.allStatuses")}</option>
            <option value="active">{t("common.status.active")}</option>
            <option value="terminated">{t("common.status.terminated")}</option>
            <option value="expired">{t("common.status.expired")}</option>
            <option value="denied">{t("common.status.denied")}</option>
          </Select>
          <ChevronDown size={14} aria-hidden="true" />
        </Label>
        <Label className="reference-select">
          <Select aria-label={t("sessions.history.protocol")} value={protocol} onChange={(event) => setProtocol(event.target.value)}>
            <option value="">{t("sessions.history.allProtocols")}</option>
            {(["ssh", "rdp", "vnc"] as const).map((value) => <option key={value} value={value}>{value.toUpperCase()}</option>)}
          </Select>
          <ChevronDown size={14} aria-hidden="true" />
        </Label>
        <Label className="session-toolbar-date">
          <span>{t("sessions.history.from")}</span>
          <Input type="date" value={from} onChange={(event) => setFrom(event.target.value)} required />
        </Label>
        <Label className="session-toolbar-date">
          <span>{t("sessions.history.to")}</span>
          <Input type="date" value={to} onChange={(event) => setTo(event.target.value)} required />
        </Label>
        <Button type="submit" variant="primary" disabled={loading}>{t("sessions.history.search")}</Button>
      </Form>
      <Notice error={error} />
      {loading ? <p className="ob-empty-state" role="status">{t("sessions.history.loading")}</p> : null}
      {!loading && page && page.sessions.length === 0 ? <p className="ob-empty-state">{t("sessions.history.empty")}</p> : null}
      {!loading && page && page.sessions.length > 0 ? (
        <div className="reference-table-wrap">
          <table className="reference-table session-history-table">
            <caption className="ob-visually-hidden">{t("sessions.history.caption")}</caption>
            <thead><tr>
              <th scope="col">{t("sessions.columns.user")}</th>
              <th scope="col">{t("sessions.columns.target")}</th>
              <th scope="col">{t("sessions.columns.protocol")}</th>
              <th scope="col">{t("sessions.columns.started")}</th>
              <th scope="col">{t("sessions.columns.duration")}</th>
              <th scope="col">{t("sessions.columns.status")}</th>
              <th scope="col">{t("sessions.columns.recording")}</th>
            </tr></thead>
            <tbody>{page.sessions.map((session) => (
              <tr key={session.id}>
                <td>
                  <span className="reference-identifier">{session.requestedBy}</span>
                  <span className="reference-cell-note"><code>{session.id}</code></span>
                </td>
                <td><span className="reference-address">{session.targetHost ?? session.privilegedAccountId}</span></td>
                <td><Badge className="reference-pill">{session.protocol.toUpperCase()}</Badge></td>
                <td>{session.createdAt ? <time dateTime={session.createdAt}>{startedAt(session.createdAt)}</time> : "—"}</td>
                <td><span className="reference-cell-muted" title={t("sessions.history.durationUnavailable")}>—</span></td>
                <td><StatusBadge status={session.status} /></td>
                <td><span className="reference-cell-muted" title={t("sessions.history.recordingUnavailable")}>—</span></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      ) : null}
      {!loading && page ? (
        <div className="reference-table-footer">
          <p className="reference-table-range">
            {t("sessions.history.resultsOnPage", { count: page.sessions.length })}
            {" · "}{t("sessions.history.page", { page: pageNumber })}
          </p>
          <nav className="reference-pager" aria-label={t("common.pager.aria")}>
            <Button variant="ghost" aria-label={t("sessions.history.previous")} disabled={cursorStack.length === 0} onClick={previousPage}>‹</Button>
            <Button variant="ghost" aria-current="page">{pageNumber}</Button>
            <Button variant="ghost" aria-label={t("sessions.history.next")} disabled={!page.next} onClick={nextPage}>›</Button>
          </nav>
        </div>
      ) : null}
    </section>
  );
}
