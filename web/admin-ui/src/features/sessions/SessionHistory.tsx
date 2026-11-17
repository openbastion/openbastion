import { FormEvent, useCallback, useEffect, useState } from "react";
import { SessionSearchResult } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { useAppTranslation } from "../../shared/i18n";
import { Notice } from "../../shared/Notice";
import { Button } from "../../shared/ui/Button";
import { Badge } from "../../shared/ui/Badge";
import { StatusBadge } from "../../shared/ui/StatusBadge";
import { Input, Select } from "@openbastion/ui";

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

export function SessionHistory() {
  const { t } = useAppTranslation();
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

  return (
    <section className="session-history" aria-labelledby="session-history-title">
      <div className="ob-section-heading">
        <div>
          <h3 id="session-history-title">{t("sessions.history.title")}</h3>
          <p className="ob-hint">{t("sessions.history.description")}</p>
        </div>
        {page ? <Badge>{t("sessions.history.pageCount", { count: page.sessions.length })}</Badge> : null}
      </div>
      <form className="session-filter-bar" onSubmit={search} aria-label={t("sessions.history.filtersAria")}>
        <label className="session-filter-query">
          {t("sessions.history.query")}
          <Input type="search" maxLength={256} value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("sessions.history.queryPlaceholder")} />
        </label>
        <label>
          {t("sessions.history.from")}
          <Input type="date" value={from} onChange={(event) => setFrom(event.target.value)} required />
        </label>
        <label>
          {t("sessions.history.to")}
          <Input type="date" value={to} onChange={(event) => setTo(event.target.value)} required />
        </label>
        <label>
          {t("sessions.history.status")}
          <Select value={status} onChange={(event) => setStatus(event.target.value)}>
            <option value="">{t("sessions.history.allStatuses")}</option>
            <option value="active">{t("common.status.active")}</option>
            <option value="terminated">{t("common.status.terminated")}</option>
            <option value="expired">{t("common.status.expired")}</option>
            <option value="denied">{t("common.status.denied")}</option>
          </Select>
        </label>
        <label>
          {t("sessions.history.protocol")}
          <Select value={protocol} onChange={(event) => setProtocol(event.target.value)}>
            <option value="">{t("sessions.history.allProtocols")}</option>
            {(["ssh", "rdp", "vnc"] as const).map((value) => <option key={value} value={value}>{value.toUpperCase()}</option>)}
          </Select>
        </label>
        <Button type="submit" variant="primary" disabled={loading}>{t("sessions.history.search")}</Button>
      </form>
      <Notice error={error} />
      {loading ? <p className="ob-empty-state" role="status">{t("sessions.history.loading")}</p> : null}
      {!loading && page && page.sessions.length === 0 ? <p className="ob-empty-state">{t("sessions.history.empty")}</p> : null}
      {!loading && page && page.sessions.length > 0 ? (
        <div className="ob-table-wrap">
          <table className="ob-data-table">
            <caption className="ob-visually-hidden">{t("sessions.history.caption")}</caption>
            <thead><tr>
              <th scope="col">{t("sessions.columns.session")}</th>
              <th scope="col">{t("sessions.columns.requester")}</th>
              <th scope="col">{t("sessions.columns.target")}</th>
              <th scope="col">{t("sessions.columns.protocol")}</th>
              <th scope="col">{t("sessions.columns.status")}</th>
              <th scope="col">{t("sessions.columns.started")}</th>
            </tr></thead>
            <tbody>{page.sessions.map((session) => (
              <tr key={session.id}>
                <td><code>{session.id}</code>{session.breakGlass ? <Badge tone="warning">{t("sessions.pending.emergency")}</Badge> : null}</td>
                <td>{session.requestedBy}</td>
                <td>{session.targetHost ?? session.privilegedAccountId}</td>
                <td><Badge>{session.protocol.toUpperCase()}</Badge></td>
                <td><StatusBadge status={session.status} /></td>
                <td>{session.createdAt ? <time dateTime={session.createdAt}>{new Date(session.createdAt).toLocaleString()}</time> : "—"}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      ) : null}
      {!loading && page ? <div className="session-pagination">
        <Button disabled={cursorStack.length === 0} onClick={previousPage}>{t("common.pager.previous")}</Button>
        <span>{t("sessions.history.page", { page: pageNumber })}</span>
        <Button disabled={!page.next} onClick={nextPage}>{t("common.pager.next")}</Button>
      </div> : null}
    </section>
  );
}
