import { FormEvent, useState } from "react";
import { ApiError } from "../../shared/api";
import { useSignedIn } from "../../shared/session";
import { useCapabilities } from "../../shared/capabilities";
import { useAppTranslation } from "../../shared/i18n";
import { Button } from "../../shared/ui/Button";
import { ConfirmDialog } from "../../shared/ui/ConfirmDialog";
import { InlineNotice } from "../../shared/ui/InlineNotice";
import { ReferencePager } from "../../shared/ui/ReferencePager";
import { Form, Input, Label } from "@openbastion/ui";

type ManagerView = { userId: string; manager: { userId: string; updatedAt: string } | null; revision: number };
type ReportsPage = { items: { userId: string; updatedAt: string }[]; page: number; pageSize: number; totalItems: number; revision: number };
type Mutation = { userId: string; managerUserId: string; revision: number; updatedAt: string };
type PendingChange = { kind: "set" | "remove"; userId: string; managerUserId: string; revision: number };

const idPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

function errorText(error: unknown): string {
  return error instanceof ApiError ? `${error.status} — ${error.message}` : String((error as Error)?.message ?? error);
}

export function ApprovalHierarchy() {
  const { t, i18n } = useAppTranslation();
  const { api } = useSignedIn();
  const { can } = useCapabilities();
  const mayRead = can("approvalHierarchy.read");
  const mayManage = can("approvalHierarchy.manage");
  const mayReadReports = can("approvalHierarchy.reports");
  const [userId, setUserId] = useState("");
  const [managerUserId, setManagerUserId] = useState("");
  const [managerView, setManagerView] = useState<ManagerView>();
  const [reportsManagerId, setReportsManagerId] = useState("");
  const [reports, setReports] = useState<ReportsPage>();
  const [loading, setLoading] = useState(false);
  const [reportsLoading, setReportsLoading] = useState(false);
  const [error, setError] = useState<unknown>();
  const [success, setSuccess] = useState<string>();
  const [pending, setPending] = useState<PendingChange>();

  async function readManager(event?: FormEvent) {
    event?.preventDefault();
    const id = userId.trim();
    if (!idPattern.test(id)) {
      setError(new Error(t("accounts.hierarchy.invalidUserId")));
      return;
    }
    setError(undefined);
    setSuccess(undefined);
    setLoading(true);
    try {
      const result = await api.request<ManagerView>("GET", `/approval-hierarchy/users/${encodeURIComponent(id)}/manager`);
      setManagerView(result);
      setManagerUserId(result.manager?.userId ?? "");
    } catch (err) {
      setManagerView(undefined);
      setError(err);
    } finally {
      setLoading(false);
    }
  }

  async function readReports(event?: FormEvent, page = 1) {
    event?.preventDefault();
    const id = reportsManagerId.trim();
    if (!idPattern.test(id)) {
      setError(new Error(t("accounts.hierarchy.invalidManagerId")));
      return;
    }
    setError(undefined);
    setSuccess(undefined);
    setReportsLoading(true);
    try {
      const result = await api.request<ReportsPage>("GET", `/approval-hierarchy/users/${encodeURIComponent(id)}/reports?page=${page}&pageSize=20`);
      setReports(result);
    } catch (err) {
      setReports(undefined);
      setError(err);
    } finally {
      setReportsLoading(false);
    }
  }

  async function confirmChange(): Promise<boolean> {
    if (!pending) return false;
    const { kind, userId: subject, managerUserId: manager, revision } = pending;
    try {
      if (kind === "set") {
        const result = await api.request<Mutation>("PUT", `/approval-hierarchy/users/${encodeURIComponent(subject)}/manager`, { managerUserId: manager }, "omit", { "If-Match": `"hierarchy-${revision}"` });
        setManagerView({ userId: result.userId, manager: { userId: result.managerUserId, updatedAt: result.updatedAt }, revision: result.revision });
        setManagerUserId(result.managerUserId);
        setSuccess(t("accounts.hierarchy.saved", { user: subject, manager }));
      } else {
        const result = await api.request<{ revision: number }>("DELETE", `/approval-hierarchy/users/${encodeURIComponent(subject)}/manager`, undefined, "omit", { "If-Match": `"hierarchy-${revision}"` });
        setManagerView({ userId: subject, manager: null, revision: result.revision });
        setManagerUserId("");
        setSuccess(t("accounts.hierarchy.removed", { user: subject }));
      }
      setError(undefined);
      setPending(undefined);
      return true;
    } catch (err) {
      setError(err);
      return false;
    }
  }

  function proposeChange(kind: "set" | "remove") {
    if (!managerView || !mayManage || !mayRead) return;
    const manager = managerUserId.trim();
    if (kind === "set" && (!idPattern.test(manager) || manager === managerView.userId)) {
      setError(new Error(manager === managerView.userId ? t("accounts.hierarchy.selfReference") : t("accounts.hierarchy.invalidManagerId")));
      return;
    }
    setError(undefined);
    setSuccess(undefined);
    setPending({ kind, userId: managerView.userId, managerUserId: manager, revision: managerView.revision });
  }

  return (
    <section className="ob-surface ob-panel" aria-labelledby="approval-hierarchy-title">
      <div className="ob-section-heading">
        <div>
          <h3 id="approval-hierarchy-title">{t("accounts.hierarchy.title")}</h3>
          <p>{t("accounts.hierarchy.description")}</p>
        </div>
      </div>
      <InlineNotice tone="info">{t("accounts.hierarchy.invariant")}</InlineNotice>
      {error ? <InlineNotice tone="danger" role="alert">{errorText(error)}</InlineNotice> : null}
      {success ? <InlineNotice tone="success" role="status">{success}</InlineNotice> : null}

      <section className="ob-surface ob-panel" aria-labelledby="hierarchy-manager-title">
        <h4 id="hierarchy-manager-title">{t("accounts.hierarchy.managerLookup")}</h4>
        <Form className="ob-form-fields" onSubmit={readManager}>
          <Label>
            {t("accounts.hierarchy.userId")}
            <Input value={userId} onChange={(event) => { setUserId(event.target.value); setManagerView(undefined); }} maxLength={128} required autoComplete="off" />
          </Label>
          <div className="ob-form-actions">
            <Button type="submit" disabled={loading || !mayRead}>{loading ? t("common.actions.working") : t("accounts.hierarchy.lookup")}</Button>
          </div>
        </Form>
        {!mayRead ? <p className="ob-empty-state">{t("accounts.hierarchy.readPermissionRequired")}</p> : null}
        {managerView ? (
          <>
            <p>{t("accounts.hierarchy.currentManager", { manager: managerView.manager?.userId ?? t("accounts.hierarchy.noManager") })}</p>
            <p className="ob-filter-help">{t("accounts.hierarchy.revision", { revision: managerView.revision })}</p>
            {mayManage ? (
              <Form className="ob-form-fields" onSubmit={(event) => { event.preventDefault(); proposeChange("set"); }}>
                <Label>
                  {t("accounts.hierarchy.newManagerId")}
                  <Input value={managerUserId} onChange={(event) => setManagerUserId(event.target.value)} maxLength={128} required autoComplete="off" />
                </Label>
                <div className="ob-form-actions">
                  <Button type="submit">{t("accounts.hierarchy.save")}</Button>
                  {managerView.manager ? <Button type="button" variant="danger" onClick={() => proposeChange("remove")}>{t("accounts.hierarchy.remove")}</Button> : null}
                </div>
              </Form>
            ) : <p className="ob-empty-state">{t("accounts.hierarchy.managePermissionRequired")}</p>}
          </>
        ) : null}
      </section>

      <section className="ob-surface ob-panel" aria-labelledby="hierarchy-reports-title">
        <h4 id="hierarchy-reports-title">{t("accounts.hierarchy.reportsTitle")}</h4>
        <Form className="ob-form-fields" onSubmit={(event) => void readReports(event, 1)}>
          <Label>
            {t("accounts.hierarchy.managerId")}
            <Input value={reportsManagerId} onChange={(event) => { setReportsManagerId(event.target.value); setReports(undefined); }} maxLength={128} required autoComplete="off" />
          </Label>
          <div className="ob-form-actions">
            <Button type="submit" disabled={reportsLoading || !mayReadReports}>{reportsLoading ? t("common.actions.working") : t("accounts.hierarchy.showReports")}</Button>
          </div>
        </Form>
        {!mayReadReports ? <p className="ob-empty-state">{t("accounts.hierarchy.reportsPermissionRequired")}</p> : null}
        {reportsLoading ? <p className="ob-empty-state" role="status">{t("common.loading")}</p> : null}
        {!reportsLoading && reports && reports.items.length === 0 ? <p className="ob-empty-state">{t("accounts.hierarchy.noReports")}</p> : null}
        {!reportsLoading && reports && reports.items.length > 0 ? (
          <div className="ob-table-wrap">
            <table className="ob-data-table">
              <caption className="ob-visually-hidden">{t("accounts.hierarchy.reportsCaption", { manager: reportsManagerId })}</caption>
              <thead><tr><th scope="col">{t("accounts.hierarchy.userId")}</th><th scope="col">{t("accounts.hierarchy.updatedAt")}</th></tr></thead>
              <tbody>{reports.items.map((item) => <tr key={item.userId}><td><code>{item.userId}</code></td><td>{new Intl.DateTimeFormat(i18n.language, { dateStyle: "medium", timeStyle: "short" }).format(new Date(item.updatedAt))}</td></tr>)}</tbody>
            </table>
          </div>
        ) : null}
        {reports ? <ReferencePager page={reports.page} pageSize={reports.pageSize} totalItems={reports.totalItems} noun={t("accounts.hierarchy.reportsNoun")} onPage={(next) => void readReports(undefined, next)} /> : null}
      </section>

      {pending ? (
        <ConfirmDialog
          title={pending.kind === "set" ? t("accounts.hierarchy.confirmSetTitle") : t("accounts.hierarchy.confirmRemoveTitle")}
          description={pending.kind === "set"
            ? t("accounts.hierarchy.confirmSetBody", { user: pending.userId, manager: pending.managerUserId })
            : t("accounts.hierarchy.confirmRemoveBody", { user: pending.userId })}
          confirmLabel={pending.kind === "set" ? t("accounts.hierarchy.save") : t("accounts.hierarchy.remove")}
          error={error ? errorText(error) : undefined}
          onCancel={() => setPending(undefined)}
          onConfirm={confirmChange}
        />
      ) : null}
    </section>
  );
}
