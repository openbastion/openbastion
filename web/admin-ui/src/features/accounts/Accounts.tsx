import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { Account, ApiError, Page, Session, accountPath } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { useSignedIn } from "../../shared/session";
import { AdminPage } from "../../shared/ui/AdminPage";
import { ScreenProfileDialog } from "./ScreenProfileDialog";
import { KerberosDialog } from "./KerberosDialog";
import { ReferenceMetric } from "../../shared/ui/ReferenceMetric";
import { ReferencePager } from "../../shared/ui/ReferencePager";
import { Alert, AppConfirmDialog, Button, Form, Input, Label, Select, Tabs, TabsContent, TabsList, TabsTrigger } from "@openbastion/ui";
import { ChevronDown, ChevronUp, Download, Filter, Plus, Search } from "@openbastion/icons";
import { PolicyForm } from "../policies/Policies";
import { AccountActions, AccountTable } from "./AccountTable";
import { ResourceTable } from "./ResourceTable";
import { ApprovalCards } from "./ApprovalCards";
import { ApprovalHierarchy } from "./ApprovalHierarchy";
import { PendingRequests } from "../sessions/PendingRequests";
import { OnboardAccount } from "./OnboardAccount";
import { askHostKey, askTlsPin } from "./pinPrompts";
import { useRoutedView } from "../../shared/useRoutedView";
import { useAppTranslation } from "../../shared/i18n";
import { useCapabilities } from "../../shared/capabilities";
import { GatedButton } from "../../shared/ui/GatedButton";
import {
  AccountFilterRule,
  accountFilterFields,
  defaultAccountFilterValue,
  maxAccountFilterRules,
  isAccountFilterField,
  matchesAccountFilterRules,
  readSavedAccountViews,
  SavedAccountView,
  writeSavedAccountViews,
} from "../../shared/savedAccountViews";

const pageSize = 20;
const approvalPreview = 3;

export type View = "resources" | "accounts" | "policies" | "requests" | "hierarchy";

// Privileged accounts of the Vault: list, onboard, rotate, disable. A secret is typed once at
// onboarding and never shown again: the API never returns one. A rotation changes the secret on
// the target, through the account's reconciliation account (ADR-0037). Each account pins its
// target's host key (ADR-0039): the secret goes only to the server that presents it. An account
// may require another person's approval, with a ticket, for every session on it (ADR-0067). A VNC
// account pins its target's TLS certificate instead of a host key (ADR-0071), and is not rotated.
//
// The reference screen ("Accès privilégiés") shows the same records twice: as access points
// (resource, address, protocol, access rule, state) and as accounts (identity, rotation). The
// environment column and the policy count have no public contract; they say so instead of
// showing a plausible number.
export function Accounts({
  onNavigate,
  initialView = "resources",
  view: routedView,
  onViewChange,
}: {
  onNavigate?: (tab: "sessions") => void;
  initialView?: View;
  // ADR-0137: when the application gives them, the tab is the address (`/access/<view>`).
  view?: View;
  onViewChange?: (view: View) => void;
} = {}) {
  const { t } = useAppTranslation();
  const { api, who } = useSignedIn();
  const { can, visible, status: capabilityStatus } = useCapabilities();
  // ADR-0131: a tab is present when the caller may do what it is for; the page opens on the first
  // one that is.
  const viewShown: Record<View, boolean> = {
    resources: visible("accounts.list"),
    accounts: visible("accounts.list"),
    policies: visible("policies.create"),
    requests: visible("sessions.approve"),
    hierarchy: visible("approvalHierarchy.read", "approvalHierarchy.manage", "approvalHierarchy.reports"),
  };
  const firstShown = (["resources", "accounts", "policies", "requests", "hierarchy"] as const).find((v) => viewShown[v]) ?? "resources";
  const [chosenView, setView] = useRoutedView<View>(initialView, routedView, onViewChange);
  const view: View = viewShown[chosenView] ? chosenView : firstShown;
  const mayList = visible("accounts.list");
  const [page, setPage] = useState(1);
  const [data, setData] = useState<Page<Account>>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>();
  const [ok, setOk] = useState<string>();
  const [filter, setFilter] = useState("");
  const [protocol, setProtocol] = useState("");
  // The inventory is the reason the screen exists: the rule builder stays closed until asked for,
  // so the table is not pushed below the fold by six paragraphs of filter help.
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [onboardOpen, setOnboardOpen] = useState(false);
  const [filterRules, setFilterRules] = useState<AccountFilterRule[]>([]);
  const [savedViews, setSavedViews] = useState<SavedAccountView[]>(readSavedAccountViews);
  const [selectedSavedView, setSelectedSavedView] = useState("");
  const [newViewName, setNewViewName] = useState("");
  const [viewNotice, setViewNotice] = useState<string>();
  const [accountAction, setAccountAction] = useState<{ kind: "disable" | "rotate"; account: Account }>();
  const [screenProfileFor, setScreenProfileFor] = useState<Account>();
  const [kerberosFor, setKerberosFor] = useState<Account>();
  const [approvals, setApprovals] = useState<Page<Session>>();
  const [approvalsError, setApprovalsError] = useState<unknown>();
  const [approvalsLoading, setApprovalsLoading] = useState(true);
  const [approvalDecision, setApprovalDecision] = useState<{ kind: "approve" | "reject"; session: Session }>();

  const load = useCallback(() => {
    // The inventory waits for the caller's capabilities, and is not asked for without the right
    // to list (the Vault would refuse).
    if (capabilityStatus === "loading") return;
    if (!mayList) { setLoading(false); return; }
    setLoading(true);
    api.request<Page<Account>>("GET", `/vault/accounts?page=${page}&pageSize=${pageSize}`)
      .then((result) => { setData(result); setError(undefined); })
      .catch(setError)
      .finally(() => setLoading(false));
  }, [api, page, mayList, capabilityStatus]);
  useEffect(load, [load]);

  // The approval list is what this caller could decide right now (GET /sessions, the only status
  // the Broker serves); it never claims to be every request of the platform.
  const loadApprovals = useCallback(() => {
    if (capabilityStatus === "loading") return;
    if (!can("sessions.approve")) { setApprovals(undefined); setApprovalsError(undefined); setApprovalsLoading(false); return; }
    setApprovalsLoading(true);
    api.request<Page<Session>>("GET", "/sessions?status=pending_approval&page=1&pageSize=100")
      .then((result) => { setApprovals(result); setApprovalsError(undefined); })
      .catch((err: unknown) => { setApprovals(undefined); setApprovalsError(err); })
      .finally(() => setApprovalsLoading(false));
  }, [api, capabilityStatus, can]);
  useEffect(loadApprovals, [loadApprovals]);

  function askApprovalDecision(kind: "approve" | "reject", session: Session) {
    setError(undefined);
    setOk(undefined);
    setApprovalDecision({ kind, session });
  }

  async function confirmApprovalDecision(): Promise<boolean> {
    if (!approvalDecision) return false;
    const { kind, session } = approvalDecision;
    try {
      await api.request("POST", `/sessions/${encodeURIComponent(session.id)}/${kind}`);
      setError(undefined);
      setOk(kind === "approve" ? t("sessions.decisions.approved", { id: session.id }) : t("sessions.decisions.rejected", { id: session.id }));
      setApprovalDecision(undefined);
      loadApprovals();
      return true;
    } catch (err) {
      setError(err);
      return false;
    }
  }

  async function act(what: string | ((result: unknown) => string), run: () => Promise<unknown>) {
    setError(undefined);
    setOk(undefined);
    try {
      const result = await run();
      setOk(typeof what === "string" ? what : what(result));
      load();
      loadApprovals();
    } catch (err) {
      setError(err);
    }
  }

  // Filtering is deliberately limited to the server page already loaded; it never implies a
  // complete inventory when the public API has not defined a search contract.
  const activeFilterCount = Number(protocol.length > 0) + filterRules.length;

  const filteredAccounts = (data?.items ?? []).filter((account) => {
    if (protocol && account.protocol.toLowerCase() !== protocol) return false;
    const query = filter.trim().toLocaleLowerCase("fr");
    if (query && ![account.id, account.name, account.username, account.targetHost, account.protocol]
      .some((value) => value.toLocaleLowerCase("fr").includes(query))) return false;
    return matchesAccountFilterRules(account, filterRules);
  });

  // One access point per target on the page: the Vault stores the target's address, and several
  // accounts may share it.
  const distinctTargets = useMemo(
    () => new Set((data?.items ?? []).map((account) => account.targetHost)).size,
    [data],
  );
  const inventoryComplete = Boolean(data && data.totalItems <= data.items.length);
  const pendingItems = approvals?.items ?? [];
  const approvalsUnavailable = Boolean(approvalsError);

  function updateFilterRule(index: number, patch: Partial<AccountFilterRule>) {
    setFilterRules((current) => current.map((rule, position) => position === index ? { ...rule, ...patch } : rule));
  }

  function addFilterRule() {
    setFilterRules((current) => {
      const nextField = accountFilterFields.find((field) => !current.some((rule) => rule.field === field));
      if (!nextField || current.length >= maxAccountFilterRules) return current;
      return [...current, {
        field: nextField,
        comparison: "is",
        value: defaultAccountFilterValue(nextField),
        join: "AND",
      }];
    });
  }

  function removeFilterRule(index: number) {
    setFilterRules((current) => current.filter((_, position) => position !== index));
  }

  function saveCurrentView(event: FormEvent) {
    event.preventDefault();
    const name = newViewName.trim().slice(0, 32);
    if (name.length < 2) {
      setViewNotice(undefined);
      setError(t("accounts.views.nameTooShort"));
      return;
    }
    const next = [
      ...savedViews.filter((view) => view.name.toLocaleLowerCase("fr") !== name.toLocaleLowerCase("fr")),
      { name, rules: filterRules },
    ].slice(-12);
    setViewNotice(undefined);
    if (!writeSavedAccountViews(next)) {
      setError(t("accounts.views.saveFailed"));
      return;
    }
    setError(undefined);
    setSavedViews(next);
    setSelectedSavedView(name);
    setNewViewName("");
    setViewNotice(t("accounts.views.saved"));
  }

  function applySavedView(name: string) {
    setSelectedSavedView(name);
    const view = savedViews.find((item) => item.name === name);
    if (view) {
      setFilterRules(view.rules);
      setFilter("");
    }
  }

  function deleteSavedView() {
    const next = savedViews.filter((view) => view.name !== selectedSavedView);
    setViewNotice(undefined);
    if (!writeSavedAccountViews(next)) {
      setError(t("accounts.views.deleteFailed"));
      return;
    }
    setError(undefined);
    setSavedViews(next);
    setSelectedSavedView("");
    setViewNotice(t("accounts.views.deleted"));
  }

  function openAccount(account: Account) {
    setView("accounts");
    setFilter(account.name || account.id);
    setProtocol("");
  }

  const actions: AccountActions = {
    pinKey(a) {
      const key = askHostKey(a);
      if (!key) return;
      act(
        (r) => t("accounts.notices.hostKeyPinned", {
          id: a.id,
          fingerprint: (r as { hostKeyFingerprint?: string } | undefined)?.hostKeyFingerprint ?? "",
        }),
        () => api.request("PUT", `${accountPath(a.id)}/host-key`, { hostKey: key }),
      );
    },
    pinTls(a) {
      const pin = askTlsPin(a);
      if (!pin) return;
      act(t("accounts.notices.tlsPinned", { id: a.id }), () =>
        api.request("PUT", `${accountPath(a.id)}/tls-pin`, { tlsCertificateSha256: pin.fingerprint, targetDomain: pin.domain }),
      );
    },
    toggleApproval(a) {
      act(a.approvalRequired ? t("accounts.notices.approvalOff", { id: a.id }) : t("accounts.notices.approvalOn", { id: a.id }), () =>
        api.request("PUT", `${accountPath(a.id)}/approval`, { approvalRequired: !a.approvalRequired }),
      );
    },
    screenProfile(a) {
      setError(undefined);
      setOk(undefined);
      setScreenProfileFor(a);
    },
    kerberos(a) {
      setError(undefined);
      setOk(undefined);
      setKerberosFor(a);
    },
    rotate(a) {
      setError(undefined);
      setOk(undefined);
      setAccountAction({ kind: "rotate", account: a });
    },
    disable(a) {
      setError(undefined);
      setOk(undefined);
      setAccountAction({ kind: "disable", account: a });
    },
  };

  const toolbar = (
    <div className="reference-table-toolbar">
      <Label className="reference-search">
        <Search size={15} aria-hidden="true" />
        <Input
          id="account-page-filter"
          type="search"
          aria-label={t("accounts.filter.searchAria")}
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          placeholder={t("accounts.filter.searchPlaceholder")}
        />
      </Label>
      <Label className="reference-select">
        <Select aria-label={t("accounts.reference.allTypes")} value={protocol} onChange={(event) => setProtocol(event.target.value)}>
          <option value="">{t("accounts.reference.allTypes")}</option>
          <option value="ssh">SSH</option>
          <option value="rdp">RDP</option>
          <option value="vnc">VNC</option>
        </Select>
        <ChevronDown size={14} aria-hidden="true" />
      </Label>
      {/* The reference screen filters on an environment the Vault does not store: the control
          keeps its place and says why it cannot filter anything. */}
      <Label className="reference-select is-unavailable">
        <Select disabled aria-label={t("accounts.reference.environment")} title={t("accounts.reference.environmentUnavailable")}>
          <option>{t("accounts.reference.environment")}</option>
        </Select>
        <ChevronDown size={14} aria-hidden="true" />
      </Label>
      {view === "accounts" ? (
        <Button
          variant="ghost"
          className="account-filter-trigger"
          aria-expanded={filtersOpen}
          aria-controls="account-filter-builder"
          onClick={() => setFiltersOpen((open) => !open)}
        >
          <Filter className="account-filter-trigger-icon" size={16} />
          <span>{t("accounts.filter.advanced")}</span>
          <span className="account-filter-count" aria-label={t("accounts.filter.activeCount", { count: activeFilterCount })}>{activeFilterCount}</span>
          <span className="account-filter-chevron">{filtersOpen ? <ChevronUp size={15} /> : <ChevronDown size={15} />}</span>
        </Button>
      ) : null}
    </div>
  );

  return (
    <AdminPage
      title={t("accounts.title")}
      subtitle={t("accounts.subtitle")}
      actions={
        <>
          <Button type="button" variant="secondary" disabled title={t("accounts.import.unavailable")}>
            <Download size={16} aria-hidden="true" />
            {t("accounts.import.label")}
          </Button>
          <GatedButton
            capability="accounts.onboard"
            type="button"
            variant="primary"
            aria-expanded={onboardOpen}
            aria-controls="onboard-account"
            onClick={() => setOnboardOpen((open) => !open)}
          >
            <Plus size={16} aria-hidden="true" />
            {onboardOpen ? t("accounts.closeForm") : t("accounts.openForm")}
          </GatedButton>
        </>
      }
      hints={[t("accounts.hints.rotation"), t("accounts.hints.hostKey"), t("accounts.hints.tls")]}
    >
      <Notice error={accountAction || screenProfileFor || kerberosFor || approvalDecision ? undefined : error} ok={accountAction || screenProfileFor || kerberosFor || approvalDecision ? undefined : ok} />
      {onboardOpen && can("accounts.onboard") ? (
        <div id="onboard-account">
          <OnboardAccount onDone={(id) => act(t("accounts.notices.onboarded", { id }), async () => undefined)} />
        </div>
      ) : null}

      <div className="reference-metrics" role="group" aria-label={t("accounts.metricsAria")}>
        <ReferenceMetric
          label={t("accounts.metrics.resources")}
          value={data ? distinctTargets : undefined}
          loading={loading}
          detail={inventoryComplete ? t("accounts.metrics.resourcesDetail") : t("accounts.metrics.resourcesPartial", { loaded: data?.items.length ?? 0, total: data?.totalItems ?? 0 })}
        />
        <ReferenceMetric
          label={t("accounts.metrics.accounts")}
          value={data?.totalItems}
          loading={loading}
          detail={t("accounts.metrics.accountsDetail")}
        />
        <ReferenceMetric
          label={t("accounts.metrics.policies")}
          detail={t("accounts.metrics.policiesUnavailable")}
        />
        <ReferenceMetric
          label={t("accounts.metrics.pending")}
          value={approvalsUnavailable ? undefined : approvals?.totalItems}
          tone="accent"
          detail={approvalsUnavailable ? t("accounts.metrics.pendingUnavailable") : t("accounts.metrics.pendingDetail")}
        />
      </div>

      <Tabs value={view} onValueChange={(next) => setView(next as View)} className="reference-tabs">
        <TabsList aria-label={t("accounts.tabsAria")}>
          {viewShown.resources ? <TabsTrigger value="resources">
            {t("accounts.tabs.resources")}
            <span className="reference-tab-count">{loading || !data ? "…" : data.totalItems}</span>
          </TabsTrigger> : null}
          {viewShown.accounts ? <TabsTrigger value="accounts">
            {t("accounts.tabs.accounts")}
            <span className="reference-tab-count">{loading || !data ? "…" : data.totalItems}</span>
          </TabsTrigger> : null}
          {viewShown.policies ? <TabsTrigger value="policies">
            {t("accounts.tabs.policies")}
            <span className="reference-tab-count">—</span>
          </TabsTrigger> : null}
          {viewShown.requests ? <TabsTrigger value="requests">
            {t("accounts.tabs.requests")}
            <span className="reference-tab-count">{approvalsUnavailable ? "—" : approvals?.totalItems ?? "…"}</span>
          </TabsTrigger> : null}
          {viewShown.hierarchy ? <TabsTrigger value="hierarchy">{t("accounts.tabs.hierarchy")}</TabsTrigger> : null}
        </TabsList>

        <TabsContent value="resources">
          <section className="ob-surface reference-panel" aria-label={t("accounts.inventoryAria")}>
            {toolbar}
            {loading ? <p className="ob-empty-state" role="status">{t("accounts.loading")}</p> : null}
            {!loading && data && data.items.length === 0 ? <p className="ob-empty-state">{t("accounts.empty")}</p> : null}
            {!loading && data && data.items.length > 0 && filteredAccounts.length > 0
              ? <ResourceTable accounts={filteredAccounts} onOpen={openAccount} />
              : null}
            {!loading && data && data.items.length > 0 && filteredAccounts.length === 0
              ? <p className="ob-empty-state">{t("accounts.noMatch")}</p>
              : null}
            {!loading && data ? (
              <ReferencePager page={data.page} pageSize={pageSize} totalItems={data.totalItems} noun={t("accounts.noun")} onPage={setPage} />
            ) : null}
          </section>
        </TabsContent>

        <TabsContent value="accounts">
          <section className="ob-surface reference-panel account-inventory" aria-label={t("accounts.inventoryAria")}>
            {toolbar}
            {loading ? <p className="ob-empty-state" role="status">{t("accounts.loading")}</p> : null}
            {!loading && data && data.items.length === 0 ? <p className="ob-empty-state">{t("accounts.empty")}</p> : null}
            {!loading && data && data.items.length > 0 ? (
              <div className="ob-filter-bar account-filter-bar">
                <div className="account-filter-toolbar-actions">
                  {activeFilterCount > 0 ? (
                    <Button type="button" onClick={() => { setFilter(""); setProtocol(""); setFilterRules([]); setSelectedSavedView(""); }}>
                      {t("accounts.filter.reset")}
                    </Button>
                  ) : null}
                </div>
                <p className="account-filter-scope">
                  <span aria-live="polite" aria-atomic="true">
                    {t("accounts.filter.scopeCount", { shown: filteredAccounts.length, total: data.items.length })}
                  </span>
                  {" — "}{t("accounts.filter.scopeNote")}
                </p>
                {filtersOpen ? (
                  <div id="account-filter-builder" className="account-filter-builder" aria-label={t("accounts.filter.builderAria")}>
                    <p className="ob-filter-help">{t("accounts.filter.help", { count: data.items.length })}</p>
                    <div className="account-filter-rules" aria-label={t("accounts.filter.rulesAria")}>
                      {filterRules.map((rule, index) => (
                        <div className="account-filter-rule" key={index}>
                          {index > 0 ? (
                            <Label className="account-filter-join-control">
                              <span>{t("accounts.filter.combination")}</span>
                              <Select
                                aria-label={t("accounts.filter.combinationAria", { position: index + 1 })}
                                value={rule.join}
                                onChange={(event) => updateFilterRule(index, { join: event.target.value as AccountFilterRule["join"] })}
                              >
                                <option value="AND">{t("accounts.filter.and")}</option>
                                <option value="OR">{t("accounts.filter.or")}</option>
                              </Select>
                            </Label>
                          ) : <span className="account-filter-join-placeholder" aria-hidden="true">{t("accounts.filter.where")}</span>}
                          <Label className="account-filter-field">
                            <span>{t("accounts.filter.field")}</span>
                            <Select
                              aria-label={t("accounts.filter.fieldAria", { position: index + 1 })}
                              value={rule.field}
                              onChange={(event) => {
                                if (!isAccountFilterField(event.target.value)) return;
                                updateFilterRule(index, { field: event.target.value, value: defaultAccountFilterValue(event.target.value) });
                              }}
                            >
                              <option value="protocol" disabled={filterRules.some((other, position) => position !== index && other.field === "protocol")}>{t("accounts.filter.fields.protocol")}</option>
                              <option value="approval" disabled={filterRules.some((other, position) => position !== index && other.field === "approval")}>{t("accounts.filter.fields.approval")}</option>
                              <option value="identity" disabled={filterRules.some((other, position) => position !== index && other.field === "identity")}>{t("accounts.filter.fields.identity")}</option>
                              <option value="rotation" disabled={filterRules.some((other, position) => position !== index && other.field === "rotation")}>{t("accounts.filter.fields.rotation")}</option>
                            </Select>
                          </Label>
                          <Label className="account-filter-operator">
                            <span>{t("accounts.filter.operator")}</span>
                            <Select
                              aria-label={t("accounts.filter.operatorAria", { position: index + 1 })}
                              value={rule.comparison}
                              onChange={(event) => updateFilterRule(index, { comparison: event.target.value as AccountFilterRule["comparison"] })}
                            >
                              <option value="is">{t("accounts.filter.is")}</option>
                              <option value="is-not">{t("accounts.filter.isNot")}</option>
                            </Select>
                          </Label>
                          <Label className="account-filter-value">
                            <span>{t("accounts.filter.value")}</span>
                            <Select
                              aria-label={t("accounts.filter.valueAria", { position: index + 1 })}
                              value={rule.value}
                              onChange={(event) => updateFilterRule(index, { value: event.target.value })}
                            >
                              {rule.field === "protocol" ? <>
                                <option value="ssh">SSH</option><option value="rdp">RDP</option><option value="vnc">VNC</option>
                              </> : null}
                              {rule.field === "approval" ? <>
                                <option value="required">{t("accounts.filter.values.required")}</option><option value="not-required">{t("accounts.filter.values.notRequired")}</option>
                              </> : null}
                              {rule.field === "identity" ? <>
                                <option value="pinned">{t("accounts.filter.values.pinned")}</option><option value="missing">{t("accounts.filter.values.missing")}</option>
                              </> : null}
                              {rule.field === "rotation" ? <>
                                <option value="due">{t("accounts.filter.values.due")}</option><option value="failed">{t("accounts.filter.values.failed")}</option><option value="none">{t("accounts.filter.values.none")}</option>
                              </> : null}
                            </Select>
                          </Label>
                          <Button variant="ghost" className="account-filter-remove" aria-label={t("accounts.filter.removeAria", { position: index + 1 })} onClick={() => removeFilterRule(index)}>×</Button>
                        </div>
                      ))}
                    </div>
                    <div className="account-filter-actions">
                      <Button type="button" disabled={filterRules.length >= maxAccountFilterRules} onClick={addFilterRule}>{t("accounts.filter.add")}</Button>
                      {filterRules.length > 0
                        ? <span className="ob-filter-help">{t("accounts.filter.maxNote")}</span>
                        : <span className="ob-filter-help">{t("accounts.filter.addHint")}</span>}
                    </div>
                    <div className="account-filter-builder-footer">
                      <span className="ob-filter-help">{t("accounts.filter.textAlwaysAnd")}</span>
                    </div>
                    <div className="ob-saved-views">
                      <Label>
                        {t("accounts.views.label")}
                        <Select value={selectedSavedView} onChange={(event) => applySavedView(event.target.value)}>
                          <option value="">{t("accounts.views.choose")}</option>
                          {savedViews.map((view) => <option key={view.name} value={view.name}>{view.name}</option>)}
                        </Select>
                      </Label>
                      <Form className="ob-saved-view-form" onSubmit={saveCurrentView}>
                        <Label>
                          {t("accounts.views.name")}
                          <Input value={newViewName} onChange={(event) => setNewViewName(event.target.value)} maxLength={32} minLength={2} required placeholder={t("accounts.views.namePlaceholder")} />
                        </Label>
                        <Button type="submit">{t("accounts.views.save")}</Button>
                      </Form>
                      <Button disabled={!selectedSavedView} onClick={deleteSavedView}>{t("accounts.views.delete")}</Button>
                    </div>
                    {viewNotice ? <Alert tone="success">{viewNotice}</Alert> : null}
                    <p className="ob-filter-help">{t("accounts.views.help")}</p>
                  </div>
                ) : null}
              </div>
            ) : null}
            {!loading && data && filteredAccounts.length > 0 ? <AccountTable accounts={filteredAccounts} actions={actions} /> : null}
            {!loading && data && data.items.length > 0 && filteredAccounts.length === 0 ? <p className="ob-empty-state">{t("accounts.noMatch")}</p> : null}
            {!loading && data ? (
              <ReferencePager page={data.page} pageSize={pageSize} totalItems={data.totalItems} noun={t("accounts.noun")} onPage={setPage} />
            ) : null}
          </section>
        </TabsContent>

        <TabsContent value="policies">
          <section className="ob-surface reference-panel accounts-policies" aria-label={t("accounts.tabs.policies")}>
            <div className="reference-panel-heading">
              <div>
                <h3>{t("policies.title")}</h3>
                <p>
                  {t("policies.prefix")} <code>vault:account:&lt;id&gt;</code> {t("policies.session")}{" "}
                  <code>recording:session:*</code> {t("policies.recording")} <code>breakglass-approve:account:&lt;id&gt;</code>{" "}
                  {t("policies.breakglass")}
                </p>
              </div>
            </div>
            <PolicyForm />
          </section>
        </TabsContent>

        <TabsContent value="requests">
          <section className="ob-surface reference-panel" aria-label={t("accounts.tabs.requests")}>
            <div className="reference-panel-heading">
              <div>
                <h3>{t("accounts.approvals.title")}</h3>
                <p>{t("accounts.approvals.hint")}</p>
              </div>
              {approvalsUnavailable ? null : <span className="reference-panel-badge">{approvals?.totalItems ?? "…"}</span>}
            </div>
            {approvalsUnavailable ? <Notice error={approvalsError ?? new Error(t("accounts.approvals.unavailable"))} /> : null}
            {!approvalsUnavailable ? (
              <PendingRequests
                pending={approvals}
                loading={approvalsLoading}
                currentUserId={who?.sub}
                onApprove={(session) => askApprovalDecision("approve", session)}
                onReject={(session) => askApprovalDecision("reject", session)}
              />
            ) : null}
          </section>
        </TabsContent>

        <TabsContent value="hierarchy">
          <ApprovalHierarchy />
        </TabsContent>
      </Tabs>

      {view !== "requests" && pendingItems.length > 0 ? (
        <section className="reference-section" aria-labelledby="accounts-approvals-title">
          <div className="reference-section-heading">
            <h3 id="accounts-approvals-title">{t("accounts.approvals.title")}</h3>
            <Button variant="ghost" className="reference-link" onClick={() => setView("requests")}>
              {t("accounts.approvals.all", { count: approvals?.totalItems ?? pendingItems.length })} <span aria-hidden="true">→</span>
            </Button>
          </div>
          <ApprovalCards sessions={pendingItems.slice(0, approvalPreview)} onOpen={() => onNavigate?.("sessions")} />
        </section>
      ) : null}

      {screenProfileFor ? (
        <ScreenProfileDialog
          account={screenProfileFor}
          error={error instanceof ApiError ? `${error.status} — ${error.message}` : error ? String((error as Error)?.message ?? error) : undefined}
          onCancel={() => { setScreenProfileFor(undefined); }}
          onSave={async (screenProfile) => {
            const account = screenProfileFor;
            try {
              await api.request("PUT", `${accountPath(account.id)}/screen-profile`, { screenProfile });
              setOk(screenProfile ? t("accounts.notices.screenProfileSet", { id: account.id }) : t("accounts.notices.screenProfileRemoved", { id: account.id }));
              setError(undefined);
              load();
              return true;
            } catch (err) {
              setError(err);
              return false;
            }
          }}
        />
      ) : null}
      {kerberosFor ? (
        <KerberosDialog
          account={kerberosFor}
          error={error instanceof ApiError ? `${error.status} — ${error.message}` : error ? String((error as Error)?.message ?? error) : undefined}
          onCancel={() => { setKerberosFor(undefined); }}
          onSave={async (kerberos) => {
            const account = kerberosFor;
            try {
              await api.request("PUT", `${accountPath(account.id)}/kerberos`, { kerberos });
              setOk(kerberos ? t("accounts.notices.kerberosSet", { id: account.id, realm: kerberos.realm }) : t("accounts.notices.kerberosRemoved", { id: account.id }));
              setError(undefined);
              load();
              return true;
            } catch (err) {
              setError(err);
              return false;
            }
          }}
        />
      ) : null}
      {approvalDecision ? (
        <AppConfirmDialog
          cancelLabel={t("common.actions.cancel")}
          workingLabel={t("common.actions.working")}
          title={approvalDecision.kind === "approve" ? t("sessions.confirm.approveTitle") : t("sessions.confirm.rejectTitle")}
          description={t("sessions.confirm.decideBody", {
            kind: approvalDecision.session.breakGlass ? t("sessions.confirm.emergency") : t("sessions.confirm.access"),
            id: approvalDecision.session.id,
            requester: approvalDecision.session.requestedBy,
            account: approvalDecision.session.privilegedAccountId,
            justification: approvalDecision.session.justification,
            ticket: approvalDecision.session.ticket ?? t("sessions.confirm.none"),
            expiresAt: approvalDecision.session.expiresAt,
          })}
          confirmLabel={approvalDecision.kind === "approve" ? t("sessions.confirm.approve") : t("sessions.confirm.reject")}
          danger={approvalDecision.kind === "reject"}
          error={error instanceof ApiError ? `${error.status} — ${error.message}` : error ? String((error as Error)?.message ?? error) : undefined}
          onCancel={() => setApprovalDecision(undefined)}
          onConfirm={confirmApprovalDecision}
        />
      ) : null}
      {accountAction ? (
        <AppConfirmDialog
          cancelLabel={t("common.actions.cancel")}
          workingLabel={t("common.actions.working")}
          title={accountAction.kind === "disable" ? t("accounts.confirm.disableTitle") : t("accounts.confirm.rotateTitle")}
          description={accountAction.kind === "disable"
            ? t("accounts.confirm.disableBody", { id: accountAction.account.id })
            : t("accounts.confirm.rotateBody", { id: accountAction.account.id })}
          confirmLabel={accountAction.kind === "disable" ? t("accounts.confirm.disable") : t("accounts.confirm.rotate")}
          danger={accountAction.kind === "disable"}
          error={error instanceof ApiError ? `${error.status} — ${error.message}` : error ? String((error as Error)?.message ?? error) : undefined}
          onCancel={() => setAccountAction(undefined)}
          onConfirm={async () => {
            const { kind, account } = accountAction;
            try {
              await api.request(kind === "disable" ? "DELETE" : "POST", kind === "disable" ? accountPath(account.id) : `${accountPath(account.id)}/rotate`);
              setOk(
                kind === "disable"
                  ? t("accounts.notices.disabled", { id: account.id })
                  : t("accounts.notices.rotated", { id: account.id }),
              );
              setError(undefined);
              setAccountAction(undefined);
              load();
              loadApprovals();
              return true;
            } catch (err) {
              setError(err);
              return false;
            }
          }}
        />
      ) : null}
    </AdminPage>
  );
}
