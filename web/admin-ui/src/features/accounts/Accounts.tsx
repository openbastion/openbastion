import { FormEvent, useCallback, useEffect, useState } from "react";
import { Account, ApiError, Page, accountPath } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { useSignedIn } from "../../shared/session";
import { AdminPage } from "../../shared/ui/AdminPage";
import { Pager } from "../../shared/ui/Pager";
import { ConfirmDialog } from "../../shared/ui/ConfirmDialog";
import { Button } from "../../shared/ui/Button";
import { InlineNotice } from "../../shared/ui/InlineNotice";
import { AccountActions, AccountTable } from "./AccountTable";
import { OnboardAccount } from "./OnboardAccount";
import { askHostKey, askTlsPin } from "./pinPrompts";
import { useAppTranslation } from "../../shared/i18n";
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

// Privileged accounts of the Vault: list, onboard, rotate, disable. A secret is typed once at
// onboarding and never shown again: the API never returns one. A rotation changes the secret on
// the target, through the account's reconciliation account (ADR-0037). Each account pins its
// target's host key (ADR-0039): the secret goes only to the server that presents it. An account
// may require another person's approval, with a ticket, for every session on it (ADR-0067). A VNC
// account pins its target's TLS certificate instead of a host key (ADR-0071), and is not rotated.
export function Accounts() {
  const { t } = useAppTranslation();
  const { api } = useSignedIn();
  const [page, setPage] = useState(1);
  const [data, setData] = useState<Page<Account>>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>();
  const [ok, setOk] = useState<string>();
  const [filter, setFilter] = useState("");
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

  const load = useCallback(() => {
    setLoading(true);
    api.request<Page<Account>>("GET", `/vault/accounts?page=${page}&pageSize=${pageSize}`)
      .then((result) => { setData(result); setError(undefined); })
      .catch(setError)
      .finally(() => setLoading(false));
  }, [api, page]);
  useEffect(load, [load]);

  async function act(what: string | ((result: unknown) => string), run: () => Promise<unknown>) {
    setError(undefined);
    setOk(undefined);
    try {
      const result = await run();
      setOk(typeof what === "string" ? what : what(result));
      load();
    } catch (err) {
      setError(err);
    }
  }

  // Filtering is deliberately limited to the server page already loaded; it never implies a
  // complete inventory when the public API has not defined a search contract.
  const activeFilterCount = Number(filter.trim().length > 0) + filterRules.length;

  const filteredAccounts = (data?.items ?? []).filter((account) => {
    const query = filter.trim().toLocaleLowerCase("fr");
    if (query && ![account.id, account.name, account.username, account.targetHost, account.protocol]
      .some((value) => value.toLocaleLowerCase("fr").includes(query))) return false;
    return matchesAccountFilterRules(account, filterRules);
  });

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

  return (
    <AdminPage
      title={t("accounts.title")}
      actions={
        <Button
          type="button"
          variant="primary"
          aria-expanded={onboardOpen}
          aria-controls="onboard-account"
          onClick={() => setOnboardOpen((open) => !open)}
        >
          {onboardOpen ? t("accounts.closeForm") : t("accounts.openForm")}
        </Button>
      }
      hints={[t("accounts.hints.rotation"), t("accounts.hints.hostKey"), t("accounts.hints.tls")]}
    >
      <Notice error={accountAction ? undefined : error} ok={accountAction ? undefined : ok} />
      {onboardOpen ? (
        <div id="onboard-account">
          <OnboardAccount onDone={(id) => act(t("accounts.notices.onboarded", { id }), async () => undefined)} />
        </div>
      ) : null}
      <section className="ob-surface account-inventory" aria-label={t("accounts.inventoryAria")}>
        {loading ? <p className="ob-empty-state" role="status">{t("accounts.loading")}</p> : null}
        {!loading && data && data.items.length === 0 ? <p className="ob-empty-state">{t("accounts.empty")}</p> : null}
        {!loading && data && data.items.length > 0 ? (
          <div className="ob-filter-bar account-filter-bar">
            <div className="account-filter-toolbar">
              <label className="account-filter-search">
                <span className="ob-visually-hidden">{t("accounts.filter.searchAria")}</span>
                <input
                  id="account-page-filter"
                  type="search"
                  value={filter}
                  onChange={(event) => setFilter(event.target.value)}
                  placeholder={t("accounts.filter.searchPlaceholder")}
                />
              </label>
              <div className="account-filter-toolbar-actions">
                <button
                  className="account-filter-trigger"
                  type="button"
                  aria-expanded={filtersOpen}
                  aria-controls="account-filter-builder"
                  onClick={() => setFiltersOpen((open) => !open)}
                >
                  <span className="account-filter-trigger-icon" aria-hidden="true">☷</span>
                  <span>{t("accounts.filter.advanced")}</span>
                  <span className="account-filter-count" aria-label={t("accounts.filter.activeCount", { count: activeFilterCount })}>{activeFilterCount}</span>
                  <span className="account-filter-chevron" aria-hidden="true">{filtersOpen ? "⌃" : "⌄"}</span>
                </button>
                {activeFilterCount > 0 ? (
                  <Button type="button" onClick={() => { setFilter(""); setFilterRules([]); setSelectedSavedView(""); }}>
                    {t("accounts.filter.reset")}
                  </Button>
                ) : null}
              </div>
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
                        <label className="account-filter-join-control">
                          <span>{t("accounts.filter.combination")}</span>
                          <select
                            aria-label={t("accounts.filter.combinationAria", { position: index + 1 })}
                            value={rule.join}
                            onChange={(event) => updateFilterRule(index, { join: event.target.value as AccountFilterRule["join"] })}
                          >
                            <option value="AND">{t("accounts.filter.and")}</option>
                            <option value="OR">{t("accounts.filter.or")}</option>
                          </select>
                        </label>
                      ) : <span className="account-filter-join-placeholder" aria-hidden="true">{t("accounts.filter.where")}</span>}
                      <label className="account-filter-field">
                        <span>{t("accounts.filter.field")}</span>
                        <select
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
                        </select>
                      </label>
                      <label className="account-filter-operator">
                        <span>{t("accounts.filter.operator")}</span>
                        <select
                          aria-label={t("accounts.filter.operatorAria", { position: index + 1 })}
                          value={rule.comparison}
                          onChange={(event) => updateFilterRule(index, { comparison: event.target.value as AccountFilterRule["comparison"] })}
                        >
                          <option value="is">{t("accounts.filter.is")}</option>
                          <option value="is-not">{t("accounts.filter.isNot")}</option>
                        </select>
                      </label>
                      <label className="account-filter-value">
                        <span>{t("accounts.filter.value")}</span>
                        <select
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
                        </select>
                      </label>
                      <button className="account-filter-remove" type="button" aria-label={t("accounts.filter.removeAria", { position: index + 1 })} onClick={() => removeFilterRule(index)}>×</button>
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
                  <label>
                    {t("accounts.views.label")}
                    <select value={selectedSavedView} onChange={(event) => applySavedView(event.target.value)}>
                      <option value="">{t("accounts.views.choose")}</option>
                      {savedViews.map((view) => <option key={view.name} value={view.name}>{view.name}</option>)}
                    </select>
                  </label>
                  <form className="ob-saved-view-form" onSubmit={saveCurrentView}>
                    <label>
                      {t("accounts.views.name")}
                      <input value={newViewName} onChange={(event) => setNewViewName(event.target.value)} maxLength={32} minLength={2} required placeholder={t("accounts.views.namePlaceholder")} />
                    </label>
                    <Button type="submit">{t("accounts.views.save")}</Button>
                  </form>
                  <Button disabled={!selectedSavedView} onClick={deleteSavedView}>{t("accounts.views.delete")}</Button>
                </div>
                {viewNotice ? <InlineNotice tone="success">{viewNotice}</InlineNotice> : null}
                <p className="ob-filter-help">{t("accounts.views.help")}</p>
              </div>
            ) : null}
          </div>
        ) : null}
        {!loading && data && filteredAccounts.length > 0 ? <AccountTable accounts={filteredAccounts} actions={actions} /> : null}
        {!loading && data && data.items.length > 0 && filteredAccounts.length === 0 ? <p className="ob-empty-state">{t("accounts.noMatch")}</p> : null}
        {!loading && data ? <Pager page={data.page} pageSize={pageSize} totalItems={data.totalItems} noun={t("accounts.noun")} onPage={setPage} /> : null}
      </section>
      {accountAction ? (
        <ConfirmDialog
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
