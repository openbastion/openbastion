import { FormEvent, useCallback, useEffect, useState } from "react";
import { ApiError, Page, Session, sessionPath } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { useSignedIn } from "../../shared/session";
import { AdminPage } from "../../shared/ui/AdminPage";
import { ScreenViewer } from "../screen/ScreenViewer";
import { AttachedScreen, SessionDetail } from "./SessionDetail";
import { ConfirmDialog } from "../../shared/ui/ConfirmDialog";
import { SessionRequest } from "./SessionRequest";
import { Button } from "../../shared/ui/Button";
import { StatusBadge } from "../../shared/ui/StatusBadge";
import { Badge, Form, Input, Label, Tabs, TabsContent, TabsList, TabsTrigger } from "@openbastion/ui";
import { Download, Search } from "@openbastion/icons";
import { ReferenceMetric } from "../../shared/ui/ReferenceMetric";
import { Modal } from "../../shared/ui/Modal";
import { SessionHistory } from "./SessionHistory";
import { SessionRecordings } from "./SessionRecordings";
import { SessionAlerts } from "./SessionAlerts";
import { RecordingPanel } from "../audit/Recording";
import { useAppTranslation } from "../../shared/i18n";
import { useCapabilities } from "../../shared/capabilities";
import { GatedButton } from "../../shared/ui/GatedButton";

type View = "live" | "history" | "recordings" | "alerts";

function formatExpiry(value: string, locale: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString(locale, { dateStyle: "short", timeStyle: "short" });
}

// The page deliberately lists only requests returned by the caller-scoped approval endpoint.
// There is no global active-session feed or SSH terminal stream in the public API/UI contract.
//
// Layout follows docs/ui/reference-screens/openbastion-sessions*.svg: one header per view, four
// indicator cards, the tab strip, then the view's panel. A figure the public API cannot produce
// stays an em dash with its reason — the reference cards' numbers are illustrative, never data.
export function Sessions({
  requestedSessionId,
  onSessionLookupComplete,
  initialView = "live",
  onOpenRecording,
}: {
  requestedSessionId?: string | null;
  onSessionLookupComplete?: () => void;
  onOpenRecording?: (sessionId: string) => void;
  initialView?: View;
} = {}) {
  const { t, i18n } = useAppTranslation();
  const { api, who } = useSignedIn();
  const [pending, setPending] = useState<Page<Session>>();
  const [pendingLoading, setPendingLoading] = useState(true);
  const [decision, setDecision] = useState<{ kind: "approve" | "reject" | "terminate"; session: Session }>();
  const [error, setError] = useState<unknown>();
  const [ok, setOk] = useState<string>();
  const [lookup, setLookup] = useState("");
  const [found, setFound] = useState<Session>();
  const [screen, setScreen] = useState<AttachedScreen>();
  const { visible } = useCapabilities();
  // ADR-0131: the recordings tab is for those who may replay; the others stay on the live view.
  const recordingsShown = visible("recordings.read");
  const [chosenView, setView] = useState<View>(initialView);
  const view: View = chosenView === "recordings" && !recordingsShown ? "live" : chosenView;
  const [requestFormOpen, setRequestFormOpen] = useState(false);
  // The recording screen lives in this page's "Enregistrements" tab: the library opens its
  // replay here instead of sending the operator to another page.
  const [replaySessionId, setReplaySessionId] = useState<string>();

  const load = useCallback(() => {
    setPendingLoading(true);
    setPending(undefined);
    api.request<Page<Session>>("GET", "/sessions?status=pending_approval")
      .then((result) => {
        setPending(result);
        setFound((current) => current ?? result.items[0]);
        setLookup((current) => current || result.items[0]?.id || "");
        setError(undefined);
      })
      .catch((err: unknown) => { setPending(undefined); setError(err); })
      .finally(() => setPendingLoading(false));
  }, [api]);
  useEffect(load, [load]);

  const findById = useCallback(async (id: string) => {
    setLookup(id);
    setFound(undefined);
    setScreen(undefined);
    setError(undefined);
    try {
      setFound(await api.request<Session>("GET", sessionPath(id)));
    } catch (err) {
      setError(err);
    }
  }, [api]);

  useEffect(() => {
    if (!requestedSessionId) return;
    setView("live");
    void findById(requestedSessionId);
    onSessionLookupComplete?.();
  }, [findById, onSessionLookupComplete, requestedSessionId]);

  function selectPending(session: Session) {
    // The approval list is already scoped to this caller. Do not make an additional GET that
    // would cross the distinct session-read policy boundary for a pending approval.
    setFound(session);
    setLookup(session.id);
    setScreen(undefined);
    setError(undefined);
    setOk(undefined);
  }

  function find(e: FormEvent) {
    e.preventDefault();
    void findById(lookup);
  }

  async function openScreen(sessionId: string) {
    setError(undefined);
    setOk(undefined);
    setScreen(undefined);
    try {
      const { attach } = await api.connectScreen(sessionId);
      setScreen((previous) => ({ sessionId, attach, key: (previous?.key ?? 0) + 1 }));
    } catch (err) {
      setError(err);
    }
  }

  function askDecision(kind: "approve" | "reject" | "terminate", session: Session) {
    setError(undefined);
    setOk(undefined);
    setDecision({ kind, session });
  }

  async function confirmDecision(): Promise<boolean> {
    if (!decision) return false;
    const { kind, session } = decision;
    const endpoint = kind === "approve" ? `${sessionPath(session.id)}/approve`
      : kind === "reject" ? `${sessionPath(session.id)}/reject` : sessionPath(session.id);
    const method = kind === "terminate" ? "DELETE" : "POST";
    try {
      await api.request(method, endpoint);
      setError(undefined);
      setOk(
        kind === "approve" ? t("sessions.decisions.approved", { id: session.id })
          : kind === "reject" ? t("sessions.decisions.rejected", { id: session.id })
            : t("sessions.decisions.terminated", { id: session.id }),
      );
      setDecision(undefined);
      setFound(undefined);
      setScreen(undefined);
      load();
      return true;
    } catch (err) {
      setError(err);
      return false;
    }
  }

  const pendingCount = pending?.totalItems;
  const pendingCountLabel = pendingLoading ? "…" : error && !pending ? "—" : String(pendingCount ?? 0);

  const header =
    view === "history"
      ? { title: t("sessions.history.title"), subtitle: t("sessions.subtitles.history") }
      : view === "recordings"
        ? { title: t("sessions.titles.recordings"), subtitle: t("sessions.subtitles.recordings") }
        : view === "alerts"
          ? { title: t("sessions.alerts.title"), subtitle: t("sessions.subtitles.alerts") }
          : { title: t("sessions.title"), subtitle: t("sessions.subtitles.live") };

  const exportAction = (
    <Button type="button" variant="secondary" disabled title={t("sessions.exportUnavailable")}>
      <Download size={16} aria-hidden="true" />
      {t(`sessions.exports.${view}`)}
    </Button>
  );

  return (
    <AdminPage
      title={header.title}
      subtitle={header.subtitle}
      actions={
        view === "live" ? (
          <>
            {exportAction}
            <GatedButton capability="sessions.create" variant="primary" onClick={() => { setView("live"); setRequestFormOpen(true); }}>{t("sessions.live.newRequest")}</GatedButton>
          </>
        ) : exportAction
      }
    >
      <Notice error={decision ? undefined : error} ok={decision ? undefined : ok} />

      <div className="reference-metrics" role="group" aria-label={t("sessions.metrics.aria")}>
        {view === "live" ? (
          <>
            <ReferenceMetric label={t("sessions.metrics.active")} detail={t("sessions.metrics.activeDetail")} />
            <ReferenceMetric label={t("sessions.metrics.recordedToday")} detail={t("sessions.metrics.recordedTodayDetail")} />
            <ReferenceMetric label={t("sessions.metrics.averageDuration")} detail={t("sessions.metrics.averageDurationDetail")} />
            <ReferenceMetric label={t("sessions.metrics.interrupted")} detail={t("sessions.metrics.interruptedDetail")} />
          </>
        ) : null}
        {view === "history" ? (
          <>
            <ReferenceMetric label={t("sessions.metrics.last30Days")} detail={t("sessions.metrics.last30DaysDetail")} />
            <ReferenceMetric label={t("sessions.metrics.recordings")} detail={t("sessions.metrics.recordingsDetail")} />
            <ReferenceMetric label={t("sessions.metrics.averageDuration")} detail={t("sessions.metrics.averageDurationDetail")} />
            <ReferenceMetric label={t("sessions.metrics.interrupted")} detail={t("sessions.metrics.interruptedDetail")} />
          </>
        ) : null}
        {view === "recordings" ? (
          <>
            <ReferenceMetric label={t("sessions.metrics.recordings")} detail={t("sessions.metrics.recordingsDetail")} />
            <ReferenceMetric label={t("sessions.metrics.totalDuration")} detail={t("sessions.metrics.totalDurationDetail")} />
            <ReferenceMetric label={t("sessions.metrics.integrity")} detail={t("sessions.metrics.integrityDetail")} />
            <ReferenceMetric label={t("sessions.metrics.expiringSoon")} detail={t("sessions.metrics.expiringSoonDetail")} />
          </>
        ) : null}
        {view === "alerts" ? (
          <>
            <ReferenceMetric label={t("sessions.metrics.alertsUnhandled")} detail={t("sessions.metrics.alertsUnavailable")} />
            <ReferenceMetric label={t("sessions.metrics.alertsCritical")} detail={t("sessions.metrics.alertsUnavailable")} />
            <ReferenceMetric label={t("sessions.metrics.alertsHigh")} detail={t("sessions.metrics.alertsUnavailable")} />
            <ReferenceMetric label={t("sessions.metrics.alertsHandled")} detail={t("sessions.metrics.alertsUnavailable")} />
          </>
        ) : null}
      </div>

      <Tabs value={view} onValueChange={(next) => setView(next as View)} className="reference-tabs session-tabs">
        <TabsList aria-label={t("sessions.tabs.aria")}>
          <TabsTrigger value="live" aria-label={t("sessions.tabs.live")}>
            {t("sessions.tabs.live")}
            <span className="reference-tab-count">{pendingCountLabel}</span>
          </TabsTrigger>
          <TabsTrigger value="history">{t("sessions.tabs.history")}</TabsTrigger>
          {recordingsShown ? <TabsTrigger value="recordings">{t("sessions.tabs.recordings")}</TabsTrigger> : null}
          <TabsTrigger value="alerts" aria-label={t("sessions.tabs.alerts")}>
            {t("sessions.tabs.alerts")}
            <Badge tone="warning" className="session-alert-tab-badge">{t("sessions.alerts.badge")}</Badge>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="live">
          <div className="sessions-live-workspace">
            <section className="sessions-live-queue" aria-labelledby="sessions-live-queue-title">
              <div className="sessions-live-panel-heading">
                <div>
                  <h3 id="sessions-live-queue-title">{t("sessions.live.queueTitle")}</h3>
                  <p>{pendingLoading ? t("sessions.pending.loading") : t("sessions.live.queueCount", { count: pendingCount ?? 0 })}</p>
                </div>
              </div>
              <Form className="sessions-live-search" onSubmit={find} aria-label={t("sessions.lookup.formAria")}>
                <Label htmlFor="session-lookup">{t("sessions.lookup.identifier")}</Label>
                <div>
                  <Input
                    id="session-lookup"
                    type="search"
                    value={lookup}
                    onChange={(e) => setLookup(e.target.value)}
                    placeholder={t("sessions.live.searchPlaceholder")}
                    required
                  />
                  <Button type="submit" variant="primary">{t("sessions.lookup.show")}</Button>
                </div>
              </Form>
              <div className="sessions-live-list" aria-label={t("sessions.live.queueAria")}>
                {pendingLoading ? <p className="sessions-live-state" role="status">{t("sessions.pending.loading")}</p> : null}
                {!pendingLoading && !error && pending?.items.length === 0 ? <p className="sessions-live-state">{t("sessions.pending.empty")}</p> : null}
                {!pendingLoading && pending?.items.map((session) => (
                  <Button
                    variant="ghost"
                    key={session.id}
                    className="sessions-live-item"
                    aria-current={found?.id === session.id ? "true" : undefined}
                    aria-label={t("sessions.live.selectRequestAria", { requester: session.requestedBy, account: session.privilegedAccountId })}
                    onClick={() => selectPending(session)}
                  >
                    <span className="sessions-live-item-top">
                      <strong>{session.requestedBy}</strong>
                      <Badge className="reference-pill">{session.protocol.toUpperCase()}</Badge>
                    </span>
                    <span className="sessions-live-item-account">{session.privilegedAccountId}</span>
                    <span className="sessions-live-item-meta">
                      <code>{session.id}</code>
                      <time dateTime={session.expiresAt}>{formatExpiry(session.expiresAt, i18n.language)}</time>
                    </span>
                  </Button>
                ))}
              </div>
              {pending?.truncated ? <p className="sessions-live-truncated">{t("sessions.pending.truncated")}</p> : null}
            </section>

            <section className="sessions-live-detail" aria-labelledby="sessions-live-detail-title">
              {found ? (
                <>
                  <header className="sessions-live-detail-heading">
                    <div>
                      <h3 id="sessions-live-detail-title">{found.privilegedAccountId}</h3>
                      <p>{found.requestedBy} <span aria-hidden="true">/</span> {found.protocol.toUpperCase()} <span aria-hidden="true">/</span> <code>{found.id}</code></p>
                    </div>
                    <StatusBadge status={found.status} />
                  </header>
                  <SessionDetail session={found} onOpenScreen={openScreen} onTerminate={askDecision.bind(null, "terminate")} />
                  {found.status === "pending_approval" ? (
                    // The Broker's rule (decide): the requester never approves their own request,
                    // and may only withdraw a break-glass one. The page offers what the caller may
                    // do and nothing else; an unknown caller sees both, and the Broker decides.
                    who?.sub && who.sub === found.requestedBy ? (
                      <div className="sessions-live-decision-actions">
                        <p className="ob-hint">{t("sessions.pending.ownRequest")}</p>
                        {found.breakGlass ? (
                          <Button variant="danger" aria-label={t("sessions.pending.withdrawAria", { id: found.id })} onClick={() => askDecision("reject", found)}>{t("sessions.pending.withdraw")}</Button>
                        ) : null}
                      </div>
                    ) : (
                      <div className="sessions-live-decision-actions">
                        <GatedButton capability="sessions.approve" variant="primary" aria-label={t("sessions.pending.approveAria", { id: found.id })} onClick={() => askDecision("approve", found)}>{t("sessions.pending.approve")}</GatedButton>
                        <GatedButton capability="sessions.approve" variant="danger" aria-label={t("sessions.pending.rejectAria", { id: found.id })} onClick={() => askDecision("reject", found)}>{t("sessions.pending.reject")}</GatedButton>
                      </div>
                    )
                  ) : null}
                  {screen ? (
                    <ScreenViewer
                      key={screen.key}
                      attach={screen.attach}
                      onReconnect={() => openScreen(screen.sessionId)}
                      onClose={() => setScreen(undefined)}
                    />
                  ) : null}
                </>
              ) : (
                <div className="sessions-live-empty">
                  <span className="sessions-live-empty-icon"><Search size={20} /></span>
                  <h3 id="sessions-live-detail-title">{t("sessions.live.selectTitle")}</h3>
                  <p>{t("sessions.live.selectDescription")}</p>
                </div>
              )}
            </section>
          </div>

          <Modal
            open={requestFormOpen}
            onOpenChange={setRequestFormOpen}
            title={t("sessions.live.newRequest")}
            description={t("sessions.live.requestModalDescription")}
            className="request-access-dialog"
          >
            <SessionRequest onDone={(session) => {
              setLookup(session.id);
              setFound(session);
              setScreen(undefined);
              setRequestFormOpen(false);
              setOk(session.status === "pending_approval"
                ? t("sessions.request.pendingApproval", { id: session.id, expiresAt: session.expiresAt })
                : t("sessions.request.status", { id: session.id, status: session.status }));
              load();
            }} onCancel={() => setRequestFormOpen(false)} />
          </Modal>
        </TabsContent>
        <TabsContent value="history"><SessionHistory /></TabsContent>
        <TabsContent value="recordings">
          <SessionRecordings onOpenRecording={onOpenRecording ?? setReplaySessionId} />
          {!onOpenRecording && replaySessionId ? (
            <div className="session-recording-replay">
              <RecordingPanel key={replaySessionId} requestedSessionId={replaySessionId} />
            </div>
          ) : null}
        </TabsContent>
        <TabsContent value="alerts"><SessionAlerts /></TabsContent>
      </Tabs>
      {decision ? (
        <ConfirmDialog
          title={
            decision.kind === "approve" ? t("sessions.confirm.approveTitle")
              : decision.kind === "reject" ? t("sessions.confirm.rejectTitle")
                : t("sessions.confirm.terminateTitle")
          }
          description={decision.kind === "terminate"
            ? t("sessions.confirm.terminateBody", { id: decision.session.id })
            : t("sessions.confirm.decideBody", {
              kind: decision.session.breakGlass ? t("sessions.confirm.emergency") : t("sessions.confirm.access"),
              id: decision.session.id,
              requester: decision.session.requestedBy,
              account: decision.session.privilegedAccountId,
              justification: decision.session.justification,
              ticket: decision.session.ticket ?? t("sessions.confirm.none"),
              expiresAt: decision.session.expiresAt,
            })}
          confirmLabel={
            decision.kind === "approve" ? t("sessions.confirm.approve")
              : decision.kind === "reject" ? t("sessions.confirm.reject")
                : t("sessions.confirm.terminate")
          }
          danger={decision.kind !== "approve"}
          error={error instanceof ApiError ? `${error.status} — ${error.message}` : error ? String((error as Error)?.message ?? error) : undefined}
          onCancel={() => setDecision(undefined)}
          onConfirm={confirmDecision}
        />
      ) : null}
    </AdminPage>
  );
}
