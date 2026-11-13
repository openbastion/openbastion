import { FormEvent, useCallback, useEffect, useState } from "react";
import { ApiError, Page, Session, sessionPath } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { useSignedIn } from "../../shared/session";
import { AdminPage } from "../../shared/ui/AdminPage";
import { ScreenViewer } from "../screen/ScreenViewer";
import { AttachedScreen, SessionDetail } from "./SessionDetail";
import { PendingRequests } from "./PendingRequests";
import { ConfirmDialog } from "../../shared/ui/ConfirmDialog";
import { SessionRequest } from "./SessionRequest";
import { Button } from "../../shared/ui/Button";

// A session request — with the ticket an account that requires approval asks for (ADR-0067) —,
// the requests waiting for this user's decision (break-glass, ADR-0012, and approval, ADR-0067),
// and a session by its identifier.
export function Sessions({
  requestedSessionId,
  onSessionLookupComplete,
}: {
  requestedSessionId?: string | null;
  onSessionLookupComplete?: () => void;
} = {}) {
  const { api } = useSignedIn();
  const [pending, setPending] = useState<Page<Session>>();
  const [pendingLoading, setPendingLoading] = useState(true);
  const [decision, setDecision] = useState<{ kind: "approve" | "reject" | "terminate"; session: Session }>();
  const [error, setError] = useState<unknown>();
  const [ok, setOk] = useState<string>();
  const [lookup, setLookup] = useState("");
  const [found, setFound] = useState<Session>();
  const [screen, setScreen] = useState<AttachedScreen>();

  const load = useCallback(() => {
    setPendingLoading(true);
    api.request<Page<Session>>("GET", "/sessions?status=pending_approval")
      .then((result) => { setPending(result); setError(undefined); })
      .catch(setError)
      .finally(() => setPendingLoading(false));
  }, [api]);
  useEffect(load, [load]);

  const findById = useCallback(async (id: string) => {
    setLookup(id);
    setFound(undefined);
    setError(undefined);
    try {
      setFound(await api.request<Session>("GET", sessionPath(id)));
    } catch (err) {
      setError(err);
    }
  }, [api]);

  useEffect(() => {
    if (!requestedSessionId) return;
    void findById(requestedSessionId);
    onSessionLookupComplete?.();
  }, [findById, onSessionLookupComplete, requestedSessionId]);

  async function act(what: string, run: () => Promise<unknown>) {
    setError(undefined);
    setOk(undefined);
    try {
      await run();
      setOk(what);
      load();
    } catch (err) {
      setError(err);
    }
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

  function terminate(s: Session) {
    askDecision("terminate", s);
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
      setOk(kind === "approve" ? `${session.id} approuvée` : kind === "reject" ? `${session.id} refusée` : `${session.id} terminée`);
      setDecision(undefined);
      load();
      return true;
    } catch (err) {
      setError(err);
      return false;
    }
  }

  return (
    <AdminPage title="Sessions">
      <Notice error={decision ? undefined : error} ok={decision ? undefined : ok} />
      <SessionRequest
        onDone={(s) => {
          setLookup(s.id);
          setFound(s);
          setScreen(undefined);
          act(
            s.status === "pending_approval" ? `${s.id} en attente de l'approbation d'une autre personne, jusqu'à ${s.expiresAt}` : `${s.id} ${s.status}`,
            async () => undefined,
          );
        }}
      />
      <PendingRequests
        pending={pending}
        loading={pendingLoading}
        onApprove={(s) => askDecision("approve", s)}
        onReject={(s) => askDecision("reject", s)}
      />
      <section className="ob-surface ob-panel session-lookup" aria-labelledby="session-lookup-title">
        <h3 id="session-lookup-title">Une session</h3>
        <form onSubmit={find} aria-label="Chercher une session">
          <div className="ob-form-fields">
            <label>
              Identifiant
              <input id="session-lookup" value={lookup} onChange={(e) => setLookup(e.target.value)} required />
            </label>
          </div>
          <div className="ob-form-actions">
            <Button type="submit" variant="primary">Afficher</Button>
          </div>
        </form>
        {found ? <SessionDetail session={found} onOpenScreen={openScreen} onTerminate={terminate} /> : null}
        {screen ? (
          <ScreenViewer
            key={screen.key}
            attach={screen.attach}
            onReconnect={() => openScreen(screen.sessionId)}
            onClose={() => setScreen(undefined)}
          />
        ) : null}
      </section>
      {decision ? (
        <ConfirmDialog
          title={decision.kind === "approve" ? "Approuver cette demande ?" : decision.kind === "reject" ? "Refuser cette demande ?" : "Mettre fin à cette session ?"}
          description={decision.kind === "terminate"
            ? `La session ${decision.session.id} sera révoquée sur le proxy. Les connexions actives seront coupées ; l'opération n'est confirmée qu'après la réponse du proxy.`
            : `${decision.session.breakGlass ? "Demande d'urgence" : "Demande d'accès"} ${decision.session.id}, formulée par ${decision.session.requestedBy} pour ${decision.session.privilegedAccountId}. Justification : ${decision.session.justification}. Ticket : ${decision.session.ticket ?? "aucun"}. Échéance : ${decision.session.expiresAt}.`}
          confirmLabel={decision.kind === "approve" ? "Confirmer l'approbation" : decision.kind === "reject" ? "Confirmer le refus" : "Mettre fin à la session"}
          danger={decision.kind !== "approve"}
          error={error instanceof ApiError ? `${error.status} — ${error.message}` : error ? String((error as Error)?.message ?? error) : undefined}
          onCancel={() => setDecision(undefined)}
          onConfirm={confirmDecision}
        />
      ) : null}
    </AdminPage>
  );
}
