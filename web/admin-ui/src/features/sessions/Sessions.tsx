import { FormEvent, useCallback, useEffect, useState } from "react";
import { Page, Session, sessionPath } from "../../shared/api";
import { Notice } from "../../shared/Notice";
import { useSignedIn } from "../../shared/session";
import { AdminPage } from "../../shared/ui/AdminPage";
import { ScreenViewer } from "../screen/ScreenViewer";
import { AttachedScreen, SessionDetail } from "./SessionDetail";
import { PendingRequests } from "./PendingRequests";
import { SessionRequest } from "./SessionRequest";

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
  const [error, setError] = useState<unknown>();
  const [ok, setOk] = useState<string>();
  const [lookup, setLookup] = useState("");
  const [found, setFound] = useState<Session>();
  const [screen, setScreen] = useState<AttachedScreen>();

  const load = useCallback(() => {
    api.request<Page<Session>>("GET", "/sessions?status=pending_approval").then(setPending, setError);
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

  function terminate(s: Session) {
    if (window.confirm(`Mettre fin à ${s.id} ?`)) act(`${s.id} terminée`, () => api.request("DELETE", sessionPath(s.id)));
  }

  return (
    <AdminPage title="Sessions">
      <Notice error={error} ok={ok} />
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
        onApprove={(s) => act(`${s.id} approuvée`, () => api.request("POST", `${sessionPath(s.id)}/approve`))}
        onReject={(s) => act(`${s.id} refusée`, () => api.request("POST", `${sessionPath(s.id)}/reject`))}
      />
      <div className="card panel">
        <h3>Une session</h3>
        <form onSubmit={find} aria-label="Chercher une session">
          <div className="fields">
            <label>
              Identifiant
              <input id="session-lookup" value={lookup} onChange={(e) => setLookup(e.target.value)} required />
            </label>
          </div>
          <div className="form-actions">
            <button type="submit" className="primary">
              Afficher
            </button>
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
      </div>
    </AdminPage>
  );
}
