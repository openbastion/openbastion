import { useState } from "react";
import {
  AppConfirmDialog, Badge, Button, Dialog, DialogContent, DialogDescription, DialogTitle,
  Sheet, SheetContent, SheetDescription, SheetTitle,
} from "@openbastion/ui";
import { useAppTranslation } from "../../shared/i18n";
import { simulatedSessions, type SimulatedSession, type TakeOverMode } from "./simulatedData";
import { SimulatedBadge } from "./SimulatedBadge";

const targets = ["srv-db-01", "win-app-02", "vnc-target"] as const;

// The mockup's live-session table, take-over, administrative session and inspection drawer.
// All state is local and lost on reload: nothing is sent anywhere (ADR-0142).
export function SimulatedSessions() {
  const { t } = useAppTranslation();
  const [sessions, setSessions] = useState<SimulatedSession[]>(simulatedSessions);
  const [inspected, setInspected] = useState<string>();
  const [takeOver, setTakeOver] = useState<{ id: string; mode: TakeOverMode }>();
  const [launchOpen, setLaunchOpen] = useState(false);
  const [launchTarget, setLaunchTarget] = useState<string>(targets[0]);
  const current = sessions.find((s) => s.id === inspected);

  function launch() {
    const id = `sim_${Math.random().toString(16).slice(2, 8)}`;
    setSessions((all) => [...all, { id, user: "admin.operator", target: launchTarget, protocol: "SSH", duration: "00:00:00", rttMs: 30, fps: null, state: "active", origin: "admin", commands: [] }]);
    setLaunchOpen(false);
    setInspected(id);
  }

  return (
    <section className="simulated-panel" aria-labelledby="simulated-sessions-title">
      <header className="simulated-panel-heading">
        <div>
          <h3 id="simulated-sessions-title">{t("simulated.sessions.title")}</h3>
          <p className="simulated-panel-note">{t("simulated.sessions.note")}</p>
        </div>
        <div className="simulated-panel-actions">
          <SimulatedBadge />
          <Button variant="primary" onClick={() => setLaunchOpen(true)}>{t("simulated.sessions.admin")}</Button>
        </div>
      </header>

      <div className="ob-table-wrap reference-table-wrap">
        <table className="ob-data-table reference-table simulated-sessions-table">
          <caption className="ob-visually-hidden">{t("simulated.sessions.title")}</caption>
          <thead>
            <tr>
              {["session", "user", "target", "duration", "rtt", "state", "actions"].map((key) => (
                <th scope="col" key={key}>{t(`simulated.sessions.columns.${key}`)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr key={s.id}>
                <td><code>{s.id}</code>{s.origin === "admin" ? <Badge tone="success" className="simulated-origin">{t("simulated.sessions.adminOrigin")}</Badge> : null}</td>
                <td><code>{s.user}</code></td>
                <td><code>{s.target}</code> <span className="simulated-muted">({s.protocol})</span></td>
                <td><code>{s.duration}</code></td>
                <td><code>{s.rttMs} ms{s.fps === null ? "" : ` · ${s.fps} fps`}</code></td>
                <td><Badge>{t(`simulated.sessions.states.${s.state}`)}{s.takeOver ? ` · ${t(`simulated.takeOver.modes.${s.takeOver}`)}` : ""}</Badge></td>
                <td className="ob-table-actions">
                  {(["shared", "exclusive"] as const).map((mode) => (
                    <Button key={mode} variant="secondary" aria-label={t("simulated.takeOver.openAria", { id: s.id, mode: t(`simulated.takeOver.modes.${mode}`) })} onClick={() => setTakeOver({ id: s.id, mode })}>{t(`simulated.takeOver.modes.${mode}`)}</Button>
                  ))}
                  <Button variant="primary" aria-label={t("simulated.inspect.openAria", { id: s.id })} onClick={() => setInspected(s.id)}>{t("simulated.inspect.action")}</Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Sheet open={Boolean(current)} onOpenChange={(open) => { if (!open) setInspected(undefined); }}>
        {current ? (
          <SheetContent className="simulated-drawer">
            <SheetTitle>{t("simulated.inspect.title", { id: current.id })}</SheetTitle>
            <SheetDescription>{t("simulated.inspect.description")}</SheetDescription>
            <SimulatedBadge />
            <div className="simulated-stream" role="img" aria-label={t("simulated.inspect.streamAria")}>
              <span>{current.protocol} · {current.target}</span>
            </div>
            <dl className="simulated-drawer-facts">
              <div><dt>{t("simulated.sessions.columns.user")}</dt><dd><code>{current.user}</code></dd></div>
              <div><dt>{t("simulated.sessions.columns.rtt")}</dt><dd><code>{current.rttMs} ms{current.fps === null ? "" : ` · ${current.fps} fps`}</code></dd></div>
              <div><dt>{t("simulated.sessions.columns.duration")}</dt><dd><code>{current.duration}</code></dd></div>
            </dl>
            <h4>{t("simulated.inspect.activity")}</h4>
            {current.commands.length === 0 ? <p className="simulated-muted">{t("simulated.inspect.noActivity")}</p> : (
              <ol className="simulated-activity">
                {current.commands.map((c) => <li key={c.at}><time>{c.at}</time> <code>{c.text}</code></li>)}
              </ol>
            )}
          </SheetContent>
        ) : null}
      </Sheet>

      {takeOver ? (
        <AppConfirmDialog
          title={t("simulated.takeOver.title", { id: takeOver.id })}
          description={t(`simulated.takeOver.modes.${takeOver.mode}Detail`)}
          confirmLabel={t("simulated.takeOver.confirm")}
          cancelLabel={t("common.actions.cancel")}
          workingLabel={t("common.actions.working")}
          danger={takeOver.mode === "exclusive"}
          onCancel={() => setTakeOver(undefined)}
          onConfirm={async () => {
            setSessions((all) => all.map((s) => (s.id === takeOver.id ? { ...s, state: "takeover", takeOver: takeOver.mode } : s)));
            setTakeOver(undefined);
            return true;
          }}
        />
      ) : null}

      <Dialog open={launchOpen} onOpenChange={setLaunchOpen}>
        <DialogContent>
          <DialogTitle>{t("simulated.sessions.admin")}</DialogTitle>
          <DialogDescription>{t("simulated.sessions.adminDescription")}</DialogDescription>
          <label htmlFor="simulated-launch-target">{t("simulated.sessions.columns.target")}</label>
          <select id="simulated-launch-target" value={launchTarget} onChange={(e) => setLaunchTarget(e.target.value)}>
            {targets.map((target) => <option key={target} value={target}>{target}</option>)}
          </select>
          <div className="simulated-dialog-actions">
            <Button variant="secondary" onClick={() => setLaunchOpen(false)}>{t("common.actions.cancel")}</Button>
            <Button variant="primary" onClick={launch}>{t("simulated.sessions.launch")}</Button>
          </div>
        </DialogContent>
      </Dialog>
    </section>
  );
}
