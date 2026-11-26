// SIMULATED DATA — ADR-0142. The public API exposes none of this: no live-session feed, no
// transport metrics (RTT/FPS), no take-over, no administrative session, no stream inspection and
// no structured audit read. These fixtures let the interface of the admin UI mockup be reviewed
// before those contracts exist. They are static, never sent to the API, never stored, and every
// surface that shows them carries the "Données simulées" badge. Remove this folder, and the three
// places that mount it (Sessions live tab, Audit journal tab), when a real contract replaces it.

export type SimulatedProtocol = "SSH" | "RDP" | "VNC";
export type TakeOverMode = "shared" | "exclusive";

export interface SimulatedSession {
  id: string;
  user: string;
  target: string;
  protocol: SimulatedProtocol;
  duration: string;
  rttMs: number;
  fps: number | null; // SSH has no frames
  state: "active" | "takeover";
  takeOver?: TakeOverMode;
  origin: "user" | "admin";
  commands: { at: string; text: string }[];
}

export const simulatedSessions: SimulatedSession[] = [
  {
    id: "sim_8f21c0", user: "camille.martin", target: "srv-db-01", protocol: "SSH", duration: "00:42:18", rttMs: 24, fps: null,
    state: "active", origin: "user",
    commands: [{ at: "14:02:11", text: "sudo systemctl status postgresql" }, { at: "14:03:40", text: "psql -c 'select count(*) from audit_log'" }],
  },
  {
    id: "sim_a93d77", user: "nora.benali", target: "win-app-02", protocol: "RDP", duration: "00:11:05", rttMs: 58, fps: 24,
    state: "active", origin: "user",
    commands: [{ at: "14:31:02", text: "Ouverture de eventvwr.msc" }],
  },
  {
    id: "sim_c4e5b1", user: "admin.operator", target: "vnc-target", protocol: "VNC", duration: "00:03:52", rttMs: 91, fps: 15,
    state: "active", origin: "admin", commands: [],
  },
];

export interface SimulatedAuditEvent {
  id: string;
  eventType: string;
  timestamp: string; // UTC ISO 8601
  actor: string;
  target: string;
  outcome: "success" | "denied";
  details: Record<string, string | number>;
}

export const simulatedAuditEvents: SimulatedAuditEvent[] = [
  { id: "sim_ev1", eventType: "session.started", timestamp: "2026-11-26T14:02:11Z", actor: "camille.martin", target: "srv-db-01", outcome: "success", details: { protocol: "SSH", recorded: "true" } },
  { id: "sim_ev2", eventType: "session.takeover.requested", timestamp: "2026-11-26T14:20:45Z", actor: "admin.operator", target: "sim_a93d77", outcome: "success", details: { mode: "shared" } },
  { id: "sim_ev3", eventType: "secret.injection.denied", timestamp: "2026-11-26T14:31:09Z", actor: "nora.benali", target: "win-app-02", outcome: "denied", details: { reason: "policy" } },
];
