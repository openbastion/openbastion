import { Badge, type BadgeTone } from "./Badge";

const labels: Record<string, string> = {
  pending_approval: "En attente",
  active: "Active",
  terminated: "Terminée",
  expired: "Expirée",
  denied: "Refusée",
};

const tones: Record<string, BadgeTone> = {
  pending_approval: "warning",
  active: "success",
  terminated: "neutral",
  expired: "neutral",
  denied: "danger",
};

// Known Broker states are translated; unknown future states remain visible verbatim and neutral.
export function StatusBadge({ status }: { status: string }) {
  return <Badge tone={tones[status] ?? "neutral"}>{labels[status] ?? status}</Badge>;
}
