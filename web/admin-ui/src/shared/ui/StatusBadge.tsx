const labels: Record<string, string> = {
  pending_approval: "En attente",
  active: "Active",
  terminated: "Terminée",
  expired: "Expirée",
  denied: "Refusée",
};

const tones: Record<string, string> = {
  pending_approval: "pending",
  active: "active",
  terminated: "muted",
  expired: "muted",
  denied: "danger",
};

// Known Broker states are translated; unknown future states remain visible verbatim and neutral.
export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`badge status-badge status-${tones[status] ?? "unknown"}`}>
      {labels[status] ?? status}
    </span>
  );
}
