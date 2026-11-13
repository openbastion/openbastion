import { Badge, type BadgeTone } from "./Badge";

import { useAppTranslation } from "../i18n";

const tones: Record<string, BadgeTone> = {
  pending_approval: "warning",
  active: "success",
  terminated: "neutral",
  expired: "neutral",
  denied: "danger",
};

// Known Broker states are translated; unknown future states remain visible verbatim and neutral.
export function StatusBadge({ status }: { status: string }) {
  const { t } = useAppTranslation();
  const known = status in tones;
  return <Badge tone={tones[status] ?? "neutral"}>{known ? t(`common.status.${status}`) : status}</Badge>;
}
