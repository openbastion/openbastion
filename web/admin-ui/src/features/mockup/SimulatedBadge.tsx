import { Badge } from "@openbastion/ui";
import { useAppTranslation } from "../../shared/i18n";

// ADR-0142: every surface fed by simulatedData says so, visibly, next to its title.
export function SimulatedBadge() {
  const { t } = useAppTranslation();
  return <Badge tone="warning" className="simulated-badge" title={t("simulated.badgeTitle")}>{t("simulated.badge")}</Badge>;
}
