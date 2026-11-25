import { useMemo, useState } from "react";
import type { Tab } from "../../app/AppShell";
import { AppCommandPalette } from "@openbastion/ui";
import { ArrowRight } from "@openbastion/icons";
import { useAppTranslation } from "../i18n";
import { useCapabilities } from "../capabilities";
import { tabAllowed } from "../../app/tabAccess";

type Command = {
  id: string;
  label: string;
  detail: string;
  keywords: string;
  run: () => void;
};

// A local command index only: it never enumerates resources or bypasses the Gateway.
export function CommandPalette({
  onClose,
  onNavigate,
  onFindSession,
}: {
  onClose: () => void;
  onNavigate: (tab: Tab) => void;
  onFindSession: (id: string) => void;
}) {
  const { t, i18n } = useAppTranslation();
  const capabilities = useCapabilities();
  const [query, setQuery] = useState("");

  const commands = useMemo<Command[]>(() => {
    const destinations: { tab: Tab; label: string; detail: string; keywords: string }[] = (
      ["overview", "accounts", "sessions", "infrastructure", "security", "posture", "settings"] as const
    ).filter((tab) => tabAllowed(capabilities, tab)).map((tab) => ({
      tab,
      label: t(`palette.destinations.${tab}.label`),
      detail: t(`palette.destinations.${tab}.detail`),
      keywords: t(`palette.destinations.${tab}.keywords`),
    }));
    const normalized = query.trim().toLocaleLowerCase(i18n.language);
    const navigation: Command[] = destinations
      .filter((item) => !normalized || `${item.label} ${item.detail} ${item.keywords}`.toLocaleLowerCase(i18n.language).includes(normalized))
      .map((item) => ({
        id: item.tab,
        label: item.label,
        detail: item.detail,
        keywords: item.keywords,
        run: () => onNavigate(item.tab),
      }));
    if (query.trim()) {
      navigation.push({
        id: "find-session",
        label: t("palette.findSession.label", { query: query.trim() }),
        detail: t("palette.findSession.detail"),
        keywords: t("palette.findSession.keywords"),
        run: () => onFindSession(query.trim()),
      });
    }
    return navigation;
  }, [capabilities, i18n.language, onFindSession, onNavigate, query, t]);

  return (
    <AppCommandPalette
      commands={commands}
      query={query}
      onQueryChange={setQuery}
      onClose={onClose}
      optionIcon={<ArrowRight className="command-enter" size={15} />}
      labels={{
        title: t("palette.title"),
        query: t("palette.queryLabel"),
        placeholder: t("palette.placeholder"),
        results: t("palette.results"),
        empty: t("palette.empty"),
        navigateHint: t("palette.footer.navigate"),
        selectHint: t("palette.footer.select"),
        closeHint: t("palette.footer.close"),
        closeButton: t("palette.footer.closeButton"),
      }}
    />
  );
}
