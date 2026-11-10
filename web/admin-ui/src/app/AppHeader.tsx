import { Audit, Policies as PoliciesIcon, Session, Users } from "@openbastion/icons";
import { TokenClaims } from "../shared/api";
import { BrandMark } from "../shared/BrandMark";

const tabs = {
  accounts: { label: "Comptes", icon: Users },
  policies: { label: "Politiques", icon: PoliciesIcon },
  sessions: { label: "Sessions", icon: Session },
  audit: { label: "Enregistrements", icon: Audit },
} as const;

export type Tab = keyof typeof tabs;

// The header of every signed-in screen: the brand, the sections, and who is signed in. The token
// is the Gateway's; the name and the roles here are read from it for display only.
export function AppHeader({
  who,
  tab,
  onTab,
  onSignOut,
}: {
  who: TokenClaims | null;
  tab: Tab;
  onTab: (tab: Tab) => void;
  onSignOut: () => void;
}) {
  const initials = who?.username ? who.username.replace(/^oidc:/, "").slice(0, 2).toUpperCase() : "?";
  return (
    <header className="app-header">
      <div className="brand">
        <BrandMark />
        <span className="brand-name">OpenBastion</span>
        <span className="brand-tag">Admin</span>
      </div>
      <nav aria-label="Sections">
        {(Object.keys(tabs) as Tab[]).map((t) => {
          const Icon = tabs[t].icon;
          return (
            <button type="button" key={t} aria-current={tab === t ? "page" : undefined} onClick={() => onTab(t)}>
              <Icon size={16} />
              {tabs[t].label}
            </button>
          );
        })}
      </nav>
      <div className="session-chip">
        <span className="avatar" aria-hidden="true">
          {initials}
        </span>
        <span className="who">
          {who?.username} {who?.roles.length ? `(${who.roles.join(", ")})` : ""}
        </span>
        <button type="button" className="ghost" onClick={onSignOut}>
          Se déconnecter
        </button>
      </div>
    </header>
  );
}
