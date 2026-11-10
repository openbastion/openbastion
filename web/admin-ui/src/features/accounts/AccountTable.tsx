import { Account } from "../../shared/api";

// What a row can ask of its account. The screen owns the calls and the notices; the table only
// says which account each button names.
export interface AccountActions {
  pinKey: (account: Account) => void;
  pinTls: (account: Account) => void;
  toggleApproval: (account: Account) => void;
  rotate: (account: Account) => void;
  disable: (account: Account) => void;
}

export function AccountTable({ accounts, actions }: { accounts: Account[]; actions: AccountActions }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Identifiant</th>
            <th>Nom</th>
            <th>Cible</th>
            <th>Utilisateur</th>
            <th>Identité de la cible</th>
            <th>Rotation</th>
            <th>Dernière rotation</th>
            <th>Approbation</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {accounts.map((a) => (
            <tr key={a.id}>
              <td>
                <code>{a.id}</code>
              </td>
              <td>{a.name}</td>
              <td>{a.targetHost}</td>
              <td>{a.username}</td>
              <td>
                <TargetIdentity account={a} />
              </td>
              <td>
                <Rotation account={a} />
              </td>
              <td>{a.lastRotatedAt ?? "—"}</td>
              <td>{a.approvalRequired ? <span className="badge">requise</span> : "—"}</td>
              <td className="actions">
                {a.protocol === "ssh" ? (
                  <button type="button" onClick={() => actions.pinKey(a)}>
                    {a.hostKeyFingerprint ? "Changer la clé d'hôte" : "Épingler la clé d'hôte"}
                  </button>
                ) : (
                  <button type="button" onClick={() => actions.pinTls(a)}>
                    {a.tlsCertificateSha256 ? "Changer le certificat TLS" : "Épingler le certificat TLS"}
                  </button>
                )}
                <button type="button" onClick={() => actions.toggleApproval(a)}>
                  {a.approvalRequired ? "Ne plus exiger l'approbation" : "Exiger l'approbation"}
                </button>
                {a.protocol === "ssh" ? (
                  <button type="button" onClick={() => actions.rotate(a)}>
                    Renouveler le secret
                  </button>
                ) : null}
                <button type="button" className="danger" onClick={() => actions.disable(a)}>
                  Désactiver
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// The pinned identity of the target: a host key for SSH (ADR-0039), a TLS certificate for a
// graphical target (ADR-0071). An account without one opens no session.
function TargetIdentity({ account: a }: { account: Account }) {
  if (a.protocol === "ssh") {
    return a.hostKeyFingerprint ? <code title={a.hostKey}>{a.hostKeyFingerprint}</code> : <span className="badge warn">non épinglée</span>;
  }
  return a.tlsCertificateSha256 ? <code title={a.targetDomain}>{a.tlsCertificateSha256}</code> : <span className="badge warn">non épinglée</span>;
}

// The rotation a secret is under, and what the Vault reports about it: a cadence (ADR-0040), a
// rotation owed after a session (ADR-0044), and scheduled rotations that keep failing (ADR-0041).
function Rotation({ account: a }: { account: Account }) {
  return (
    <>
      <span className="badge">{a.rotationPolicy}</span>
      {a.rotationIntervalDays ? (
        <span className="cell-note">
          tous les {a.rotationIntervalDays} j — prochaine : {a.nextRotationAt ?? "—"}
        </span>
      ) : null}
      {a.rotationOwedSince ? (
        <span
          className="badge warn"
          title={`Une session s'est terminée le ${a.rotationOwedSince} : le Vault fait tourner ce secret, et réessaie tant qu'il n'y arrive pas.`}
        >
          renouvellement dû
        </span>
      ) : null}
      {a.rotationFailures ? (
        <span
          className="badge warn"
          title="Rotations planifiées échouées d'affilée : le secret n'a pas changé. Voir le journal du Vault."
        >
          en échec ({a.rotationFailures})
        </span>
      ) : null}
    </>
  );
}
