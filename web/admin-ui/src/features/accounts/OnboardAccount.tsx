import { FormEvent, useState } from "react";
import { useSignedIn } from "../../shared/session";
import { FormCard } from "../../shared/ui/FormCard";

// Onboarding one privileged account: the target, how its secret rotates, the identity its target
// must present, and the secret — typed once, sent once, never shown again (the API never returns
// it). A VNC or RDP account has no host key and no rotation; its TLS pin comes next, by its own
// route (ADR-0071).
export function OnboardAccount({ onDone }: { onDone: (id: string) => void }) {
  const { api } = useSignedIn();
  const [f, setF] = useState({
    id: "",
    name: "",
    username: "",
    targetHost: "",
    protocol: "ssh",
    rotationPolicy: "manual",
    initialSecret: "",
    reconciliationAccountId: "",
    hostKey: "",
    rotationIntervalDays: "30",
  });
  const [approvalRequired, setApprovalRequired] = useState(false);
  const [error, setError] = useState<unknown>();
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const ssh = f.protocol === "ssh";

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(undefined);
    try {
      // The API takes the secret as bytes (base64 in JSON); it is never sent anywhere else.
      const bytes = new TextEncoder().encode(f.initialSecret);
      let bin = "";
      bytes.forEach((b) => (bin += String.fromCharCode(b)));
      // Only a scheduled account takes an interval (ADR-0040): the Vault refuses one elsewhere.
      const { rotationIntervalDays, ...rest } = f;
      const schedule = f.rotationPolicy === "scheduled" ? { rotationIntervalDays: Number(rotationIntervalDays) } : {};
      // A VNC or RDP account has no host key and no rotation; its TLS pin comes next, by its own route.
      const shape = ssh ? { ...rest, ...schedule } : { ...rest, rotationPolicy: "manual", reconciliationAccountId: "", hostKey: "" };
      await api.request("POST", "/vault/accounts", { ...shape, approvalRequired, initialSecret: btoa(bin) });
      setF({ ...f, id: "", name: "", initialSecret: "", hostKey: "" });
      onDone(f.id);
    } catch (err) {
      setError(err);
    }
  }

  return (
    <FormCard label="Enregistrer un compte" title="Enregistrer un compte" submitLabel="Enregistrer" onSubmit={submit} error={error}>
      <label>
        Identifiant
        <input value={f.id} onChange={set("id")} required pattern="[A-Za-z0-9_.\-]+" />
      </label>
      <label>
        Nom
        <input value={f.name} onChange={set("name")} required />
      </label>
      <label>
        Cible (hôte:port)
        <input value={f.targetHost} onChange={set("targetHost")} required />
      </label>
      <label>
        Utilisateur sur la cible
        <input value={f.username} onChange={set("username")} required />
      </label>
      <label>
        Protocole
        <select value={f.protocol} onChange={set("protocol")}>
          <option value="ssh">SSH</option>
          <option value="vnc">VNC</option>
          <option value="rdp">RDP</option>
        </select>
      </label>
      {ssh ? (
        <label>
          Rotation
          <select value={f.rotationPolicy} onChange={set("rotationPolicy")}>
            <option value="manual">manuelle</option>
            <option value="post_use">après usage</option>
            <option value="scheduled">planifiée</option>
          </select>
        </label>
      ) : null}
      {ssh && f.rotationPolicy === "scheduled" ? (
        <label>
          Intervalle de rotation (jours, 1 à 365)
          <input type="number" min={1} max={365} value={f.rotationIntervalDays} onChange={set("rotationIntervalDays")} required />
        </label>
      ) : null}
      {ssh ? (
        <label>
          Compte de réconciliation (même cible ; vide : pas de rotation — obligatoire pour une rotation planifiée)
          <input value={f.reconciliationAccountId} onChange={set("reconciliationAccountId")} />
        </label>
      ) : null}
      {ssh ? (
        <label className="wide">
          Clé d'hôte de la cible (relevée sur la cible : /etc/ssh/ssh_host_ed25519_key.pub), ou autorité : @cert-authority &lt;nom&gt; &lt;clé de l'autorité&gt;
          <textarea value={f.hostKey} onChange={set("hostKey")} required rows={2} spellCheck={false} placeholder="ssh-ed25519 AAAA…" />
        </label>
      ) : (
        <p className="ob-hint wide">Une fois le compte enregistré, épinglez le certificat TLS de sa cible : sans lui, le compte n'ouvre aucune session.</p>
      )}
      <label className="check">
        <input type="checkbox" checked={approvalRequired} onChange={(e) => setApprovalRequired(e.target.checked)} />
        Approbation requise : chaque session attend l'accord d'une autre personne, avec un ticket
      </label>
      <label>
        Secret initial
        <input type="password" autoComplete="new-password" value={f.initialSecret} onChange={set("initialSecret")} required />
      </label>
    </FormCard>
  );
}
