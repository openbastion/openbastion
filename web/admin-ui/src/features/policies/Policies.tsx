import { FormEvent, useState } from "react";
import { Notice } from "../../shared/Notice";
import { useSignedIn } from "../../shared/session";

// Creating a policy (POST /policies). Who created it is the Gateway's verified identity, never
// this form. The public API has no list of policies: this page cannot show them.
export function Policies() {
  const { api } = useSignedIn();
  const [f, setF] = useState({ name: "", role: "", resourcePattern: "", effect: "allow" });
  const [error, setError] = useState<unknown>();
  const [ok, setOk] = useState<string>();
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(undefined);
    setOk(undefined);
    try {
      await api.request("POST", "/policies", f);
      setOk(`Politique ${f.name} créée`);
      setF({ name: "", role: "", resourcePattern: "", effect: "allow" });
    } catch (err) {
      setError(err);
    }
  }

  return (
    <section>
      <h2>Politiques</h2>
      <p className="hint">
        Une politique donne à un rôle un motif de ressource : <code>vault:account:&lt;id&gt;</code> pour ouvrir une session,{" "}
        <code>recording:session:*</code> pour relire les enregistrements, <code>breakglass-approve:account:&lt;id&gt;</code> pour décider d'une
        demande d'urgence. L'API publique ne liste pas les politiques.
      </p>
      <form onSubmit={submit} aria-label="Créer une politique">
        <label>Nom<input value={f.name} onChange={set("name")} required /></label>
        <label>Rôle<input value={f.role} onChange={set("role")} required /></label>
        <label>Motif de ressource<input value={f.resourcePattern} onChange={set("resourcePattern")} required /></label>
        <label>
          Effet
          <select value={f.effect} onChange={set("effect")}>
            <option value="allow">autoriser</option>
            <option value="deny">refuser</option>
          </select>
        </label>
        <button type="submit">Créer</button>
      </form>
      <Notice error={error} ok={ok} />
    </section>
  );
}
