import { FormEvent, useState } from "react";
import { useSignedIn } from "../../shared/session";
import { AdminPage } from "../../shared/ui/AdminPage";
import { FormCard } from "../../shared/ui/FormCard";

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
      const name = f.name;
      await api.request("POST", "/policies", f);
      setOk(`Politique ${name} créée`);
      setF({ name: "", role: "", resourcePattern: "", effect: "allow" });
    } catch (err) {
      setError(err);
    }
  }

  return (
    <AdminPage
      title="Politiques"
      hints={[
        <>
          Une politique donne à un rôle un motif de ressource : <code>vault:account:&lt;id&gt;</code> pour ouvrir une session,{" "}
          <code>recording:session:*</code> pour relire les enregistrements, <code>breakglass-approve:account:&lt;id&gt;</code> pour décider d'une
          demande d'urgence. L'API publique ne liste pas les politiques.
        </>,
      ]}
    >
      <FormCard label="Créer une politique" title="Nouvelle politique" submitLabel="Créer" onSubmit={submit} error={error} ok={ok}>
        <label>
          Nom
          <input value={f.name} onChange={set("name")} required />
        </label>
        <label>
          Rôle
          <input value={f.role} onChange={set("role")} required />
        </label>
        <label>
          Motif de ressource
          <input value={f.resourcePattern} onChange={set("resourcePattern")} required />
        </label>
        <label>
          Effet
          <select value={f.effect} onChange={set("effect")}>
            <option value="allow">autoriser</option>
            <option value="deny">refuser</option>
          </select>
        </label>
      </FormCard>
    </AdminPage>
  );
}
