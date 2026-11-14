import { FormEvent, useState } from "react";
import { useSignedIn } from "../../shared/session";
import { AdminPage } from "../../shared/ui/AdminPage";
import { FormCard } from "../../shared/ui/FormCard";
import { useAppTranslation } from "../../shared/i18n";

// Creating a policy (POST /policies). Who created it is the Gateway's verified identity, never
// this form. The public API has no list of policies: this page cannot show them.
export function Policies() {
  const { t } = useAppTranslation();
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
      setOk(t("policies.created", { name }));
      setF({ name: "", role: "", resourcePattern: "", effect: "allow" });
    } catch (err) {
      setError(err);
    }
  }

  return (
    <AdminPage
      title={t("policies.title")}
      hints={[
        <>
          {t("policies.prefix")} <code>vault:account:&lt;id&gt;</code> {t("policies.session")}{" "}
          <code>recording:session:*</code> {t("policies.recording")} <code>breakglass-approve:account:&lt;id&gt;</code>{" "}
          {t("policies.breakglass")}
        </>,
      ]}
    >
      <FormCard
        label={t("policies.form.label")}
        title={t("policies.form.title")}
        submitLabel={t("policies.form.submit")}
        onSubmit={submit}
        error={error}
        ok={ok}
      >
        <label>
          {t("policies.form.name")}
          <input value={f.name} onChange={set("name")} required />
        </label>
        <label>
          {t("policies.form.role")}
          <input value={f.role} onChange={set("role")} required />
        </label>
        <label>
          {t("policies.form.resourcePattern")}
          <input value={f.resourcePattern} onChange={set("resourcePattern")} required />
        </label>
        <label>
          {t("policies.form.effect")}
          <select value={f.effect} onChange={set("effect")}>
            <option value="allow">{t("policies.form.allow")}</option>
            <option value="deny">{t("policies.form.deny")}</option>
          </select>
        </label>
      </FormCard>
    </AdminPage>
  );
}
