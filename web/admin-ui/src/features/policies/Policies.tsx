import { FormEvent, useState } from "react";
import { FormField, Input, Select } from "@openbastion/ui";
import { useSignedIn } from "../../shared/session";
import { FormCard } from "../../shared/ui/FormCard";
import { useAppTranslation } from "../../shared/i18n";

// Creating a policy (POST /policies). Who created it is the Gateway's verified identity, never
// this form. The public API has no list of policies: the form cannot show them.
//
// The policy screen lives in the "Politiques" tab of Privileged access, so it renders the form
// alone; the surrounding tab carries the heading and the resource patterns it accepts.
export function PolicyForm() {
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
    <FormCard
      label={t("policies.form.label")}
      title={t("policies.form.title")}
      submitLabel={t("policies.form.submit")}
      onSubmit={submit}
      error={error}
      ok={ok}
    >
      <FormField id="policy-name" label={t("policies.form.name")} required>
        <Input value={f.name} onChange={set("name")} />
      </FormField>
      <FormField id="policy-role" label={t("policies.form.role")} required>
        <Input value={f.role} onChange={set("role")} />
      </FormField>
      <FormField id="policy-resource" label={t("policies.form.resourcePattern")} required>
        <Input value={f.resourcePattern} onChange={set("resourcePattern")} />
      </FormField>
      <FormField id="policy-effect" label={t("policies.form.effect")}>
        <Select value={f.effect} onChange={set("effect")}>
          <option value="allow">{t("policies.form.allow")}</option>
          <option value="deny">{t("policies.form.deny")}</option>
        </Select>
      </FormField>
    </FormCard>
  );
}
