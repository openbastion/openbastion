import { FormEvent, useState } from "react";
import { Checkbox, FormField, Label, Select } from "@openbastion/ui";
import { Account, ScreenChannel, ScreenColorDepth, ScreenProfile } from "../../shared/api";
import { Button } from "../../shared/ui/Button";
import { InlineNotice } from "../../shared/ui/InlineNotice";
import { Modal } from "../../shared/ui/Modal";
import { useAppTranslation } from "../../shared/i18n";

export const screenChannels: ScreenChannel[] = ["graphics", "bitmap"];
export const screenColorDepths: ScreenColorDepth[] = [16, 32];

// Without a profile, everything is allowed: graphics and 32 bpp by default (ADR-0132 §1).
export const openScreenProfile: ScreenProfile = { channels: ["graphics", "bitmap"], defaultChannel: "graphics", colorDepths: [16, 32], defaultColorDepth: 32 };

// The checks the Vault makes, made first so the form says what is wrong before it is sent: each
// set non-empty, each default inside its set. The Vault checks again; it is the authority.
export function screenProfileProblem(p: ScreenProfile): "noChannel" | "noDepth" | "defaultChannel" | "defaultDepth" | undefined {
  if (p.channels.length === 0) return "noChannel";
  if (p.colorDepths.length === 0) return "noDepth";
  if (!p.channels.includes(p.defaultChannel)) return "defaultChannel";
  if (!p.colorDepths.includes(p.defaultColorDepth)) return "defaultDepth";
  return undefined;
}

function toggle<T>(values: T[], value: T, on: boolean, order: T[]): T[] {
  const next = on ? [...values, value] : values.filter((v) => v !== value);
  return order.filter((v) => next.includes(v));
}

// The screen profile of an RDP account (ADR-0132), set by its administrator: the channels and the
// depths its operators may choose, and the defaults. "Remove the profile" goes back to everything
// allowed. The screen owns the call; this dialog owns the form.
export function ScreenProfileDialog({
  account,
  error,
  onSave,
  onCancel,
}: {
  account: Account;
  error?: string;
  onSave: (profile: ScreenProfile | null) => Promise<boolean>;
  onCancel: () => void;
}) {
  const { t } = useAppTranslation();
  const [profile, setProfile] = useState<ScreenProfile>(account.screenProfile ?? openScreenProfile);
  const [working, setWorking] = useState(false);
  const problem = screenProfileProblem(profile);

  async function save(value: ScreenProfile | null) {
    setWorking(true);
    try {
      if (await onSave(value)) onCancel();
    } finally {
      setWorking(false);
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!problem) void save(profile);
  }

  return (
    <Modal
      open
      onOpenChange={(open) => { if (!open && !working) onCancel(); }}
      title={t("accounts.screenProfile.title", { id: account.id })}
      description={t("accounts.screenProfile.description")}
      className="screen-profile-dialog"
    >
      <form className="screen-profile-form" onSubmit={submit} aria-label={t("accounts.screenProfile.title", { id: account.id })}>
        <fieldset>
          <legend>{t("accounts.screenProfile.channels")}</legend>
          {screenChannels.map((channel) => (
            <Label className="check" key={channel}>
              <Checkbox
                checked={profile.channels.includes(channel)}
                onChange={(e) => setProfile({ ...profile, channels: toggle(profile.channels, channel, e.target.checked, screenChannels) })}
              />
              {t(`screen.channel.${channel}`)}
            </Label>
          ))}
        </fieldset>
        <FormField id="screen-profile-default-channel" label={t("accounts.screenProfile.defaultChannel")}>
          <Select value={profile.defaultChannel} onChange={(e) => setProfile({ ...profile, defaultChannel: e.target.value as ScreenChannel })}>
            {screenChannels.map((channel) => <option key={channel} value={channel}>{t(`screen.channel.${channel}`)}</option>)}
          </Select>
        </FormField>
        <fieldset>
          <legend>{t("accounts.screenProfile.colorDepths")}</legend>
          {screenColorDepths.map((depth) => (
            <Label className="check" key={depth}>
              <Checkbox
                checked={profile.colorDepths.includes(depth)}
                onChange={(e) => setProfile({ ...profile, colorDepths: toggle(profile.colorDepths, depth, e.target.checked, screenColorDepths) })}
              />
              {t(`screen.depth.d${depth}`)}
            </Label>
          ))}
        </fieldset>
        <FormField id="screen-profile-default-depth" label={t("accounts.screenProfile.defaultColorDepth")}>
          <Select value={String(profile.defaultColorDepth)} onChange={(e) => setProfile({ ...profile, defaultColorDepth: Number(e.target.value) as ScreenColorDepth })}>
            {screenColorDepths.map((depth) => <option key={depth} value={depth}>{t(`screen.depth.d${depth}`)}</option>)}
          </Select>
        </FormField>
        <p className="ob-hint">{t("accounts.screenProfile.hint")}</p>
        {problem ? <InlineNotice tone="warning">{t(`accounts.screenProfile.problems.${problem}`)}</InlineNotice> : null}
        {error ? <InlineNotice tone="danger">{error}</InlineNotice> : null}
        <div className="ob-form-actions">
          <Button type="button" disabled={working} onClick={onCancel}>{t("common.actions.cancel")}</Button>
          {account.screenProfile ? (
            <Button type="button" disabled={working} onClick={() => void save(null)}>{t("accounts.screenProfile.remove")}</Button>
          ) : null}
          <Button type="submit" variant="primary" disabled={working || Boolean(problem)}>
            {working ? t("common.actions.working") : t("accounts.screenProfile.save")}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
