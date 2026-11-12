import { describe, expect, it } from "vitest";
import { Account } from "./api";
import { AccountFilterRule } from "./savedAccountViews";
import {
  matchesAccountFilterRules,
  parseSavedAccountViews,
} from "./savedAccountViews";

const ssh: Account = {
  id: "acc_ssh", name: "SSH", username: "svc", targetHost: "ssh.internal:22",
  protocol: "ssh", rotationPolicy: "manual", createdAt: "2026-11-01T00:00:00Z",
  hostKeyFingerprint: "SHA256:pinned", approvalRequired: true,
};
const vnc: Account = {
  id: "acc_vnc", name: "VNC", username: "svc", targetHost: "vnc.internal:5900",
  protocol: "vnc", rotationPolicy: "manual", createdAt: "2026-11-01T00:00:00Z",
  tlsCertificateSha256: "AA:BB", approvalRequired: false,
};

describe("account filter rule evaluation", () => {
  it("combines rules with AND and OR from left to right", () => {
    const rules: AccountFilterRule[] = [
      { field: "protocol", comparison: "is", value: "ssh", join: "AND" },
      { field: "approval", comparison: "is", value: "not-required", join: "AND" },
    ];
    expect(matchesAccountFilterRules(ssh, [...rules])).toBe(false);
    expect(matchesAccountFilterRules(vnc, [...rules])).toBe(false);

    const disjunction = [...rules];
    disjunction[1] = { ...disjunction[1], join: "OR" };
    expect(matchesAccountFilterRules(ssh, disjunction)).toBe(true);
    expect(matchesAccountFilterRules(vnc, disjunction)).toBe(true);
  });

  it("supports negative comparisons and field-specific values", () => {
    expect(matchesAccountFilterRules(vnc, [
      { field: "protocol", comparison: "is-not", value: "ssh", join: "AND" },
    ])).toBe(true);
    expect(matchesAccountFilterRules(ssh, [
      { field: "identity", comparison: "is", value: "pinned", join: "AND" },
    ])).toBe(true);
    expect(matchesAccountFilterRules(vnc, [
      { field: "rotation", comparison: "is", value: "none", join: "AND" },
    ])).toBe(true);
  });

  it("migrates existing version-one saved categorical views", () => {
    expect(parseSavedAccountViews([{
      name: "Vue historique",
      filters: { protocol: "ssh", approval: "required", identity: "all", rotation: "all" },
    }])).toEqual([{
      name: "Vue historique",
      rules: [
        { field: "protocol", comparison: "is", value: "ssh", join: "AND" },
        { field: "approval", comparison: "is", value: "required", join: "AND" },
      ],
    }]);
  });

  it("limits rules to the four available fields and rejects duplicate fields", () => {
    const four: AccountFilterRule[] = [
      { field: "protocol", comparison: "is", value: "ssh", join: "AND" },
      { field: "approval", comparison: "is", value: "required", join: "OR" },
      { field: "identity", comparison: "is", value: "pinned", join: "AND" },
      { field: "rotation", comparison: "is", value: "due", join: "OR" },
    ];
    expect(matchesAccountFilterRules(ssh, four)).toBe(true);
    expect(parseSavedAccountViews([{ name: "Quatre champs", rules: four }])).toHaveLength(1);
    expect(parseSavedAccountViews([{ name: "Trop de règles", rules: [...four, four[0]] }])).toEqual([]);
    expect(parseSavedAccountViews([{ name: "Champ dupliqué", rules: [four[0], { ...four[0], value: "rdp" }] }])).toEqual([]);
  });

  it("rejects malformed or unsupported saved filter values", () => {
    expect(parseSavedAccountViews([{
      name: "Valeur invalide",
      rules: [{ field: "protocol", comparison: "is", value: "telnet", join: "OR" }],
    }])).toEqual([]);
  });
});
