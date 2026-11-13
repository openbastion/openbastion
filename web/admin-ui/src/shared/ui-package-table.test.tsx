import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@openbastion/ui";

describe("@openbastion/ui table primitives", () => {
  it("preserves native table semantics, headers and caption", () => {
    render(<Table aria-label="Comptes privilégiés"><TableCaption>Comptes actuellement chargés</TableCaption><TableHeader><TableRow><TableHead>Compte</TableHead><TableHead>État</TableHead></TableRow></TableHeader><TableBody><TableRow><TableCell>svc-linux</TableCell><TableCell>Actif</TableCell></TableRow></TableBody></Table>);
    expect(screen.getByRole("table", { name: "Comptes privilégiés" })).not.toBeNull();
    expect(screen.getByRole("columnheader", { name: "Compte" })).not.toBeNull();
    expect(screen.getByRole("cell", { name: "svc-linux" })).not.toBeNull();
    expect(screen.getByText("Comptes actuellement chargés")).not.toBeNull();
  });
});
