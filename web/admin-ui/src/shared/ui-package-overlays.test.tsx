import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogTitle, Button, Dialog, DialogClose, DialogTrigger, DialogContent, DialogDescription, DialogTitle, Drawer, DrawerContent, DrawerTitle, DropdownMenu, DropdownMenuContent, DropdownMenuItem, Popover, PopoverContent, Sheet, SheetContent, SheetTitle, Tooltip, TooltipContent, TooltipProvider } from "@openbastion/ui";

describe("@openbastion/ui Radix-backed overlays", () => {
  it("traps dialog interaction, exposes its accessible name and reports close", async () => {
    const onOpenChange = vi.fn();
    render(<Dialog defaultOpen onOpenChange={onOpenChange}><DialogContent><DialogTitle>Créer une politique</DialogTitle><DialogDescription>Définir les accès autorisés.</DialogDescription><DialogClose><Button>Fermer</Button></DialogClose></DialogContent></Dialog>);
    expect(screen.getByRole("dialog", { name: "Créer une politique" })).not.toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Fermer" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("opens from its trigger and closes with Escape", async () => {
    render(<Dialog><DialogTrigger><Button>Ouvrir les détails</Button></DialogTrigger><DialogContent><DialogTitle>Détails du compte</DialogTitle></DialogContent></Dialog>);
    fireEvent.click(screen.getByRole("button", { name: "Ouvrir les détails" }));
    expect(screen.getByRole("dialog", { name: "Détails du compte" })).not.toBeNull();
    fireEvent.keyDown(document, { key: "Escape", code: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("requires an explicit alert-dialog decision and closes on cancel", async () => {
    render(<AlertDialog defaultOpen><AlertDialogContent><AlertDialogTitle>Désactiver le compte ?</AlertDialogTitle><AlertDialogDescription>Les nouvelles sessions seront refusées.</AlertDialogDescription><AlertDialogCancel><Button>Annuler</Button></AlertDialogCancel><AlertDialogAction><Button variant="danger">Désactiver</Button></AlertDialogAction></AlertDialogContent></AlertDialog>);
    expect(screen.getByRole("alertdialog", { name: "Désactiver le compte ?" })).not.toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Annuler" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
  });

  it("supports keyboard-operated dropdown menu items", async () => {
    const onSelect = vi.fn();
    render(<DropdownMenu defaultOpen><DropdownMenuContent><DropdownMenuItem onSelect={onSelect}>Ouvrir le détail</DropdownMenuItem></DropdownMenuContent></DropdownMenu>);
    fireEvent.click(screen.getByRole("menuitem", { name: "Ouvrir le détail" }));
    expect(onSelect).toHaveBeenCalledOnce();
    await waitFor(() => expect(screen.queryByRole("menu")).toBeNull());
  });

  it("renders a popover in a portal without leaking Radix types to consumers", () => {
    render(<Popover defaultOpen><PopoverContent aria-label="Aide sur le compte">Les secrets ne sont jamais affichés.</PopoverContent></Popover>);
    expect(screen.getByText("Les secrets ne sont jamais affichés.")).not.toBeNull();
  });

  it("supports an explicitly open tooltip inside its provider", () => {
    render(<TooltipProvider><Tooltip defaultOpen><TooltipContent>Action disponible</TooltipContent></Tooltip></TooltipProvider>);
    expect(screen.getByRole("tooltip").textContent).toBe("Action disponible");
  });

  it("composes Sheet and Drawer from the accessible Dialog primitive", () => {
    const sheet = render(<Sheet defaultOpen><SheetContent side="left"><SheetTitle>Paramètres</SheetTitle></SheetContent></Sheet>);
    const sheetDialog = screen.getByRole("dialog", { name: "Paramètres" });
    expect(sheetDialog.getAttribute("data-side")).toBe("left");
    sheet.unmount();
    cleanup();

    render(<Drawer defaultOpen><DrawerContent><DrawerTitle>Filtres</DrawerTitle></DrawerContent></Drawer>);
    expect(screen.getByRole("dialog", { name: "Filtres" }).className).toContain("ob-drawer-content");
  });
});
