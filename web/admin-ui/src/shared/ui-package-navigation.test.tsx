import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger, Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator, Collapsible, CollapsibleContent, CollapsibleTrigger, Command, CommandEmpty, CommandInput, CommandItem, CommandList, ContextMenu, ContextMenuContent, ContextMenuItem, ContextMenuTrigger, HoverCard, HoverCardContent, Menubar, MenubarContent, MenubarItem, MenubarMenu, MenubarTrigger, NavigationMenu, NavigationMenuContent, NavigationMenuItem, NavigationMenuLink, NavigationMenuList, NavigationMenuTrigger, Pagination, PaginationContent, PaginationEllipsis, PaginationItem, PaginationLink, Sidebar, SidebarContent, SidebarGroup, SidebarGroupLabel, SidebarMenu, SidebarMenuButton, SidebarMenuItem, Tabs, TabsContent, TabsList, TabsTrigger } from "@openbastion/ui";

describe("@openbastion/ui navigation primitives", () => {
  it("opens an accordion section with its native keyboard-accessible trigger", () => {
    render(<Accordion type="single"><AccordionItem value="access"><AccordionTrigger>Accès</AccordionTrigger><AccordionContent>Règles d’accès privilégié</AccordionContent></AccordionItem></Accordion>);
    fireEvent.click(screen.getByRole("button", { name: "Accès" }));
    expect(screen.getByText("Règles d’accès privilégié")).not.toBeNull();
  });

  it("opens and closes a controlled collapsible disclosure", () => {
    const change = vi.fn();
    render(<Collapsible defaultOpen onOpenChange={change}><CollapsibleTrigger><button type="button">Afficher les détails</button></CollapsibleTrigger><CollapsibleContent>Détails techniques</CollapsibleContent></Collapsible>);
    expect(screen.getByText("Détails techniques")).not.toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Afficher les détails" }));
    expect(change).toHaveBeenCalledWith(false);
  });

  it("exposes breadcrumb semantics and the current page", () => {
    render(<Breadcrumb><BreadcrumbList><BreadcrumbItem><BreadcrumbLink href="/accounts">Comptes</BreadcrumbLink></BreadcrumbItem><BreadcrumbSeparator /><BreadcrumbItem><BreadcrumbPage>Serveur A</BreadcrumbPage></BreadcrumbItem></BreadcrumbList></Breadcrumb>);
    expect(screen.getByRole("navigation", { name: "Fil d’Ariane" })).not.toBeNull();
    expect(screen.getByText("Serveur A").getAttribute("aria-current")).toBe("page");
  });

  it("supports tab selection without coupling the content to application routing", () => {
    render(<Tabs defaultValue="overview"><TabsList><TabsTrigger value="overview">Vue générale</TabsTrigger><TabsTrigger value="events">Événements</TabsTrigger></TabsList><TabsContent value="overview">Résumé</TabsContent><TabsContent value="events">Journal d’audit</TabsContent></Tabs>);
    fireEvent.mouseDown(screen.getByRole("tab", { name: "Événements" }), { button: 0 });
    expect(screen.getByText("Journal d’audit")).not.toBeNull();
    expect(screen.getByRole("tab", { name: "Événements" }).getAttribute("data-state")).toBe("active");
  });

  it("filters command items and supports arrow-key focus navigation", () => {
    const selected = vi.fn();
    render(<Command><CommandInput aria-label="Rechercher une commande" /><CommandList><CommandItem value="open-account">Ouvrir un compte</CommandItem><CommandItem value="open-session" onSelect={selected}>Ouvrir une session</CommandItem><CommandEmpty>Aucun résultat</CommandEmpty></CommandList></Command>);
    const input = screen.getByRole("combobox", { name: "Rechercher une commande" });
    fireEvent.change(input, { target: { value: "session" } });
    expect(screen.queryByRole("option", { name: "Ouvrir un compte" })).toBeNull();
    const item = screen.getByRole("option", { name: "Ouvrir une session" });
    fireEvent.keyDown(input, { key: "ArrowDown" });
    expect(document.activeElement).toBe(item);
    fireEvent.click(item);
    expect(selected).toHaveBeenCalledWith("open-session");
    fireEvent.change(input, { target: { value: "absent" } });
    expect(screen.getByRole("status").textContent).toBe("Aucun résultat");
  });

  it("renders an accessible sidebar with an active destination", () => {
    render(<Sidebar label="Navigation"><SidebarContent><SidebarGroup><SidebarGroupLabel>Accès</SidebarGroupLabel><SidebarMenu><SidebarMenuItem><SidebarMenuButton active>Comptes</SidebarMenuButton></SidebarMenuItem></SidebarMenu></SidebarGroup></SidebarContent></Sidebar>);
    expect(screen.getByRole("complementary", { name: "Navigation" })).not.toBeNull();
    expect(screen.getByRole("button", { name: "Comptes" }).getAttribute("aria-current")).toBe("page");
  });

  it("renders pagination controls with the current page announced", () => {
    render(<Pagination><PaginationContent><PaginationItem><PaginationLink isActive aria-label="Page 2">2</PaginationLink></PaginationItem><PaginationItem><PaginationEllipsis /></PaginationItem></PaginationContent></Pagination>);
    expect(screen.getByRole("navigation", { name: "Pagination" })).not.toBeNull();
    expect(screen.getByRole("button", { name: "Page 2" }).getAttribute("aria-current")).toBe("page");
  });

  it("opens a menubar menu and selects an action", async () => {
    const select = vi.fn();
    render(<Menubar><MenubarMenu><MenubarTrigger>Actions</MenubarTrigger><MenubarContent><MenubarItem onSelect={select}>Exporter</MenubarItem></MenubarContent></MenubarMenu></Menubar>);
    fireEvent.pointerDown(screen.getByRole("menuitem", { name: "Actions" }), { button: 0, ctrlKey: false });
    fireEvent.click(await screen.findByRole("menuitem", { name: "Exporter" }));
    await waitFor(() => expect(select).toHaveBeenCalledOnce());
  });

  it("opens a navigation menu panel from its active item", () => {
    render(<NavigationMenu value="resources"><NavigationMenuList><NavigationMenuItem value="resources"><NavigationMenuTrigger>Ressources</NavigationMenuTrigger><NavigationMenuContent><NavigationMenuLink href="/servers">Serveurs</NavigationMenuLink></NavigationMenuContent></NavigationMenuItem></NavigationMenuList></NavigationMenu>);
    expect(screen.getByRole("link", { name: "Serveurs" })).not.toBeNull();
  });

  it("supports a context menu on a region", async () => {
    render(<ContextMenu><ContextMenuTrigger>Zone de travail</ContextMenuTrigger><ContextMenuContent><ContextMenuItem>Copier</ContextMenuItem></ContextMenuContent></ContextMenu>);
    fireEvent.contextMenu(screen.getByText("Zone de travail"));
    expect(await screen.findByRole("menuitem", { name: "Copier" })).not.toBeNull();
  });

  it("renders hover-card content in a portal", () => {
    render(<HoverCard defaultOpen><HoverCardContent>Informations sur la cible</HoverCardContent></HoverCard>);
    expect(screen.getByText("Informations sur la cible")).not.toBeNull();
  });
});
