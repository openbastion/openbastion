import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import {
  AppBreadcrumbs,
  AppHeader,
  AppNavigation,
  AppPage,
  AppPageHead,
  AppShell,
  AppSidebar,
  AppSidebarBrand,
  AppSidebarFooter,
} from "@openbastion/ui";
import type { AppNavigationSection } from "@openbastion/ui";

const Icon = ({ size }: { size?: number | string }) => <svg aria-hidden="true" data-size={size} />;

const sections: AppNavigationSection[] = [
  {
    id: "workspace",
    label: "Espace de travail",
    items: [
      { id: "overview", label: "Vue d’ensemble", description: "L’état de l’instance", icon: Icon, active: true },
      { id: "accounts", label: "Accès privilégiés", description: "Comptes et politiques", icon: Icon, favorite: true },
    ],
  },
];

function Shell() {
  return (
    <AppShell
      skipLink={<a className="skip-link" href="#main-content">Aller au contenu principal</a>}
      sidebar={
        <AppSidebar
          brand={
            <AppSidebarBrand
              name="OpenBastion"
              tagline="Console d’administration"
              expandLabel="Développer la navigation"
              collapseLabel="Réduire la navigation"
              onToggleCollapse={() => undefined}
              controlsId="admin-navigation"
            />
          }
          footer={<AppSidebarFooter title="Console" detail="Instance unique" />}
        >
          <AppNavigation label="Sections" sections={sections} favorites={{ label: "Favoris", items: [sections[0].items[1]] }} />
        </AppSidebar>
      }
      header={<AppHeader breadcrumbs={<AppBreadcrumbs items={[{ label: "Espace de travail" }, { label: "Vue d’ensemble" }]} />} actions={<span>Production</span>} />}
      banner={<p role="status">Capacités indisponibles</p>}
      footer={<footer aria-label="Informations légales">Licence AGPL-3.0</footer>}
    >
      <p>Écran</p>
    </AppShell>
  );
}

describe("@openbastion/ui — AppShell structure (ADR-0137 §8, incrément 3)", () => {
  it("renders the workspace grid: sidebar landmark, content column, main landmark and footer as grid items", () => {
    render(<Shell />);
    const sidebar = screen.getByRole("complementary", { name: "Navigation principale" });
    const main = screen.getByRole("main");
    const footer = screen.getByRole("contentinfo", { name: "Informations légales" });
    const grid = sidebar.parentElement;
    expect(grid?.classList.contains("app-workspace")).toBe(true);
    expect(main.parentElement?.classList.contains("app-content")).toBe(true);
    expect(main.getAttribute("id")).toBe("main-content");
    expect(main.getAttribute("tabindex")).toBe("-1");
    expect(footer.parentElement).toBe(grid);
    expect(within(main).getByRole("status").textContent).toBe("Capacités indisponibles");
    expect(screen.getByRole("link", { name: "Aller au contenu principal" }).getAttribute("href")).toBe("#main-content");
  });

  it("marks the sidebar as a modal dialog on a narrow viewport and disables the content behind it", () => {
    render(
      <AppShell mobileOpen onMobileClose={() => undefined} sidebar={<AppSidebar mobileOpen><span /></AppSidebar>}>
        <p>Écran</p>
      </AppShell>,
    );
    const dialog = screen.getByRole("dialog", { name: "Navigation principale" });
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    expect(screen.getByRole("main").hasAttribute("inert")).toBe(true);
    expect(dialog.parentElement?.classList.contains("mobile-navigation-open")).toBe(true);
  });

  it("announces the collapsed state on the brand control and reports the click", () => {
    const onToggleCollapse = vi.fn();
    render(
      <AppSidebarBrand
        name="OpenBastion"
        expandLabel="Développer la navigation"
        collapseLabel="Réduire la navigation"
        onToggleCollapse={onToggleCollapse}
        controlsId="admin-navigation"
      />,
    );
    const collapse = screen.getByRole("button", { name: "Réduire la navigation" });
    expect(collapse.getAttribute("aria-expanded")).toBe("true");
    expect(collapse.getAttribute("aria-controls")).toBe("admin-navigation");
    fireEvent.click(collapse);
    expect(onToggleCollapse).toHaveBeenCalledTimes(1);
  });

  it("renders favorites first, marks the current destination and reports selection", () => {
    const onSelect = vi.fn();
    render(<AppNavigation label="Sections" sections={sections} favorites={{ label: "Favoris", items: [sections[0].items[1]] }} onSelect={onSelect} />);
    const navigation = screen.getByRole("navigation", { name: "Sections" });
    const groups = within(navigation).getAllByRole("heading", { level: 2 });
    expect(groups.map((heading) => heading.textContent)).toEqual(["Favoris", "Espace de travail"]);
    const current = within(navigation).getByRole("button", { name: "Vue d’ensemble" });
    expect(current.getAttribute("aria-current")).toBe("page");
    expect(current.querySelector("svg")?.getAttribute("data-size")).toBe("18");
    fireEvent.click(within(navigation).getAllByRole("button", { name: "Accès privilégiés" })[0]);
    expect(onSelect).toHaveBeenCalledWith("accounts");
  });

  it("exposes the favorite state and its accessible name, and opens external resources in a new tab", () => {
    const onToggleFavorite = vi.fn();
    render(
      <AppNavigation
        label="Sections"
        sections={sections}
        onToggleFavorite={onToggleFavorite}
        favoriteActionLabel={(item) => (item.favorite ? `Retirer ${item.label}` : `Ajouter ${item.label}`)}
        resources={{ label: "Ressources", items: [{ id: "docs", label: "Documentation", href: "https://example.test/docs", external: true, icon: Icon }] }}
      />,
    );
    const navigation = screen.getByRole("navigation", { name: "Sections" });
    const remove = within(navigation).getByRole("button", { name: "Retirer Accès privilégiés" });
    expect(remove.getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(remove);
    expect(onToggleFavorite).toHaveBeenCalledWith("accounts");
    const docs = within(navigation).getByRole("link", { name: "Documentation" });
    expect(docs.getAttribute("href")).toBe("https://example.test/docs");
    expect(docs.getAttribute("target")).toBe("_blank");
    expect(docs.getAttribute("rel")).toBe("noreferrer");
  });

  it("shows the destination description as a title only when the sidebar is collapsed", () => {
    const { rerender } = render(<AppNavigation label="Sections" sections={sections} />);
    expect(screen.getByRole("button", { name: "Vue d’ensemble" }).getAttribute("title")).toBeNull();
    rerender(<AppNavigation label="Sections" sections={sections} collapsed />);
    expect(screen.getByRole("button", { name: "Vue d’ensemble" }).getAttribute("title")).toBe("Vue d’ensemble — L’état de l’instance");
  });

  it("renders the breadcrumb as a named landmark whose last item is the current page", () => {
    render(<AppBreadcrumbs items={[{ label: "Espace de travail", href: "/ui/" }, { label: "Vue d’ensemble" }]} />);
    const trail = screen.getByRole("navigation", { name: "Fil d’Ariane" });
    const link = within(trail).getByRole("link", { name: "Espace de travail" });
    expect(link.getAttribute("href")).toBe("/ui/");
    expect(within(trail).getByText("Vue d’ensemble").getAttribute("aria-current")).toBe("page");
    expect(trail.querySelectorAll(".ob-breadcrumb-separator")).toHaveLength(1);
  });

  it("puts the header actions in their own cluster and can be inert behind a modal", () => {
    render(<AppHeader breadcrumbs={<span>Fil</span>} search={<button type="button">Rechercher</button>} actions={<span>Production</span>} inert />);
    const header = screen.getByRole("banner");
    expect(header.hasAttribute("inert")).toBe(true);
    expect(within(header).getByRole("button", { name: "Rechercher" })).toBeTruthy();
    expect(within(header).getByText("Production").parentElement?.classList.contains("header-actions")).toBe(true);
  });

  it("frames a screen with its heading, subtitle, a single hint and the action that belongs to it", () => {
    render(
      <AppPage title="Comptes" subtitle="Les comptes du coffre" hints={["Le secret n’est jamais rendu"]} actions={<button type="button">Enregistrer</button>}>
        <p>Contenu</p>
      </AppPage>,
    );
    const heading = screen.getByRole("heading", { level: 2, name: "Comptes" });
    expect(heading.getAttribute("tabindex")).toBe("-1");
    expect(screen.getByText("Les comptes du coffre").className).toBe("ob-page-subtitle");
    expect(screen.getByText("Le secret n’est jamais rendu").className).toBe("ob-hint");
    expect(screen.queryByText("Consignations")).toBeNull();
    expect(screen.getByRole("button", { name: "Enregistrer" }).parentElement?.classList.contains("page-actions")).toBe(true);
  });

  it("folds several hints into one disclosure whose label the application supplies", () => {
    render(<AppPageHead title="Sessions" hints={["Un", "Deux", "Trois"]} hintsLabel="À savoir avant d’agir (3)" />);
    const disclosure = screen.getByText("À savoir avant d’agir (3)").closest("details");
    expect(disclosure?.classList.contains("page-hints")).toBe(true);
    expect(within(disclosure as HTMLElement).getAllByText(/^(Un|Deux|Trois)$/)).toHaveLength(3);
  });
});
