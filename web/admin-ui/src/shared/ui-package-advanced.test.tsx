import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AspectRatio, Avatar, Calendar, Carousel, Chart, Image, Progress, Resizable, ScrollArea, Toggle, ToggleGroup, ToggleGroupItem, isSafeImageSource, resolveImageSource } from "@openbastion/ui";

describe("@openbastion/ui advanced presentation primitives", () => {
  it("applies a semantic aspect ratio without inline styles", () => {
    render(<AspectRatio ratio="square" data-testid="ratio"><span>Contenu</span></AspectRatio>);
    expect(screen.getByTestId("ratio").getAttribute("data-ratio")).toBe("square");
    expect(screen.getByText("Contenu")).not.toBeNull();
  });

  it("uses avatar fallback when its image source is unsafe", () => {
    render(<Avatar src="javascript:alert(1)" alt="Alice" fallback="AL" />);
    expect(screen.getByText("AL").getAttribute("aria-label")).toBe("Alice");
    expect(screen.queryByRole("img")).toBeNull();
  });

  it("falls back after an avatar image fails to load", () => {
    render(<Avatar src="https://example.test/avatar.png" alt="Alice" fallback="AL" />);
    fireEvent.error(screen.getByRole("img", { name: "Alice" }));
    expect(screen.getByText("AL")).not.toBeNull();
  });

  it("uses a native date input for calendar selection", () => {
    render(<><label htmlFor="rotation-date">Date de rotation</label><Calendar id="rotation-date" defaultValue="2026-11-12" /></>);
    expect((screen.getByLabelText("Date de rotation") as HTMLInputElement).type).toBe("date");
    expect((screen.getByLabelText("Date de rotation") as HTMLInputElement).value).toBe("2026-11-12");
  });

  it("moves between carousel items and announces the current position", () => {
    const change = vi.fn();
    render(<Carousel label="Sessions récentes" items={[<span key="a">Session A</span>, <span key="b">Session B</span>]} onIndexChange={change} />);
    fireEvent.click(screen.getByRole("button", { name: "Élément suivant" }));
    expect(screen.getByText("Session B")).not.toBeNull();
    expect(screen.getByText("2 / 2")).not.toBeNull();
    expect(change).toHaveBeenCalledWith(1);
  });

  it("exposes chart values in an accessible SVG description", () => {
    render(<Chart title="Connexions" description="Par jour" data={[{ label: "Lun", value: 4 }, { label: "Mar", value: 7 }]} />);
    expect(screen.getByRole("img", { name: "Connexions. Valeur: Lun: 4, Mar: 7" })).not.toBeNull();
  });

  it("rejects executable image URLs and uses a safe fallback", () => {
    expect(isSafeImageSource("javascript:alert(1)")).toBe(false);
    expect(isSafeImageSource("//evil.example/image.png")).toBe(false);
    expect(isSafeImageSource("http://insecure.example/image.png")).toBe(false);
    expect(isSafeImageSource("https://cdn.example/image.png")).toBe(true);
    expect(resolveImageSource("javascript:alert(1)", "/assets/fallback.png")).toBe("/assets/fallback.png");
    render(<Image src="data:text/html,alert(1)" fallback="/assets/fallback.png" alt="Aperçu" placeholder="Aucun aperçu" />);
    const fallback = screen.getByRole("img", { name: "Aperçu" }) as HTMLImageElement;
    expect(fallback.getAttribute("src")).toBe("/assets/fallback.png");
    fireEvent.error(fallback);
    expect(screen.getByRole("img", { name: "Aperçu" }).textContent).toBe("Aucun aperçu");
  });

  it("provides a native accessible progress indicator", () => {
    render(<Progress label="Rotation" value={35} max={70} />);
    expect(screen.getByRole("progressbar", { name: "Rotation" }).getAttribute("value")).toBe("35");
  });

  it("exposes native resize and scroll regions with accessible names", () => {
    render(<><Resizable axis="horizontal" label="Panneau ajustable">Contenu</Resizable><ScrollArea label="Journal" axis="vertical">Événements</ScrollArea></>);
    const resizable = screen.getByRole("region", { name: "Panneau ajustable" });
    expect(resizable.getAttribute("data-axis")).toBe("horizontal");
    fireEvent.keyDown(resizable, { key: "ArrowRight" });
    expect(resizable.getAttribute("data-size")).toBe("1");
    expect(screen.getByRole("region", { name: "Journal" }).getAttribute("data-axis")).toBe("vertical");
  });

  it("supports an accessible pressed state for a standalone toggle", () => {
    const change = vi.fn();
    render(<Toggle aria-label="Mode compact" defaultPressed onPressedChange={change} />);
    const toggle = screen.getByRole("button", { name: "Mode compact" });
    expect(toggle.getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(toggle);
    expect(change).toHaveBeenCalledWith(false);
    expect(toggle.getAttribute("aria-pressed")).toBe("false");
  });

  it("supports multiple-selection toggle groups", () => {
    const change = vi.fn();
    render(<ToggleGroup type="multiple" defaultValue={["ssh"]} onValueChange={change}><ToggleGroupItem value="ssh">SSH</ToggleGroupItem><ToggleGroupItem value="rdp">RDP</ToggleGroupItem></ToggleGroup>);
    fireEvent.click(screen.getByRole("button", { name: "RDP" }));
    expect(change).toHaveBeenCalledWith(["ssh", "rdp"]);
    expect(screen.getByRole("button", { name: "RDP" }).getAttribute("aria-pressed")).toBe("true");
  });

  it("supports single-selection toggle groups", () => {
    const change = vi.fn();
    render(<ToggleGroup type="single" defaultValue="list" onValueChange={change}><ToggleGroupItem value="list">Liste</ToggleGroupItem><ToggleGroupItem value="grid">Grille</ToggleGroupItem></ToggleGroup>);
    fireEvent.click(screen.getByRole("button", { name: "Grille" }));
    expect(change).toHaveBeenCalledWith("grid");
    expect(screen.getByRole("button", { name: "Grille" }).getAttribute("aria-pressed")).toBe("true");
  });
});
