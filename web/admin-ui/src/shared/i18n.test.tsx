import { afterEach, describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import en from "./i18n/locales/en";
import fr from "./i18n/locales/fr";
import {
  changeLanguage,
  currentLanguage,
  languageStorageKey,
  readLanguage,
  supportedLanguages,
  useAppTranslation,
  writeLanguage,
} from "./i18n";
import { LanguageSwitcher } from "./ui/LanguageSwitcher";

function keysOf(value: unknown, prefix = ""): string[] {
  if (typeof value !== "object" || value === null) return [prefix];
  return Object.entries(value as Record<string, unknown>)
    .flatMap(([key, child]) => keysOf(child, prefix ? `${prefix}.${key}` : key))
    .sort();
}

// A screen whose label has no English translation would silently show French in English mode:
// this is what the parity test forbids.
describe("i18n resources", () => {
  it("defines the same keys in French and English", () => {
    expect(keysOf(en)).toEqual(keysOf(fr));
  });

  it("ships exactly French and English, French as the default", () => {
    expect([...supportedLanguages]).toEqual(["fr", "en"]);
    expect(currentLanguage()).toBe("fr");
  });
});

describe("language storage", () => {
  afterEach(() => {
    changeLanguage("fr");
    window.localStorage.clear();
  });

  it("reads only a supported language and falls back to French", () => {
    const stored = (value: string | null) => readLanguage({ getItem: () => value });
    expect(stored("en")).toBe("en");
    expect(stored("fr")).toBe("fr");
    expect(stored("de")).toBe("fr");
    expect(stored(null)).toBe("fr");
    expect(readLanguage({ getItem: () => { throw new Error("blocked"); } })).toBe("fr");
  });

  it("writes the choice and survives unavailable storage", () => {
    expect(writeLanguage("en", { setItem: () => undefined })).toBe(true);
    expect(writeLanguage("en", { setItem: () => { throw new Error("blocked"); } })).toBe(false);
  });
});

describe("LanguageSwitcher", () => {
  afterEach(() => {
    changeLanguage("fr");
    window.localStorage.clear();
  });

  it("switches the interface at once and remembers it", () => {
    function Screen() {
      const { t } = useAppTranslation();
      return (
        <>
          <LanguageSwitcher />
          <p>{t("shell.nav.overview.label")}</p>
        </>
      );
    }
    render(<Screen />);
    expect(screen.getByText("Vue générale")).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Langue"), { target: { value: "en" } });
    expect(screen.getByText("Overview")).toBeTruthy();
    expect(screen.getByLabelText("Language")).toBeTruthy();
    expect(document.documentElement.lang).toBe("en");
    expect(window.localStorage.getItem(languageStorageKey)).toBe("en");

    fireEvent.change(screen.getByLabelText("Language"), { target: { value: "fr" } });
    expect(screen.getByText("Vue générale")).toBeTruthy();
    expect(document.documentElement.lang).toBe("fr");
    expect(window.localStorage.getItem(languageStorageKey)).toBe("fr");
  });
});
