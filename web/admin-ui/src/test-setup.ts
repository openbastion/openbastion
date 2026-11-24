import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

// One clean document and clean storage per test. The operator preferences and the theme live in
// localStorage and on <html data-theme>/<html data-density>; a leftover from the previous test
// would make the next one pass for the wrong reason. This is what makes the navigation tests a
// real non-regression net for the router migration (ADR-0137, increments 7 to 11): a route test
// must never inherit the previous route's persisted default destination.
afterEach(() => {
  cleanup();
  window.localStorage.clear();
  window.sessionStorage.clear();
  delete document.documentElement.dataset.theme;
  delete document.documentElement.dataset.density;
});
