import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { Api } from "../shared/api";
import "@openbastion/icons/styles.css";
import "./styles.css";

// ONE client for the page's lifetime. App's `api = new Api()` default only applies when no prop
// is passed, and it is evaluated on every render: the token set at login landed on an instance
// the next render had already replaced, so every call after signing in went out unauthenticated.
const api = new Api();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App api={api} />
  </StrictMode>,
);
