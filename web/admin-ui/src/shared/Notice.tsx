import { ApiError } from "./api";

// Notice shows an outcome. Text only: React escapes it, nothing is ever inserted as HTML.
export function Notice({ error, ok }: { error?: unknown; ok?: string }) {
  if (error) {
    const msg = error instanceof ApiError ? `${error.status} — ${error.message}` : String((error as Error)?.message ?? error);
    return <p className="notice error" role="alert">{msg}</p>;
  }
  if (ok) return <p className="notice ok" role="status">{ok}</p>;
  return null;
}
