import { ApiError } from "./api";
import { InlineNotice } from "./ui/InlineNotice";

// API-aware application wrapper; the shared primitive only owns presentation and live-region semantics.
export function Notice({ error, ok }: { error?: unknown; ok?: string }) {
  if (error) {
    const msg = error instanceof ApiError ? `${error.status} — ${error.message}` : String((error as Error)?.message ?? error);
    return <InlineNotice tone="danger">{msg}</InlineNotice>;
  }
  if (ok) return <InlineNotice tone="success">{ok}</InlineNotice>;
  return null;
}
