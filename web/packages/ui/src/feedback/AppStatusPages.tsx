import type { ReactNode } from "react";
import { Alert } from "../components/Alert";

export type AppStatusPageProps = { title: string; detail: string; action?: ReactNode };

// Generic explicit refusals (ADR-0137 §5). The texts and the names of the missing rights belong to
// the application; the package only gives them a role and a shape.
export function AppForbiddenPage({ title, detail, action }: AppStatusPageProps) {
  return (
    <Alert tone="danger" data-status="403">
      <strong>{title}</strong>
      <p>{detail}</p>
      {action}
    </Alert>
  );
}

export function AppNotFoundPage({ title, detail, action }: AppStatusPageProps) {
  return (
    <Alert tone="warning" role="status" data-status="404">
      <strong>{title}</strong>
      <p>{detail}</p>
      {action}
    </Alert>
  );
}
