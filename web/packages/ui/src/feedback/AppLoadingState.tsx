import { cn } from "../lib/cn";

export type AppLoadingStateProps = {
  // Announced to assistive technology, in the application's language.
  label: string;
  lines?: number;
  className?: string;
};

// A screen waiting for its data: one polite status region, a few placeholder lines. No timer and
// no application state; the caller decides when it is shown.
export function AppLoadingState({ label, lines = 3, className }: AppLoadingStateProps) {
  return (
    <div className={cn("app-loading-state", className)} role="status" aria-busy="true" aria-live="polite">
      <span className="ob-visually-hidden">{label}</span>
      {Array.from({ length: lines }, (_, index) => (
        <span key={index} className="ob-skeleton" aria-hidden="true" />
      ))}
    </div>
  );
}
