import { type ReactNode } from "react";
import { AppBrandMark } from "./AppBrandMark";

function Chevron({ direction }: { direction: "left" | "right" }) {
  return (
    <svg
      viewBox="0 0 24 24"
      width="16"
      height="16"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {direction === "left" ? <path d="m15 18-6-6 6-6" /> : <path d="m9 18 6-6-6-6" />}
    </svg>
  );
}

export type AppSidebarBrandProps = {
  name: string;
  tagline?: string;
  mark?: ReactNode;
  collapsed?: boolean;
  expandLabel: string;
  collapseLabel: string;
  onToggleCollapse?: () => void;
  controlsId?: string;
  expandIcon?: ReactNode;
  collapseIcon?: ReactNode;
};

// The top of the sidebar: the mark, the product name and its tagline, and the control that
// collapses the navigation. Collapsing is a presentation choice the application persists; the
// shell only announces it (aria-expanded) and reports the click.
export function AppSidebarBrand({
  name,
  tagline,
  mark,
  collapsed = false,
  expandLabel,
  collapseLabel,
  onToggleCollapse,
  controlsId,
  expandIcon,
  collapseIcon,
}: AppSidebarBrandProps) {
  return (
    <div className="sidebar-brand">
      {mark ?? <AppBrandMark />}
      <span className="sidebar-brand-copy">
        <strong>{name}</strong>
        {tagline ? <small>{tagline}</small> : null}
      </span>
      {onToggleCollapse ? (
        <button
          type="button"
          className="sidebar-collapse-toggle"
          aria-label={collapsed ? expandLabel : collapseLabel}
          aria-controls={controlsId}
          aria-expanded={!collapsed}
          onClick={onToggleCollapse}
        >
          {collapsed ? (expandIcon ?? <Chevron direction="right" />) : (collapseIcon ?? <Chevron direction="left" />)}
        </button>
      ) : null}
    </div>
  );
}
