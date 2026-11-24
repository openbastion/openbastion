import type { ComponentType, ReactNode } from "react";

// The shell knows nothing about the application: destinations, their labels, their icons and
// their capability guards all come from the caller (ADR-0137 §3 and §8). These types are the
// whole contract between an application and the shared navigation.
export type AppNavigationIcon = ComponentType<{ size?: number | string; className?: string }>;

export type AppNavigationItemDescriptor = {
  id: string;
  label: string;
  // Shown as the button title when the sidebar is collapsed: what the destination is.
  description?: string;
  icon?: AppNavigationIcon;
  active?: boolean;
  favorite?: boolean;
};

export type AppNavigationSection = {
  id: string;
  label: string;
  items: AppNavigationItemDescriptor[];
};

export type AppNavigationResource = {
  id: string;
  label: string;
  href: string;
  icon?: AppNavigationIcon;
  // Off by default: a resource that leaves the application opens in a new tab without a handle.
  external?: boolean;
};

export type AppBreadcrumbItem = {
  label: string;
  href?: string;
};

export type AppShellSlot = ReactNode;
