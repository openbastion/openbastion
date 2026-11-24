import { Fragment } from "react";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "../components/Breadcrumb";
import { cn } from "../lib/cn";
import type { AppBreadcrumbItem } from "./types";

export type AppBreadcrumbsProps = {
  items: AppBreadcrumbItem[];
  label?: string;
  className?: string;
};

// Built on the Breadcrumb primitive: a real navigation landmark, an ordered list, and the last
// item marked as the current page. The application supplies the trail (workspace, destination),
// the shell only renders it.
export function AppBreadcrumbs({ items, label = "Fil d’Ariane", className = "topbar-breadcrumb" }: AppBreadcrumbsProps) {
  return (
    <Breadcrumb label={label} className={cn("topbar-breadcrumb", className)}>
      <BreadcrumbList>
        {items.map((item, index) => (
          <Fragment key={`${item.label}-${index}`}>
            {index > 0 ? <BreadcrumbSeparator /> : null}
            <BreadcrumbItem>
              {item.href ? (
                <BreadcrumbLink href={item.href}>{item.label}</BreadcrumbLink>
              ) : index === items.length - 1 ? (
                <BreadcrumbPage>{item.label}</BreadcrumbPage>
              ) : (
                <span>{item.label}</span>
              )}
            </BreadcrumbItem>
          </Fragment>
        ))}
      </BreadcrumbList>
    </Breadcrumb>
  );
}
