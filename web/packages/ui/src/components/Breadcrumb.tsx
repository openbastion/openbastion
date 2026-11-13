import { forwardRef, type AnchorHTMLAttributes, type HTMLAttributes, type ReactNode } from "react";
import { cn } from "../lib/cn";

export type BreadcrumbProps = HTMLAttributes<HTMLElement> & { children: ReactNode; label?: string };
export const Breadcrumb = forwardRef<HTMLElement, BreadcrumbProps>(function Breadcrumb({ className, label = "Fil d’Ariane", ...props }, ref) { return <nav {...props} ref={ref} aria-label={label} className={cn("ob-breadcrumb", className)} />; });
Breadcrumb.displayName = "Breadcrumb";
export type BreadcrumbListProps = HTMLAttributes<HTMLOListElement>;
export const BreadcrumbList = forwardRef<HTMLOListElement, BreadcrumbListProps>(function BreadcrumbList({ className, ...props }, ref) { return <ol {...props} ref={ref} className={cn("ob-breadcrumb-list", className)} />; });
BreadcrumbList.displayName = "BreadcrumbList";
export type BreadcrumbItemProps = HTMLAttributes<HTMLLIElement>;
export const BreadcrumbItem = forwardRef<HTMLLIElement, BreadcrumbItemProps>(function BreadcrumbItem({ className, ...props }, ref) { return <li {...props} ref={ref} className={cn("ob-breadcrumb-item", className)} />; });
BreadcrumbItem.displayName = "BreadcrumbItem";
export type BreadcrumbLinkProps = AnchorHTMLAttributes<HTMLAnchorElement>;
export const BreadcrumbLink = forwardRef<HTMLAnchorElement, BreadcrumbLinkProps>(function BreadcrumbLink({ className, ...props }, ref) { return <a {...props} ref={ref} className={cn("ob-breadcrumb-link", className)} />; });
BreadcrumbLink.displayName = "BreadcrumbLink";
export type BreadcrumbPageProps = HTMLAttributes<HTMLSpanElement>;
export const BreadcrumbPage = forwardRef<HTMLSpanElement, BreadcrumbPageProps>(function BreadcrumbPage({ className, ...props }, ref) { return <span {...props} ref={ref} aria-current="page" className={cn("ob-breadcrumb-page", className)} />; });
BreadcrumbPage.displayName = "BreadcrumbPage";
export function BreadcrumbSeparator({ children = "/" }: { children?: ReactNode }) { return <li className="ob-breadcrumb-separator" aria-hidden="true">{children}</li>; }
