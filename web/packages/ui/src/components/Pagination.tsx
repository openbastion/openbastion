import { forwardRef, type ButtonHTMLAttributes, type HTMLAttributes, type ReactNode } from "react";
import { cn } from "../lib/cn";

export type PaginationProps = HTMLAttributes<HTMLElement> & { label?: string };
export const Pagination = forwardRef<HTMLElement, PaginationProps>(function Pagination({ className, label = "Pagination", ...props }, ref) { return <nav {...props} ref={ref} aria-label={label} className={cn("ob-pagination", className)} />; });
Pagination.displayName = "Pagination";
export type PaginationContentProps = HTMLAttributes<HTMLUListElement>;
export const PaginationContent = forwardRef<HTMLUListElement, PaginationContentProps>(function PaginationContent({ className, ...props }, ref) { return <ul {...props} ref={ref} className={cn("ob-pagination-content", className)} />; });
PaginationContent.displayName = "PaginationContent";
export type PaginationItemProps = HTMLAttributes<HTMLLIElement>;
export const PaginationItem = forwardRef<HTMLLIElement, PaginationItemProps>(function PaginationItem({ className, ...props }, ref) { return <li {...props} ref={ref} className={cn("ob-pagination-item", className)} />; });
PaginationItem.displayName = "PaginationItem";
export type PaginationLinkProps = ButtonHTMLAttributes<HTMLButtonElement> & { isActive?: boolean };
export const PaginationLink = forwardRef<HTMLButtonElement, PaginationLinkProps>(function PaginationLink({ isActive = false, className, ...props }, ref) { return <button {...props} ref={ref} type={props.type ?? "button"} aria-current={isActive ? "page" : undefined} data-active={isActive || undefined} className={cn("ob-pagination-link", className)} />; });
PaginationLink.displayName = "PaginationLink";
export function PaginationPrevious({ children = "Précédent", ...props }: PaginationLinkProps) { return <PaginationLink aria-label="Page précédente" {...props}>{children}</PaginationLink>; }
export function PaginationNext({ children = "Suivant", ...props }: PaginationLinkProps) { return <PaginationLink aria-label="Page suivante" {...props}>{children}</PaginationLink>; }
export function PaginationEllipsis({ children = "…" }: { children?: ReactNode }) { return <span className="ob-pagination-ellipsis" aria-hidden="true">{children}</span>; }
