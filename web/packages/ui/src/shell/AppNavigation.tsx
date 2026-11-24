import { type ReactNode } from "react";
import { cn } from "../lib/cn";
import type { AppNavigationItemDescriptor, AppNavigationResource, AppNavigationSection } from "./types";

export type AppNavigationProps = {
  label: string;
  sections: AppNavigationSection[];
  favorites?: { label: string; items: AppNavigationItemDescriptor[] };
  resources?: { label: string; items: AppNavigationResource[] };
  collapsed?: boolean;
  onSelect?: (id: string) => void;
  onToggleFavorite?: (id: string) => void;
  // Accessible names for the favorite toggle, in the application's language. Without them the
  // toggle falls back to the destination label, which is still a usable name.
  favoriteActionLabel?: (item: AppNavigationItemDescriptor) => string;
  favoriteTitle?: (item: AppNavigationItemDescriptor) => string;
  favoriteIcon?: ReactNode;
  favoriteIconActive?: ReactNode;
  className?: string;
};

function NavigationItem({
  item,
  collapsed,
  onSelect,
  onToggleFavorite,
  favoriteActionLabel,
  favoriteTitle,
  favoriteIcon = "☆",
  favoriteIconActive = "★",
}: {
  item: AppNavigationItemDescriptor;
  collapsed: boolean;
  onSelect?: (id: string) => void;
  onToggleFavorite?: (id: string) => void;
  favoriteActionLabel?: (item: AppNavigationItemDescriptor) => string;
  favoriteTitle?: (item: AppNavigationItemDescriptor) => string;
  favoriteIcon?: ReactNode;
  favoriteIconActive?: ReactNode;
}) {
  const Icon = item.icon;
  return (
    <div className="nav-entry">
      <button
        type="button"
        className="nav-item"
        aria-label={item.label}
        aria-current={item.active ? "page" : undefined}
        title={collapsed && item.description ? `${item.label} — ${item.description}` : undefined}
        onClick={onSelect ? () => onSelect(item.id) : undefined}
      >
        {Icon ? <Icon size={18} /> : null}
        <span className="nav-item-label">{item.label}</span>
      </button>
      {onToggleFavorite ? (
        <button
          type="button"
          className="nav-favorite-toggle"
          aria-label={favoriteActionLabel ? favoriteActionLabel(item) : item.label}
          aria-pressed={Boolean(item.favorite)}
          title={favoriteTitle ? favoriteTitle(item) : undefined}
          onClick={() => onToggleFavorite(item.id)}
        >
          {item.favorite ? favoriteIconActive : favoriteIcon}
        </button>
      ) : null}
    </div>
  );
}

// The navigation landmark: favorites first, then the declared sections, then external resources.
// Every destination, its order, its icon and its favorite state come from the caller; the shell
// adds the landmarks, the current-page marker and the collapsed behaviour.
export function AppNavigation({
  label,
  sections,
  favorites,
  resources,
  collapsed = false,
  onSelect,
  onToggleFavorite,
  favoriteActionLabel,
  favoriteTitle,
  favoriteIcon,
  favoriteIconActive,
  className,
}: AppNavigationProps) {
  return (
    <nav aria-label={label} className={cn(className)}>
      {favorites && favorites.items.length > 0 ? (
        <div className="nav-group">
          <h2 className="nav-group-title">{favorites.label}</h2>
          {favorites.items.map((item) => (
            <NavigationItem
              key={`favorite-${item.id}`}
              item={item}
              collapsed={collapsed}
              onSelect={onSelect}
              onToggleFavorite={onToggleFavorite}
              favoriteActionLabel={favoriteActionLabel}
              favoriteTitle={favoriteTitle}
              favoriteIcon={favoriteIcon}
              favoriteIconActive={favoriteIconActive}
            />
          ))}
        </div>
      ) : null}
      {sections.map((section) => (
        <div className="nav-group" key={section.id}>
          <h2 className="nav-group-title">{section.label}</h2>
          {section.items.map((item) => (
            <NavigationItem
              key={item.id}
              item={item}
              collapsed={collapsed}
              onSelect={onSelect}
              onToggleFavorite={onToggleFavorite}
              favoriteActionLabel={favoriteActionLabel}
              favoriteTitle={favoriteTitle}
              favoriteIcon={favoriteIcon}
              favoriteIconActive={favoriteIconActive}
            />
          ))}
        </div>
      ))}
      {resources && resources.items.length > 0 ? (
        <div className="nav-group nav-resources">
          <h2 className="nav-group-title">{resources.label}</h2>
          {resources.items.map((resource) => {
            const Icon = resource.icon;
            return (
              <a
                key={resource.id}
                className="sidebar-resource-link"
                href={resource.href}
                target={resource.external ? "_blank" : undefined}
                rel={resource.external ? "noreferrer" : undefined}
              >
                {Icon ? <Icon size={16} /> : null}
                {resource.label}
              </a>
            );
          })}
        </div>
      ) : null}
    </nav>
  );
}
