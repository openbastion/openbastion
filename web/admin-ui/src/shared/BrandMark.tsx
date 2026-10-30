// The OpenBastion shield, shared by the application header and the login card so the two stay
// identical. Decorative: the brand name is always spelled out next to it.
export function BrandMark({ className = "brand-mark" }: { className?: string }) {
  return (
    <span className={className} aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 3 4.5 6v5.4c0 4.4 3.1 8.2 7.5 9.6 4.4-1.4 7.5-5.2 7.5-9.6V6L12 3Z" />
        <path d="m9.4 12.2 1.9 1.9 3.5-3.8" />
      </svg>
    </span>
  );
}
