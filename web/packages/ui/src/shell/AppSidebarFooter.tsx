export type AppSidebarFooterProps = {
  title: string;
  detail: string;
};

// The state of the console, at the bottom of the sidebar. It states a fact, not a destination.
export function AppSidebarFooter({ title, detail }: AppSidebarFooterProps) {
  return (
    <div className="sidebar-footer">
      <div className="sidebar-footer-heading">
        <span className="sidebar-status-dot" aria-hidden="true" />
        <strong>{title}</strong>
      </div>
      <p>{detail}</p>
    </div>
  );
}
