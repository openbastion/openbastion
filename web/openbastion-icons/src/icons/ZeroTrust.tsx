import type { SVGProps } from "react";

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, "width" | "height"> {
  size?: number | string;
  ariaLabel?: string;
}

export function ZeroTrust({ size = 24, ariaLabel, ...props }: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" role="img" aria-hidden={ariaLabel ? undefined : true} aria-label={ariaLabel} stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      <style>{".accent{stroke:var(--ob-icon-accent, currentColor);} .secondary{stroke:var(--ob-icon-accent, currentColor);}"}</style>
      <path d="M12 2.8 20 6v5.6c0 5-3.4 8.1-8 9.9-4.6-1.8-8-4.9-8-9.9V6z"/><circle className="accent" cx="12" cy="9" r="1.4"/><circle cx="8.5" cy="14" r="1.2"/><circle cx="15.5" cy="14" r="1.2"/><path d="m11.2 10.2-2 2.6m3.6-2.6 2 2.6m-4.9-.8h4.2"/>
      <path className="accent" d="M17 19h3"/>
    </svg>
  );
}
