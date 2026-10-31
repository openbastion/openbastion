import type { SVGProps } from "react";

export interface IconProps extends Omit<SVGProps<SVGSVGElement>, "width" | "height"> {
  size?: number | string;
  ariaLabel?: string;
}

export function Firewall({ size = 24, ariaLabel, ...props }: IconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" role="img" aria-hidden={ariaLabel ? undefined : true} aria-label={ariaLabel} stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
      <style>{".accent{stroke:var(--ob-icon-accent, #00D1FF);} .secondary{stroke:var(--ob-icon-accent, #00D1FF);}"}</style>
      <path d="M12 2.8 20 6v5.6c0 5-3.4 8.1-8 9.9-4.6-1.8-8-4.9-8-9.9V6z"/><path className="accent" d="m8.7 12.1 2.1 2.1 4.6-4.8"/>
      <path className="accent" d="M4 4h2.5M4 4v2.5"/>
    </svg>
  );
}
